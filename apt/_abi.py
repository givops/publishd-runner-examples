"""Self-contained Script ABI v1, dpkg-deb/reprepro, and OpenSSH/rsync helpers for apt."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

MAX_REQUEST_BYTES = 4 * 1024 * 1024
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SSH_ALIAS_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")
SSH_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class Rejected(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(text: str) -> dict[str, object]:
    decoder = json.JSONDecoder(object_pairs_hook=strict_object)
    stripped = text.lstrip(" \t\r\n")
    obj, end = decoder.raw_decode(stripped)
    if stripped[end:].strip(" \t\r\n") or not isinstance(obj, dict):
        raise ValueError("Invalid JSON root")
    return obj


def text_value(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("Invalid string")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("Control character")
    return value


def request(operation: str) -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("Request too large")
    value = read_json(raw.decode("utf-8"))
    common = {"abiVersion", "operation", "operationId", "optionId", "serverId", "channelId"}
    fields = {"projectId", "version"} if operation == "publish" else {"projectIds", "purpose"}
    if set(value) != common | fields:
        raise ValueError("Invalid schema")
    if type(value["abiVersion"]) is not int or value["abiVersion"] != 1 or value["operation"] != operation:
        raise ValueError("Invalid ABI")
    for name in ("operationId", "optionId"):
        text_value(value[name], 255)
    for name in ("serverId", "channelId"):
        if not KEY_RE.fullmatch(text_value(value[name], 128)):
            raise ValueError("Invalid key")
    if operation == "publish":
        text_value(value["projectId"], 255)
        text_value(value["version"], 1024)
    else:
        if value["purpose"] not in {"REFRESH", "VERIFY"}:
            raise ValueError("Invalid purpose")
        projects = value["projectIds"]
        if not isinstance(projects, list) or len(projects) > 20000:
            raise ValueError("Invalid scope")
        for project in projects:
            text_value(project, 255)
        if len(projects) != len(set(projects)):
            raise ValueError("Duplicate project")
    return value


def load_config() -> dict[str, object]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    path = Path(parser.parse_args().config)
    if not path.is_absolute():
        raise ValueError("Config path must be absolute")
    return read_json(path.read_text(encoding="utf-8"))


def destination(config: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    matches = [
        d for d in config["destinations"]  # type: ignore[index]
        if d["serverId"] == req["serverId"]
        and d["channelId"] == req["channelId"]
        and req["optionId"] in d["optionIds"]
    ]
    if len(matches) != 1:
        raise Rejected("DESTINATION_REJECTED")
    return matches[0]


def absolute(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError("Private path must be a string")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Private path must be absolute")
    return path


@contextlib.contextmanager
def resource_lock(target: dict[str, object]):
    path = absolute(target["resourceLock"])
    with path.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".pending-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def result(req: dict[str, object], outcome: str, code: str | None = None) -> dict[str, object]:
    value: dict[str, object] = {"abiVersion": 1, "operationId": req["operationId"], "outcome": outcome}
    if code:
        value["errorCode"] = code
    return value


def journaled_publish(config: dict[str, object], target: dict[str, object],
                      req: dict[str, object], prepare, mutate) -> dict[str, object]:
    journal = absolute(config["journalRoot"]) / (digest(str(req["operationId"])) + ".json")
    fingerprint = digest(json.dumps(req, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if journal.exists():
        old = read_json(journal.read_text(encoding="utf-8"))
        if old["fingerprint"] != fingerprint:
            return result(req, "REJECTED", "OPERATION_CONFLICT")
        stored = old.get("result")
        return stored if isinstance(stored, dict) else result(req, "UNKNOWN", "PUBLICATION_UNCERTAIN")
    try:
        prepared = prepare(config, target, req)
    except Rejected as error:
        return result(req, "REJECTED", error.code)
    atomic_json(journal, {"fingerprint": fingerprint})
    try:
        outcome = mutate(config, target, req, prepared)
        if outcome not in {"APPLIED", "ALREADY_PRESENT"}:
            raise ValueError("Invalid mutation outcome")
        response = result(req, outcome)
    except Exception:
        response = result(req, "UNKNOWN", "PUBLICATION_UNCERTAIN")
    atomic_json(journal, {"fingerprint": fingerprint, "result": response})
    return response


def inventory_result(req: dict[str, object], deployments: list[dict[str, object]]) -> dict[str, object]:
    return {
        "abiVersion": 1,
        "operationId": req["operationId"],
        "serverId": req["serverId"],
        "channelId": req["channelId"],
        "complete": True,
        "observationMode": "AUTHORITATIVE",
        "sourceObservedAt": None,
        "sourceStale": False,
        "deployments": deployments,
    }


def apt_command(arguments: list[str]) -> bytes:
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        env=SSH_ENV,
    ).stdout


def package_name(config: dict[str, object], project: str) -> str:
    projects = config.get("projects")
    if not isinstance(projects, dict):
        raise Rejected("ARTIFACT_REJECTED")
    name = projects.get(project)
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name):
        raise Rejected("ARTIFACT_REJECTED")
    return name


def scope(target: dict[str, object]) -> list[str]:
    values = [str(target[key]) for key in ("distribution", "component", "architecture")]
    if any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", value) for value in values):
        raise ValueError("Invalid private repository scope")
    return values


def deb_metadata(path: Path) -> dict[str, str]:
    output = apt_command(["/usr/bin/dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"])
    fields: dict[str, str] = {}
    for line in output.decode("utf-8").splitlines():
        key, value = line.split(":", 1)
        fields[key] = value.strip()
    if set(fields) != {"Package", "Version", "Architecture"}:
        raise ValueError("Invalid package metadata")
    return fields


def control_records(text: str):
    """Parse Debian control paragraphs; reject duplicates and malformed content."""
    record: dict[str, str] = {}
    previous: str | None = None
    for line in text.splitlines() + [""]:
        if not line:
            if record:
                yield record
            record, previous = {}, None
        elif line[0].isspace():
            if previous is None:
                raise ValueError("Invalid control continuation")
            record[previous] += "\n" + line
        else:
            key, value = line.split(":", 1)
            if key in record:
                raise ValueError("Duplicate control field")
            record[key] = value.lstrip()
            previous = key


def destination_rows(config: dict[str, object], target: dict[str, object],
                     projects: list[str]) -> list[dict[str, object]]:
    distribution, component, architecture = scope(target)
    root = absolute(target["root"]).resolve(strict=True)
    index = root / "dists" / distribution / component / ("binary-" + architecture) / "Packages"
    if index.is_symlink() or index.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Invalid destination index")
    index_bytes = index.read_bytes()
    release_file = root / "dists" / distribution / "Release"
    releases = list(control_records(release_file.read_text(encoding="utf-8")))
    if len(releases) != 1:
        raise ValueError("Invalid release")
    relative_index = f"{component}/binary-{architecture}/Packages"
    checksums = [line.split() for line in releases[0]["SHA256"].splitlines() if line.strip()]
    expected = [parts for parts in checksums if len(parts) == 3 and parts[2] == relative_index]
    if (
        len(expected) != 1
        or expected[0][0] != hashlib.sha256(index_bytes).hexdigest()
        or expected[0][1] != str(len(index_bytes))
    ):
        raise ValueError("Incomplete or inconsistent export")
    mapping = {package_name(config, project): project for project in projects}
    if len(mapping) != len(projects):
        raise ValueError("Ambiguous private project mapping")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for entry in control_records(index_bytes.decode("utf-8")):
        package = entry.get("Package")
        if package not in mapping:
            continue
        version = text_value(entry["Version"], 1024)
        if entry["Architecture"] not in {architecture, "all"}:
            raise ValueError("Index architecture mismatch")
        project = mapping[package]
        if project in seen:
            raise ValueError("Ambiguous published version")
        seen.add(project)
        filename = Path(entry["Filename"])
        if filename.is_absolute() or ".." in filename.parts:
            raise ValueError("Invalid pool filename")
        artifact = (root / filename).resolve(strict=True)
        if not artifact.is_relative_to(root):
            raise ValueError("Pool file outside repository")
        checksum = entry["SHA256"]
        if not re.fullmatch(r"[a-f0-9]{64}", checksum):
            raise ValueError("Invalid pool checksum")
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != checksum:
            raise ValueError("Pool checksum mismatch")
        if deb_metadata(artifact) != {"Package": package, "Version": version, "Architecture": entry["Architecture"]}:
            raise ValueError("Pool metadata mismatch")
        rows.append({"projectId": project, "version": version, "sourceObservedAt": None})
        if len(rows) > 20000:
            raise ValueError("Inventory too large")
    return sorted(rows, key=lambda row: str(row["projectId"]))


def ssh_command(arguments: list[str], payload: bytes = b"", timeout: float = 120) -> bytes:
    """Bound stdin/stdout/stderr pipes and elapsed time for SSH and rsync."""
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SSH_ENV,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    output, errors = bytearray(), bytearray()
    pending = memoryview(payload)
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            if pending:
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Remote command timed out")
                for key, _ in selector.select(remaining):
                    if key.fileobj is process.stdin:
                        count = process.stdin.write(pending[:4096])
                        process.stdin.flush()
                        pending = pending[count:]
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        block = key.fileobj.read1(65536)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            key.data.extend(block)
                            limit = 4 * 1024 * 1024 if key.data is output else 16384
                            if len(key.data) > limit:
                                raise ValueError("Remote output exceeded limit")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError("Remote command failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def ssh_settings(target: dict[str, object]) -> dict[str, str]:
    remote = target["ssh"]
    if not isinstance(remote, dict):
        raise ValueError("Invalid SSH settings")
    host = remote.get("host")
    if not isinstance(host, str) or not SSH_ALIAS_RE.fullmatch(host):
        raise ValueError("Invalid SSH alias")
    for key in ("configFile", "publishScript", "inventoryScript", "config", "stagingRoot"):
        absolute(remote[key])
    return remote  # type: ignore[return-value]


def ssh_arguments(remote: dict[str, str]) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-F", remote["configFile"],
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=10",
        "-oServerAliveInterval=15",
        "-oServerAliveCountMax=2",
        "-oForwardAgent=no",
        "-oClearAllForwardings=yes",
    ]


def invoke_ssh(target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    remote = ssh_settings(target)
    script = remote["publishScript" if req["operation"] == "publish" else "inventoryScript"]
    arguments = ssh_arguments(remote) + [
        remote["host"],
        shlex.join(["/usr/bin/python3", "-I", script, "--config", remote["config"]]),
    ]
    payload = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    response = read_json(ssh_command(arguments, payload).decode("utf-8"))
    if (
        type(response.get("abiVersion")) is not int
        or response["abiVersion"] != 1
        or response.get("operationId") != req["operationId"]
    ):
        raise ValueError("Invalid remote response")
    return response


def remote_apt_inventory(config: dict[str, object], target: dict[str, object],
                         req: dict[str, object]) -> dict[str, object]:
    response = invoke_ssh(target, req)
    if (
        response.get("serverId") != req["serverId"]
        or response.get("channelId") != req["channelId"]
        or response.get("complete") is not True
        or response.get("observationMode") != "AUTHORITATIVE"
        or response.get("sourceStale") is not False
        or response.get("sourceObservedAt") is not None
    ):
        raise ValueError("Invalid remote inventory")
    rows = response.get("deployments")
    project_ids = req["projectIds"]
    if not isinstance(rows, list) or not isinstance(project_ids, list) or len(rows) > len(project_ids):
        raise ValueError("Invalid remote inventory scope")
    seen: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"projectId", "version", "sourceObservedAt"}
            or row["projectId"] not in project_ids
            or row["projectId"] in seen
            or row["sourceObservedAt"] is not None
        ):
            raise ValueError("Invalid remote inventory row")
        text_value(row["version"], 1024)
        seen.add(str(row["projectId"]))
    return inventory_result(req, rows)


def remote_apt_publish(config: dict[str, object], target: dict[str, object],
                       req: dict[str, object], resolve_fn) -> dict[str, object]:
    def prepare(c, t, r):
        ssh_settings(t)
        return resolve_fn(c, t, r)

    def mutate(c, t, r, artifact: Path):
        remote = ssh_settings(t)
        with tempfile.TemporaryDirectory(prefix="publishd-transfer-") as temporary:
            root = Path(temporary)
            shutil.copyfile(artifact, root / "artifact.deb")
            dest = str(absolute(remote["stagingRoot"]) / digest(str(r["operationId"]))) + "/"
            ssh_command([
                "/usr/bin/rsync",
                "--recursive",
                "--perms",
                "--chmod=D700,F600",
                "--protect-args",
                "--timeout=120",
                "--rsh",
                shlex.join(ssh_arguments(remote)),
                "--",
                str(root) + "/",
                remote["host"] + ":" + dest,
            ])
        response = invoke_ssh(t, r)
        if set(response) != {"abiVersion", "operationId", "outcome"} or response["outcome"] not in {
            "APPLIED",
            "ALREADY_PRESENT",
        }:
            raise ValueError("Remote publication did not confirm completion")
        return str(response["outcome"])

    return journaled_publish(config, target, req, prepare, mutate)


def run(operation: str, publish=None, inventory=None) -> None:
    req = None
    try:
        req = request(operation)
        config = load_config()
        target = destination(config, req)
        with resource_lock(target):
            response = publish(config, target, req) if operation == "publish" else inventory(config, target, req)
        print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    except Rejected as error:
        if operation == "publish" and req is not None:
            print(json.dumps(result(req, "REJECTED", error.code), ensure_ascii=False, separators=(",", ":")))
        else:
            print("Inventory scope rejected", file=sys.stderr)
            sys.exit(1)
    except Exception:
        print("APT adapter could not complete the request", file=sys.stderr)
        sys.exit(1)

"""Self-contained Script ABI v1 + OpenSSH/rsync helpers for rsync-ssh."""
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
import subprocess
import sys
import tempfile
import time

MAX_REQUEST_BYTES = 4 * 1024 * 1024
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SSH_ALIAS_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")

# Run ssh and rsync without ambient SSH_AUTH_SOCK or user environment options.
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


def command(arguments: list[str], payload: bytes = b"", timeout: float = 120) -> bytes:
    """Bound stdin/stdout/stderr pipes and elapsed wall-clock time."""
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
    # Quote only trusted static paths; opaque request fields travel exclusively over JSON stdin.
    arguments = ssh_arguments(remote) + [
        remote["host"],
        shlex.join(["/usr/bin/python3", "-I", script, "--config", remote["config"]]),
    ]
    payload = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    response = read_json(command(arguments, payload).decode("utf-8"))
    if (
        type(response.get("abiVersion")) is not int
        or response["abiVersion"] != 1
        or response.get("operationId") != req["operationId"]
    ):
        raise ValueError("Invalid remote response")
    return response


def resolve_local_candidate(config: dict[str, object], req: dict[str, object]) -> Path:
    root = absolute(config["artifactRoot"]) / digest(str(req["projectId"])) / digest(str(req["version"]))
    candidates: list[Path] = []
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise Rejected("ARTIFACT_REJECTED")
        for entry in root.iterdir():
            if entry.is_symlink() or not entry.is_dir():
                raise Rejected("ARTIFACT_REJECTED")
            metadata_file = entry / "metadata.json"
            try:
                if metadata_file.is_symlink():
                    raise ValueError("Invalid metadata file")
                metadata = read_json(metadata_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise Rejected("ARTIFACT_REJECTED") from None
            if metadata != {"projectId": req["projectId"], "version": req["version"]}:
                raise Rejected("ARTIFACT_REJECTED")
            payload = entry / "payload.bin"
            if payload.is_symlink() or not payload.is_file():
                raise Rejected("ARTIFACT_REJECTED")
            candidates.append(payload)
    if not candidates:
        raise Rejected("ARTIFACT_UNAVAILABLE")
    if len(candidates) != 1:
        raise Rejected("ARTIFACT_AMBIGUOUS")
    return candidates[0]


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
        print("SSH/rsync adapter could not complete the request", file=sys.stderr)
        sys.exit(1)

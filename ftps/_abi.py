"""Self-contained Script ABI v1 + Explicit FTPS transport helpers."""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import fcntl
import ftplib
import hashlib
import io
import json
import netrc
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import sys
import tempfile

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_BLOB_BYTES = 512 * 1024 * 1024
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64_RE = re.compile(r"[a-f0-9]{64}")
HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.:_-]{0,251}[A-Za-z0-9])?")


class Rejected(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


@dataclass(frozen=True)
class FtpsSettings:
    host: str
    port: int
    remote_root: str
    login: str
    password: str
    ssl_context: ssl.SSLContext
    passive: bool
    timeout_seconds: int


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
    # Persist before any FTPS connection or mutation. Crashes never replay.
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


def load_ftps_settings(target: dict[str, object]) -> FtpsSettings:
    raw = target.get("ftps")
    if not isinstance(raw, dict):
        raise ValueError("Missing ftps configuration block")

    host = text_value(raw.get("host"), 253)
    if not HOST_RE.fullmatch(host):
        raise ValueError("Invalid FTPS host")

    port = raw.get("port", 21)
    if type(port) is not int or not (1 <= port <= 65535):
        raise ValueError("Invalid FTPS port")

    remote_root = text_value(raw.get("remoteRoot"), 1024)
    posix_root = PurePosixPath(remote_root)
    if not posix_root.is_absolute() or ".." in posix_root.parts:
        raise ValueError("FTPS remoteRoot must be a clean absolute path")
    normalized_root = str(posix_root)

    passive = raw.get("passive", True)
    if type(passive) is not bool:
        raise ValueError("FTPS passive flag must be boolean")

    timeout = raw.get("timeoutSeconds", 60)
    if type(timeout) is not int or not (1 <= timeout <= 300):
        raise ValueError("FTPS timeoutSeconds must be an integer between 1 and 300")

    netrc_path = absolute(raw.get("netrcFile"))
    st = os.lstat(netrc_path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("FTPS netrcFile must be a regular non-symlink file")
    if st.st_uid != os.geteuid():
        raise ValueError("FTPS netrcFile must be owned by the invoking user")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError("FTPS netrcFile must have mode 0600")

    parsed_netrc = netrc.netrc(str(netrc_path))
    auth = parsed_netrc.authenticators(host)
    if not auth or not auth[0] or auth[2] is None or not auth[2]:
        raise ValueError("FTPS credentials for host missing from netrcFile")
    login, _, password = auth

    ca_raw = raw.get("caFile")
    ca_file: str | None = None
    if ca_raw is not None:
        ca_path = absolute(ca_raw)
        ca_stat = os.lstat(ca_path)
        if not stat.S_ISREG(ca_stat.st_mode):
            raise ValueError("FTPS caFile must be a regular non-symlink file")
        ca_file = str(ca_path)

    ssl_context = ssl.create_default_context(cafile=ca_file)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    return FtpsSettings(
        host=host,
        port=port,
        remote_root=normalized_root,
        login=login,
        password=password,
        ssl_context=ssl_context,
        passive=passive,
        timeout_seconds=timeout,
    )


@contextlib.contextmanager
def ftps_session(settings: FtpsSettings):
    ftp = ftplib.FTP_TLS(context=settings.ssl_context, timeout=settings.timeout_seconds, encoding="utf-8")
    try:
        ftp.connect(settings.host, settings.port, timeout=settings.timeout_seconds)
        ftp.auth()
        ftp.login(settings.login, settings.password)
        ftp.prot_p()
        ftp.set_pasv(settings.passive)
        ftp.voidcmd("TYPE I")
        yield ftp
        ftp.quit()
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def remote_join(base: str, child: str) -> str:
    return f"/{child}" if base == "/" else f"{base.rstrip('/')}/{child}"


def list_entry_names(ftp: ftplib.FTP_TLS) -> set[str]:
    entries = ftp.nlst()
    # Restore binary TYPE I after retrlines-based NLST (which switches control to TYPE A).
    ftp.voidcmd("TYPE I")
    names: set[str] = set()
    for raw in entries:
        name = raw.rstrip("/").rsplit("/", 1)[-1]
        if name and name not in {".", ".."}:
            names.add(name)
    return names


def download_bytes(ftp: ftplib.FTP_TLS, filename: str, max_bytes: int) -> bytes:
    buf = bytearray()

    def collect(chunk: bytes) -> None:
        if len(buf) + len(chunk) > max_bytes:
            raise ValueError("Remote file exceeded byte limit")
        buf.extend(chunk)

    ftp.retrbinary(f"RETR {filename}", collect)
    return bytes(buf)


def upload_bytes_atomic(ftp: ftplib.FTP_TLS, part_name: str, final_name: str, data: bytes) -> None:
    ftp.storbinary(f"STOR {part_name}", io.BytesIO(data))
    ftp.rename(part_name, final_name)


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
        print("FTPS adapter could not complete the request", file=sys.stderr)
        sys.exit(1)

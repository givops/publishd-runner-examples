"""Self-contained Script ABI v1 helper for local-repository."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

MAX_REQUEST_BYTES = 4 * 1024 * 1024
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


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
    # The operator provisions the parent; never replace or unlink this shared inode.
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
    # Persist before the first destination mutation. A crash never permits replay.
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
        # Keep private paths, raw tool output, and configuration out of public diagnostics.
        print("Adapter could not complete the request", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Heavily commented Script ABI v1 inventory starter template (Python 3.11+ stdlib only).

Must observe the ACTUAL destination directly (never read artifactRoot or journalRoot).
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_PROJECTS = 20000
KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64_RE = re.compile(r"[a-f0-9]{64}")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_strict_json(text: str) -> dict[str, object]:
    decoder = json.JSONDecoder(object_pairs_hook=strict_object)
    stripped = text.lstrip(" \t\r\n")
    obj, end = decoder.raw_decode(stripped)
    if stripped[end:].strip(" \t\r\n") or not isinstance(obj, dict):
        raise ValueError("Expected one JSON object")
    return obj


def validate_text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("Invalid string")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("Disallowed control or surrogate character")
    return value


def read_inventory_request() -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("Request exceeds 4 MiB")
    req = read_strict_json(raw.decode("utf-8"))
    expected = {"abiVersion", "operation", "operationId", "optionId",
                "serverId", "channelId", "projectIds", "purpose"}
    if set(req) != expected:
        raise ValueError("Unexpected request schema")
    if type(req["abiVersion"]) is not int or req["abiVersion"] != 1 or req["operation"] != "inventory":
        raise ValueError("Unsupported ABI version or operation")
    validate_text(req["operationId"], 255)
    validate_text(req["optionId"], 255)
    for key in ("serverId", "channelId"):
        if not KEY_RE.fullmatch(validate_text(req[key], 128)):
            raise ValueError("Invalid routing key")
    if req["purpose"] not in {"REFRESH", "VERIFY"}:
        raise ValueError("Invalid inventory purpose")
    projects = req["projectIds"]
    if not isinstance(projects, list) or len(projects) > MAX_PROJECTS:
        raise ValueError("Invalid projectIds scope")
    for project in projects:
        validate_text(project, 255)
    if len(projects) != len(set(projects)):
        raise ValueError("Duplicate projectId in projectIds")
    return req


def load_private_config() -> dict[str, object]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    path = Path(parser.parse_args().config)
    if not path.is_absolute():
        raise ValueError("Config path must be absolute")
    return read_strict_json(path.read_text(encoding="utf-8"))


def resolve_destination(config: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    matches = [
        d for d in config["destinations"]  # type: ignore[index]
        if d["serverId"] == req["serverId"]
        and d["channelId"] == req["channelId"]
        and req["optionId"] in d["optionIds"]
    ]
    if len(matches) != 1:
        raise ValueError("Destination not allowlisted")
    return matches[0]


def require_absolute(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError("Path must be a string")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Private path must be absolute")
    return path


@contextlib.contextmanager
def resource_lock(target: dict[str, object]):
    lock_path = require_absolute(target["resourceLock"])
    with lock_path.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


# =============================================================================
# === CUSTOMIZE STEP 1: QUERY LIVE DESTINATION STATE FOR REQUESTED PROJECTS ===
# =============================================================================
def inspect_destination(config: dict[str, object], target: dict[str, object],
                        project_ids: list[str]) -> list[dict[str, object]]:
    """Read and verify the currently deployed version for each requested project.

    Rules:
      - Return one entry per deployed projectId in `project_ids`:
        {"projectId": project_id, "version": exact_version, "sourceObservedAt": None}
      - Omit projects that are not deployed on the destination.
      - Raise an exception if the destination is unreachable, corrupt, or inconsistent
        so publishd-runner never mistakes a broken scan for an empty deployment.
      - Never read artifactRoot or journalRoot here.
    """
    root = require_absolute(target["root"])
    if not root.is_dir():
        raise ValueError("Destination root is unavailable")

    deployments: list[dict[str, object]] = []
    for project_id in sorted(project_ids):
        folder = root / sha256_text(project_id)
        release_file = folder / "release.json"
        if not release_file.exists():
            continue
        if release_file.is_symlink() or not release_file.is_file():
            raise ValueError("Invalid destination pointer")

        current = read_strict_json(release_file.read_text(encoding="utf-8"))
        if set(current) != {"projectId", "version", "sha256"} or current["projectId"] != project_id:
            raise ValueError("Destination metadata mismatch")
        version = validate_text(current["version"], 1024)
        checksum = current["sha256"]
        if not isinstance(checksum, str) or not HEX64_RE.fullmatch(checksum):
            raise ValueError("Invalid destination checksum")

        blob = folder / f"{checksum}.bin"
        if blob.is_symlink() or not blob.is_file():
            raise ValueError("Missing destination artifact blob")
        if hashlib.sha256(blob.read_bytes()).hexdigest() != checksum:
            raise ValueError("Destination artifact checksum mismatch")

        deployments.append({
            "projectId": project_id,
            "version": version,
            "sourceObservedAt": None,
        })
    return deployments


def main() -> int:
    try:
        req = read_inventory_request()
        config = load_private_config()
        target = resolve_destination(config, req)
        with resource_lock(target):
            deployments = inspect_destination(config, target, list(req["projectIds"]))  # type: ignore[arg-type]
        response = {
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
        print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception:
        print("Inventory check failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

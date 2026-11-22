#!/usr/bin/env python3
"""Heavily commented Script ABI v1 publish starter template (Python 3.11+ stdlib only).

Copy this entire folder into your private operator directory (for example
/opt/publishd/my-target/) and edit the marked CUSTOMIZE sections below.
Do not emit logs or diagnostics to stdout; stdout must be one ABI JSON object.
"""
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
HEX64_RE = re.compile(r"[a-f0-9]{64}")


class Rejected(Exception):
    """Domain rejection BEFORE any destination mutation occurs."""

    def __init__(self, code: str) -> None:
        self.code = code


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


def read_publish_request() -> dict[str, str | int]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("Request exceeds 4 MiB")
    req = read_strict_json(raw.decode("utf-8"))
    expected = {"abiVersion", "operation", "operationId", "optionId",
                "serverId", "channelId", "projectId", "version"}
    if set(req) != expected:
        raise ValueError("Unexpected request schema")
    if type(req["abiVersion"]) is not int or req["abiVersion"] != 1 or req["operation"] != "publish":
        raise ValueError("Unsupported ABI version or operation")
    validate_text(req["operationId"], 255)
    validate_text(req["optionId"], 255)
    for key in ("serverId", "channelId"):
        if not KEY_RE.fullmatch(validate_text(req[key], 128)):
            raise ValueError("Invalid routing key")
    validate_text(req["projectId"], 255)
    validate_text(req["version"], 1024)
    return req  # type: ignore[return-value]


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
        raise Rejected("DESTINATION_REJECTED")
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
    # Operator provisions the lock parent directory; never unlink or replace this inode.
    with lock_path.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".pending-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def abi_result(req: dict[str, object], outcome: str, error_code: str | None = None) -> dict[str, object]:
    doc: dict[str, object] = {
        "abiVersion": 1,
        "operationId": req["operationId"],
        "outcome": outcome,
    }
    if error_code is not None:
        doc["errorCode"] = error_code
    return doc


# =============================================================================
# === CUSTOMIZE STEP 1: VALIDATE INPUT ARTIFACT BEFORE ANY MUTATION         ===
# =============================================================================
def prepare_artifact(config: dict[str, object], target: dict[str, object],
                     req: dict[str, object]) -> tuple[bytes, str]:
    """Locate and validate the exact artifact before persisting a started journal.

    Raise Rejected(code) using safe Script ABI v1 codes:
      - ARTIFACT_UNAVAILABLE: zero candidates exist for (projectId, version)
      - ARTIFACT_AMBIGUOUS: multiple candidates match
      - ARTIFACT_REJECTED: invalid metadata, checksum, symlink, or package policy

    IMPORTANT: Do NOT write or mutate destination state inside this function.
    """
    project_id = str(req["projectId"])
    version = str(req["version"])

    # Default skeleton layout:
    #   <artifactRoot>/<sha256(projectId)>/<sha256(version)>/<candidate>/metadata.json + payload.bin
    # Replace this block with your own lookup (tarball check, signature verify, etc.).
    candidate_parent = (
        require_absolute(config["artifactRoot"])
        / sha256_text(project_id)
        / sha256_text(version)
    )
    candidates: list[Path] = []
    if candidate_parent.exists():
        if candidate_parent.is_symlink() or not candidate_parent.is_dir():
            raise Rejected("ARTIFACT_REJECTED")
        for entry in candidate_parent.iterdir():
            if entry.is_symlink() or not entry.is_dir():
                raise Rejected("ARTIFACT_REJECTED")
            meta_file = entry / "metadata.json"
            payload_file = entry / "payload.bin"
            try:
                if meta_file.is_symlink() or payload_file.is_symlink() or not payload_file.is_file():
                    raise Rejected("ARTIFACT_REJECTED")
                meta = read_strict_json(meta_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise Rejected("ARTIFACT_REJECTED") from None
            if meta != {"projectId": project_id, "version": version}:
                raise Rejected("ARTIFACT_REJECTED")
            candidates.append(payload_file)

    if not candidates:
        raise Rejected("ARTIFACT_UNAVAILABLE")
    if len(candidates) > 1:
        raise Rejected("ARTIFACT_AMBIGUOUS")

    data = candidates[0].read_bytes()
    return data, hashlib.sha256(data).hexdigest()


# =============================================================================
# === CUSTOMIZE STEP 2: UPLOAD / PROMOTE TO DESTINATION UNDER JOURNAL GUARD ===
# =============================================================================
def mutate_destination(config: dict[str, object], target: dict[str, object],
                       req: dict[str, object], prepared: tuple[bytes, str]) -> str:
    """Transfer and atomically promote the validated artifact to your target.

    Return:
      - "APPLIED": destination was updated with this release
      - "ALREADY_PRESENT": destination already holds the exact version and checksum

    Raise an Exception if transfer/promotion fails or is interrupted; the journal
    wrapper will record and return UNKNOWN / PUBLICATION_UNCERTAIN automatically.
    """
    data, checksum = prepared
    project_id = str(req["projectId"])
    version = str(req["version"])

    dest_folder = require_absolute(target["root"]) / sha256_text(project_id)
    dest_folder.mkdir(parents=True, exist_ok=True)
    blob_path = dest_folder / f"{checksum}.bin"
    release_file = dest_folder / "release.json"

    # Optional idempotent shortcut if destination already matches verbatim.
    if release_file.exists() and not release_file.is_symlink() and blob_path.is_file() and not blob_path.is_symlink():
        existing = read_strict_json(release_file.read_text(encoding="utf-8"))
        if (
            existing == {"projectId": project_id, "version": version, "sha256": checksum}
            and HEX64_RE.fullmatch(checksum)
            and hashlib.sha256(blob_path.read_bytes()).hexdigest() == checksum
        ):
            return "ALREADY_PRESENT"

    # Stage blob + fsync + atomic replace, then atomically swap release.json pointer.
    fd, tmp_blob = tempfile.mkstemp(dir=dest_folder, prefix=".payload-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_blob, blob_path)
    finally:
        if os.path.exists(tmp_blob):
            os.unlink(tmp_blob)

    atomic_write_json(release_file, {
        "projectId": project_id,
        "version": version,
        "sha256": checksum,
    })
    return "APPLIED"


def journaled_publish(config: dict[str, object], target: dict[str, object],
                      req: dict[str, object]) -> dict[str, object]:
    journal_file = require_absolute(config["journalRoot"]) / f"{sha256_text(str(req['operationId']))}.json"
    fingerprint = sha256_text(json.dumps(req, ensure_ascii=False, sort_keys=True, separators=(",", ":")))

    if journal_file.exists():
        previous = read_strict_json(journal_file.read_text(encoding="utf-8"))
        if previous.get("fingerprint") != fingerprint:
            return abi_result(req, "REJECTED", "OPERATION_CONFLICT")
        stored = previous.get("result")
        if isinstance(stored, dict):
            return stored
        # Started journal with no recorded completion MUST NEVER replay automatically.
        return abi_result(req, "UNKNOWN", "PUBLICATION_UNCERTAIN")

    try:
        prepared = prepare_artifact(config, target, req)
    except Rejected as error:
        return abi_result(req, "REJECTED", error.code)

    # Write and fsync the started journal BEFORE the first mutation step.
    atomic_write_json(journal_file, {"fingerprint": fingerprint})
    try:
        outcome = mutate_destination(config, target, req, prepared)
        if outcome not in {"APPLIED", "ALREADY_PRESENT"}:
            raise ValueError("Unexpected mutate_destination outcome")
        response = abi_result(req, outcome)
    except Exception:
        response = abi_result(req, "UNKNOWN", "PUBLICATION_UNCERTAIN")

    atomic_write_json(journal_file, {"fingerprint": fingerprint, "result": response})
    return response


def main() -> int:
    req: dict[str, object] | None = None
    try:
        req = read_publish_request()
        config = load_private_config()
        target = resolve_destination(config, req)
        with resource_lock(target):
            response = journaled_publish(config, target, req)
        print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Rejected as error:
        if req is not None:
            print(json.dumps(abi_result(req, "REJECTED", error.code), ensure_ascii=False, separators=(",", ":")))
            return 0
        print("Publish request rejected", file=sys.stderr)
        return 1
    except Exception:
        # Keep private paths, credentials, and raw exceptions out of public diagnostics.
        print("Publish script failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

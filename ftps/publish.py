#!/usr/bin/env python3
"""Explicit FTPS (AUTH TLS + PROT P + TYPE I) staged publication adapter."""
from __future__ import annotations

import ftplib
import hashlib
import json
from pathlib import Path
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    HEX64_RE,
    MAX_BLOB_BYTES,
    MAX_MANIFEST_BYTES,
    FtpsSettings,
    Rejected,
    absolute,
    digest,
    download_bytes,
    ftps_session,
    journaled_publish,
    list_entry_names,
    load_ftps_settings,
    read_json,
    remote_join,
    run,
    upload_bytes_atomic,
)


def prepare(config: dict[str, object], target: dict[str, object],
            req: dict[str, object]) -> tuple[FtpsSettings, bytes, str, int]:
    # Validate FTPS credentials/mode-0600 netrc and TLS config BEFORE journaling.
    settings = load_ftps_settings(target)

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
                    raise ValueError("Invalid metadata symlink")
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

    data = candidates[0].read_bytes()
    if len(data) > MAX_BLOB_BYTES:
        raise Rejected("ARTIFACT_REJECTED")
    checksum = hashlib.sha256(data).hexdigest()
    return settings, data, checksum, len(data)


def already_deployed(ftp: ftplib.FTP_TLS, entries: set[str], project_id: str,
                     version: str, checksum: str, size: int) -> bool:
    if "current.json" not in entries:
        return False
    raw = download_bytes(ftp, "current.json", MAX_MANIFEST_BYTES)
    current = read_json(raw.decode("utf-8"))
    if current != {"projectId": project_id, "version": version, "sha256": checksum, "size": size}:
        return False
    blob_name = f"{checksum}.bin"
    if blob_name not in entries or not HEX64_RE.fullmatch(checksum):
        return False
    remote_blob = download_bytes(ftp, blob_name, MAX_BLOB_BYTES)
    return len(remote_blob) == size and hashlib.sha256(remote_blob).hexdigest() == checksum


def mutate(config: dict[str, object], target: dict[str, object], req: dict[str, object],
           prepared: tuple[FtpsSettings, bytes, str, int]) -> str:
    settings, data, checksum, size = prepared
    project_id = str(req["projectId"])
    version = str(req["version"])
    op_digest = digest(str(req["operationId"]))[:24]
    project_dir = remote_join(settings.remote_root, digest(project_id))

    with ftps_session(settings) as ftp:
        ftp.cwd(settings.remote_root)
        try:
            ftp.cwd(project_dir)
        except ftplib.error_perm:
            ftp.mkd(digest(project_id))
            ftp.cwd(project_dir)

        entries = list_entry_names(ftp)
        if already_deployed(ftp, entries, project_id, version, checksum, size):
            return "ALREADY_PRESENT"

        blob_part = f".payload-{op_digest}.part"
        blob_final = f"{checksum}.bin"
        upload_bytes_atomic(ftp, blob_part, blob_final, data)

        manifest_bytes = json.dumps(
            {"projectId": project_id, "version": version, "sha256": checksum, "size": size},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        manifest_part = f".current-{op_digest}.part"
        upload_bytes_atomic(ftp, manifest_part, "current.json", manifest_bytes)
        return "APPLIED"


if __name__ == "__main__":
    run("publish", publish=lambda c, t, r: journaled_publish(c, t, r, prepare, mutate))

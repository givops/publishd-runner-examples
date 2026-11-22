#!/usr/bin/env python3
"""Direct AUTHORITATIVE inventory check over Explicit FTPS (AUTH TLS + PROT P + TYPE I)."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    HEX64_RE,
    MAX_BLOB_BYTES,
    MAX_MANIFEST_BYTES,
    digest,
    download_bytes,
    ftps_session,
    inventory_result,
    list_entry_names,
    load_ftps_settings,
    read_json,
    remote_join,
    run,
    text_value,
)


def inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    settings = load_ftps_settings(target)
    rows: list[dict[str, object]] = []

    with ftps_session(settings) as ftp:
        ftp.cwd(settings.remote_root)
        root_entries = list_entry_names(ftp)

        for project_id in sorted(req["projectIds"]):  # type: ignore[arg-type]
            proj_hash = digest(project_id)
            if proj_hash not in root_entries:
                continue
            ftp.cwd(remote_join(settings.remote_root, proj_hash))
            proj_entries = list_entry_names(ftp)
            if "current.json" not in proj_entries:
                continue

            raw_manifest = download_bytes(ftp, "current.json", MAX_MANIFEST_BYTES)
            current = read_json(raw_manifest.decode("utf-8"))
            if set(current) != {"projectId", "version", "sha256", "size"} or current["projectId"] != project_id:
                raise ValueError("Invalid remote FTPS manifest")
            version = text_value(current["version"], 1024)
            checksum = current["sha256"]
            size = current["size"]
            if not isinstance(checksum, str) or not HEX64_RE.fullmatch(checksum):
                raise ValueError("Invalid remote checksum")
            if type(size) is not int or size < 0 or size > MAX_BLOB_BYTES:
                raise ValueError("Invalid remote size")

            blob_name = f"{checksum}.bin"
            if blob_name not in proj_entries:
                raise ValueError("Missing remote FTPS artifact blob")
            blob = download_bytes(ftp, blob_name, MAX_BLOB_BYTES)
            if len(blob) != size or hashlib.sha256(blob).hexdigest() != checksum:
                raise ValueError("Remote FTPS artifact checksum or size mismatch")

            rows.append({
                "projectId": project_id,
                "version": version,
                "sourceObservedAt": None,
            })

    return inventory_result(req, rows)


if __name__ == "__main__":
    run("inventory", inventory=inventory)

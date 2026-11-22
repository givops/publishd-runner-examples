#!/usr/bin/env python3
"""Authoritative inventory reader: delegates over SSH when ssh config exists, or reads local root directly."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    absolute,
    digest,
    inventory_result,
    invoke_ssh,
    read_json,
    run,
    text_value,
)


def remote_inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
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


def local_inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    root = absolute(target["root"])
    if not root.is_dir():
        raise ValueError("Destination is unavailable")
    rows: list[dict[str, object]] = []
    for project in sorted(req["projectIds"]):  # type: ignore[arg-type]
        folder = root / digest(project)
        state = folder / "current.json"
        if not state.exists():
            continue
        if state.is_symlink() or not state.is_file():
            raise ValueError("Invalid destination state")
        current = read_json(state.read_text(encoding="utf-8"))
        if set(current) != {"projectId", "version", "sha256"} or current["projectId"] != project:
            raise ValueError("Invalid destination state")
        text_value(current["version"], 1024)
        checksum = current["sha256"]
        if not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum):
            raise ValueError("Invalid checksum")
        blob = folder / (checksum + ".bin")
        if blob.is_symlink() or not blob.is_file() or hashlib.sha256(blob.read_bytes()).hexdigest() != checksum:
            raise ValueError("Destination content mismatch")
        rows.append({"projectId": project, "version": current["version"], "sourceObservedAt": None})
    return inventory_result(req, rows)


def inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    if "ssh" in target:
        return remote_inventory(config, target, req)
    return local_inventory(config, target, req)


if __name__ == "__main__":
    run("inventory", inventory=inventory)

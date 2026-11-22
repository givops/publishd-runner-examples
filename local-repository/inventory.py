#!/usr/bin/env python3
"""Read and checksum-verify destination files independently of artifact/journal state."""
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
    read_json,
    run,
    text_value,
)


def inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
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


if __name__ == "__main__":
    run("inventory", inventory=inventory)

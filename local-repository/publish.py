#!/usr/bin/env python3
"""Publish an exact artifact to a local content-addressed repository."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    Rejected,
    absolute,
    atomic_json,
    digest,
    journaled_publish,
    read_json,
    run,
)


def prepare(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> Path:
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


def mutate(config: dict[str, object], target: dict[str, object], req: dict[str, object], payload: Path) -> str:
    folder = absolute(target["root"]) / digest(str(req["projectId"]))
    folder.mkdir(parents=True, exist_ok=True)
    data = payload.read_bytes()
    checksum = hashlib.sha256(data).hexdigest()
    blob = folder / (checksum + ".bin")
    fd, temporary = tempfile.mkstemp(dir=folder, prefix=".payload-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, blob)
        atomic_json(
            folder / "current.json",
            {"projectId": req["projectId"], "version": req["version"], "sha256": checksum},
        )
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return "APPLIED"


if __name__ == "__main__":
    run("publish", publish=lambda c, t, r: journaled_publish(c, t, r, prepare, mutate))

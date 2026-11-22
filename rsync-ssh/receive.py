#!/usr/bin/env python3
"""Destination-side finalizer invoked over SSH on the repository host."""
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
    absolute,
    atomic_json,
    digest,
    journaled_publish,
    resolve_local_candidate,
    run,
)


def prepare_staged(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> Path:
    return resolve_local_candidate(config, req)


def mutate_repository(config: dict[str, object], target: dict[str, object],
                      req: dict[str, object], payload: Path) -> str:
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


def publish(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    if "ssh" in target:
        raise ValueError("Remote helper configuration must be local")
    staged = dict(config, artifactRoot=str(absolute(config["artifactRoot"]) / digest(str(req["operationId"]))))
    return journaled_publish(staged, target, req, prepare_staged, mutate_repository)


if __name__ == "__main__":
    run("publish", publish=publish)

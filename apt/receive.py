#!/usr/bin/env python3
"""Run reprepro on the repository host after validating the SSH-staged .deb package."""
from __future__ import annotations

from pathlib import Path
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import absolute, digest, journaled_publish, run  # noqa: E402
from publish import mutate, prepare  # noqa: E402


def publish(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    if "ssh" in target:
        raise ValueError("Remote helper configuration must be local")
    staged = dict(config, artifactRoot=str(absolute(config["artifactRoot"]) / digest(str(req["operationId"]))))
    return journaled_publish(staged, target, req, prepare, mutate)


if __name__ == "__main__":
    run("publish", publish=publish)

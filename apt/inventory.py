#!/usr/bin/env python3
"""Read and verify the published APT Release/Packages index and pool .deb files."""
from __future__ import annotations

from pathlib import Path
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import destination_rows, inventory_result, remote_apt_inventory, run  # noqa: E402


def inventory(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    if "ssh" in target:
        return remote_apt_inventory(config, target, req)
    return inventory_result(req, destination_rows(config, target, list(req["projectIds"])))  # type: ignore[arg-type]


if __name__ == "__main__":
    run("inventory", inventory=inventory)

#!/usr/bin/env python3
"""Stage a validated artifact over rsync and promote it via SSH receive.py."""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
import sys
import tempfile

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    absolute,
    command,
    digest,
    invoke_ssh,
    journaled_publish,
    resolve_local_candidate,
    run,
    ssh_arguments,
    ssh_settings,
)


def prepare(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> Path:
    ssh_settings(target)
    return resolve_local_candidate(config, req)


def mutate(config: dict[str, object], target: dict[str, object], req: dict[str, object], artifact: Path) -> str:
    remote = ssh_settings(target)
    with tempfile.TemporaryDirectory(prefix="publishd-transfer-") as temporary:
        root = Path(temporary)
        candidate = root / digest(str(req["projectId"])) / digest(str(req["version"])) / "candidate"
        candidate.mkdir(parents=True)
        shutil.copyfile(artifact, candidate / "payload.bin")
        (candidate / "metadata.json").write_text(
            json.dumps({"projectId": req["projectId"], "version": req["version"]}, ensure_ascii=False),
            encoding="utf-8",
        )
        destination_dir = str(absolute(remote["stagingRoot"]) / digest(str(req["operationId"]))) + "/"
        command([
            "/usr/bin/rsync",
            "--recursive",
            "--perms",
            "--chmod=D700,F600",
            "--protect-args",
            "--timeout=120",
            "--rsh",
            shlex.join(ssh_arguments(remote)),
            "--",
            str(root) + "/",
            remote["host"] + ":" + destination_dir,
        ])
    response = invoke_ssh(target, req)
    if set(response) != {"abiVersion", "operationId", "outcome"} or response["outcome"] not in {
        "APPLIED",
        "ALREADY_PRESENT",
    }:
        # Staging has started: conservatively report uncertainty on any non-confirming response.
        raise ValueError("Remote publication did not confirm completion")
    return str(response["outcome"])


if __name__ == "__main__":
    run("publish", publish=lambda c, t, r: journaled_publish(c, t, r, prepare, mutate))

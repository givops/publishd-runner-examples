#!/usr/bin/env python3
"""Exact package resolution and publication to a local or remote-SSH reprepro repository."""
from __future__ import annotations

from pathlib import Path
import sys

_DIR = str(Path(__file__).resolve().parent)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from _abi import (  # noqa: E402
    Rejected,
    absolute,
    apt_command,
    deb_metadata,
    destination_rows,
    journaled_publish,
    package_name,
    remote_apt_publish,
    run,
    scope,
)


def resolve_artifact(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> Path:
    package = package_name(config, str(req["projectId"]))
    _, _, architecture = scope(target)
    root = absolute(config["artifactRoot"])
    if not root.is_dir():
        raise Rejected("ARTIFACT_UNAVAILABLE")
    candidates: list[Path] = []
    count = 0
    for path in root.rglob("*.deb"):
        count += 1
        if count > 20000 or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise Rejected("ARTIFACT_REJECTED")
        try:
            fields = deb_metadata(path)
        except Exception:
            raise Rejected("ARTIFACT_REJECTED") from None
        # Version equality is exact opaque text, not Debian ordering, substring, or filename matching.
        if (
            fields["Package"] == package
            and fields["Version"] == req["version"]
            and fields["Architecture"] in {architecture, "all"}
        ):
            candidates.append(path)
    if not candidates:
        raise Rejected("ARTIFACT_UNAVAILABLE")
    if len(candidates) != 1:
        raise Rejected("ARTIFACT_AMBIGUOUS")
    return candidates[0]


def prepare(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> Path:
    artifact = resolve_artifact(config, target, req)
    # Validate current destination repository health before admitting any mutation.
    destination_rows(config, target, [str(req["projectId"])])
    return artifact


def mutate(config: dict[str, object], target: dict[str, object], req: dict[str, object], artifact: Path) -> str:
    distribution, component, architecture = scope(target)
    apt_command([
        "/usr/bin/reprepro",
        "--basedir", str(absolute(target["root"])),
        "--component", component,
        "--architecture", architecture,
        "includedeb", distribution, str(artifact),
    ])
    return "APPLIED"


def publish(config: dict[str, object], target: dict[str, object], req: dict[str, object]) -> dict[str, object]:
    if "ssh" in target:
        return remote_apt_publish(config, target, req, resolve_artifact)
    return journaled_publish(config, target, req, prepare, mutate)


if __name__ == "__main__":
    run("publish", publish=publish)

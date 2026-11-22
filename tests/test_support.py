"""Shared disposable fixture helpers for isolated template tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

REPO_ROOT = Path(__file__).resolve().parents[1]
OPTION_ID = "00000000-0000-4000-8000-000000000028"


def isolate_template(work_root: Path, template_name: str) -> Path:
    """Copy a single template directory outside the repository tree to prove zero parent imports."""
    dest = work_root / "isolated" / template_name
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / template_name, dest)
    return dest


def create_synthetic_fixture(root: Path, option_id: str = OPTION_ID,
                             project: str = "sample-project", version: str = "2:4.1~rc1") -> Path:
    """Provision a synthetic artifactRoot, journalRoot, destination, and local config."""
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    artifact = (
        root
        / "artifacts"
        / hashlib.sha256(project.encode("utf-8")).hexdigest()
        / hashlib.sha256(version.encode("utf-8")).hexdigest()
        / "one"
    )
    artifact.mkdir(parents=True)
    (artifact / "metadata.json").write_text(
        json.dumps({"projectId": project, "version": version}),
        encoding="utf-8",
    )
    (artifact / "payload.bin").write_bytes(b"Synthetic publication fixture\n")
    (root / "destination").mkdir()
    config = {
        "artifactRoot": str(root / "artifacts"),
        "journalRoot": str(root / "journal"),
        "destinations": [
            {
                "optionIds": [option_id],
                "serverId": "test",
                "channelId": "candidate",
                "root": str(root / "destination"),
                "resourceLock": str(root / "repository.lock"),
            }
        ],
    }
    config_file = root / "config.json"
    config_file.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return config_file


def new_op_id() -> str:
    return str(uuid.uuid4())


def run_isolated(script_dir: Path, script_name: str, config_file: Path,
                 payload: dict[str, object] | None = None, raw: str | bytes | None = None,
                 timeout: int = 20) -> subprocess.CompletedProcess[str]:
    if raw is None:
        stdin_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    elif isinstance(raw, bytes):
        stdin_text = raw.decode("utf-8")
    else:
        stdin_text = raw
    return subprocess.run(
        [sys.executable, "-I", str(script_dir / script_name), "--config", str(config_file)],
        input=stdin_text,
        text=True,
        capture_output=True,
        cwd=str(script_dir),
        timeout=timeout,
    )

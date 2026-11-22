"""Repository hygiene and public release invariants."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import unittest

from test_support import REPO_ROOT

TEMPLATES = ("minimal-template", "local-repository", "ftps", "rsync-ssh", "apt")


class RepoHygieneTests(unittest.TestCase):
    def test_license_and_trademark_notice_present(self) -> None:
        license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("MIT License", readme)
        self.assertIn("GivOps", readme)
        self.assertIn("not** licensed under the MIT License", readme)
        self.assertTrue((REPO_ROOT / "PROTOCOL.md").is_file())

    def test_templates_are_self_contained_with_zero_parent_imports(self) -> None:
        for template in TEMPLATES:
            folder = REPO_ROOT / template
            self.assertTrue((folder / "publish.py").is_file(), template)
            self.assertTrue((folder / "inventory.py").is_file(), template)
            self.assertTrue((folder / "config.example.json").is_file(), template)
            self.assertTrue((folder / "runner-profile.example.yaml").is_file(), template)
            for py_file in folder.glob("*.py"):
                source = py_file.read_text(encoding="utf-8")
                self.assertNotIn("parents[", source, str(py_file))
                tree = ast.parse(source, filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        self.assertEqual(node.level, 0, f"Relative import in {py_file}")
                        if node.module:
                            self.assertFalse(
                                node.module.startswith(("adapter_support", "ssh_support", "apt_support")),
                                f"Cross-template helper import in {py_file}: {node.module}",
                            )

    def test_example_configs_use_example_invalid_and_valid_json(self) -> None:
        for cfg in REPO_ROOT.glob("*/config*.json"):
            json.loads(cfg.read_text(encoding="utf-8"))
        for cfg in REPO_ROOT.glob("*/remote-config*.json"):
            json.loads(cfg.read_text(encoding="utf-8"))
        ftps_cfg = json.loads((REPO_ROOT / "ftps" / "config.example.json").read_text(encoding="utf-8"))
        self.assertTrue(ftps_cfg["destinations"][0]["ftps"]["host"].endswith(".example.invalid"))
        netrc_text = (REPO_ROOT / "ftps" / "netrc.example").read_text(encoding="utf-8")
        self.assertIn(".example.invalid", netrc_text)
        for ssh_cfg in REPO_ROOT.glob("*/ssh-config.example"):
            self.assertIn(".example.invalid", ssh_cfg.read_text(encoding="utf-8"))

    def test_no_internal_ids_developer_paths_or_real_hosts(self) -> None:
        forbidden = [
            re.compile(r"\bTASK-\d+\b"),
            re.compile(r"/home/[a-zA-Z0-9_-]+"),
            re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
        ]
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in forbidden:
                self.assertIsNone(
                    pattern.search(text),
                    f"Forbidden pattern {pattern.pattern!r} matched in {path.relative_to(REPO_ROOT)}",
                )


if __name__ == "__main__":
    unittest.main()

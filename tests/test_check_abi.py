"""Tests for tools/check-abi.py CLI against templates, Bash scripts, and invalid outputs."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_support import (
    OPTION_ID,
    REPO_ROOT,
    create_synthetic_fixture,
    isolate_template,
    new_op_id,
)

CHECK_ABI = REPO_ROOT / "tools" / "check-abi.py"


class CheckAbiCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="publishd-abi-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.work_root = Path(self.temporary.name)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECK_ABI), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_validates_isolated_minimal_template_with_negative_probes(self) -> None:
        template_dir = isolate_template(self.work_root, "minimal-template")
        config_file = create_synthetic_fixture(self.work_root / "fixture", OPTION_ID, "sample-project", "2:4.1~rc1")

        pub = self.run_cli(
            "publish",
            "--option-id", OPTION_ID,
            "--server-id", "test",
            "--channel-id", "candidate",
            "--project-id", "sample-project",
            "--version", "2:4.1~rc1",
            "--expect-outcome", "APPLIED",
            "--probe-negative-inputs",
            "--",
            sys.executable, "-I", str(template_dir / "publish.py"), "--config", str(config_file),
        )
        self.assertEqual(pub.returncode, 0, pub.stderr)
        self.assertEqual(json.loads(pub.stdout)["response"]["outcome"], "APPLIED")

        inv = self.run_cli(
            "inventory",
            "--purpose", "VERIFY",
            "--require-authoritative",
            "--option-id", OPTION_ID,
            "--server-id", "test",
            "--channel-id", "candidate",
            "--project-id", "sample-project",
            "--probe-negative-inputs",
            "--",
            sys.executable, "-I", str(template_dir / "inventory.py"), "--config", str(config_file),
        )
        self.assertEqual(inv.returncode, 0, inv.stderr)
        parsed = json.loads(inv.stdout)
        self.assertEqual(parsed["response"]["deployments"][0]["version"], "2:4.1~rc1")

    def test_validates_bash_script(self) -> None:
        bash_script = self.work_root / "publish.sh"
        bash_script.write_text(
            "req=$(cat)\n"
            "op_id=$(printf '%s' \"$req\" | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"operationId\"])')\n"
            "printf '{\"abiVersion\":1,\"operationId\":\"%s\",\"outcome\":\"ALREADY_PRESENT\"}\\n' \"$op_id\"\n",
            encoding="utf-8",
        )
        res = self.run_cli("publish", "--expect-outcome", "ALREADY_PRESENT", "--", "/bin/sh", str(bash_script))
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_rejects_malformed_abi_outputs_and_lingering_setsid_children(self) -> None:
        op_id = new_op_id()
        bad_outputs = [
            '{"abiVersion":1,"abiVersion":1,"operationId":"' + op_id + '","outcome":"APPLIED"}',
            '{"abiVersion":1,"operationId":"' + op_id + '","outcome":"APPLIED","extra":1}',
            '{"abiVersion":1,"operationId":"' + op_id + '","outcome":"APPLIED"} {}',
            '{"abiVersion":true,"operationId":"' + op_id + '","outcome":"APPLIED"}',
            '{"abiVersion":1,"operationId":"' + op_id + '","outcome":"REJECTED","errorCode":"UNSAFE_CODE"}',
            '{"abiVersion":1,"operationId":"' + op_id + '","outcome":"APPLIED","errorCode":"ARTIFACT_REJECTED"}',
            '{"abiVersion":1,"operationId":"' + new_op_id() + '","outcome":"APPLIED"}',
        ]
        for idx, body in enumerate(bad_outputs):
            script = self.work_root / f"bad_{idx}.py"
            script.write_text(f"import sys\nsys.stdin.read()\nprint({body!r})\n", encoding="utf-8")
            res = self.run_cli("publish", "--operation-id", op_id, "--", sys.executable, str(script))
            self.assertNotEqual(res.returncode, 0, f"Expected failure for bad output #{idx}: {body}")

        # Background child escaping synchronous completion violates setsid rule.
        leaker = self.work_root / "leaker.py"
        leaker.write_text(
            "import json, subprocess, sys\n"
            "req = json.load(sys.stdin)\n"
            "subprocess.Popen(['/bin/sleep', '30'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "print(json.dumps({'abiVersion': 1, 'operationId': req['operationId'], 'outcome': 'APPLIED'}))\n",
            encoding="utf-8",
        )
        leaked = self.run_cli("publish", "--operation-id", op_id, "--", sys.executable, str(leaker))
        self.assertNotEqual(leaked.returncode, 0)
        self.assertIn("setsid", leaked.stderr)

    def test_inventory_validation_and_validate_json_subcommand(self) -> None:
        op_id = new_op_id()
        req = {
            "abiVersion": 1,
            "operation": "inventory",
            "operationId": op_id,
            "optionId": OPTION_ID,
            "serverId": "test",
            "channelId": "candidate",
            "projectIds": ["proj-a"],
            "purpose": "VERIFY",
        }
        req_file = self.work_root / "inv-req.json"
        req_file.write_text(json.dumps(req), encoding="utf-8")

        good_resp = {
            "abiVersion": 1,
            "operationId": op_id,
            "serverId": "test",
            "channelId": "candidate",
            "complete": True,
            "observationMode": "AUTHORITATIVE",
            "sourceObservedAt": None,
            "sourceStale": False,
            "deployments": [{"projectId": "proj-a", "version": "1.0", "sourceObservedAt": None}],
        }
        good_file = self.work_root / "good-resp.json"
        good_file.write_text(json.dumps(good_resp), encoding="utf-8")
        ok = self.run_cli(
            "validate-json",
            "--operation", "inventory",
            "--request-file", str(req_file),
            "--response-file", str(good_file),
            "--require-authoritative",
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)

        # CACHED mode rejected when --require-authoritative is set; out-of-scope projectId rejected always.
        for mutate in [
            {"observationMode": "CACHED"},
            {"complete": False},
            {"deployments": [{"projectId": "rogue-proj", "version": "1.0", "sourceObservedAt": None}]},
        ]:
            bad = dict(good_resp, **mutate)
            bad_file = self.work_root / "bad-resp.json"
            bad_file.write_text(json.dumps(bad), encoding="utf-8")
            fail = self.run_cli(
                "validate-json",
                "--operation", "inventory",
                "--request-file", str(req_file),
                "--response-file", str(bad_file),
                "--require-authoritative",
            )
            self.assertNotEqual(fail.returncode, 0)


if __name__ == "__main__":
    unittest.main()

"""Offline tests for isolated minimal-template/ and local-repository/ starter folders."""
from __future__ import annotations

import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_support import (
    OPTION_ID,
    create_synthetic_fixture,
    isolate_template,
    new_op_id,
    run_isolated,
)


class LocalAdapterMixin:
    template_name: str

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work_root = Path(self.temporary.name)
        self.template_dir = isolate_template(self.work_root, self.template_name)
        self.root = self.work_root / "fixture"
        self.config_file = create_synthetic_fixture(self.root, OPTION_ID, "sample-project", "2:4.1~rc1")
        self.config = json.loads(self.config_file.read_text(encoding="utf-8"))

    def save(self) -> None:
        self.config_file.write_text(json.dumps(self.config), encoding="utf-8")

    def publish_request(self, version: str = "2:4.1~rc1", operation_id: str | None = None) -> dict[str, object]:
        return {
            "abiVersion": 1,
            "operation": "publish",
            "operationId": operation_id or new_op_id(),
            "optionId": OPTION_ID,
            "serverId": "test",
            "channelId": "candidate",
            "projectId": "sample-project",
            "version": version,
        }

    def inventory_request(self, projects: list[str] | None = None) -> dict[str, object]:
        return {
            "abiVersion": 1,
            "operation": "inventory",
            "operationId": new_op_id(),
            "optionId": OPTION_ID,
            "serverId": "test",
            "channelId": "candidate",
            "projectIds": ["sample-project"] if projects is None else projects,
            "purpose": "VERIFY",
        }

    def process(self, request: dict[str, object], raw: str | None = None) -> subprocess.CompletedProcess[str]:
        return run_isolated(self.template_dir, f"{request['operation']}.py", self.config_file, request, raw)

    def invoke(self, request: dict[str, object]) -> dict[str, object]:
        response = self.process(request)
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stderr, "")
        return json.loads(response.stdout)

    def test_publish_and_authoritative_inventory(self) -> None:
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])
        first = self.invoke(self.publish_request())
        self.assertEqual(first["outcome"], "APPLIED")

        # Inventory must read live destination state, never artifactRoot or journalRoot.
        shutil.rmtree(self.config["artifactRoot"])
        shutil.rmtree(self.config["journalRoot"])
        inv = self.invoke(self.inventory_request())
        self.assertTrue(inv["complete"])
        self.assertEqual(inv["observationMode"], "AUTHORITATIVE")
        self.assertFalse(inv["sourceStale"])
        self.assertIsNone(inv["sourceObservedAt"])
        self.assertEqual(
            inv["deployments"],
            [{"projectId": "sample-project", "version": "2:4.1~rc1", "sourceObservedAt": None}],
        )

    def test_missing_exact_versions_rejected_without_mutation(self) -> None:
        for version in ["4.1", "2:4.1", "2:4.1~rc", "2:4.1~rc10", " 2:4.1~rc1", "-x;$(echo nope)", "é/../*"]:
            response = self.invoke(self.publish_request(version))
            self.assertEqual((response["outcome"], response.get("errorCode")), ("REJECTED", "ARTIFACT_UNAVAILABLE"))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_rejected_destination(self) -> None:
        for field, value in [("serverId", "other"), ("channelId", "stable"), ("optionId", new_op_id())]:
            req = self.publish_request()
            req[field] = value
            resp = self.invoke(req)
            self.assertEqual((resp["outcome"], resp["errorCode"]), ("REJECTED", "DESTINATION_REJECTED"))
        self.assertFalse(Path(self.config["journalRoot"]).exists())

    def test_duplicate_artifacts_rejected(self) -> None:
        source = next(Path(self.config["artifactRoot"]).rglob("metadata.json")).parent
        shutil.copytree(source, source.parent / "two")
        resp = self.invoke(self.publish_request())
        self.assertEqual((resp["outcome"], resp["errorCode"]), ("REJECTED", "ARTIFACT_AMBIGUOUS"))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_malformed_and_symlink_artifacts_rejected(self) -> None:
        metadata = next(Path(self.config["artifactRoot"]).rglob("metadata.json"))
        metadata.write_text("invalid JSON", encoding="utf-8")
        resp = self.invoke(self.publish_request())
        self.assertEqual((resp["outcome"], resp["errorCode"]), ("REJECTED", "ARTIFACT_REJECTED"))

        # Also test symlink rejection.
        payload = metadata.parent / "payload.bin"
        metadata.write_text(json.dumps({"projectId": "sample-project", "version": "2:4.1~rc1"}), encoding="utf-8")
        target = self.work_root / "outside.bin"
        target.write_bytes(b"outside")
        payload.unlink()
        payload.symlink_to(target)
        resp2 = self.invoke(self.publish_request())
        self.assertEqual((resp2["outcome"], resp2["errorCode"]), ("REJECTED", "ARTIFACT_REJECTED"))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_stable_operation_identity_and_conflict(self) -> None:
        op_id = new_op_id()
        req = self.publish_request(operation_id=op_id)
        first = self.invoke(req)
        shutil.rmtree(self.config["artifactRoot"])
        self.assertEqual(self.invoke(req), first)
        req["version"] = "different"
        conflict = self.invoke(req)
        self.assertEqual((conflict["outcome"], conflict["errorCode"]), ("REJECTED", "OPERATION_CONFLICT"))

    def test_uncertain_start_is_never_replayed(self) -> None:
        req = self.publish_request()
        fingerprint = hashlib.sha256(
            json.dumps(req, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        journal = Path(self.config["journalRoot"])
        journal.mkdir()
        (journal / (hashlib.sha256(str(req["operationId"]).encode("utf-8")).hexdigest() + ".json")).write_text(
            json.dumps({"fingerprint": fingerprint}),
            encoding="utf-8",
        )
        response = self.invoke(req)
        self.assertEqual((response["outcome"], response["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_strict_json_input(self) -> None:
        req = self.publish_request()
        for raw in [
            json.dumps(req) + " {}",
            json.dumps(req)[:-1] + ',"version":"duplicate"}',
            json.dumps(dict(req, abiVersion=True)),
            json.dumps(dict(req, extraField="unexpected")),
        ]:
            response = self.process(req, raw)
            self.assertNotEqual(response.returncode, 0)
            self.assertEqual(response.stdout, "")

    def test_shared_resource_lock_blocks_scripts(self) -> None:
        lock = Path(self.config["destinations"][0]["resourceLock"])
        with lock.open("a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            proc = subprocess.Popen(
                [sys.executable, "-I", str(self.template_dir / "inventory.py"), "--config", str(self.config_file)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.template_dir),
            )
            try:
                assert proc.stdin is not None
                proc.stdin.write(json.dumps(self.inventory_request()))
                proc.stdin.close()
                time.sleep(0.15)
                self.assertIsNone(proc.poll())
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)
                proc.wait(timeout=10)
                stderr = proc.stderr.read() if proc.stderr else ""
                for s in (proc.stdout, proc.stderr):
                    if s:
                        s.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_destination_corruption_fails_inventory(self) -> None:
        self.invoke(self.publish_request())
        blob = next(Path(self.config["destinations"][0]["root"]).rglob("*.bin"))
        blob.write_bytes(b"corrupted")
        response = self.process(self.inventory_request())
        self.assertNotEqual(response.returncode, 0)
        self.assertEqual(response.stdout, "")

    def test_request_size_and_project_count_limits(self) -> None:
        projects_20k = [f"project-{i:05d}" for i in range(20000)]
        req_20k = self.inventory_request(projects=projects_20k)
        raw_20k = json.dumps(req_20k, ensure_ascii=False, separators=(",", ":"))
        self.assertGreater(len(raw_20k.encode("utf-8")), 65536)
        self.assertLess(len(raw_20k.encode("utf-8")), 4 * 1024 * 1024)
        self.assertEqual(self.invoke(req_20k)["deployments"], [])

        req_20001 = self.inventory_request(projects=[f"project-{i:05d}" for i in range(20001)])
        too_many = self.process(req_20001)
        self.assertNotEqual(too_many.returncode, 0)
        self.assertEqual(too_many.stdout, "")

        # Exact 4 MiB boundary vs 4 MiB + 1 byte.
        base_req = self.inventory_request(projects=["é" * 255])
        raw_base = json.dumps(base_req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        at_limit = (raw_base + b" " * (4 * 1024 * 1024 - len(raw_base))).decode("utf-8")
        ok_resp = self.process(base_req, at_limit)
        self.assertEqual(ok_resp.returncode, 0, ok_resp.stderr)
        over_resp = self.process(base_req, at_limit + " ")
        self.assertNotEqual(over_resp.returncode, 0)
        self.assertEqual(over_resp.stdout, "")


class MinimalTemplateTests(LocalAdapterMixin, unittest.TestCase):
    template_name = "minimal-template"

    def test_republish_same_version_returns_already_present(self) -> None:
        first = self.invoke(self.publish_request())
        self.assertEqual(first["outcome"], "APPLIED")
        second = self.invoke(self.publish_request())
        self.assertEqual(second["outcome"], "ALREADY_PRESENT")


class LocalRepositoryTests(LocalAdapterMixin, unittest.TestCase):
    template_name = "local-repository"


if __name__ == "__main__":
    unittest.main()

"""Offline tests for isolated ftps/ template against an ephemeral Explicit FTPS server."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import unittest
import tempfile

from ftps_fixture import LoopbackFtpsServer, generate_pki
from test_support import (
    OPTION_ID,
    create_synthetic_fixture,
    isolate_template,
    new_op_id,
    run_isolated,
)


class FtpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.pki_dir = tempfile.TemporaryDirectory(prefix="publishd-ftps-pki-")
        cls.addClassCleanup(cls.pki_dir.cleanup)
        cls.pki = generate_pki(Path(cls.pki_dir.name))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="publishd-ftps-")
        self.addCleanup(self.temporary.cleanup)
        self.work_root = Path(self.temporary.name)
        self.template_dir = isolate_template(self.work_root, "ftps")
        self.root = self.work_root / "fixture"
        self.config_file = create_synthetic_fixture(self.root, OPTION_ID, "sample-project", "2:4.1~rc1")
        self.config = json.loads(self.config_file.read_text(encoding="utf-8"))

        self.remote_root = self.work_root / "ftps-server-root"
        (self.remote_root / "pub" / "releases").mkdir(parents=True)

        self.server = LoopbackFtpsServer(
            self.remote_root,
            certfile=self.pki["server_cert"],
            keyfile=self.pki["server_key"],
            username="deployer",
            password="fixture-secret-pass",
        )
        self.server.start()
        self.addCleanup(self.server.stop)

        self.netrc_file = self.work_root / "ftps.netrc"
        self.netrc_file.write_text(
            "machine 127.0.0.1\n  login deployer\n  password fixture-secret-pass\n"
            "machine localhost\n  login deployer\n  password fixture-secret-pass\n",
            encoding="utf-8",
        )
        self.netrc_file.chmod(0o600)

        target = self.config["destinations"][0]
        target.pop("root")
        target["ftps"] = {
            "host": "127.0.0.1",
            "port": self.server.port,
            "remoteRoot": "/pub/releases",
            "netrcFile": str(self.netrc_file),
            "caFile": str(self.pki["ca_cert"]),
            "passive": True,
            "timeoutSeconds": 15,
        }
        self.save()

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

    def process(self, req: dict[str, object], raw: str | None = None):
        return run_isolated(self.template_dir, f"{req['operation']}.py", self.config_file, req, raw)

    def invoke(self, req: dict[str, object]) -> dict[str, object]:
        res = self.process(req)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stderr, "")
        return json.loads(res.stdout)

    def test_ftps_publish_prot_p_type_i_rnto_and_authoritative_inventory(self) -> None:
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

        pub = self.invoke(self.publish_request())
        self.assertEqual(pub["outcome"], "APPLIED")
        self.assertIn("AUTH", self.server.commands)
        self.assertIn("PROT", self.server.commands)
        self.assertIn("TYPE", self.server.commands)
        # Verify atomic .part upload followed by RNFR/RNTO rename for both blob and current.json.
        self.assertEqual(len(self.server.renames), 2)
        self.assertTrue(self.server.renames[0][0].endswith(".part"))
        self.assertTrue(self.server.renames[0][1].endswith(".bin"))
        self.assertTrue(self.server.renames[1][0].endswith(".part"))
        self.assertTrue(self.server.renames[1][1].endswith("/current.json"))

        # Subsequent publish of the exact same version with a new operationId yields ALREADY_PRESENT.
        again = self.invoke(self.publish_request())
        self.assertEqual(again["outcome"], "ALREADY_PRESENT")

        # Inventory must still succeed after deleting local artifactRoot & journalRoot.
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

    def test_pre_transfer_rejections_make_zero_ftps_connections(self) -> None:
        # Missing artifact
        r1 = self.invoke(self.publish_request("9.9.9"))
        self.assertEqual((r1["outcome"], r1["errorCode"]), ("REJECTED", "ARTIFACT_UNAVAILABLE"))

        # Bad destination
        bad_dest = self.publish_request()
        bad_dest["channelId"] = "other"
        r2 = self.invoke(bad_dest)
        self.assertEqual((r2["outcome"], r2["errorCode"]), ("REJECTED", "DESTINATION_REJECTED"))

        # Ambiguous artifact
        source = next(Path(self.config["artifactRoot"]).rglob("metadata.json")).parent
        shutil.copytree(source, source.parent / "two")
        r3 = self.invoke(self.publish_request())
        self.assertEqual((r3["outcome"], r3["errorCode"]), ("REJECTED", "ARTIFACT_AMBIGUOUS"))

        # Malformed artifact
        shutil.rmtree(source.parent / "two")
        (source / "metadata.json").write_text("bad json", encoding="utf-8")
        r4 = self.invoke(self.publish_request())
        self.assertEqual((r4["outcome"], r4["errorCode"]), ("REJECTED", "ARTIFACT_REJECTED"))

        self.assertEqual(self.server.connection_count, 0)
        self.assertFalse(Path(self.config["journalRoot"]).exists())

    def test_netrc_0644_refused_with_zero_connections(self) -> None:
        self.netrc_file.chmod(0o644)
        pub = self.process(self.publish_request())
        self.assertNotEqual(pub.returncode, 0)
        self.assertEqual(pub.stdout, "")
        self.assertNotIn("fixture-secret-pass", pub.stderr)

        inv = self.process(self.inventory_request())
        self.assertNotEqual(inv.returncode, 0)
        self.assertEqual(inv.stdout, "")
        self.assertEqual(self.server.connection_count, 0)
        self.assertFalse(Path(self.config["journalRoot"]).exists())

    def test_untrusted_ca_and_hostname_mismatch_fail_closed(self) -> None:
        # 1) Untrusted CA file
        self.config["destinations"][0]["ftps"]["caFile"] = str(self.pki["untrusted_ca_cert"])
        self.save()
        inv_untrusted = self.process(self.inventory_request())
        self.assertNotEqual(inv_untrusted.returncode, 0)
        self.assertEqual(inv_untrusted.stdout, "")

        req = self.publish_request()
        pub_untrusted = self.invoke(req)
        self.assertEqual((pub_untrusted["outcome"], pub_untrusted["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        # Started/uncertain journal must not replay even after fixing CA!
        self.config["destinations"][0]["ftps"]["caFile"] = str(self.pki["ca_cert"])
        self.save()
        self.assertEqual(self.invoke(req), pub_untrusted)

        # 2) Server certificate with wrong SAN hostname
        wrong_server = LoopbackFtpsServer(
            self.remote_root,
            certfile=self.pki["wrong_cert"],
            keyfile=self.pki["wrong_key"],
            username="deployer",
            password="fixture-secret-pass",
        )
        wrong_server.start()
        self.addCleanup(wrong_server.stop)
        self.config["destinations"][0]["ftps"]["port"] = wrong_server.port
        self.save()

        inv_wrong_host = self.process(self.inventory_request())
        self.assertNotEqual(inv_wrong_host.returncode, 0)
        self.assertEqual(inv_wrong_host.stdout, "")
        pub_wrong_host = self.invoke(self.publish_request())
        self.assertEqual((pub_wrong_host["outcome"], pub_wrong_host["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))

    def test_interrupted_rnto_is_uncertain_and_never_replayed(self) -> None:
        self.server.fail_on_rnto = True
        req = self.publish_request()
        first = self.invoke(req)
        self.assertEqual((first["outcome"], first["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        # .part file exists on server, but current.json was NOT promoted -> inventory sees empty deployments.
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

        # Clear fault and replay the exact same operationId -> MUST return UNKNOWN without re-uploading.
        self.server.fail_on_rnto = False
        before_conns = self.server.connection_count
        self.assertEqual(self.invoke(req), first)
        self.assertEqual(self.server.connection_count, before_conns)
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_remote_blob_corruption_fails_inventory(self) -> None:
        self.assertEqual(self.invoke(self.publish_request())["outcome"], "APPLIED")
        blob = next(self.remote_root.rglob("*.bin"))
        blob.write_bytes(b"corrupted over remote storage")
        inv = self.process(self.inventory_request())
        self.assertNotEqual(inv.returncode, 0)
        self.assertEqual(inv.stdout, "")


if __name__ == "__main__":
    unittest.main()

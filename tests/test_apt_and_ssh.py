"""Offline tests for isolated apt/ (local & remote SSH) and rsync-ssh/ templates."""
from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from test_minimal_and_local import LocalAdapterMixin
from test_support import (
    OPTION_ID,
    REPO_ROOT,
    create_synthetic_fixture,
    isolate_template,
    new_op_id,
    run_isolated,
)


def load_abi_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AptBaseMixin(LocalAdapterMixin):
    template_name = "apt"

    def setUp(self) -> None:
        super().setUp()
        shutil.rmtree(self.config["artifactRoot"])
        Path(self.config["artifactRoot"]).mkdir()
        self.config["projects"] = {"sample-project": "sample-app"}
        self.target = self.config["destinations"][0]
        self.target.update(distribution="synthetic", component="main", architecture="amd64")
        self.repository = Path(self.target["root"])
        (self.repository / "conf").mkdir()
        self.distributions = self.repository / "conf" / "distributions"
        self.distributions.write_text(
            "Codename: synthetic\nArchitectures: amd64\nComponents: main\nDescription: Synthetic disposable test\n",
            encoding="utf-8",
        )
        self.tool("export", "synthetic")
        self.package("2:4.1~rc1", "exact.deb")
        self.save()

    def tool(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["/usr/bin/reprepro", "--basedir", str(self.repository), *arguments],
            capture_output=True,
            check=check,
        )

    def package(self, version: str, filename: str, package: str = "sample-app", architecture: str = "amd64") -> Path:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "DEBIAN").mkdir()
            (root / "DEBIAN" / "control").write_text(
                f"Package: {package}\n"
                f"Version: {version}\n"
                f"Architecture: {architecture}\n"
                f"Maintainer: Fixture <fixture@example.invalid>\n"
                f"Section: misc\n"
                f"Priority: optional\n"
                f"Description: Synthetic disposable package\n",
                encoding="utf-8",
            )
            (root / "synthetic.txt").write_text("synthetic payload " + version, encoding="utf-8")
            artifact = Path(self.config["artifactRoot"]) / filename
            subprocess.run(
                ["/usr/bin/dpkg-deb", "--build", "--root-owner-group", str(root), str(artifact)],
                check=True,
                capture_output=True,
            )
            return artifact

    def test_malformed_and_symlink_artifacts_rejected(self) -> None:
        bad = Path(self.config["artifactRoot"]) / "invalid.deb"
        bad.write_bytes(b"invalid")
        self.assertEqual(self.invoke(self.publish_request())["errorCode"], "ARTIFACT_REJECTED")
        bad.unlink()

        real_deb = next(Path(self.config["artifactRoot"]).glob("*.deb"))
        outside = self.work_root / "outside.deb"
        shutil.copyfile(real_deb, outside)
        real_deb.unlink()
        real_deb.symlink_to(outside)
        self.assertEqual(self.invoke(self.publish_request())["errorCode"], "ARTIFACT_REJECTED")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_request_size_and_project_count_limits(self) -> None:
        projects_20k = [f"project-{i:05d}" for i in range(20000)]
        mapping_20k = {p: p for p in projects_20k}
        mapping_20k["é" * 255] = "sample-utf8"
        self.config["projects"] = mapping_20k
        self.save()
        if hasattr(self, "remote"):
            self.remote["projects"] = mapping_20k
            self.remote_file.write_text(json.dumps(self.remote), encoding="utf-8")
        super().test_request_size_and_project_count_limits()


class LocalAptTests(AptBaseMixin, unittest.TestCase):
    def test_duplicate_artifacts_rejected(self) -> None:
        artifact = next(Path(self.config["artifactRoot"]).glob("*.deb"))
        shutil.copy(artifact, artifact.parent / "duplicate.deb")
        self.assertEqual(self.invoke(self.publish_request())["errorCode"], "ARTIFACT_AMBIGUOUS")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_destination_corruption_fails_inventory(self) -> None:
        self.invoke(self.publish_request())
        artifact = next((self.repository / "pool").rglob("*.deb"))
        artifact.write_bytes(b"corrupted")
        response = self.process(self.inventory_request())
        self.assertNotEqual(response.returncode, 0)
        self.assertEqual(response.stdout, "")

    def test_exact_metadata_despite_deceptive_filenames(self) -> None:
        self.package("2:4.1~rc10", "contains-2_4.1~rc1.deb")
        self.package("2:4.1~rc1", "wrong-package.deb", package="other-app")
        self.package("2:4.1~rc1", "wrong-architecture.deb", architecture="arm64")
        self.assertEqual(self.invoke(self.publish_request())["outcome"], "APPLIED")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], "2:4.1~rc1")

    def test_exact_epoch_and_revision_are_preserved(self) -> None:
        self.package("3:4.1~rc1-2", "next.deb")
        self.invoke(self.publish_request("3:4.1~rc1-2"))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], "3:4.1~rc1-2")

    def test_debian_equivalent_versions_do_not_match_opaque_request(self) -> None:
        self.package("1.0", "equivalent.deb")
        for version in ["1.00", "1.0-0", "0:1.0"]:
            response = self.invoke(self.publish_request(version))
            self.assertEqual(response["errorCode"], "ARTIFACT_UNAVAILABLE")

    def test_architecture_all_is_accepted_but_duplicate_identity_is_rejected(self) -> None:
        root = Path(self.config["artifactRoot"])
        next(root.glob("*.deb")).unlink()
        self.package("2:4.1~rc1", "all.deb", architecture="all")
        self.assertEqual(self.invoke(self.publish_request())["outcome"], "APPLIED")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], "2:4.1~rc1")
        self.package("2:4.1~rc1", "native.deb")
        self.assertEqual(self.invoke(self.publish_request())["errorCode"], "ARTIFACT_AMBIGUOUS")

    def test_external_repository_change_is_authoritative(self) -> None:
        artifact = self.package("7.0-1", "external.deb")
        self.tool("--component", "main", "includedeb", "synthetic", str(artifact))
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], "7.0-1")
        self.tool("remove", "synthetic", "sample-app")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_partial_index_fails_completeness(self) -> None:
        self.invoke(self.publish_request())
        index = self.repository / "dists/synthetic/main/binary-amd64/Packages"
        index.write_bytes(b"")
        response = self.process(self.inventory_request())
        self.assertNotEqual(response.returncode, 0)
        self.assertEqual(response.stdout, "")

    def test_real_tool_partial_failure_is_uncertain_and_never_replayed(self) -> None:
        self.distributions.write_text(self.distributions.read_text() + "SignWith: ! /bin/false\n", encoding="utf-8")
        request = self.publish_request()
        response = self.invoke(request)
        self.assertEqual((response["outcome"], response["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        self.assertIn(b"sample-app", self.tool("list", "synthetic").stdout)
        self.distributions.write_text(
            self.distributions.read_text().replace("SignWith: ! /bin/false\n", ""),
            encoding="utf-8",
        )
        self.tool("export", "synthetic")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], request["version"])
        self.assertEqual(self.invoke(request), response)


class SshFixture:
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        Path.home().mkdir(mode=0o700, parents=True, exist_ok=True)
        cls.ssh_temp = tempfile.TemporaryDirectory(prefix="publishd-ssh-", dir=Path.home())
        cls.addClassCleanup(cls.ssh_temp.cleanup)
        cls.ssh_root = Path(cls.ssh_temp.name)
        for name in ("host", "client"):
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.ssh_root / name)],
                check=True,
            )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]
        cls.known_hosts = cls.ssh_root / "known_hosts"
        public_key = (cls.ssh_root / "host.pub").read_text(encoding="utf-8").split()
        cls.known_hosts.write_text(f"[127.0.0.1]:{cls.port} {public_key[0]} {public_key[1]}\n", encoding="utf-8")
        cls.ssh_config = cls.ssh_root / "client_config"
        cls.ssh_config.write_text(
            f"Host fixture\n"
            f" HostName 127.0.0.1\n"
            f" Port {cls.port}\n"
            f" User {pwd.getpwuid(os.getuid()).pw_name}\n"
            f" IdentityFile {cls.ssh_root}/client\n"
            f" IdentitiesOnly yes\n"
            f" UserKnownHostsFile {cls.known_hosts}\n",
            encoding="utf-8",
        )
        config = cls.ssh_root / "sshd_config"
        config.write_text(
            f"Port {cls.port}\n"
            f"ListenAddress 127.0.0.1\n"
            f"HostKey {cls.ssh_root}/host\n"
            f"PidFile {cls.ssh_root}/pid\n"
            f"AuthorizedKeysFile {cls.ssh_root}/client.pub\n"
            f"PasswordAuthentication no\n"
            f"KbdInteractiveAuthentication no\n"
            f"UsePAM no\n"
            f"StrictModes yes\n"
            f"AllowTcpForwarding no\n"
            f"X11Forwarding no\n",
            encoding="utf-8",
        )
        cls.ssh_log = (cls.ssh_root / "log").open("w+", encoding="utf-8")
        cls.addClassCleanup(cls.ssh_log.close)
        cls.sshd = subprocess.Popen(
            ["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
            stdout=cls.ssh_log,
            stderr=cls.ssh_log,
        )
        cls.addClassCleanup(cls.stop_sshd)
        for _ in range(100):
            if cls.sshd.poll() is not None:
                cls.ssh_log.seek(0)
                raise RuntimeError(cls.ssh_log.read())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise RuntimeError("SSH fixture did not start")

    @classmethod
    def stop_sshd(cls) -> None:
        cls.sshd.terminate()
        cls.sshd.wait(timeout=5)

    def setUp(self) -> None:
        super().setUp()
        self.remote = copy.deepcopy(self.config)
        # Spaces and shell metacharacters exercise SSH and rsync quoting.
        self.staging = self.root / "remote staging ' ; $"
        self.staging.mkdir()
        self.remote["artifactRoot"] = str(self.staging)
        self.remote["journalRoot"] = str(self.root / "remote-journal")
        self.remote["destinations"][0]["resourceLock"] = str(self.root / "remote.lock")
        self.remote_file = self.root / "remote config ' ; $.json"
        self.remote_file.write_text(json.dumps(self.remote), encoding="utf-8")
        self.config["destinations"][0]["ssh"] = {
            "host": "fixture",
            "configFile": str(self.ssh_config),
            "stagingRoot": str(self.staging),
            "config": str(self.remote_file),
            "publishScript": str(self.template_dir / "receive.py"),
            "inventoryScript": str(self.template_dir / "inventory.py"),
        }
        self.save()

    def test_local_destination_is_not_used(self) -> None:
        self.config["destinations"][0].pop("root")
        self.save()
        self.assertEqual(self.invoke(self.publish_request())["outcome"], "APPLIED")
        self.assertEqual(len(self.invoke(self.inventory_request())["deployments"]), 1)

    def test_remote_lock_blocks_inventory(self) -> None:
        with Path(self.remote["destinations"][0]["resourceLock"]).open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
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
                time.sleep(0.3)
                self.assertIsNone(proc.poll())
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                proc.wait(timeout=10)
                diagnostic = proc.stderr.read() if proc.stderr else ""
                for s in (proc.stdout, proc.stderr):
                    if s:
                        s.close()
                self.assertEqual(proc.returncode, 0, diagnostic)

    def test_untrusted_host_key_fails_closed(self) -> None:
        invalid = self.root / "untrusted_config"
        invalid.write_text(
            self.ssh_config.read_text(encoding="utf-8").replace(
                str(self.known_hosts),
                str(self.root / "empty_known_hosts"),
            ),
            encoding="utf-8",
        )
        self.config["destinations"][0]["ssh"]["configFile"] = str(invalid)
        self.save()
        response = self.invoke(self.publish_request())
        self.assertEqual((response["outcome"], response["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        inventory = self.process(self.inventory_request())
        self.assertNotEqual(inventory.returncode, 0)
        self.assertEqual(inventory.stdout, "")
        self.assertNotIn(str(self.root), inventory.stderr)

    def test_missing_remote_script_is_uncertain_and_not_replayed(self) -> None:
        ssh = self.config["destinations"][0]["ssh"]
        script = ssh["publishScript"]
        ssh["publishScript"] = str(self.root / "missing-script")
        self.save()
        req = self.publish_request()
        first = self.invoke(req)
        self.assertEqual(first["outcome"], "UNKNOWN")
        ssh["publishScript"] = script
        self.save()
        self.assertEqual(self.invoke(req), first)
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_remote_started_journal_is_not_replayed(self) -> None:
        req = self.publish_request()
        fingerprint = hashlib.sha256(
            json.dumps(req, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        journal = Path(self.remote["journalRoot"])
        journal.mkdir()
        (journal / (hashlib.sha256(str(req["operationId"]).encode("utf-8")).hexdigest() + ".json")).write_text(
            json.dumps({"fingerprint": fingerprint}),
            encoding="utf-8",
        )
        self.assertEqual(self.invoke(req)["outcome"], "UNKNOWN")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_remote_allowlist_is_enforced(self) -> None:
        self.remote["destinations"][0]["optionIds"] = []
        self.remote_file.write_text(json.dumps(self.remote), encoding="utf-8")
        self.assertEqual(self.invoke(self.publish_request())["outcome"], "UNKNOWN")
        self.assertFalse(Path(self.remote["journalRoot"]).exists())

    def test_lost_response_after_remote_mutation_is_uncertain(self) -> None:
        ssh = self.config["destinations"][0]["ssh"]
        helper = self.root / "lost_response.py"
        helper.write_text(
            "import subprocess, sys\n"
            + "subprocess.run("
            + repr(["/usr/bin/python3", "-I", ssh["publishScript"], "--config", ssh["config"]])
            + ", input=sys.stdin.buffer.read(), stdout=subprocess.DEVNULL, check=True)\n"
            + "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        ssh["publishScript"] = str(helper)
        self.save()
        req = self.publish_request()
        first = self.invoke(req)
        self.assertEqual((first["outcome"], first["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        self.assertEqual(len(self.invoke(self.inventory_request())["deployments"]), 1)
        self.assertEqual(self.invoke(req), first)

    def test_remote_journal_returns_original_result(self) -> None:
        req = self.publish_request()
        result = self.invoke(req)
        self.assertEqual(result["outcome"], "APPLIED")
        abi = load_abi_module(self.template_dir / "_abi.py", f"abi_{self.template_name}")
        shutil.rmtree(self.staging)
        self.assertEqual(abi.invoke_ssh(self.config["destinations"][0], req), result)
        req["version"] = "changed"
        self.assertEqual(abi.invoke_ssh(self.config["destinations"][0], req)["errorCode"], "OPERATION_CONFLICT")


class RsyncSshTests(SshFixture, LocalAdapterMixin, unittest.TestCase):
    template_name = "rsync-ssh"

    def test_opaque_shell_characters_are_data(self) -> None:
        project = "sample-project"
        version = "$(touch SHOULD_NOT_EXIST); ' version / *"
        old = next(Path(self.config["artifactRoot"]).rglob("metadata.json")).parent
        new = old.parent.parent / hashlib.sha256(version.encode("utf-8")).hexdigest() / "candidate"
        new.parent.mkdir()
        shutil.move(str(old), str(new))
        (new / "metadata.json").write_text(json.dumps({"projectId": project, "version": version}), encoding="utf-8")
        self.assertEqual(self.invoke(self.publish_request(version))["outcome"], "APPLIED")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], version)


class RemoteAptTests(SshFixture, AptBaseMixin, unittest.TestCase):
    def test_duplicate_artifacts_rejected(self) -> None:
        artifact = next(Path(self.config["artifactRoot"]).glob("*.deb"))
        shutil.copy(artifact, artifact.parent / "duplicate.deb")
        self.assertEqual(self.invoke(self.publish_request())["errorCode"], "ARTIFACT_AMBIGUOUS")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"], [])

    def test_destination_corruption_fails_inventory(self) -> None:
        self.invoke(self.publish_request())
        artifact = next((self.repository / "pool").rglob("*.deb"))
        artifact.write_bytes(b"corrupted")
        response = self.process(self.inventory_request())
        self.assertNotEqual(response.returncode, 0)
        self.assertEqual(response.stdout, "")

    def test_real_tool_partial_failure_is_uncertain_and_never_replayed(self) -> None:
        self.distributions.write_text(self.distributions.read_text() + "SignWith: ! /bin/false\n", encoding="utf-8")
        request = self.publish_request()
        response = self.invoke(request)
        self.assertEqual((response["outcome"], response["errorCode"]), ("UNKNOWN", "PUBLICATION_UNCERTAIN"))
        self.assertIn(b"sample-app", self.tool("list", "synthetic").stdout)
        self.distributions.write_text(
            self.distributions.read_text().replace("SignWith: ! /bin/false\n", ""),
            encoding="utf-8",
        )
        self.tool("export", "synthetic")
        self.assertEqual(self.invoke(self.inventory_request())["deployments"][0]["version"], request["version"])
        self.assertEqual(self.invoke(request), response)


class TransportLimitTests(unittest.TestCase):
    def test_timeout_and_output_limits(self) -> None:
        abi = load_abi_module(REPO_ROOT / "rsync-ssh" / "_abi.py", "rsync_ssh_abi_limits")
        for program, exception, timeout in [
            ("import time; time.sleep(2)", TimeoutError, 0.05),
            ("import sys; sys.stdout.buffer.write(b'x' * (4 * 1024 * 1024 + 1))", ValueError, 5),
            ("import sys; sys.stderr.buffer.write(b'x' * 16385)", ValueError, 5),
        ]:
            with self.subTest(program=program), self.assertRaises(exception):
                abi.command([sys.executable, "-c", program], timeout=timeout)


if __name__ == "__main__":
    unittest.main()

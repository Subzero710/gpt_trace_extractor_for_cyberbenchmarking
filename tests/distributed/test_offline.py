"""Offline tests of real PKI files, source transactions and configuration contracts.

They run the actual TLS record engine offline, with no VM, socket or deployment claim.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
sys.dont_write_bytecode = True
from gpt_trace_transport.pki import provision, verify_bundle
from gpt_trace_transport.wire import Endpoint, IdentityFailure, certificate_sha


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file() and ".local-preparation-patch-backups" not in p.parts}


class SourceTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ROOT / "patch_local_preparation.py"
        if not source.is_file():
            raise RuntimeError("keep the autonomous patch_local_preparation.py at the repository root to test its engine")
        cls.engine = load("distributed_source_engine_test", source)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repository"
        self.root.mkdir()
        # Derive a fixture only from actual checked-out sources and verify every original Git blob.
        for name, raw in self.engine.baseline(ROOT).items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            current = ROOT / name
            path.chmod(stat.S_IMODE(current.stat().st_mode) if current.exists() else self.engine.DATA["modes"][name])
        self.before = snapshot(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def apply(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.engine.apply(self.root)

    def rollback(self):
        with self.engine.locked(self.root), contextlib.redirect_stdout(io.StringIO()):
            self.engine.restore_transaction(self.root, self.engine.latest(self.root))

    def test_check_and_dry_run_leave_every_file_and_timestamp_unchanged(self):
        for mode in ("--check", "--dry-run"):
            result = subprocess.run([sys.executable, ROOT / "patch_local_preparation.py", mode, "--root", self.root],
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("without writes", result.stdout)
            self.assertEqual(snapshot(self.root), self.before)
            self.assertFalse((self.root / self.engine.BACKUP_DIRECTORY).exists())

    def test_apply_is_idempotent_and_rollback_restores_bytes_and_modes(self):
        self.apply()
        applied = snapshot(self.root)
        self.apply()
        self.assertEqual(snapshot(self.root), applied)
        self.engine.verify(self.root, quiet=True)
        unrelated = self.root / "unrelated-user-notes.txt"
        unrelated.write_text("preserve this file\n")
        self.rollback()
        restored = snapshot(self.root)
        for name, (raw, mode, _) in self.before.items():
            self.assertEqual(restored[name][:2], (raw, mode), name)
        self.assertEqual(set(restored), set(self.before) | {unrelated.name})
        self.assertEqual(unrelated.read_text(), "preserve this file\n")

    def test_user_configured_resource_dimensions_are_preserved(self):
        path = self.root / "config/runner.toml"
        source = path.read_text().replace("memory_mb = 5120", "memory_mb = 4096").replace("vcpus = 6", "vcpus = 4")
        path.write_text(source)
        self.apply()
        self.assertEqual(path.read_text(), source)

    def test_unknown_source_revision_fails_before_source_writes(self):
        (self.root / "README.md").write_text("unknown upstream revision\n")
        before = snapshot(self.root)
        with self.assertRaises(self.engine.PatchError): self.engine.planned(self.root)
        self.assertEqual(snapshot(self.root), before)

    def test_unknown_new_path_is_not_overwritten(self):
        path = self.root / "shared/gpt_trace_transport/local_templates.py"
        path.write_text("user-owned control configuration\n")
        before = snapshot(self.root)
        with self.assertRaises(self.engine.PatchError): self.engine.planned(self.root)
        self.assertEqual(snapshot(self.root), before)

    def test_symlink_escape_is_rejected_without_touching_its_target(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside workspace\n")
        path = self.root / "README.md"
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(self.engine.PatchError): self.engine.planned(self.root)
        self.assertEqual(outside.read_text(), "outside workspace\n")

    def test_concurrent_writer_lock_is_enforced(self):
        with self.engine.locked(self.root):
            with self.assertRaises(self.engine.PatchError): self.apply()
        self.assertEqual(snapshot(self.root), self.before)

    def test_failed_atomic_write_restores_the_entire_transaction(self):
        original = self.engine.atomic
        reached = []
        def fail_once(root, name, raw, *args, **kwargs):
            if name == "scripts/distributed.py" and not reached:
                reached.append(name)
                raise OSError("injected source disk write failure")
            return original(root, name, raw, *args, **kwargs)
        with patch.object(self.engine, "atomic", fail_once):
            with self.assertRaises(OSError): self.apply()
        self.assertEqual(reached, ["scripts/distributed.py"])
        restored = snapshot(self.root)
        self.assertEqual({name: value[:2] for name, value in restored.items()},
                         {name: value[:2] for name, value in self.before.items()})
        journal = json.loads((self.root / self.engine.journal_path(self.engine.latest(self.root))).read_text())
        self.assertEqual(journal["status"], "rolled_back")

    def test_rollback_refuses_a_subsequent_edit_before_restoring_any_file(self):
        self.apply()
        path = self.root / "README.md"
        path.write_bytes(path.read_bytes() + b"\nuser edit after migration\n")
        before = snapshot(self.root)
        with self.assertRaises(self.engine.PatchError): self.rollback()
        self.assertEqual(snapshot(self.root), before)

    def test_rollback_checks_backup_integrity_before_any_source_write(self):
        self.apply()
        backup = self.root / self.engine.BACKUP_DIRECTORY / self.engine.latest(self.root) / "originals/README.md"
        backup.write_bytes(b"corrupted backup")
        before = snapshot(self.root)
        with self.assertRaises(self.engine.PatchError): self.rollback()
        self.assertEqual(snapshot(self.root), before)

    def test_rollback_refuses_a_subsequent_permission_change(self):
        self.apply()
        (self.root / "README.md").chmod(0o600)
        before = snapshot(self.root)
        with self.assertRaises(self.engine.PatchError): self.rollback()
        self.assertEqual(snapshot(self.root), before)

    def test_incomplete_or_unowned_transaction_cannot_restore_any_file(self):
        self.apply()
        manifest = self.root / self.engine.journal_path(self.engine.latest(self.root))
        original = json.loads(manifest.read_bytes())
        for attack in ("omitted-file", "unowned-directory"):
            changed = json.loads(json.dumps(original))
            if attack == "omitted-file": changed["files"].pop()
            else: changed["created_directories"].append("state/persistent-user-data")
            manifest.write_text(json.dumps(changed))
            before = snapshot(self.root)
            with self.assertRaises(self.engine.PatchError): self.rollback()
            self.assertEqual(snapshot(self.root), before)

    def test_verify_reports_incomplete_source_instead_of_success(self):
        with self.assertRaises(self.engine.PatchError): self.engine.verify(self.root, quiet=True)
        self.assertEqual(snapshot(self.root), self.before)


class OfflineCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.result = provision(cls.directory / "pki", server_name="execution-broker.test",
            execution_address="192.168.90.10", control_address="192.168.90.20")
        cls.control = cls.directory / "pki/control"
        cls.expected = {"control_id": "control", "execution_id": "execution", "execution_address": "192.168.90.10",
            "control_address": "192.168.90.20", "server_name": "execution-broker.test", "port": 9443}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def verify(self, role="control", expected=None):
        return verify_bundle(self.control, self.result["control"]["manifest_sha256"], role, expected or self.expected)

    def handshake(self, hostname):
        # OpenSSL's actual TLS engine over in-memory records; no socket or mocked TLS result.
        manifest = self.verify()
        endpoint = Endpoint("mtls", Path("/unused.sock"), "https://execution-broker.test:9443", "192.168.90.10",
            self.control / "ca.crt", self.control / "admin.crt", self.control / "admin.key", manifest["server_sha256"])
        server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        execution = self.directory / "pki/execution"
        server_context.load_verify_locations(cafile=str(execution / "ca.crt"))
        server_context.load_cert_chain(str(execution / "server.crt"), str(execution / "server.key"))
        server_context.verify_mode = ssl.CERT_REQUIRED
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
        client = endpoint.client_context().wrap_bio(client_in, client_out, server_hostname=hostname)
        server = server_context.wrap_bio(server_in, server_out, server_side=True)
        completed = set()
        for _ in range(100):
            for name, stream in (("client", client), ("server", server)):
                if name in completed: continue
                try:
                    stream.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    completed.add(name)
            for output, target in ((client_out, server_in), (server_out, client_in)):
                while output.pending: target.write(output.read())
            if len(completed) == 2: return client, server, client_out, server_in
        raise AssertionError("real TLS record handshake did not converge")

    def test_real_certificate_bundles_and_scopes_validate_offline(self):
        manifest = self.verify()
        self.assertEqual(manifest["server_sha256"], self.result["server_certificate_sha256"])
        self.assertFalse((self.control / "server.key").exists())
        self.assertFalse((self.directory / "pki/execution/admin.key").exists())
        self.assertNotEqual(certificate_sha(self.control / "admin.crt"), certificate_sha(self.control / "controller.crt"))
        endpoint = Endpoint("mtls", Path("/unused.sock"), "https://execution-broker.test:9443", "192.168.90.10",
            self.control / "ca.crt", self.control / "admin.crt", self.control / "admin.key", manifest["server_sha256"])
        self.assertTrue(endpoint.client_context().check_hostname)

    def test_wrong_role_or_host_identity_is_rejected(self):
        with self.assertRaises(ValueError): self.verify("execution")
        with self.assertRaises(ValueError): self.verify(expected={**self.expected, "control_id": "wrong-host"})

    def test_actual_mtls_handshake_and_encrypted_bytes_without_network(self):
        client, server, output, target = self.handshake("execution-broker.test")
        self.assertEqual(hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest(), self.result["server_certificate_sha256"])
        self.assertEqual(hashlib.sha256(server.getpeercert(binary_form=True)).hexdigest(), certificate_sha(self.control / "admin.crt"))
        content = os.urandom(4096)
        self.assertEqual(client.write(content), len(content))
        while output.pending: target.write(output.read())
        self.assertEqual(server.read(8192), content)

    def test_actual_tls_engine_rejects_wrong_dns_identity(self):
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake("wrong-host.test")

    def test_altered_token_and_key_permissions_are_rejected(self):
        token = self.control / "workstation_broker_admin_token"
        raw = token.read_bytes()
        try:
            token.write_bytes(b"x" * 64)
            with self.assertRaises(ValueError): self.verify()
        finally:
            token.write_bytes(raw)
        key = self.control / "admin.key"
        try:
            key.chmod(0o644)
            with self.assertRaises(IdentityFailure): self.verify()
        finally:
            key.chmod(0o600)

    def test_public_or_equal_host_addresses_are_rejected_before_creation(self):
        output = self.directory / "invalid"
        for execution, control in (("8.8.8.8", "192.168.1.2"), ("192.168.1.2", "192.168.1.2")):
            with self.assertRaises(ValueError):
                provision(output, server_name="execution.test", execution_address=execution, control_address=control)
        self.assertFalse(output.exists())


class SourceContractTests(unittest.TestCase):
    def test_original_mcp_manifest_and_registry_pin_are_unchanged(self):
        manifest = (ROOT / "apps/kali-workstation/tool-manifest.json").read_bytes()
        registry = json.loads((ROOT / "apps/registry/apps.json").read_bytes())
        sha = hashlib.sha256(json.dumps(json.loads(manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual([x["manifest_sha256"] for x in registry["apps"] if x["id"] == "kali-workstation"], [sha])
        engine = load("distributed_contract_engine_test", ROOT / "patch_local_preparation.py")
        self.assertEqual(engine.blob_sha(manifest), engine.DATA["catalog"]["apps/kali-workstation/tool-manifest.json"])

    def test_guest_semantics_retain_the_original_golden_fingerprint(self):
        image = load("distributed_golden_builder_test", ROOT / "infra/workstation/image/build.py")
        self.assertEqual(image.golden_build_input_sha256(), "4130895e6f37115739a3b832d8b5e6ce3c371a403968cda95c57a249e4a0f29e")


if __name__ == "__main__":
    unittest.main()

"""Offline tests of real PKI files, source transactions and configuration contracts.

They run the actual TLS record engine offline, with no VM, socket or deployment claim.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import ssl
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

    def test_golden_fingerprint_pins_512_gib_virtual_disk(self):
        image = load("distributed_golden_builder_test", ROOT / "infra/workstation/image/build.py")
        self.assertEqual(image.VIRTUAL_DISK_GIB, 512)
        fingerprint = image.golden_build_input_sha256()
        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
        with patch.object(image, "VIRTUAL_DISK_GIB", 256):
            self.assertNotEqual(fingerprint, image.golden_build_input_sha256())


if __name__ == "__main__":
    unittest.main()

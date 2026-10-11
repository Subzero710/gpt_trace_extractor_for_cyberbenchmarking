"""Real sockets, TLS handshakes and file writes; this suite does not claim to test KVM."""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
from gpt_trace_transport.gateway import Gateway
from gpt_trace_transport.pki import provision, issue, verify_bundle
from gpt_trace_transport.wire import Endpoint, WireClient, IdentityFailure, TransportFailure, certificate_sha, safe_file


class FileBackend(http.server.BaseHTTPRequestHandler):
    """A file-transfer endpoint, not a simulated VM/broker implementation."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        return

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, self.headers.get("Authorization"), raw))
        if self.path == "/v1/artifact_stage_chunk":
            payload = json.loads(raw)
            data = base64.b64decode(payload["content_base64"], validate=True)
            with self.server.target.open("ab") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            if self.server.disconnect:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
        if self.server.delay:
            time.sleep(self.server.delay)
        data = json.dumps({"received_sha256": hashlib.sha256(raw).hexdigest()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(999999999 if self.server.oversized else len(data)+100 if self.server.truncated else len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            return


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.result = provision(cls.directory / "pki", server_name="execution-broker.test",
            execution_address="192.168.90.10", control_address="192.168.90.20")
        cls.authority = cls.directory / "pki/authority"
        cls.credentials = cls.directory / "pki/control"
        cls.socket = cls.directory / "broker.sock"
        cls.backend = UnixServer(str(cls.socket), FileBackend)
        cls.backend.requests, cls.backend.delay, cls.backend.disconnect = [], 0, False
        cls.backend.oversized = cls.backend.truncated = False
        cls.backend.target = cls.directory / "received.bin"
        cls.backend_thread = threading.Thread(target=cls.backend.serve_forever, daemon=True)
        cls.backend_thread.start()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_verify_locations(cafile=str(cls.authority / "ca.crt"))
        context.load_cert_chain(str(cls.authority / "server.crt"), str(cls.authority / "server.key"))
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        cls.roles = {certificate_sha(cls.credentials / (name + ".crt")):
                     (name, "urn:gpt-trace:control:" + name, (cls.credentials / ("workstation_broker_" + name + "_token")).read_text().strip())
                     for name in ("admin", "controller")}
        cls.gateway = Gateway(("127.0.0.1", 0), context, WireClient(Endpoint("unix", cls.socket)), cls.roles, "127.0.0.1", timeout=0.15)
        cls.gateway_thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.gateway_thread.start()
        cls.endpoint = Endpoint("mtls", cls.socket, "https://execution-broker.test:" + str(cls.gateway.server_port),
            "127.0.0.1", cls.credentials / "ca.crt", cls.credentials / "admin.crt", cls.credentials / "admin.key",
            certificate_sha(cls.authority / "server.crt"), operation_timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.gateway.shutdown()
        cls.backend.shutdown()
        cls.gateway.server_close()
        cls.backend.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.backend.requests.clear()
        self.backend.target.unlink(missing_ok=True)
        self.backend.disconnect, self.backend.delay = False, 0
        self.backend.oversized = self.backend.truncated = False

    def credential(self, role="admin"):
        return (self.credentials / ("workstation_broker_" + role + "_token")).read_text().strip()

    def test_unix_compatibility_preserves_exact_bytes(self):
        payload = {"content_base64": base64.b64encode(os.urandom(1048576)).decode()}
        raw = json.dumps(payload).encode()
        status, response = WireClient(Endpoint("unix", self.socket)).exchange("POST", "/v1/artifact_stage_chunk", raw,
            "Bearer " + self.credential())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response)["received_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.backend.target.read_bytes(), base64.b64decode(payload["content_base64"]))

    def test_mtls_roundtrip_writes_the_authenticated_bytes(self):
        data = os.urandom(1048576)
        raw = json.dumps({"content_base64": base64.b64encode(data).decode()}).encode()
        status, response = WireClient(self.endpoint).exchange("POST", "/v1/artifact_stage_chunk", raw, "Bearer " + self.credential())
        self.assertEqual(status, 200)
        self.assertEqual(self.backend.target.read_bytes(), data)
        self.assertEqual(json.loads(response)["received_sha256"], hashlib.sha256(raw).hexdigest())

    def test_certificate_and_token_scopes_are_bound_together(self):
        endpoint = replace(self.endpoint, cert=self.credentials / "controller.crt", key=self.credentials / "controller.key")
        client = WireClient(endpoint)
        for action in ("destroy_all", "create_attempt", "create_evaluator", "evaluator_rpc", "preflight_templates", "reconcile_attempt"):
            status, _ = client.exchange("POST", "/v1/" + action, b"{}", "Bearer " + self.credential("controller"))
            self.assertEqual(status, 403)
        status, _ = client.exchange("POST", "/v1/inspect_attempt", b"{}", "Bearer " + self.credential())
        self.assertEqual(status, 401)
        status, _ = client.exchange("POST", "/v1/inspect_attempt", b"{}", "Bearer " + self.credential("controller"))
        self.assertEqual(status, 200)
        self.assertEqual(len(self.backend.requests), 1)

    def test_wrong_server_pin_is_rejected_before_authorization_is_sent(self):
        with self.assertRaises(IdentityFailure):
            WireClient(replace(self.endpoint, server_sha256="0" * 64)).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
        self.assertEqual(self.backend.requests, [])

    def test_wrong_server_hostname_rejects_tls(self):
        endpoint = replace(self.endpoint, url="https://wrong-name.test:" + str(self.gateway.server_port))
        with self.assertRaises(IdentityFailure):
            WireClient(endpoint).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
        self.assertEqual(self.backend.requests, [])

    def test_unpinned_client_identity_is_forbidden(self):
        issue(self.authority, "intruder", "URI:urn:gpt-trace:control:intruder", "clientAuth")
        endpoint = replace(self.endpoint, cert=self.authority / "intruder.crt", key=self.authority / "intruder.key")
        status, _ = WireClient(endpoint).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
        self.assertEqual(status, 403)
        self.assertEqual(self.backend.requests, [])

    def test_expired_client_certificate_is_rejected_by_handshake(self):
        expired = self.directory / "expired.crt"
        subprocess.run(["openssl", "x509", "-req", "-in", str(self.authority / "admin.csr"),
            "-CA", str(self.authority / "ca.crt"), "-CAkey", str(self.authority / "ca.key"),
            "-set_serial", "999", "-days", "-1", "-extfile", str(self.authority / "admin.ext"), "-out", str(expired)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        with self.assertRaises(TransportFailure):
            WireClient(replace(self.endpoint, cert=expired)).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
        self.assertEqual(self.backend.requests, [])

    def test_private_key_permissions_and_symlinks_are_rejected(self):
        key = self.directory / "unsafe.key"
        key.write_bytes((self.credentials / "admin.key").read_bytes())
        key.chmod(0o644)
        with self.assertRaises(IdentityFailure): WireClient(replace(self.endpoint, key=key))
        key.unlink()
        key.symlink_to(self.credentials / "admin.key")
        with self.assertRaises(IdentityFailure): WireClient(replace(self.endpoint, key=key))

    def test_bundle_identity_hash_and_role_are_verified(self):
        expected = {"control_id": "control", "execution_id": "execution", "execution_address": "192.168.90.10",
                    "control_address": "192.168.90.20", "server_name": "execution-broker.test", "port": 9443}
        verified = verify_bundle(self.credentials, self.result["control"]["manifest_sha256"], "control", expected)
        self.assertEqual(verified["server_sha256"], self.endpoint.server_sha256)
        with self.assertRaises(ValueError): verify_bundle(self.credentials, "0" * 64, "control", expected)
        with self.assertRaises(ValueError): verify_bundle(self.credentials, self.result["control"]["manifest_sha256"], "execution", expected)

    def test_disconnect_after_mutation_is_not_replayed_or_reported_absent(self):
        self.backend.disconnect = True
        data = os.urandom(127)
        raw = json.dumps({"content_base64": base64.b64encode(data).decode()}).encode()
        status, response = WireClient(self.endpoint).exchange("POST", "/v1/artifact_stage_chunk", raw, "Bearer " + self.credential())
        self.assertEqual(status, 503)
        self.assertIn("unconfirmed", json.loads(response)["detail"])
        self.assertEqual(len(self.backend.requests), 1)
        self.assertEqual(self.backend.target.read_bytes(), data)
        self.backend.disconnect = False
        self.assertEqual(WireClient(self.endpoint).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())[0], 200)

    def test_upstream_timeout_is_an_explicit_unconfirmed_outcome(self):
        self.backend.delay = 0.4
        status, response = WireClient(self.endpoint).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
        self.assertEqual(status, 503)
        self.assertIn("unconfirmed", json.loads(response)["detail"])

    def test_oversized_and_truncated_responses_fail_closed(self):
        for name in ("oversized", "truncated"):
            setattr(self.backend, name, True)
            status, response = WireClient(self.endpoint).exchange("POST", "/v1/probe", b"{}", "Bearer " + self.credential())
            self.assertEqual(status, 503)
            self.assertIn("unconfirmed", json.loads(response)["detail"])
            setattr(self.backend, name, False)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import ssl
import threading
import time
from pathlib import Path

from .wire import (CONTROLLER_ACTIONS, MAX_BODY, Endpoint, WireClient,
                   TransportFailure, certificate_sha, private_address, safe_file, token)


class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, address, context, upstream, roles, allowed_peer, timeout=1900):
        self.context, self.upstream = context, upstream
        self.roles, self.allowed_peer, self.operation_timeout = roles, allowed_peer, timeout
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if client_address[0] != self.allowed_peer or not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(10)
            secured = self.context.wrap_socket(request, server_side=True)
            super().process_request_thread(secured, client_address)
        except (ssl.SSLError, OSError):
            self.shutdown_request(request)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PrivateBroker/1"

    def log_message(self, *_):
        # Tokens, bodies and identities are not written to HTTP access logs.
        return

    def respond(self, status, data):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def fail(self, status, detail):
        self.respond(status, json.dumps({"detail": detail}).encode())

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        certificate = self.connection.getpeercert()
        digest = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        role = self.server.roles.get(digest)
        if role is None or set(certificate.get("subjectAltName", ())) != {("URI", role[1])}:
            return self.fail(403, "unrecognized client certificate identity")
        is_health = self.command == "GET" and self.path == "/healthz"
        match = re.fullmatch(r"/v1/([a-z_]{1,64})", self.path)
        if not is_health and (self.command != "POST" or match is None):
            return self.fail(404, "unknown broker route")
        if not is_health:
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or not hmac.compare_digest(auth[0], "Bearer " + role[2]):
                return self.fail(401, "token does not belong to authenticated certificate scope")
            if role[0] == "controller" and match[1] not in CONTROLLER_ACTIONS:
                return self.fail(403, "controller lifecycle/evaluator action forbidden")
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect"):
            return self.fail(400, "chunked and expect framing forbidden")
        if is_health and not lengths:
            lengths = ["0"]
        if len(lengths) != 1 or not lengths[0].isdigit():
            return self.fail(400, "exactly one content length required")
        size = int(lengths[0])
        if size > MAX_BODY:
            return self.fail(413, "broker frame too large")
        try:
            deadline = time.monotonic() + 60
            raw, remaining = bytearray(), size
            while remaining:
                self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                if time.monotonic() >= deadline:
                    raise TimeoutError("request body deadline")
                piece = self.rfile.read1(min(65536, remaining))
                if not piece:
                    raise OSError("truncated request")
                raw.extend(piece)
                remaining -= len(piece)
            status, data = self.server.upstream.exchange(self.command, self.path, bytes(raw),
                "" if is_health else "Bearer " + role[2], timeout=self.server.operation_timeout)
            self.connection.settimeout(30)
            self.respond(status, data)
            completed = getattr(self.server.upstream, "response_sent", None)
            if completed is not None:
                completed(self.command, self.path, status, bytes(raw), role[0])
        except (TransportFailure, OSError, TimeoutError):
            self.fail(503, "broker communication failed; VM outcome unconfirmed; reconcile before any retry")


def start_from_env(socket_path: Path | None, *, upstream=None, operation_timeout=1900):
    if os.environ.get("WORKSTATION_BROKER_LISTENER", "unix") == "unix":
        return None
    if os.environ["WORKSTATION_BROKER_LISTENER"] != "mtls":
        raise RuntimeError("unknown broker listener")
    address = private_address(os.environ["WORKSTATION_BROKER_LISTEN_ADDRESS"])
    peer = private_address(os.environ["WORKSTATION_BROKER_ALLOWED_PEER"])
    port = int(os.environ["WORKSTATION_BROKER_LISTEN_PORT"])
    if not 1024 <= port <= 65535 or address == peer:
        raise ValueError("invalid broker listener address/port")
    directory = Path(os.environ["WORKSTATION_BROKER_TLS_DIR"])
    safe_file(directory / "server.key", secret=True)
    safe_file(directory / "server.crt")
    safe_file(directory / "ca.crt")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_verify_locations(cafile=str(directory / "ca.crt"))
    context.load_cert_chain(str(directory / "server.crt"), str(directory / "server.key"))
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    roles = {}
    for role in ("admin", "controller"):
        credential = token(Path(os.environ[f"WORKSTATION_BROKER_{role.upper()}_TOKEN_FILE"]))
        roles[certificate_sha(directory / (role + ".crt"))] = (
            role, "urn:gpt-trace:" + os.environ["WORKSTATION_BROKER_CONTROL_ID"] + ":" + role, credential)
    if len(roles) != 2 or len({row[2] for row in roles.values()}) != 2:
        raise ValueError("client certificates and tokens must be distinct")
    if upstream is None:
        if socket_path is None: raise ValueError("native upstream socket required")
        upstream = WireClient(Endpoint("unix", socket_path))
    server = Gateway((address, port), context, upstream, roles, peer, timeout=operation_timeout)
    thread = threading.Thread(target=server.serve_forever, name="private-broker-mtls", daemon=True)
    thread.start()
    return server

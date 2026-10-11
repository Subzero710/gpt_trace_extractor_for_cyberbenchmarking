"""Short-lived post-broker-exit Unix HTTP endpoint for authenticated shutdown proof.

It is never a general broker and never listens on TCP. Cloudflare Tunnel
continues to route to the same private Unix socket across the handoff.
"""
from __future__ import annotations
import http.server
import json
import os
import socketserver
import threading
from pathlib import Path


class UnixConfirmationServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False


class ConfirmationHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def do_GET(self): self.handle_operation()
    def do_POST(self): self.handle_operation()
    def handle_operation(self):
        length = self.headers.get_all('Content-Length', [])
        if (self.command != 'POST' or self.path not in ('/v1/shutdown_status','/v1/shutdown_complete')
                or self.headers.get_all('Transfer-Encoding') or len(length) != 1
                or not length[0].isdigit() or int(length[0]) > 4096):
            self.respond(404, b'{"detail":"confirmation only"}')
            return
        self.connection.settimeout(10)
        raw = self.rfile.read(int(length[0]))
        if len(raw) != int(length[0]):
            self.respond(400, b'{"detail":"truncated body"}')
            return
        authorization = self.headers.get_all('Authorization', [])
        status, data = self.server.confirmation.exchange(self.command, self.path, raw,
            authorization[0] if len(authorization) == 1 else '')
        self.respond(status, data)
        self.server.confirmation.response_sent(self.command, self.path, status, raw, 'admin')
    def respond(self, status, data):
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(data)


def start_confirmation(socket_path, confirmation):
    socket_path = Path(socket_path)
    if socket_path.is_symlink(): raise ValueError('unsafe confirmation socket symlink')
    if socket_path.exists():
        if not socket_path.is_socket(): raise ValueError('unexpected confirmation socket path')
        socket_path.unlink()  # Broker process is verified dead by caller.
    if socket_path.parent.stat().st_mode & 0o077:
        raise ValueError('confirmation socket directory must be mode 0700')
    server = UnixConfirmationServer(str(socket_path), ConfirmationHandler)
    try:
        os.chmod(socket_path, 0o600)
        server.confirmation = confirmation
        threading.Thread(target=server.serve_forever, daemon=True, name='shutdown-unix-proof').start()
        return server
    except BaseException:
        server.server_close()
        socket_path.unlink(missing_ok=True)
        raise

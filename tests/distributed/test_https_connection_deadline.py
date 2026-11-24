"""Real TLS keep-alive and deadline cancellation, using only loopback."""
from __future__ import annotations

import functools
import http.server
import socket
import ssl
import subprocess
import threading
import time

import pytest

import superbench_pool as pool


@pytest.fixture
def https_origin(tmp_path, monkeypatch):
    certificate = tmp_path / 'certificate.pem'
    key = tmp_path / 'key.pem'
    host = '127.0.0.1'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=IP:' + host,
                    '-keyout', str(key), '-out', str(certificate)],
                   check=True, capture_output=True, timeout=pool._operation_timeout())
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    client_context = ssl.create_default_context(cafile=str(certificate))
    requests = []
    release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            requests.append((self.path, self.client_address))
            if self.path == '/stall':
                release.wait(5)
                self.close_connection = True
                return
            body = self.path.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer((host, 0), Handler) as server:
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        monkeypatch.setattr(pool, '_HTTPS_CONNECTIONS', threading.local())
        monkeypatch.setattr(pool, '_network_https_connection', functools.partial(
            pool._network_https_connection, port=server.server_port, context=client_context))
        try:
            yield host, requests
        finally:
            release.set()
            pool._drop_expected_https_connection(host)
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


def read_metadata(host, path):
    return pool._read_expected_https_once('https://' + host + path,
        timeout=10, limit=1024, user_agent='tls-regression', expected_host=host)


def test_real_https_metadata_reuses_tls_connection(https_origin):
    host, requests = https_origin
    assert read_metadata(host, '/first') == b'/first'
    connection = pool._HTTPS_CONNECTIONS.connections[host]
    tls = connection.sock
    assert isinstance(tls, ssl.SSLSocket)
    assert read_metadata(host, '/second') == b'/second'
    assert connection.sock is tls
    assert tls.fileno() >= 0
    assert read_metadata(host, '/third') == b'/third'
    assert [path for path, _ in requests] == ['/first', '/second', '/third']
    assert len({address for _, address in requests}) == 1


def test_deadline_interrupts_reused_tls_socket(https_origin, monkeypatch):
    host, requests = https_origin
    assert read_metadata(host, '/first') == b'/first'
    connection = pool._HTTPS_CONNECTIONS.connections[host]
    tls = connection.sock
    # The socket's own timeout is longer than the supervised attempt. Only
    # cancellation through the duplicate descriptor can interrupt this read.
    tls.settimeout(5)
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 0.5)
    start = time.monotonic()
    with pytest.raises(TimeoutError, match='attempt exceeded'):
        with pool._network_deadline() as attempt:
            attempt.watch(tls)
            duplicate, = attempt.sockets
            assert type(duplicate) is socket.socket
            assert duplicate.fileno() != tls.fileno()
            assert not duplicate.get_inheritable()
            connection.request('GET', '/stall')
            connection.getresponse()
    assert time.monotonic() - start < 3
    assert duplicate.fileno() == -1
    assert [path for path, _ in requests] == ['/first', '/stall']
    assert len({address for _, address in requests}) == 1

"""Cloudflare Tunnel HTTPS transport, generic roles and UDS handoff tests.

No Cloudflare account, Docker or KVM deployment is simulated as a live success.
"""
from __future__ import annotations
import hashlib
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'shared')]
from gpt_trace_transport.wire import Endpoint, IdentityFailure, WireClient
from gpt_trace_transport.unix_confirmation import start_confirmation
from gpt_trace_transport.wire import token_value


class TunnelWireTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.endpoint=Endpoint('https',Path('/unused'),'https://broker.example.org')

    def test_https_from_env_with_system_tls(self):
        with patch.dict(os.environ, {'WORKSTATION_BROKER_TRANSPORT':'https',
             'WORKSTATION_BROKER_URL':'https://broker.example.org'}):
            endpoint=Endpoint.from_env(Path('/unused'))
        ctx=endpoint.client_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode,ssl.CERT_REQUIRED)
        self.assertIsNone(endpoint.access_client_id_file if hasattr(endpoint,'access_client_id_file') else None)

    def test_real_tls_http_sends_only_scoped_broker_authorization(self):
        certificate=self.root/'cert.pem';key=self.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(key),'-out',str(certificate),'-subj','/CN=broker.example.org',
            '-addext','subjectAltName=DNS:broker.example.org'],check=True,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def do_POST(self):
                body=self.rfile.read(int(self.headers['Content-Length']))
                requests.append((self.headers,body))
                result=b'{"status":"ok"}'
                self.send_response(200)
                self.send_header('Content-Length',str(len(result)))
                self.send_header('Content-Type','application/json')
                self.end_headers();self.wfile.write(result)
        class Service(http.server.ThreadingHTTPServer):daemon_threads=True
        server=Service(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate),str(key))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        real_create=socket.create_connection
        client_context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(certificate))
        try:
            client=WireClient(self.endpoint)
            client.context=client_context
            with patch('socket.create_connection', side_effect=lambda _target, timeout: real_create(('127.0.0.1',server.server_port), timeout)):
                reply=client.request('probe',{'number':1},'admin-scoped-token')
            self.assertEqual(reply, {'status':'ok'})
            self.assertEqual(json.loads(requests[0][1]),{'number':1})
            headers=requests[0][0]
            self.assertEqual(headers['Authorization'],'Bearer admin-scoped-token')
            self.assertEqual(headers['Host'],'broker.example.org')
            self.assertIsNone(headers.get('CF-Access-Client-Id'))
            self.assertIsNone(headers.get('CF-Access-Client-Secret'))
        finally:
            server.shutdown();server.server_close()


class UnixShutdownTests(unittest.TestCase):
    def test_authenticated_post_exit_exchange_and_disallowed_routes(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);root.chmod(0o700)
            path=root/'broker.sock'
            class Confirmation:
                def __init__(self):self.completed=threading.Event();self.called=[]
                def exchange(self,method,url,body,authorization):
                    self.called.append((method,url,authorization))
                    if authorization!='Bearer correct':return 403,b'{}'
                    if json.loads(body) != {'shutdown_id':'123'}:return 409,b'{}'
                    return 200,b'{"broker_stopped":true}'
                def response_sent(self,method,url,status,body,role):
                    if url=='/v1/shutdown_complete' and status==200 and role=='admin':self.completed.set()
            conf=Confirmation()
            server=start_confirmation(path,conf)
            try:
                client=WireClient(Endpoint('unix',path))
                status,_=client.exchange('POST','/v1/destroy_all',b'{}','Bearer correct')
                self.assertEqual(status,404)
                status,_=client.exchange('POST','/v1/shutdown_status',b'{"shutdown_id":"123"}','Bearer wrong')
                self.assertEqual(status,403)
                status,_=client.exchange('POST','/v1/shutdown_complete',b'{"shutdown_id":"123"}','Bearer correct')
                self.assertEqual(status,200)
                self.assertTrue(conf.completed.is_set())
            finally:
                server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()

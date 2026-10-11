"""Cloudflare Tunnel HTTPS transport, generic roles and UDS handoff tests.

No Cloudflare account, Docker or KVM deployment is simulated as a live success.
"""
from __future__ import annotations
import hashlib
import http.server
import importlib.util
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'shared'), str(ROOT/'scripts')]
from gpt_trace_transport.wire import Endpoint, IdentityFailure, WireClient
from gpt_trace_transport.unix_confirmation import start_confirmation
from gpt_trace_transport.wire import token_value


def dispatcher():
    spec=importlib.util.spec_from_file_location('tunnel_dispatch_test', ROOT/'scripts/distributed.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'config').mkdir()
        (self.root/'config/distributed.toml').write_bytes((ROOT/'config/distributed.toml').read_bytes())
        self.module=dispatcher()
        self.patch=patch.object(self.module, 'ROOT', self.root)
        self.patch.start();self.addCleanup(self.patch.stop)

    def env(self,role='control',extra=''):
        src=self.root/'.env'
        src.write_text('DIST_ROLE='+role+'\n'+extra)
        src.chmod(0o600)
        return src

    def test_roles_are_generic_without_ip_hostname_or_pkis(self):
        self.env('control')
        cfg=self.module.config(credentials=False)
        self.assertEqual(cfg['deployment']['role'],'control')
        self.assertNotIn('network',cfg)
        self.assertNotIn('bundle',cfg)
        self.assertNotIn('fossil', (ROOT/'config/distributed.toml').read_text())
        self.env('execution')
        self.assertEqual(self.module.config(credentials=False)['deployment']['role'],'execution')

    def test_strict_configuration_and_url(self):
        with self.assertRaisesRegex(ValueError, 'missing/unsafe'):
            self.module.config(credentials=False)
        source=self.env(extra='DIST_ROLE=execution\n')
        with self.assertRaisesRegex(ValueError,'duplicate'):
            self.module.config(credentials=False)
        source=self.env()
        source.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'0600'):
            self.module.config(credentials=False)
        source.chmod(0o600)
        for origin in ('http://broker.example.org','https://127.0.0.1','https://foo.test:8080',
                       'https://u:p@foo.test','https://foo.test/path','https://foo.test?x=1'):
            with self.subTest(origin=origin),self.assertRaises(ValueError):
                self.module.broker_origin(origin)
        self.assertEqual(self.module.broker_origin('https://Broker.Example.Org/'),'https://broker.example.org')

    def test_execution_requirements_never_uses_legacy_network_config(self):
        from types import ModuleType
        requirements=ModuleType('host_requirements')
        requirements.verify_host_requirements=lambda **kw: True
        self.env('execution')
        cfg=self.module.config(credentials=False)
        with patch.object(self.module,'host'),patch.dict(sys.modules,{'host_requirements':requirements}):
            self.assertIsNone(self.module.execution(cfg,'requirements',None))

    def test_execution_tunnel_has_dedicated_project_and_no_public_port(self):
        self.env('execution','DIST_BROKER_TUNNEL_TOKEN=eyJ1234567890abcdefghijabcdefghijabcdefghij\n')
        cfg=self.module.config(credentials=False)
        calls=[]
        with patch.object(self.module,'run',side_effect=lambda args: calls.append(args)):
            self.module.execution_tunnel(cfg,'up')
            self.module.execution_tunnel(cfg,'down')
        self.assertIn(['up','-d','--wait','--wait-timeout','120'],[call[-5:] for call in calls])
        self.assertEqual(calls[-1][-1],'down')
        self.assertTrue(all('eyJ' not in str(call) for call in calls))
        compose=(ROOT/'compose.execution-tunnel.yaml').read_text()
        self.assertNotIn('ports:',compose)
        self.assertIn('broker.sock', (ROOT/'docs/distributed.md').read_text())

    def test_env_only_credentials_are_rejected_if_missing_or_equal(self):
        pair = ('DIST_BROKER_ADMIN_TOKEN='+'a'*64+'\n'
                'DIST_BROKER_CONTROLLER_TOKEN='+'b'*64+'\n')
        self.env(extra='DIST_BROKER_URL=https://broker.example.net\n')
        with self.assertRaises(Exception): self.module.config()
        self.env(extra='DIST_BROKER_URL=https://broker.example.net\n'+pair)
        cfg=self.module.config()
        self.module.environment(cfg)
        self.assertEqual(os.environ['WORKSTATION_BROKER_TRANSPORT'],'https')
        self.assertEqual(os.environ['WORKSTATION_BROKER_URL'],'https://broker.example.net')
        self.assertEqual(os.environ['DIST_BROKER_ADMIN_TOKEN'],'a'*64)
        self.assertFalse((self.root/'.secrets').exists())
        self.assertNotIn('WORKSTATION_CONTROL_PLANE_ADDRESS',
                         {k: v for k,v in os.environ.items() if k.startswith('DIST_')})
        self.env(extra='DIST_BROKER_URL=https://broker.example.net\n'
                       + 'DIST_BROKER_ADMIN_TOKEN='+'a'*64+'\n'
                       + 'DIST_BROKER_CONTROLLER_TOKEN='+'a'*64+'\n')
        with self.assertRaisesRegex(ValueError,'different tokens'): self.module.config()
        self.env('execution','DIST_BROKER_TUNNEL_TOKEN=eyJ1234567890abcdefghijabcdefghijabcdefghij\n'+pair)
        self.assertEqual(self.module.config()['deployment']['role'],'execution')


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

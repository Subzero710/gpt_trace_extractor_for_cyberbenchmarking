"""Cloudflare Access transport, generic roles and post-exit UDS handoff tests.

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
from create_broker_tokens import provision


def dispatcher():
    spec=importlib.util.spec_from_file_location('access_dispatch_test', ROOT/'scripts/distributed.py')
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

    def test_broker_credentials_are_distinct_generated_once(self):
        root=self.root/'generated'
        provision(root)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o700)
        names=sorted(root.iterdir())
        self.assertEqual(len(names),2)
        self.assertNotEqual(names[0].read_text(),names[1].read_text())
        self.assertTrue(all(stat.S_IMODE(name.stat().st_mode)==0o600 for name in names))
        with self.assertRaises(ValueError):provision(root)
        assert all('PRIVATE KEY' not in name.read_text() for name in names)

    def test_control_materialization_and_execution_local(self):
        directory=self.root/'.secrets/distributed'
        provision(directory)
        self.env(extra='DIST_BROKER_URL=https://broker.example.net\n'
                       'DIST_ACCESS_CLIENT_ID=id_123456789.access\n'
                       'DIST_ACCESS_CLIENT_SECRET=cfast_123456789123456789\n')
        cfg=self.module.config()
        self.module.environment(cfg)
        self.assertEqual((directory/'access_client_id').read_text().strip(),'id_123456789.access')
        self.assertEqual(stat.S_IMODE((directory/'access_client_secret').stat().st_mode),0o600)
        self.assertEqual(os.environ['WORKSTATION_BROKER_TRANSPORT'],'access')
        self.env('execution','DIST_BROKER_TUNNEL_TOKEN=eyJ1234567890abcdefghijabcdefghijabcdefghij\n')
        self.assertEqual(self.module.config()['deployment']['role'],'execution')


class AccessWireTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for name,value in [('id','sample-identifier.access'),('secret','cfast_12345678912345678912345')]:
            path=self.root/name
            path.write_text(value+'\n');path.chmod(0o600)
        self.endpoint=Endpoint('access',Path('/unused'),'https://broker.example.org',
            access_client_id_file=self.root/'id', access_client_secret_file=self.root/'secret')

    def test_access_env_and_verified_tls(self):
        with patch.dict(os.environ, {'WORKSTATION_BROKER_TRANSPORT':'access',
             'WORKSTATION_BROKER_URL':'https://broker.example.org',
             'WORKSTATION_BROKER_ACCESS_CLIENT_ID_FILE':str(self.root/'id'),
             'WORKSTATION_BROKER_ACCESS_CLIENT_SECRET_FILE':str(self.root/'secret')}):
            endpoint=Endpoint.from_env(Path('/unused'))
        ctx=endpoint.client_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode,ssl.CERT_REQUIRED)
        headers=endpoint.access_headers()
        self.assertEqual(headers['CF-Access-Client-Id'],'sample-identifier.access')
        self.assertEqual(headers['CF-Access-Client-Secret'],'cfast_12345678912345678912345')
        (self.root/'secret').chmod(0o644)
        with self.assertRaises(IdentityFailure):endpoint.client_context()

    def test_unauthenticated_edge_must_deny_health(self):
        from unittest.mock import MagicMock
        endpoint=self.endpoint
        with patch('http.client.HTTPSConnection') as fake:
            fake.return_value.getresponse.return_value.status=200
            with self.assertRaisesRegex(IdentityFailure,'not enforced'):
                WireClient(endpoint).check_access_policy()
            self.assertEqual(fake.return_value.request.call_args.args[:2],('GET','/healthz'))
            for status in (302,401,403):
                fake.return_value.getresponse.return_value.status=status
                WireClient(endpoint).check_access_policy()

    def test_real_tls_http_transport_sends_both_independent_credentials(self):
        # Test real TLS, certificate-name validation and HTTP bytes over loopback.
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
            self.assertEqual(headers['CF-Access-Client-Secret'],'cfast_12345678912345678912345')
            self.assertEqual(headers['Authorization'],'Bearer admin-scoped-token')
            self.assertEqual(headers['Host'],'broker.example.org')
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

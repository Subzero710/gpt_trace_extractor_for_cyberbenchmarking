"""User-supplied auth and read-only .env behavior; no secret generation/pairing."""
from __future__ import annotations
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'), str(ROOT/'shared')]
import distributed


def state_module():
    spec=importlib.util.spec_from_file_location('state_manual_env_test',ROOT/'scripts/project_state.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManualTokenTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'config').mkdir()
        (self.root/'config/distributed.toml').write_bytes((ROOT/'config/distributed.toml').read_bytes())
        self.secret_a='A'*64
        self.secret_b='B'*64

    def env(self,role='control',admin=None,controller=None):
        payload=(f'DIST_ROLE={role}\nDIST_BROKER_ADMIN_TOKEN={self.secret_a if admin is None else admin}\n'
                 f'DIST_BROKER_CONTROLLER_TOKEN={self.secret_b if controller is None else controller}\n')
        payload += ('DIST_BROKER_URL=https://broker.example.org\n' if role=='control'
                    else 'DIST_BROKER_TUNNEL_TOKEN=eyJ1234567890abcdefghijabcdefghijabcdefghij\n')
        file=self.root/'.env';file.write_text(payload);file.chmod(0o600)
        return file

    def test_broker_configuration_only_reads_manually_supplied_values(self):
        for role in ('control','execution'):
            env=self.env(role)
            before=env.read_bytes(),env.stat().st_mtime_ns
            with patch.object(distributed,'ROOT',self.root):
                cfg=distributed.config()
                self.assertEqual(cfg['local']['DIST_BROKER_ADMIN_TOKEN'],self.secret_a)
                self.assertEqual(cfg['local']['DIST_BROKER_CONTROLLER_TOKEN'],self.secret_b)
            self.assertEqual((env.read_bytes(),env.stat().st_mtime_ns),before)
        self.assertFalse((self.root/'.secrets').exists())

    def test_missing_duplicate_equal_or_weak_broker_tokens_are_rejected(self):
        for a,b in (('',self.secret_b),(self.secret_a,''),(self.secret_a,self.secret_a),('short',self.secret_b)):
            self.env(admin=a,controller=b)
            with patch.object(distributed,'ROOT',self.root),self.assertRaises(Exception):
                distributed.config()
        env=self.env()
        with env.open('a') as f: f.write('DIST_BROKER_ADMIN_TOKEN='+'Z'*64+'\n')
        with patch.object(distributed,'ROOT',self.root),self.assertRaisesRegex(ValueError,'duplicate'):
            distributed.config()

    def test_project_state_never_modifies_env_or_generates_app_secret(self):
        s=state_module()
        env=self.root/'.env'
        env.write_text('POSTGRES_PASSWORD=super-password\nTEACHER_BROWSER_TUNNEL_TOKEN=abc\n'
            'TEACHER_BROWSER_PUBLIC_URL=https://browser.example.org\n'
            'TEACHER_BROWSER_PASSWORD=super-password-long\n'
            'APP_CONTROL_TOKEN='+('C'*64)+'\nDIST_ROLE=control\n'
            'DIST_BROKER_URL=https://broker.example.org\n'
            'DIST_BROKER_ADMIN_TOKEN='+self.secret_a+'\n'
            'DIST_BROKER_CONTROLLER_TOKEN='+self.secret_b+'\n')
        env.chmod(0o600)
        before=(env.read_bytes(),env.stat().st_mtime_ns,env.stat().st_mode)
        with patch.object(s,'ENV_PATH',env),patch.object(s,'SECRETS_DIR',self.root/'.secrets'),patch.object(s,'TEACHER_BROWSER_PASSWORD',self.root/'.secrets/teacher_browser_password'),patch.object(sys,'argv',['project_state.py','core']):
            self.assertEqual(s.main(),0)
        self.assertEqual((env.read_bytes(),env.stat().st_mtime_ns,env.stat().st_mode),before)
        self.assertFalse((self.root/'.secrets/app_control_token').exists())
        self.assertTrue((self.root/'.secrets/teacher_browser_password').is_file())
        env.chmod(0o644)
        with patch.object(s,'ENV_PATH',env),patch.object(sys,'argv',['project_state.py','core']),self.assertRaisesRegex(SystemExit,'chmod 600'):
            s.main()
        self.assertEqual(env.stat().st_mode & 0o777,0o644)

    def test_compose_uses_operator_supplied_environment_secrets(self):
        cfg=json.loads((ROOT/'compose.control.yaml').read_text())
        for name,env in (('app_control_token','APP_CONTROL_TOKEN'),
            ('workstation_broker_admin_token','DIST_BROKER_ADMIN_TOKEN'),
            ('workstation_broker_controller_token','DIST_BROKER_CONTROLLER_TOKEN')):
            self.assertEqual(cfg['secrets'][name],{'environment':env})
        self.assertFalse((ROOT/'scripts/pair_broker.py').exists())
        self.assertFalse((ROOT/'scripts/create_broker_tokens.py').exists())

if __name__=='__main__': unittest.main()

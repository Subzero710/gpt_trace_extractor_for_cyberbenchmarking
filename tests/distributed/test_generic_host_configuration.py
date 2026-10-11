"""Versioned role/config contract; Cloudflare-specific cases live in test_cloudflare_tunnel."""
from __future__ import annotations
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class VersionedConfigurationTests(unittest.TestCase):
    def test_shared_config_has_no_host_identity_or_secrets(self):
        content=(ROOT/'config/distributed.toml').read_text()
        for forbidden in ('fossil','acer','192.168.','tls_directory','bundle_manifest_sha256','server_name'):
            self.assertNotIn(forbidden,content)
        self.assertIn('role = ""',content)
        self.assertEqual(content,(ROOT/'config/distributed.example.toml').read_text())

if __name__=='__main__':unittest.main()

"""Generic two-host config and automatically generated credential-bundle pins."""
from __future__ import annotations
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "shared"))
from gpt_trace_transport.pki import provision, verify_bundle

def dispatcher():
    spec = importlib.util.spec_from_file_location("generic_host_dispatch", ROOT / "scripts/distributed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class GenericRoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "config/distributed.toml").write_bytes((ROOT / "config/distributed.toml").read_bytes())
        self.mod = dispatcher()
        self.patched = patch.object(self.mod, "ROOT", self.root)
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def dotenv(self, role="control"):
        src = self.root / ".env"
        src.write_text('POSTGRES_PASSWORD="has spaces # embedded"\nDIST_ROLE={role}\nDIST_CONTROL_ADDRESS=192.168.51.2\nDIST_EXECUTION_ADDRESS=192.168.51.3\nDIST_SERVER_NAME=broker.internal\n'.format(role=role))
        src.chmod(0o600)
        return src

    def test_generic_role_selection(self):
        f = self.dotenv("control")
        a = self.mod.config(credentials=False)
        self.assertEqual(a["deployment"]["role"], "control")
        self.assertEqual(a["network"]["execution_address"], "192.168.51.3")
        self.assertNotIn("bundle_manifest_sha256", a["deployment"])
        f.write_text(f.read_text().replace("DIST_ROLE=control", "DIST_ROLE=execution"))
        self.assertEqual(self.mod.config(credentials=False)["deployment"]["role"], "execution")

    def test_fail_closed_without_local_role_and_duplicate_keys(self):
        with self.assertRaisesRegex(ValueError, "missing/unsafe local .env"):
            self.mod.config(credentials=False)
        src = self.dotenv()
        src.write_text(src.read_text() + "DIST_ROLE=execution\n")
        with self.assertRaisesRegex(ValueError, "duplicate .env"):
            self.mod.config(credentials=False)

    def test_reject_hardcoded_identity_in_tracked_toml(self):
        self.dotenv()
        toml = self.root / "config/distributed.toml"
        toml.write_text(toml.read_text().replace('role = ""', 'role = "control"'))
        with self.assertRaisesRegex(ValueError, "cannot hardcode"):
            self.mod.config(credentials=False)

class CredentialPinTests(unittest.TestCase):
    def test_auto_pin_role_specific_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "pki"
            result = provision(target, server_name="broker.internal",
                execution_address="192.168.51.3", control_address="192.168.51.2")
            expected = {"control_id": "control", "execution_id": "execution",
                "execution_address": "192.168.51.3", "control_address": "192.168.51.2",
                "server_name": "broker.internal", "port": 9443}
            for role in ("control", "execution"):
                folder = target / role
                self.assertEqual((folder / "manifest.sha256").read_text().strip(), result[role]["manifest_sha256"])
                self.assertEqual(verify_bundle(folder, None, role, expected)["role"], role)
                self.assertIn("DIST_ROLE=" + role, (folder / "distributed.env").read_text())
                self.assertNotIn("SHA256", (folder / "distributed.env").read_text())
            self.assertNotEqual(result["control"]["manifest_sha256"], result["execution"]["manifest_sha256"])
            # Exercise the actual dispatcher + real PKI files for both roles.
            for role in ("control", "execution"):
                with tempfile.TemporaryDirectory() as local:
                    local_root = Path(local)
                    (local_root / "config").mkdir()
                    (local_root / "config/distributed.toml").write_bytes((ROOT / "config/distributed.toml").read_bytes())
                    (local_root / ".env").write_bytes((target / role / "distributed.env").read_bytes())
                    (local_root / ".env").chmod(0o600)
                    bundle = local_root / ".secrets/distributed"
                    bundle.mkdir(mode=0o700, parents=True)
                    for item in (target / role).iterdir():
                        if item.name != "distributed.env":
                            dst = bundle / item.name
                            dst.write_bytes(item.read_bytes())
                            dst.chmod(item.stat().st_mode & 0o777)
                    d = dispatcher()
                    with patch.object(d, "ROOT", local_root):
                        self.assertEqual(d.config()["bundle"]["role"], role)
            pin = target / "control/manifest.sha256"
            pin.write_text("0" * 64 + "\n")
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                verify_bundle(target / "control", None, "control", expected)
            pin.unlink()
            with self.assertRaises(FileNotFoundError):
                verify_bundle(target / "control", None, "control", expected)

if __name__ == "__main__": unittest.main()

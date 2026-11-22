"""Offline shutdown is not allowed to hash the Golden or create guests."""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from workstation_broker import server
from workstation_broker.templates import TemplateRegistry


IDENTITY = {
    "task_id": "shutdown-test", "attempt": 1,
    "environment_id": "offline", "fingerprint": "a" * 64,
}


def _broker(tmp_path, monkeypatch, *, cleanup_only):
    base = tmp_path / "golden.qcow2"
    base.write_bytes(b"unchanged golden")
    base.chmod(0o444)
    monkeypatch.setattr(server.pwd, "getpwall", lambda: [SimpleNamespace(pw_name="qemu")])
    monkeypatch.setattr(server.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1234))
    return server.Broker(tmp_path / "attempts", base, "admin", "controller",
                         template_root=tmp_path / "templates", cleanup_only=cleanup_only)


def test_offline_broker_does_not_validate_or_hash_golden(tmp_path, monkeypatch):
    def forbidden(_registry):
        pytest.fail("offline shutdown tried to validate the Golden image")

    monkeypatch.setattr(TemplateRegistry, "expected", forbidden)
    broker = _broker(tmp_path, monkeypatch, cleanup_only=True)
    assert broker.base_digest is None
    assert broker.templates.base == broker.base


def test_normal_broker_still_validates_golden(tmp_path, monkeypatch):
    observed = []

    def expected(_registry):
        observed.append(True)
        return {"golden_sha256": "b" * 64}

    monkeypatch.setattr(TemplateRegistry, "expected", expected)
    broker = _broker(tmp_path, monkeypatch, cleanup_only=False)
    assert broker.base_digest == "b" * 64
    assert observed == [True]


def test_offline_owned_attempt_checks_xml_and_backing_without_hash(tmp_path, monkeypatch):
    broker = _broker(tmp_path, monkeypatch, cleanup_only=True)
    name, network, folder = broker._paths(IDENTITY)
    disk = folder / "disk"
    disk.mkdir(parents=True)
    (disk / "overlay.qcow2").write_bytes(b"overlay")
    xml = server.domain_xml(name, network, disk / "overlay.qcow2", disk / "identity.iso",
                            9000, broker.memory_mb, broker.vcpus, IDENTITY, "c" * 64)
    owner = json.loads(ET.fromstring(xml).find(f"./metadata/{{{server.META_NS}}}attempt").text)
    state = {"identity": IDENTITY, "name": name, "network": network,
             "metadata": owner, "base": str(broker.base)}
    (folder / "state.json").write_text(json.dumps(state))

    def fake_run(*args, **kwargs):
        if args[0] == "virsh" and args[3] == "dumpxml":
            return xml
        if args[0] == "virsh" and args[3] == "net-list":
            return (network + "\n").encode()
        if args[0] == "qemu-img" and args[1] == "info":
            return json.dumps({"format": "qcow2", "full-backing-filename": str(broker.base)}).encode()
        pytest.fail("unexpected offline command: " + repr(args))

    monkeypatch.setattr(server, "run", fake_run)
    previous_mount = Path.is_mount
    monkeypatch.setattr(Path, "is_mount", lambda path: path == disk or previous_mount(path))
    previous_stat = Path.stat

    def host_owned_base(path, *args, **kwargs):
        value = previous_stat(path, *args, **kwargs)
        if path == broker.base:
            fields = list(value)
            fields[4] = 0
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "stat", host_owned_base)
    monkeypatch.setattr(TemplateRegistry, "immutable_sha256",
                        lambda *_: pytest.fail("Golden hash in cleanup"))
    monkeypatch.setattr(TemplateRegistry, "verify_record",
                        lambda *_: pytest.fail("template image hash in cleanup"))
    assert broker._read(IDENTITY, require_firewall=False) == state

    state["base"] = str(folder / "other.qcow2")
    (folder / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="backing path differs"):
        broker._read(IDENTITY, require_firewall=False)

    state["base"] = str(broker.base)
    (folder / "state.json").write_text(json.dumps(state))
    forged_xml = server.domain_xml(name, network, disk / "overlay.qcow2",
                                   disk / "identity.iso", 9000,
                                   broker.memory_mb, broker.vcpus,
                                   {**IDENTITY, "task_id": "foreign"}, "c" * 64)
    monkeypatch.setattr(server, "run", lambda *args, **kwargs:
                        forged_xml if args[0] == "virsh" and args[3] == "dumpxml" else fake_run(*args, **kwargs))
    with pytest.raises(ValueError, match="identity mismatch"):
        broker._read(IDENTITY, require_firewall=False)


@pytest.mark.asyncio
async def test_offline_broker_cannot_create_guests(tmp_path, monkeypatch):
    broker = _broker(tmp_path, monkeypatch, cleanup_only=True)
    with pytest.raises(RuntimeError, match="cannot create guests"):
        await broker.create(IDENTITY)


def test_local_shutdown_proves_absence_before_success(tmp_path, monkeypatch, capsys):
    import contextlib
    from workstation_broker import local_shutdown, admission

    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    steps = []

    @contextlib.contextmanager
    def phase(name):
        steps.append("begin:" + name)
        yield
        steps.append("end:" + name)

    class OfflineBroker:
        def __init__(self, *args, **kwargs):
            assert kwargs["cleanup_only"] is True
            steps.append("construct")
            self.templates = SimpleNamespace(root=tmp_path / "templates")

        def destroy_all(self):
            steps.append("destroy")

    class OfflinePreparations:
        def __init__(self, *args):
            steps.append("preparations")

        def cancel_all(self):
            steps.append("cancel")

    def inventory(_broker):
        steps.append("inventory")
        return {"project": server.PROJECT, "absent": True,
                "domains": [], "networks": [], "firewall_tables": [],
                "states": [], "preparations": []}

    monkeypatch.setattr(local_shutdown.os, "geteuid", lambda: 0)
    monkeypatch.setattr(local_shutdown, "safe", lambda path, **kw: path)
    monkeypatch.setattr(local_shutdown, "host_operation", phase)
    monkeypatch.setattr(local_shutdown, "PreparationManager", OfflinePreparations)
    monkeypatch.setattr(server, "Broker", OfflineBroker)
    monkeypatch.setattr(server, "inventory", inventory)
    monkeypatch.setattr(admission, "barrier_path", lambda: tmp_path / "barrier")
    monkeypatch.setattr(admission, "mark_draining", lambda _: steps.append("barrier"))

    original_path = local_shutdown.Path
    monkeypatch.setattr(local_shutdown, "Path", lambda value:
                        SimpleNamespace(iterdir=lambda: []) if str(value) == "/proc" else original_path(value))

    def systemctl(args, **kwargs):
        assert args[0] == "systemctl" and args[1] == "show"
        return "inactive" if any("ActiveState" in arg for arg in args) else "0"

    monkeypatch.setattr(local_shutdown.subprocess, "check_output", systemctl)
    environment = {
        "WORKSTATION_BROKER_SOCKET": str(runtime / "broker.sock"),
        "WORKSTATION_BROKER_CONTROL_ID": "control",
        "WORKSTATION_BROKER_EXECUTION_ID": "execution",
        "WORKSTATION_BASE_IMAGE": str(tmp_path / "base.qcow2"),
        "WORKSTATION_CONFIG": str(Path(__file__).resolve().parents[3] / "config/runner.toml"),
        "WORKSTATION_BROKER_STATE": str(tmp_path / "attempts"),
        "WORKSTATION_BROKER_ADMIN_TOKEN": "a" * 40,
        "WORKSTATION_BROKER_CONTROLLER_TOKEN": "b" * 40,
        "WORKSTATION_TEMPLATE_ROOT": str(tmp_path / "templates"),
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    local_shutdown.main()
    result = json.loads(capsys.readouterr().out)
    assert result["broker_stopped"] is True
    assert result["inventory"]["absent"] is True
    assert result["scope"] == "execution-local"
    assert steps.index("barrier") < steps.index("cancel") < steps.index("destroy") < steps.index("inventory")
    assert "begin:offline-broker-initialization" in steps
    assert "end:offline-final-absence" in steps

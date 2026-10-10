from __future__ import annotations

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from workstation_broker.server import Broker, META_NS, suffix
from workstation_broker.templates import TemplateRegistry, backing

IDENT = {"task_id": "task-1", "attempt": 1, "environment_id": "env-1", "fingerprint": "a"*64}
ID = "swe-gym-lite/python_mypy"


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def files(tmp_path):
    root = tmp_path/"templates"
    folder = root/"swe-gym-lite/generations"/("a"*64)
    (folder/"repos").mkdir(parents=True)
    base = tmp_path/"kali-base.qcow2"
    common, repo = folder/"common.qcow2", folder/"repos/python_mypy.qcow2"
    for path, raw in ((base, b"kali"), (common, b"common"), (repo, b"repo")):
        path.write_bytes(raw)
        path.chmod(0o444)
    manifest = {"schema_version": 1, "generation": "a"*64, "source_fingerprint": "f"*64,
                "templates": {ID: {"chain": [{"path": "repos/python_mypy.qcow2", "sha256": sha(repo)},
                     {"path": "common.qcow2", "sha256": sha(common)}, {"path": str(base), "sha256": sha(base)}]}}}
    (folder/"manifest.json").write_text(json.dumps(manifest))
    registry_path = root/"swe-gym-lite/registry.json"
    registry_path.write_text(json.dumps({"schema_version": 1, "generation": "a"*64}))
    infos = {base: {"format": "qcow2"}, common: {"format": "qcow2", "backing-filename": str(base)},
             repo: {"format": "qcow2", "backing-filename": "../common.qcow2"}}
    registry = TemplateRegistry(root, base, lambda path: infos[path])
    return SimpleNamespace(root=root, folder=folder, base=base, common=common, repo=repo,
                           manifest=manifest, registry_path=registry_path, registry=registry, infos=infos)


def test_registry_resolves_relative_backing_against_image_not_cwd(files, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    selected = files.registry.select(ID)
    assert selected["backing_path"] == str(files.repo)
    assert selected["backing_sha256"] == sha(files.repo)
    assert selected["template_generation"] == "a"*64
    assert backing(files.infos[files.repo], files.repo) == files.common


@pytest.mark.parametrize("template_id", ["/tmp/evil.qcow2", "../evil", "swe-gym-lite/../evil", "swe-gym-lite/unknown", "swe-gym-lite/a/b"])
def test_registry_rejects_paths_and_unknown_ids(files, template_id):
    with pytest.raises(ValueError): files.registry.select(template_id)


def test_registry_rejects_symlink_mutable_digest_and_backing_mismatch(files, tmp_path):
    files.repo.chmod(0o644)
    with pytest.raises(ValueError, match="mutable"): files.registry.select(ID)
    files.repo.write_bytes(b"changed")
    files.repo.chmod(0o444)
    with pytest.raises(ValueError, match="digest"): files.registry.select(ID)
    files.repo.chmod(0o644)
    files.repo.write_bytes(b"repo")
    files.repo.chmod(0o444)
    files.infos[files.repo]["backing-filename"] = "../missing.qcow2"
    with pytest.raises(ValueError, match="backing"): files.registry.select(ID)
    files.infos[files.repo]["backing-filename"] = "../common.qcow2"
    files.repo.unlink()
    elsewhere = tmp_path/"elsewhere"
    elsewhere.write_bytes(b"repo")
    files.repo.symlink_to(elsewhere)
    with pytest.raises(ValueError, match="untrusted"): files.registry.select(ID)


def test_recovery_uses_original_generation_after_registry_publication(files):
    selected = files.registry.select(ID)
    files.registry_path.write_text(json.dumps({"schema_version": 1, "generation": "b"*64}))
    assert files.registry.verify_record(selected) == selected
    with pytest.raises(ValueError, match="identity changed"):
        files.registry.verify_record({**selected, "backing_sha256": "0"*64})
    with pytest.raises(ValueError):
        files.registry.verify_record({**selected, "template_generation": "../escape"})


@pytest.mark.asyncio
async def test_broker_overlay_inspect_destroy_and_normal_golden(files, tmp_path, monkeypatch):
    import workstation_broker.server as server
    broker = Broker.__new__(Broker)
    broker.root = tmp_path/"attempts"
    broker.root.mkdir()
    broker.base, broker.base_digest = files.base, sha(files.base)
    broker.templates, broker.qemu_uid = files.registry, os.getuid()
    domains, networks, firewalls, xmls = set(), set(), set(), {}
    created_backings = []
    def run(*args, **kwargs):
        if args[0] == "qemu-img":
            if args[1] == "create":
                path = Path(args[-1])
                path.write_bytes(b"overlay")
                files.infos[path] = {"format": "qcow2", "backing-filename": args[args.index("-b")+1]}
                created_backings.append(args[args.index("-b")+1])
                return b""
            return json.dumps(files.infos[Path(args[-1])]).encode()
        if args[0] == "ip": return b"[]"
        if args[0] == "xorriso":
            Path(args[args.index("-o")+1]).write_bytes(b"iso")
            return b""
        if args[0] == "virsh":
            action = args[3]
            if action == "list": return "\n".join(sorted(domains)).encode()
            if action == "net-list": return "\n".join(sorted(networks)).encode()
            if action == "define":
                raw = Path(args[4]).read_bytes()
                name = ET.fromstring(raw).findtext("name")
                domains.add(name)
                xmls[name] = raw
            elif action == "net-define": networks.add(ET.fromstring(Path(args[4]).read_bytes()).findtext("name"))
            elif action == "dumpxml": return xmls[args[4]]
            elif action == "domstate": return b"running"
            elif action == "undefine": domains.discard(args[4])
            elif action == "net-undefine": networks.discard(args[4])
        return b""
    monkeypatch.setattr(server, "run", run)
    files.registry.image_info = server.qemu_image_info
    monkeypatch.setattr(broker, "_mount", lambda directory: (directory/"disk").mkdir())
    monkeypatch.setattr(broker, "_unmount", lambda directory: None)
    monkeypatch.setattr(Path, "is_mount", lambda path: path.name == "disk" and path.is_dir())
    monkeypatch.setattr(broker, "_firewall", lambda ident, *args: firewalls.add(suffix(ident)))
    monkeypatch.setattr(broker, "_remove_firewall", lambda ident: firewalls.discard(suffix(ident)))
    monkeypatch.setattr(server.subprocess, "run", lambda args, **kwargs: SimpleNamespace(
        returncode=0 if args[-1].removeprefix("gt_") in firewalls else 1))
    async def rpc(ident, method, args): return {"identity": ident, "guest_agent_version": "3.0.0"}
    monkeypatch.setattr(broker, "rpc", rpc)
    before = {path: path.read_bytes() for path in (files.base, files.common, files.repo)}
    result = await broker.create(IDENT, ID)
    assert result["template_id"] == ID and created_backings == [str(files.repo)]
    assert result["backing_sha256"] == sha(files.repo)
    stored = broker._read(IDENT)
    assert stored["base"] == str(files.repo)
    metadata = json.loads(ET.fromstring(xmls[result["domain"]]).find(f"./metadata/{{{META_NS}}}attempt").text)
    assert metadata["template_generation"] == "a"*64
    assert (await broker.inspect_verified(IDENT))["backing_path"] == str(files.repo)
    broker.destroy(IDENT)
    assert before == {path: path.read_bytes() for path in before}
    assert not (broker.root/suffix(IDENT)).exists()
    normal = {**IDENT, "task_id": "gaia"}
    result = await broker.create(normal)
    assert result["template_id"] is None
    assert created_backings[-1] == str(files.base)
    broker.destroy(normal)


@pytest.mark.asyncio
async def test_templated_creation_failure_preserves_attempt_for_operator(files, tmp_path, monkeypatch):
    import workstation_broker.server as server
    broker = Broker.__new__(Broker)
    broker.root = tmp_path / "attempts"
    broker.root.mkdir()
    broker.base, broker.base_digest, broker.templates = files.base, sha(files.base), files.registry
    destroyed = []
    monkeypatch.setattr(server, "run", lambda *args, **kwargs: b"")
    def fail_mount(directory):
        raise RuntimeError("quota reservation failed")
    monkeypatch.setattr(broker, "_mount", fail_mount)
    monkeypatch.setattr(broker, "destroy", lambda *args, **kwargs: destroyed.append(args))
    with pytest.raises(RuntimeError, match="quota reservation"):
        await broker.create(IDENT, ID)
    assert (broker.root / suffix(IDENT)).is_dir()
    assert destroyed == []
    assert files.repo.read_bytes() == b"repo"


def test_explicit_abandon_is_idempotent_after_partial_cleanup(files, tmp_path, monkeypatch):
    import workstation_broker.server as server
    broker = Broker.__new__(Broker)
    broker.root = tmp_path / "attempts"
    broker.root.mkdir()
    monkeypatch.setattr(server, "run", lambda *args, **kwargs: b"")
    monkeypatch.setattr(broker, "_remove_firewall", lambda *args: None)
    monkeypatch.setattr(broker, "_unmount", lambda *args: None)
    monkeypatch.setattr(broker, "assert_absent", lambda *args: None)
    broker.destroy(IDENT, strict=False)
    broker.destroy(IDENT, strict=False)
    assert not (broker.root / suffix(IDENT)).exists()

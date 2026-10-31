from __future__ import annotations

import base64
import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from test_templates import files, IDENT, ID
from workstation_broker import server
from workstation_broker.server import Broker, create_app, suffix


@pytest.fixture
def host(files, tmp_path, monkeypatch):
    broker = Broker.__new__(Broker)
    broker.root = tmp_path / "attempts"
    broker.root.mkdir()
    broker.base, broker.base_digest = files.base, server.file_sha256(files.base)
    broker.templates, broker.qemu_uid = files.registry, os.getuid()
    broker.admin_token, broker.controller_token = "a"*40, "c"*40
    domains, networks, firewall, xmls, backings, states = set(), set(), set(), {}, [], {}
    def run(*args, **kwargs):
        if args[:2] == ("qemu-img", "create"):
            path = Path(args[-1])
            path.write_bytes(b"fresh-overlay")
            selected = args[args.index("-b") + 1]
            files.infos[path] = {"format":"qcow2","backing-filename":selected}
            backings.append(selected)
        elif args[:2] == ("qemu-img", "info"):
            return json.dumps(files.infos[Path(args[-1])]).encode()
        elif args[0] == "ip": return b"[]"
        elif args[0] == "xorriso": Path(args[args.index("-o")+1]).write_bytes(b"iso")
        elif args[0] == "virsh":
            action = args[3]
            if action == "list": return "\n".join(domains).encode()
            if action == "net-list": return "\n".join(networks).encode()
            if action == "define":
                raw = Path(args[4]).read_bytes()
                name = ET.fromstring(raw).findtext("name")
                domains.add(name)
                xmls[name] = raw
            elif action == "net-define": networks.add(ET.fromstring(Path(args[4]).read_bytes()).findtext("name"))
            elif action == "dumpxml": return xmls[args[4]]
            elif action == "domstate": return states.get(args[4], "running").encode()
            elif action == "undefine": domains.discard(args[4])
            elif action == "net-undefine": networks.discard(args[4])
        return b""
    monkeypatch.setattr(server, "run", run)
    files.registry.image_info = server.qemu_image_info
    monkeypatch.setattr(broker, "_mount", lambda directory: (directory / "disk").mkdir())
    monkeypatch.setattr(broker, "_unmount", lambda directory: None)
    monkeypatch.setattr(Path, "is_mount", lambda path: path.name == "disk" and path.is_dir())
    monkeypatch.setattr(broker, "_firewall", lambda ident, *args: firewall.add(suffix(ident)))
    monkeypatch.setattr(broker, "_remove_firewall", lambda ident: firewall.discard(suffix(ident)))
    monkeypatch.setattr(server.subprocess, "run", lambda args, **kwargs: SimpleNamespace(returncode=0 if args[-1].removeprefix("gt_") in firewall else 1))
    async def rpc(ident, method, args):
        return {"identity":ident,"guest_agent_version":"3.0.0","trusted_artifacts_version":1}
    monkeypatch.setattr(broker, "rpc", rpc)
    return SimpleNamespace(broker=broker, files=files, xmls=xmls, domains=domains, networks=networks,
                           firewall=firewall, backings=backings, states=states)


@pytest.mark.asyncio
async def test_evaluator_uses_original_immutable_backing_without_teacher_mutations_or_routes(host):
    broker = host.broker
    teacher = await broker.create(IDENT, ID, host.files.task1)
    Path(teacher["overlay"]).write_bytes(b"TEACHER CORRUPTION: conda gitconfig etc PATH background process")
    # A registry update must never redirect this evaluator to a newer template.
    host.files.registry_path.chmod(0o644)
    host.files.registry_path.write_text(json.dumps({"schema_version":2,"generation":"f"*64}))
    host.files.registry_path.chmod(0o444)
    evaluator = await broker.create_evaluator(IDENT)
    assert evaluator["template_generation"] == teacher["template_generation"]
    assert evaluator["backing_sha256"] == teacher["backing_sha256"]
    assert host.backings == [str(host.files.repo), str(host.files.repo)]
    assert evaluator["overlay"] != teacher["overlay"]
    assert Path(evaluator["overlay"]).read_bytes() == b"fresh-overlay"
    assert evaluator["identity"] == {**IDENT,"purpose":"evaluator","evaluator_retry":evaluator["identity"]["evaluator_retry"]}
    assert evaluator["network"] is None
    xml = ET.fromstring(host.xmls[evaluator["domain"]])
    for tag in ("interface", "filesystem", "graphics", "input"):
        assert xml.find("./devices/" + tag) is None
    assert xml.find("./devices/vsock") is not None
    assert host.networks == {teacher["network"]} and host.firewall == {suffix(IDENT)}
    broker.destroy_evaluator(IDENT, evaluator["identity"]["evaluator_retry"])
    assert evaluator["domain"] not in host.domains and teacher["domain"] in host.domains
    assert broker.inspect_evaluators(IDENT) == {"evaluators":[]}


@pytest.mark.asyncio
async def test_failed_evaluator_is_preserved_until_explicit_resume_and_retry_is_fresh(host):
    broker = host.broker
    teacher = await broker.create(IDENT, ID, host.files.task1)
    failed = await broker.create_evaluator(IDENT)
    Path(failed["overlay"]).write_bytes(b"half-mutated evaluation")
    with pytest.raises(ValueError, match="explicit"):
        await broker.create_evaluator(IDENT)
    assert Path(failed["overlay"]).read_bytes() == b"half-mutated evaluation"
    host.states[failed["domain"]] = "shut off"
    retried = await broker.create_evaluator(IDENT, abandon_stale=True)
    assert failed["identity"] != retried["identity"]
    assert not Path(failed["overlay"]).exists()
    assert Path(retried["overlay"]).read_bytes() == b"fresh-overlay"
    assert retried["backing_sha256"] == teacher["backing_sha256"]
    assert len(broker.inspect_evaluators(IDENT)["evaluators"]) == 1


@pytest.mark.asyncio
async def test_evaluator_construction_failure_keeps_index_and_partial_disk_for_reset(host, monkeypatch):
    broker = host.broker
    await broker.create(IDENT, ID, host.files.task1)
    def fail(directory):
        (directory / "disk").mkdir()
        raise RuntimeError("quota/VM failure")
    monkeypatch.setattr(broker, "_mount", fail)
    with pytest.raises(RuntimeError): await broker.create_evaluator(IDENT)
    record = broker.inspect_evaluators(IDENT)["evaluators"][0]
    assert Path(record["state_directory"]).exists()
    broker.abandon_evaluators(IDENT)
    broker.destroy(IDENT, strict=False)
    assert not Path(record["state_directory"]).exists() and host.domains == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("action,payload", [
    ("create_evaluator", IDENT), ("inspect_evaluators", IDENT), ("evaluator_rpc", IDENT),
    ("materialize_template_artifact", IDENT), ("abandon_evaluators", IDENT),
    ("rpc", {**IDENT,"purpose":"evaluator","evaluator_retry":"a"*32,"method":"exec_command"}),
    ("rpc", {**IDENT,"method":"template_import_begin"}),
])
async def test_evaluator_and_template_delivery_are_inaccessible_to_controller(host, action, payload):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(host.broker)), base_url="http://broker") as client:
        response = await client.post("/v1/"+action,json=payload,headers={"authorization":"Bearer " + "c"*40})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_template_artifact_over_256_mib_is_streamed_by_broker_in_bounded_chunks(host, tmp_path, monkeypatch):
    broker = host.broker
    # Sparse data exercises the real file reader and digest without allocating
    # a >256 MiB byte string in either the runner or this test.
    source = tmp_path / "large-source"
    size = 268435456 + 17
    with source.open("wb") as stream: stream.truncate(size)
    sha = server.file_sha256(source)
    source.chmod(0o444)
    key = "d"*64
    monkeypatch.setattr(broker, "_read", lambda ident: {"metadata":{}})
    monkeypatch.setattr(broker.templates, "artifact", lambda *args: {"host_path":source,"size":size,"sha256":sha,
        "artifact_id":key,"kind":"task_source","logical_task_id":"task-1","source_identity":{"base_commit":"b"*40}})
    seen, digest = [], hashlib.sha256()
    async def rpc(ident, method, args):
        if method == "health": return {"trusted_artifacts_version":1}
        if method == "template_import_begin":
            assert args["size"] == size
            return {"ready":True}
        if method == "template_import_chunk":
            raw = base64.b64decode(args["content_base64"], validate=True)
            assert len(raw) <= 1048576
            seen.append(len(raw))
            digest.update(raw)
        if method == "template_import_end":
            assert digest.hexdigest() == sha
            return {"path":"/var/lib/gpt-trace-template-artifacts/"+key+"/payload","size":size,"sha256":sha}
        return {}
    monkeypatch.setattr(broker, "rpc", rpc)
    monkeypatch.setattr(Path, "read_bytes", lambda path: (_ for _ in ()).throw(AssertionError("whole-file loading forbidden")))
    result = await broker.materialize_template_artifact(IDENT, key)
    assert result["size"] == size and sum(seen) == size and len(seen) == 257


@pytest.mark.asyncio
async def test_hidden_data_rpc_resolves_only_exact_evaluator_identity(host, monkeypatch):
    broker = host.broker
    await broker.create(IDENT, ID, host.files.task1)
    evaluator = await broker.create_evaluator(IDENT)
    targets = []
    async def rpc(ident, method, args):
        targets.append(ident)
        return {"received":True}
    monkeypatch.setattr(broker, "rpc", rpc)
    payload = {**IDENT,"evaluator_retry":evaluator["identity"]["evaluator_retry"],"method":"exec_command",
               "args":{"stdin":"EVALUATOR_ONLY_HIDDEN_TEST_PATCH"}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(broker)), base_url="http://broker") as client:
        response = await client.post('/v1/evaluator_rpc',json=payload,headers={'authorization':'Bearer '+'a'*40})
        assert response.status_code == 200 and targets == [evaluator["identity"]]
        forged = {**payload,"task_id":"another-teacher"}
        assert (await client.post('/v1/evaluator_rpc',json=forged,headers={'authorization':'Bearer '+'a'*40})).status_code == 409
        assert targets == [evaluator["identity"]]

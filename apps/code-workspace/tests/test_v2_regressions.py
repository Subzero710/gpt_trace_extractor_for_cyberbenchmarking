import hashlib, io, json, tarfile
from pathlib import Path
import pytest
from starlette.testclient import TestClient
from code_workspace.core import WorkspaceManager
from code_workspace.server import create_app
from code_workspace.templates import TemplateManager, TemplateError, hash_template

TOKEN="x"*32

def _tar_bytes():
    b=io.BytesIO()
    with tarfile.open(fileobj=b,mode="w") as tf:
        data=b"hello\n"; info=tarfile.TarInfo("hello.txt"); info.size=len(data); tf.addfile(info,io.BytesIO(data))
    return b.getvalue()

def test_seed_restores_integrity_contract(tmp_path):
    m=WorkspaceManager(tmp_path/"workspace",tmp_path/"state")
    with TestClient(create_app(m,TOKEN)) as c:
        raw=_tar_bytes()
        r=c.post("/control/seed",content=raw,headers={"Authorization":f"Bearer {TOKEN}","Content-Type":"application/x-tar"})
        assert r.status_code==200
        assert r.json()["sha256"]==hashlib.sha256(raw).hexdigest()

def test_seed_rejects_wrong_content_type(tmp_path):
    m=WorkspaceManager(tmp_path/"workspace",tmp_path/"state")
    with TestClient(create_app(m,TOKEN)) as c:
        r=c.post("/control/seed",content=b"x",headers={"Authorization":f"Bearer {TOKEN}","Content-Type":"application/octet-stream"})
        assert r.status_code==415

def test_create_app_remains_compatible_with_v1_manager(tmp_path):
    m=WorkspaceManager(tmp_path/"workspace",tmp_path/"state")
    with TestClient(create_app(m,TOKEN)) as c:
        assert c.get("/manifest").status_code==200

def test_template_collision_is_preflighted_without_partial_copy(tmp_path):
    templates=tmp_path/"templates"; src=templates/"sample"; src.mkdir(parents=True)
    (src/"a.txt").write_text("a"); (src/"z.txt").write_text("z")
    digest=hash_template(src)
    (templates/"manifest.json").write_text(json.dumps({"schema_version":1,"templates":[{"id":"sample","version":"1","description":"x","hash":digest}]}))
    workspace=tmp_path/"workspace"; workspace.mkdir(); (workspace/"z.txt").write_text("existing")
    tm=TemplateManager(templates,workspace,10002,10002)
    with pytest.raises(TemplateError,match="collision"): tm.apply({"template_id":"sample"})
    assert not (workspace/"a.txt").exists()
    assert (workspace/"z.txt").read_text()=="existing"

def test_v1_input_schemas_are_preserved_exactly():
    from code_workspace.contracts import TOOLS
    by={x["name"]:x["inputSchema"] for x in TOOLS}
    assert by["exec_command"]["additionalProperties"] is False
    assert by["read_file"]["properties"]["max_bytes"]["maximum"]==1048576
    assert by["write_file"]["properties"]["expected_sha256"]["pattern"]=="^[0-9a-f]{64}$"
    assert by["apply_patch"]["properties"]["replacements"]["minItems"]==1
    assert by["list_directory"]["properties"]["max_entries"]["maximum"]==10000
    assert by["search_files"]["properties"]["max_results"]["maximum"]==1000
    for name in ("workspace_stat","create_terminal","get_system_info","git_status","http_request"):
        assert by[name]["additionalProperties"] is False

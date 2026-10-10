from __future__ import annotations

import base64
import hashlib

import pytest

from kali_workstation.guest import files
from kali_workstation.guest.agent import Agent


def test_trusted_import_uses_selected_size_without_relaxing_ordinary_imports(tmp_path, monkeypatch):
    monkeypatch.setattr(files, "TEMPLATE_ROOT", tmp_path / "trusted")
    monkeypatch.setattr(files, "MAX_FILE", 2)
    data = b"selected immutable template bytes"
    encoded = {"content_base64":base64.b64encode(data).decode()}
    sha = hashlib.sha256(data).hexdigest()
    ordinary = files.ImportSession()
    ordinary.begin({"path":str(tmp_path / "ordinary"),"sha256":sha})
    with pytest.raises(ValueError,match="limit"): ordinary.chunk(encoded)
    ordinary.abort()
    trusted = files.ImportSession(trusted_template=True)
    path = tmp_path / "trusted/artifact/payload"
    trusted.begin({"path":str(path),"sha256":sha,"size":len(data)})
    trusted.chunk(encoded)
    assert trusted.finish({"size":len(data)}) == {"path":str(path),"sha256":sha,"size":len(data)}
    assert path.read_bytes() == data and files.MAX_FILE == 2


@pytest.mark.parametrize("attack", ["outside", "traversal", "overrun", "wrong-sha"])
def test_trusted_import_rejects_bad_scope_size_or_digest(tmp_path, monkeypatch, attack):
    monkeypatch.setattr(files, "TEMPLATE_ROOT", tmp_path / "trusted")
    session = files.ImportSession(trusted_template=True)
    data = b"bytes"
    path = tmp_path / "outside" if attack == "outside" else tmp_path / "trusted/../outside" if attack == "traversal" else tmp_path / "trusted/a/payload"
    if attack in {"outside","traversal"}:
        with pytest.raises(ValueError): session.begin({"path":str(path),"sha256":"a"*64,"size":5})
        return
    session.begin({"path":str(path),"sha256":"a"*64,"size":4 if attack == "overrun" else 5})
    if attack == "overrun":
        with pytest.raises(ValueError): session.chunk({"content_base64":base64.b64encode(data).decode()})
    else:
        session.chunk({"content_base64":base64.b64encode(data).decode()})
        with pytest.raises(ValueError): session.finish({"size":5})
    session.abort()
    assert not path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["prepare", "resume", "browser_goto", "create_terminal"])
async def test_evaluator_agent_never_starts_browser_or_model_session(method):
    agent = Agent.__new__(Agent)
    agent.identity = {"task_id":"task","attempt":1,"environment_id":"env","fingerprint":"a"*64,
                      "purpose":"evaluator","evaluator_retry":"b"*32}
    agent.secret = "s"*64
    request = {"identity":agent.identity,"secret":agent.secret,"args":{}}
    health = await agent.call({**request,"method":"health"})
    assert health["trusted_artifacts_version"] == 1
    with pytest.raises(ValueError,match="no browser"):
        await agent.call({**request,"method":method})

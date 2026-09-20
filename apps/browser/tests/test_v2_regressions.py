import asyncio, base64, json
from pathlib import Path
import pytest
from browser_mcp.interaction import InteractionService
from browser_mcp.dom import DomService
from browser_mcp.navigation import NavigationService
from browser_mcp.network import NetworkService

class Error(RuntimeError): pass

def test_v1_browser_input_schemas_are_preserved_exactly():
    from browser_mcp.contracts import TOOLS
    by={x["name"]:x["inputSchema"] for x in TOOLS}
    for name in ("search","navigate","read_page","click","type","press","wait","screenshot","download","tabs"):
        assert by[name]["additionalProperties"] is False
    assert by["click"]["properties"]["ref"]["pattern"]=="^e[1-9][0-9]*$"
    assert by["download"]["properties"]["max_bytes"]["maximum"]==10485760
    for name in ("upload_file","inspect_dom","performance_trace","close_page"):
        assert by[name]["additionalProperties"] is False

@pytest.mark.asyncio
async def test_upload_preserves_filename_and_mime_type(tmp_path):
    class Locator:
        first=None
        async def set_input_files(self,value): self.value=value
    loc=Locator(); loc.first=loc
    class Page:
        def locator(self,s): return loc
    class R:
        page=Page(); state_root=tmp_path; error=Error
        async def info(self): return {"page_id":"p","context_id":"c","url":"about:blank","title":""}
    out=await InteractionService(R()).upload({"selector":"input","filename":"evidence.bin","mime_type":"application/x-test","content_base64":base64.b64encode(b"abc").decode()})
    assert loc.value["name"]=="evidence.bin"
    assert loc.value["mimeType"]=="application/x-test"
    assert loc.value["buffer"]==b"abc"
    assert out["filename"]=="evidence.bin"

@pytest.mark.asyncio
async def test_inspect_dom_honors_max_chars():
    class Locator:
        first=None
        async def evaluate(self,script,limit): return [{"tag":"div","text":"x"*80,"attributes":{}} for _ in range(limit)]
    class Page:
        def locator(self,s):
            x=Locator(); x.first=x; return x
    class R: page=Page()
    out=await DomService(R()).inspect({"selector":"html","max_nodes":20,"max_chars":120})
    assert len(json.dumps(out["nodes"],ensure_ascii=False,separators=(",",":")))<=120
    assert out["truncated"] is True

@pytest.mark.asyncio
async def test_close_last_page_returns_null_active_id():
    class Page:
        def __init__(self): self.closed=False
        async def close(self): self.closed=True
        def is_closed(self): return self.closed
    p=Page()
    class R:
        page=p; pages={"p":p}
        def page_from(self,i): return p
        def unregister(self,x): self.pages.clear(); self.page=None
        def ensure_page(self): pass
        def pid(self,x): assert x is not None; return "p"
        async def info(self,x): return {}
    out=await NavigationService(R()).close({})
    assert out=={"active_page_id":None,"pages":[]}

@pytest.mark.asyncio
async def test_performance_trace_honors_max_bytes(tmp_path):
    class Tracing:
        async def stop(self,path): Path(path).write_bytes(b"x"*32)
    class Context: tracing=Tracing()
    class R:
        context=Context(); state_root=tmp_path; error=Error
        def cid(self,c): return "c"
    s=NetworkService(R()); s.tracing.add("c")
    with pytest.raises(Error,match="max_bytes"):
        await s.trace({"action":"stop","max_bytes":8})

from types import SimpleNamespace

import httpx
import pytest

from browser_mcp.server import create_app


class FakeRuntime:
    def healthy(self): return True
    def state_response(self): return {"status": "idle"}
    async def start(self): pass
    async def shutdown(self): pass


@pytest.mark.asyncio
async def test_health_manifest_and_control_are_separate() -> None:
    app = create_app(FakeRuntime(), control_token="y" * 32)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/healthz")).json()["app_id"] == "browser"
        manifest = (await client.get("/manifest")).json()
        assert "tabs" in {tool["name"] for tool in manifest["tools"]}
        assert (await client.get("/control/state")).status_code == 401
        allowed = await client.get("/control/state", headers={"authorization": "Bearer " + "y" * 32})
        assert allowed.json() == {"status": "idle"}

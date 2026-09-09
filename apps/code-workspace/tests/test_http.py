from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from code_workspace.core import WorkspaceManager
from code_workspace.server import create_app


@pytest.mark.asyncio
async def test_health_manifest_and_control_auth(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "workspace", tmp_path / "state")
    app = create_app(manager, control_token="x" * 32)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["app_id"] == "code-workspace"
        manifest = await client.get("/manifest")
        assert manifest.status_code == 200
        assert manifest.json()["tools"][0]["name"] == "exec_command"
        denied = await client.get("/control/state")
        assert denied.status_code == 401
        allowed = await client.get("/control/state", headers={"authorization": "Bearer " + "x" * 32})
        assert allowed.json() == {"status": "idle"}


def test_mcp_initialize_and_dns_rebinding_guard(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "workspace", tmp_path / "state")
    app = create_app(manager, control_token="x" * 32)
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    with TestClient(app, base_url="http://localhost:8000") as client:
        response = client.post("/mcp", headers=headers, json=payload)
        assert response.status_code == 200
        assert response.json()["result"]["serverInfo"] == {
            "name": "code-workspace",
            "version": "1.0.0",
        }
        denied = client.post("/mcp", headers={**headers, "host": "attacker.example"}, json=payload)
        assert denied.status_code == 421

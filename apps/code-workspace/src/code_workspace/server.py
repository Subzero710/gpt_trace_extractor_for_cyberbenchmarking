from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager, TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from .contracts import APP_ID, TOOLS, VERSION, canonical_bytes, manifest
from .core import WorkspaceError, WorkspaceManager

LOG = logging.getLogger(__name__)
MAX_CONTROL_BODY = 180 * 1024 * 1024


def _load_control_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"cannot read control token at {path}") from exc
    if len(token) < 32:
        raise RuntimeError("control token is missing or too short")
    return token


def _verify_manifest(path: Path) -> None:
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot load MCP tool manifest {path}") from exc
    if canonical_bytes(stored) != canonical_bytes(manifest()):
        raise RuntimeError("MCP implementation and tool-manifest.json differ")


async def _json_body(request: Request) -> dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_CONTROL_BODY:
                raise WorkspaceError("control request is too large")
        except ValueError as exc:
            raise WorkspaceError("invalid content-length") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_CONTROL_BODY:
            raise WorkspaceError("control request is too large")
    try:
        value = json.loads(body)
    except Exception as exc:
        raise WorkspaceError("control request must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise WorkspaceError("control request must be a JSON object")
    return value


def create_app(
    manager: WorkspaceManager,
    *,
    control_token: str,
    allowed_hosts: list[str] | None = None,
) -> Starlette:
    server = Server(APP_ID, version=VERSION)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(**tool) for tool in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
        if not isinstance(arguments, dict):
            raise WorkspaceError("tool arguments must be an object")
        async with manager.lock:
            if name == "exec_command":
                result = await manager.exec_command(arguments)
            elif name == "read_file":
                result = manager.read_file(arguments)
            elif name == "write_file":
                result = manager.write_file(arguments)
            elif name == "apply_patch":
                result = manager.apply_patch(arguments)
            elif name == "list_directory":
                result = manager.list_directory(arguments)
            elif name == "search_files":
                result = manager.search_files(arguments)
            else:
                raise WorkspaceError(f"unknown tool: {name}")
        return [types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))]

    session_manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts or ["localhost:8000"],
            allowed_origins=["https://chatgpt.com"],
        ),
    )

    async def mcp_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    def authorized(request: Request) -> bool:
        supplied = request.headers.get("authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {control_token}")

    async def health(_: Request) -> JSONResponse:
        try:
            state = manager.state_response()
        except WorkspaceError as exc:
            return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)
        return JSONResponse({"status": "ok", "app_id": APP_ID, "task_state": state["status"]})

    async def get_manifest(_: Request) -> JSONResponse:
        return JSONResponse(manifest())

    async def state(request: Request) -> JSONResponse:
        if not authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            return JSONResponse(manager.state_response())
        except WorkspaceError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)

    async def control(request: Request) -> JSONResponse:
        if not authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            body = await _json_body(request)
            operation = request.path_params["operation"]
            if operation == "prepare":
                result = await manager.prepare(body)
            elif operation == "resume":
                result = await manager.assert_resume(body)
            elif operation == "reset":
                result = await manager.reset(body)
            else:
                return JSONResponse({"detail": "not found"}, status_code=404)
            return JSONResponse(result)
        except WorkspaceError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    app = Starlette(
        routes=[
            Route("/healthz", health, methods=["GET"]),
            Route("/manifest", get_manifest, methods=["GET"]),
            Route("/control/state", state, methods=["GET"]),
            Route("/control/{operation}", control, methods=["POST"]),
            Mount("/mcp", app=mcp_http),
        ],
        lifespan=lifespan,
    )
    return CORSMiddleware(
        app,
        allow_origins=["https://chatgpt.com"],
        allow_methods=["GET", "POST", "DELETE"],
        expose_headers=["Mcp-Session-Id"],
    )


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    workspace_root = Path(os.environ.get("CODE_WORKSPACE_ROOT", "/workspace"))
    state_root = Path(os.environ.get("CODE_WORKSPACE_STATE_ROOT", "/state"))
    manifest_path = Path(os.environ.get("MCP_TOOL_MANIFEST", "/app/tool-manifest.json"))
    token_path = Path(os.environ.get("APP_CONTROL_TOKEN_FILE", "/run/secrets/app_control_token"))
    _verify_manifest(manifest_path)
    manager = WorkspaceManager(workspace_root, state_root)
    allowed_hosts = [item.strip() for item in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if item.strip()]
    if not allowed_hosts:
        raise RuntimeError("MCP_ALLOWED_HOSTS must contain at least one exact host[:port]")
    app = create_app(
        manager,
        control_token=_load_control_token(token_path),
        allowed_hosts=allowed_hosts,
    )
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level=os.environ.get("LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()

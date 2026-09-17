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
from .core import BrowserAppError, BrowserPolicy, BrowserRuntime

MAX_CONTROL_BODY = 1024 * 1024


def _boolean(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "true" if default else "false").strip().lower()
    if raw not in {"true", "false"}:
        raise RuntimeError(f"{name} must be true or false")
    return raw == "true"


def _control_token(path: Path) -> str:
    value = os.environ.get("APP_CONTROL_TOKEN", "").strip()
    if not value:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"cannot read control token at {path}") from exc
    if len(value) < 32:
        raise RuntimeError("control token is missing or too short")
    return value


def _verify_manifest(path: Path) -> None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot load MCP tool manifest {path}") from exc
    if canonical_bytes(value) != canonical_bytes(manifest()):
        raise RuntimeError("MCP implementation and tool-manifest.json differ")


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_CONTROL_BODY:
        raise BrowserAppError("control body is too large")
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise BrowserAppError("control request must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise BrowserAppError("control request must be a JSON object")
    return value


def create_app(
    runtime: BrowserRuntime,
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
            raise BrowserAppError("tool arguments must be an object")
        result = await runtime.call(name, arguments)
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
        return hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {control_token}")

    async def health(_: Request) -> JSONResponse:
        if not runtime.healthy():
            return JSONResponse({"status": "error", "app_id": APP_ID}, status_code=503)
        return JSONResponse({"status": "ok", "app_id": APP_ID, "task_state": runtime.state_response()["status"]})

    async def get_manifest(_: Request) -> JSONResponse:
        return JSONResponse(manifest())

    async def state(request: Request) -> JSONResponse:
        if not authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            return JSONResponse(runtime.state_response())
        except BrowserAppError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)

    async def control(request: Request) -> JSONResponse:
        if not authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            payload = await _body(request)
            operation = request.path_params["operation"]
            if operation == "prepare":
                result = await runtime.prepare(payload)
            elif operation == "resume":
                result = await runtime.assert_resume(payload)
            elif operation == "reset":
                result = await runtime.reset(payload)
            else:
                return JSONResponse({"detail": "not found"}, status_code=404)
            return JSONResponse(result)
        except BrowserAppError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        await runtime.start()
        try:
            async with session_manager.run():
                yield
        finally:
            await runtime.shutdown()

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


def build_runtime() -> BrowserRuntime:
    try:
        seed = int(os.environ["APP_BROWSER_FINGERPRINT_SEED"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("APP_BROWSER_FINGERPRINT_SEED must be configured as a positive integer") from exc
    allowed = {
        item.strip().casefold()
        for item in os.environ.get("APP_BROWSER_ALLOWED_PRIVATE_HOSTS", "").split(",")
        if item.strip()
    }
    return BrowserRuntime(
        Path(os.environ.get("APP_BROWSER_STATE_ROOT", "/browser-state")),
        fingerprint_seed=seed,
        search_url_template=os.environ.get("APP_BROWSER_SEARCH_URL_TEMPLATE", "https://duckduckgo.com/?q={query}"),
        policy=BrowserPolicy(allowed),
        humanize=_boolean("APP_BROWSER_HUMANIZE", True),
        humanize_preset=os.environ.get("APP_BROWSER_HUMANIZE_PRESET", "default"),
        timezone=os.environ.get("APP_BROWSER_TIMEZONE", "").strip(),
        locale=os.environ.get("APP_BROWSER_LOCALE", "").strip(),
        geoip=_boolean("APP_BROWSER_GEOIP", False),
    )


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    manifest_path = Path(os.environ.get("MCP_TOOL_MANIFEST", "/app/tool-manifest.json"))
    token_path = Path(os.environ.get("APP_CONTROL_TOKEN_FILE", "/run/secrets/app_control_token"))
    _verify_manifest(manifest_path)
    allowed_hosts = [item.strip() for item in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if item.strip()]
    if not allowed_hosts:
        raise RuntimeError("MCP_ALLOWED_HOSTS must contain at least one exact host[:port]")
    app = create_app(
        build_runtime(),
        control_token=_control_token(token_path),
        allowed_hosts=allowed_hosts,
    )
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level=os.environ.get("LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()

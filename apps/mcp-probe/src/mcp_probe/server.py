from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import (
    StreamableHTTPSessionManager,
    TransportSecuritySettings,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

APP_ID = "mcp-plus-capability-probe"
VERSION = "0.1.0"

TOOLS = [
    types.Tool(
        name="probe_ping",
        description=(
            "Read-only connectivity probe. Returns a fixed acknowledgement and "
            "does not modify any state."
        ),
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        annotations=types.ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    ),
    types.Tool(
        name="probe_read_state",
        description=(
            "Read-only capability probe. Returns the current private probe value "
            "and revision without modifying them."
        ),
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        annotations=types.ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    ),
    types.Tool(
        name="probe_write_state",
        description=(
            "WRITE/MODIFY capability probe. Changes the private probe value. "
            "This tool is intentionally non-read-only so we can determine whether "
            "this ChatGPT account permits MCP write actions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "description": "New private probe value to store.",
                }
            },
            "required": ["value"],
            "additionalProperties": False,
        },
        annotations=types.ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    ),
]


class ProbeState:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"value": "initial", "revision": 0}
        except Exception as exc:
            raise RuntimeError(f"cannot read probe state at {self._path}") from exc
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("value"), str)
            or not isinstance(payload.get("revision"), int)
        ):
            raise RuntimeError("probe state is malformed")
        return {"value": payload["value"], "revision": payload["revision"]}

    async def read(self) -> dict[str, Any]:
        async with self._lock:
            return self._read_unlocked()

    async def write(self, value: str) -> dict[str, Any]:
        if not isinstance(value, str):
            raise ValueError("value must be a string")
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        if len(value) > 200:
            raise ValueError("value must be at most 200 characters")

        async with self._lock:
            current = self._read_unlocked()
            revision = current["revision"] + (0 if current["value"] == value else 1)
            payload = {"value": value, "revision": revision}
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(tmp, self._path)
            return payload


def _tool_manifest() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for tool in TOOLS:
        dumped = tool.model_dump(by_alias=True, exclude_none=True)
        rows.append(dumped)
    return {"app_id": APP_ID, "version": VERSION, "tools": rows}


def create_app(state: ProbeState, *, allowed_hosts: list[str]) -> Starlette:
    server = Server(APP_ID, version=VERSION)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict[str, Any]
    ) -> list[types.ContentBlock]:
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be an object")

        if name == "probe_ping":
            result: dict[str, Any] = {"ok": True, "app_id": APP_ID}
        elif name == "probe_read_state":
            result = await state.read()
        elif name == "probe_write_state":
            result = await state.write(arguments.get("value"))
        else:
            raise ValueError(f"unknown tool: {name}")

        return [
            types.TextContent(
                type="text",
                text=json.dumps(
                    result,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        ]

    session_manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=["https://chatgpt.com"],
        ),
    )

    async def mcp_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "app_id": APP_ID, "version": VERSION})

    async def manifest(_: Request) -> JSONResponse:
        return JSONResponse(_tool_manifest())

    async def state_endpoint(_: Request) -> JSONResponse:
        return JSONResponse(await state.read())

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", health, methods=["GET"]),
            Route("/manifest", manifest, methods=["GET"]),
            Route("/state", state_endpoint, methods=["GET"]),
            Mount("/mcp", app=mcp_http),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

    raw_hosts = os.environ.get("MCP_ALLOWED_HOSTS", "")
    allowed_hosts = [item.strip() for item in raw_hosts.split(",") if item.strip()]
    if not allowed_hosts:
        raise RuntimeError("MCP_ALLOWED_HOSTS must contain at least one exact host[:port]")

    state = ProbeState(
        Path(os.environ.get("MCP_PROBE_STATE_PATH", "/tmp/mcp-probe-state.json"))
    )
    app = create_app(state, allowed_hosts=allowed_hosts)

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()

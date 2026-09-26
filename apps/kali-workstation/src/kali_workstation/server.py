from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import tomllib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager, TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.responses import StreamingResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from .contracts import APP_ID, VERSION, SPECS, canonical_bytes, manifest



def verify_manifest(path: Path):
    if canonical_bytes(json.loads(path.read_text())) != canonical_bytes(manifest()):
        raise RuntimeError("MCP implementation and tool-manifest.json differ")


class WorkstationController:
    def __init__(self, broker_socket: Path, token: str, max_seed: int = 268435456,
                 max_transfer: int = 67108864):
        self.token = token
        self.max_seed = max_seed
        self.max_transfer = max_transfer
        self.client = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(broker_socket)),
                                        base_url="http://broker", timeout=httpx.Timeout(1850, connect=10), trust_env=False)
        self.active: dict | None = None

    def backend_token(self, environment_id: str) -> str:
        return hmac.new(self.token.encode(), f"backend\0{APP_ID}\0{environment_id}".encode(), hashlib.sha256).hexdigest()

    def authorized(self, request: Request, ident: dict | None = None) -> bool:
        candidate = ident or self.active
        return bool(candidate and hmac.compare_digest(request.headers.get("authorization", ""),
                        f"Bearer {self.backend_token(candidate['environment_id'])}"))

    async def broker(self, operation: str, ident: dict, *, method: str | None = None, args: dict | None = None) -> dict:
        payload = {**ident}
        if method is not None: payload["method"] = method
        if args is not None: payload["args"] = args
        response = await self.client.post(f"/v1/{operation}", json=payload,
                                          headers={"authorization": f"Bearer {self.token}"})
        if response.status_code != 200:
            raise RuntimeError(f"broker {operation} failed: {response.text[:1000]}")
        return response.json()

    async def call(self, name: str, arguments: dict) -> dict:
        if self.active is None: raise RuntimeError("no active workstation")
        if name not in SPECS: raise ValueError("unknown MCP tool")
        input_model = SPECS[name][1]
        output_model = SPECS[name][2]
        args = input_model.model_validate(arguments).model_dump(exclude_none=True)
        if name in {"observe_screen", "computer_input", "import_file", "export_file"}:
            operation = {"observe_screen": "capture_screen", "computer_input": "send_input",
                         "import_file": "artifact_import", "export_file": "artifact_export"}[name]
            result = await self.broker(operation, self.active, args=args)
        else:
            method = name if SPECS[name][0] != "browser" else "browser_" + name
            result = await self.broker("rpc", self.active, method=method, args=args)
        return output_model.model_validate(result).model_dump()


def create_app(controller: WorkstationController) -> Starlette:
    server = Server(APP_ID, version=VERSION)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(**{k: v for k, v in row.items() if k != "category"}) for row in manifest()["tools"]]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]):
        result = await controller.call(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False, separators=(",", ":")))], result

    manager = StreamableHTTPSessionManager(
        app=server, event_store=None, json_response=True, stateless=True,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=["kali-workstation-controller:8000"], allowed_origins=["https://chatgpt.com"]),
    )

    async def mcp_http(scope: Scope, receive: Receive, send: Send):
        headers = {key.decode("latin1").lower(): value.decode("latin1") for key, value in scope.get("headers", [])}
        ident = controller.active
        if ident is None or not hmac.compare_digest(headers.get("authorization", ""),
                f"Bearer {controller.backend_token(ident['environment_id'])}"):
            await JSONResponse({"detail": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        await manager.handle_request(scope, receive, send)

    async def health(_: Request):
        return JSONResponse({"status": "ok", "app_id": APP_ID})

    async def get_manifest(_: Request):
        return JSONResponse(manifest())

    async def control(request: Request):
        try:
            raw = await request.body()
            if len(raw) > 65536: raise ValueError("control payload too large")
            payload = json.loads(raw)
            ident = {"task_id": payload["task_id"], "attempt": payload["attempt"],
                     "environment_id": payload["environment_id"], "fingerprint": payload["task_fingerprint"]}
            if not controller.authorized(request, ident):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
            operation = request.path_params["operation"]
            if operation == "prepare":
                if controller.active is not None and controller.active != ident:
                    raise ValueError("controller already bound to another attempt")
                await controller.broker("inspect_attempt", ident)
                result = await controller.broker("rpc", ident, method="prepare")
                controller.active = ident
            elif operation == "resume":
                if controller.active not in (None, ident): raise ValueError("controller bound to another attempt")
                await controller.broker("inspect_attempt", ident)
                result = await controller.broker("rpc", ident, method="resume")
                controller.active = ident
            elif operation == "reset":
                if controller.active not in (None, ident): raise ValueError("controller identity mismatch")
                controller.active = None
                result = {"status": "idle"}
            else: return JSONResponse({"detail": "unknown operation"}, status_code=404)
            return JSONResponse({"task_id": ident["task_id"], "environment_id": ident["environment_id"],
                                 "task_fingerprint": ident["fingerprint"], **result})
        except (ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
            return JSONResponse({"detail": str(exc)[:1000]}, status_code=409)

    async def seed(request: Request):
        if not controller.authorized(request): return JSONResponse({"detail": "unauthorized"}, status_code=401)
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/x-tar":
            return JSONResponse({"detail": "invalid content type"}, status_code=415)
        try:
            await controller.broker("rpc", controller.active, method="seed_begin")
            digest = hashlib.sha256()
            total = 0
            async for raw in request.stream():
                for start in range(0, len(raw), 1048576):
                    chunk = raw[start:start + 1048576]
                    total += len(chunk)
                    if total > controller.max_seed: raise ValueError("seed archive too large")
                    digest.update(chunk)
                    await controller.broker("rpc", controller.active, method="seed_chunk",
                        args={"content_base64": base64.b64encode(chunk).decode()})
            result = await controller.broker("rpc", controller.active, method="seed_end",
                args={"archive_bytes": total, "sha256": digest.hexdigest()})
            return JSONResponse(result)
        except (RuntimeError, ValueError) as exc:
            try: await controller.broker("rpc", controller.active, method="seed_abort")
            except RuntimeError: pass
            return JSONResponse({"detail": str(exc)}, status_code=409)

    async def artifacts(request: Request):
        if not controller.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        ident = controller.active
        try:
            if request.method == "POST":
                upload = await controller.broker("artifact_stage_begin", ident)
                upload_id = upload["upload_id"]
                digest = hashlib.sha256()
                total = 0
                try:
                    async for raw in request.stream():
                        for offset in range(0, len(raw), 1048576):
                            chunk = raw[offset:offset + 1048576]
                            total += len(chunk)
                            if total > controller.max_transfer:
                                raise ValueError("artifact upload exceeds configured limit")
                            digest.update(chunk)
                            await controller.broker("artifact_stage_chunk", ident,
                                args={"upload_id": upload_id, "content_base64": base64.b64encode(chunk).decode()})
                    result = await controller.broker("artifact_stage_end", ident,
                        args={"upload_id": upload_id, "size": total, "sha256": digest.hexdigest()})
                except BaseException:
                    await controller.broker("artifact_stage_abort", ident, args={"upload_id": upload_id})
                    raise
                return JSONResponse(result)
            artifact_id = request.path_params["artifact_id"]
            if len(artifact_id) != 64 or any(ch not in "0123456789abcdef" for ch in artifact_id):
                raise ValueError("invalid artifact ID")
            first = await controller.broker("artifact_read", ident, args={"artifact_id": artifact_id, "offset": 0})
            size = first["size"]
            if size > controller.max_transfer or first["sha256"] != artifact_id:
                raise ValueError("invalid stored artifact")
            async def stream():
                digest = hashlib.sha256()
                offset = 0
                while offset < size:
                    row = first if offset == 0 else await controller.broker("artifact_read", ident,
                        args={"artifact_id": artifact_id, "offset": offset})
                    chunk = base64.b64decode(row["content_base64"], validate=True)
                    if not chunk or offset + len(chunk) > size:
                        raise RuntimeError("artifact changed while downloading")
                    digest.update(chunk)
                    offset += len(chunk)
                    yield chunk
                if digest.hexdigest() != artifact_id:
                    raise RuntimeError("artifact checksum mismatch")
            return StreamingResponse(stream(), media_type="application/octet-stream",
                headers={"content-length": str(size), "x-artifact-sha256": artifact_id})
        except (RuntimeError, ValueError, KeyError) as exc:
            return JSONResponse({"detail": str(exc)[:1000]}, status_code=409)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            try: yield
            finally: await controller.client.aclose()

    app = Starlette(routes=[Route("/healthz", health), Route("/manifest", get_manifest),
                            Route("/control/seed", seed, methods=["POST"]),
                            Route("/control/artifacts", artifacts, methods=["POST"]),
                            Route("/control/artifacts/{artifact_id}", artifacts, methods=["GET"]),
                            Route("/control/{operation}", control, methods=["POST"]),
                            Mount("/mcp", app=mcp_http)], lifespan=lifespan)
    return CORSMiddleware(app, allow_origins=["https://chatgpt.com"], allow_methods=["GET", "POST", "DELETE"])


def main():
    import uvicorn
    verify_manifest(Path(os.environ.get("MCP_TOOL_MANIFEST", "/app/tool-manifest.json")))
    token = Path(os.environ.get("APP_CONTROL_TOKEN_FILE", "/run/secrets/app_control_token")).read_text().strip()
    if len(token) < 32: raise RuntimeError("missing controller token")
    config = tomllib.loads(Path(os.environ["WORKSTATION_CONFIG"]).read_text())["workstation"]
    controller = WorkstationController(Path(os.environ["WORKSTATION_BROKER_SOCKET"]), token,
                                       config["max_seed_bytes"], config["max_transfer_bytes"])
    uvicorn.run(create_app(controller), host="0.0.0.0", port=8000)


if __name__ == "__main__": main()

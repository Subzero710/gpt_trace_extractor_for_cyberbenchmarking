from __future__ import annotations

import contextlib
import hmac
import ipaddress
import json
import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

MAX_CONTROL_BODY = 1024 * 1024
MAX_SEED_UPLOAD_BYTES = 672 * 1024 * 1024
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


@dataclass(frozen=True, slots=True)
class ActiveBackend:
    task_id: str
    attempt: int
    environment_id: str
    task_fingerprint: str
    backend_url: str
    backend_token: str

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("backend_token", None)
        return value


class GatewayState:
    def __init__(self, *, app_id: str, backend_prefix: str, control_token: str) -> None:
        self.app_id = app_id
        self.backend_prefix = backend_prefix
        self.control_token = control_token
        self.active: ActiveBackend | None = None
        self.client = httpx.AsyncClient(timeout=None, trust_env=False)

    def authorized(self, request: Request) -> bool:
        return hmac.compare_digest(
            request.headers.get("authorization", ""),
            f"Bearer {self.control_token}",
        )

    def validate_backend_url(self, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("backend_url must be a non-empty string")
        parsed = urlparse(value)
        hostname = parsed.hostname or ""
        expected_name = hostname == "kali-workstation-controller"
        if (
            parsed.scheme != "http"
            or parsed.port != 8000
            or parsed.hostname is None
            or not expected_name
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "backend_url must be the trusted workstation controller at port 8000"
            )
        return value.rstrip("/")

    async def close(self) -> None:
        await self.client.aclose()


def _token() -> str:
    path = Path(os.environ.get("APP_CONTROL_TOKEN_FILE", "/run/secrets/app_control_token"))
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"cannot read gateway control token: {path}") from exc
    if len(value) < 32:
        raise RuntimeError("gateway control token is missing or too short")
    return value


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_CONTROL_BODY:
        raise ValueError("control body is too large")
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise ValueError("control request must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("control request must be a JSON object")
    return value


def _identity(value: dict[str, Any]) -> tuple[str, int, str, str]:
    task_id = value.get("task_id")
    attempt = value.get("attempt")
    environment_id = value.get("environment_id")
    fingerprint = value.get("task_fingerprint")
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("task_id is required")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(environment_id, str) or not environment_id:
        raise ValueError("environment_id is required")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError("task_fingerprint must be a SHA-256 hex digest")
    return task_id, attempt, environment_id, fingerprint


def _matches(active: ActiveBackend, payload: dict[str, Any]) -> bool:
    try:
        identity = _identity(payload)
    except ValueError:
        return False
    return identity == (
        active.task_id,
        active.attempt,
        active.environment_id,
        active.task_fingerprint,
    )


def create_app(state: GatewayState) -> Starlette:
    async def health(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "app_id": state.app_id,
                "active": state.active is not None,
            }
        )

    async def status(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return JSONResponse(
            {
                "app_id": state.app_id,
                "active": state.active.public() if state.active else None,
            }
        )

    async def activate(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            payload = await _body(request)
            task_id, attempt, environment_id, fingerprint = _identity(payload)
            backend_url = state.validate_backend_url(payload.get("backend_url"))
            backend_token = payload.get("backend_token")
            if not isinstance(backend_token, str) or len(backend_token) < 32:
                raise ValueError("backend_token is missing or too short")
            candidate = ActiveBackend(
                task_id,
                attempt,
                environment_id,
                fingerprint,
                backend_url,
                backend_token,
            )
            if state.active is not None and state.active != candidate:
                return JSONResponse(
                    {"detail": "gateway is already bound to another task environment"},
                    status_code=409,
                )
            state.active = candidate
            return JSONResponse(candidate.public())
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)

    async def deactivate(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            payload = await _body(request)
            task_id, attempt, environment_id, fingerprint = _identity(payload)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        if state.active is None:
            return JSONResponse(
                {
                    "task_id": task_id,
                    "attempt": attempt,
                    "environment_id": environment_id,
                    "task_fingerprint": fingerprint,
                    "status": "idle",
                }
            )
        if not _matches(state.active, payload):
            return JSONResponse({"detail": "gateway identity mismatch"}, status_code=409)
        state.active = None
        return JSONResponse(
            {
                "task_id": task_id,
                "attempt": attempt,
                "environment_id": environment_id,
                "task_fingerprint": fingerprint,
                "status": "idle",
            }
        )

    async def backend_health(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        active = state.active
        if active is None:
            return JSONResponse({"detail": "no active backend"}, status_code=503)
        try:
            response = await state.client.get(f"{active.backend_url}/healthz", timeout=5.0)
        except httpx.HTTPError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=503)
        if response.status_code != 200:
            return JSONResponse(
                {"detail": f"backend health returned HTTP {response.status_code}"},
                status_code=503,
            )
        try:
            data = response.json()
        except ValueError:
            data = {"status": "ok"}
        return JSONResponse(data)

    async def seed_proxy(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        if state.app_id != "kali-workstation":
            return JSONResponse({"detail": "not found"}, status_code=404)
        active = state.active
        if active is None:
            return JSONResponse({"detail": "no active backend"}, status_code=503)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if content_type != "application/x-tar":
            return JSONResponse({"detail": "seed content-type must be application/x-tar"}, status_code=415)
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > MAX_SEED_UPLOAD_BYTES:
                    return JSONResponse({"detail": "seed archive is too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid content-length"}, status_code=400)

        async def body_stream():
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_SEED_UPLOAD_BYTES:
                    raise ValueError("seed archive is too large")
                yield chunk

        try:
            response = await state.client.post(
                f"{active.backend_url}/control/seed",
                content=body_stream(),
                headers={
                    "authorization": f"Bearer {active.backend_token}",
                    "content-type": "application/x-tar",
                },
                timeout=180.0,
            )
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=413)
        except httpx.HTTPError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=503)
        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text[:1000]}
        return JSONResponse(data, status_code=response.status_code)

    async def artifact_proxy(request: Request):
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        active = state.active
        if state.app_id != "kali-workstation" or active is None:
            return JSONResponse({"detail": "no active workstation"}, status_code=503)
        suffix = request.path_params.get("artifact_id")
        if suffix is not None and not re.fullmatch(r"[0-9a-f]{64}", suffix):
            return JSONResponse({"detail": "invalid artifact ID"}, status_code=400)
        url = f"{active.backend_url}/control/artifacts" + (f"/{suffix}" if suffix else "")
        headers = {"authorization": f"Bearer {active.backend_token}"}
        try:
            if request.method == "POST":
                declared = request.headers.get("content-length")
                if declared is not None and int(declared) > MAX_SEED_UPLOAD_BYTES:
                    return JSONResponse({"detail": "artifact too large"}, status_code=413)
                async def body():
                    total = 0
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > MAX_SEED_UPLOAD_BYTES:
                            raise ValueError("artifact too large")
                        yield chunk
                response = await state.client.post(url, headers=headers, content=body(), timeout=180)
                return JSONResponse(response.json(), status_code=response.status_code)
            outbound = state.client.build_request("GET", url, headers=headers)
            response = await state.client.send(outbound, stream=True)
            if response.status_code != 200:
                data = await response.aread()
                await response.aclose()
                return JSONResponse({"detail": data.decode(errors="replace")[:1000]}, status_code=response.status_code)
            return StreamingResponse(response.aiter_bytes(), media_type="application/octet-stream",
                headers={k: v for k, v in response.headers.items() if k in {"content-length", "x-artifact-sha256"}},
                background=BackgroundTask(response.aclose))
        except (httpx.HTTPError, ValueError) as exc:
            return JSONResponse({"detail": str(exc)[:1000]}, status_code=503)

    async def control_proxy(request: Request) -> JSONResponse:
        if not state.authorized(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        active = state.active
        if active is None:
            return JSONResponse({"detail": "no active backend"}, status_code=503)
        try:
            payload = await _body(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        if not _matches(active, {**payload, "attempt": active.attempt}):
            # Backend control payload intentionally omits attempt. Match the stable fields.
            if not (
                payload.get("task_id") == active.task_id
                and payload.get("environment_id") == active.environment_id
                and payload.get("task_fingerprint") == active.task_fingerprint
            ):
                return JSONResponse({"detail": "gateway/backend identity mismatch"}, status_code=409)
        operation = request.path_params["operation"]
        if operation not in {"prepare", "resume", "reset"}:
            return JSONResponse({"detail": "not found"}, status_code=404)
        try:
            response = await state.client.post(
                f"{active.backend_url}/control/{operation}",
                json=payload,
                headers={"authorization": f"Bearer {active.backend_token}"},
                timeout=180.0,
            )
        except httpx.HTTPError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=503)
        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text[:1000]}
        return JSONResponse(data, status_code=response.status_code)

    async def mcp_proxy(request: Request):
        active = state.active
        if active is None:
            return JSONResponse({"detail": "no active task backend"}, status_code=503)
        path = request.url.path
        query = request.url.query

        # FastMCP's mounted Streamable HTTP endpoint is canonical at /mcp/.
        # The public gateway contract intentionally remains /mcp. Forward the
        # root MCP route to the backend's canonical path so clients never see
        # the backend framework's redirect or private backend hostname.
        backend_path = "/mcp/" if path == "/mcp" else path
        target = f"{active.backend_url}{backend_path}"
        if query:
            target += f"?{query}"
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.casefold() not in HOP_BY_HOP
        }
        headers["authorization"] = f"Bearer {active.backend_token}"

        # When the trusted backend is reached through its Docker-inspected
        # private IP, the MCP transport's DNS-rebinding protection would reject
        # the automatic "Host: <ip>:8000" authority. Every runtime backend is
        # explicitly configured to allow localhost:8000, so use that internal
        # authority while keeping the TCP destination pinned to backend_url.
        backend_hostname = urlparse(active.backend_url).hostname or ""
        try:
            backend_ip = ipaddress.ip_address(backend_hostname)
        except ValueError:
            backend_ip = None
        if backend_ip is not None:
            headers["host"] = "localhost:8000"

        body = await request.body()
        try:
            outgoing = state.client.build_request(
                request.method,
                target,
                headers=headers,
                content=body,
            )
            response = await state.client.send(outgoing, stream=True)
        except httpx.HTTPError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=503)
        response_headers = {
            key: value
            for key, value in response.headers.items()
            if key.casefold() not in HOP_BY_HOP
        }
        return StreamingResponse(
            response.aiter_raw(),
            status_code=response.status_code,
            headers=response_headers,
            background=BackgroundTask(response.aclose),
        )

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await state.close()

    app = Starlette(
        routes=[
            Route("/healthz", health, methods=["GET"]),
            Route("/control/status", status, methods=["GET"]),
            Route("/control/activate", activate, methods=["POST"]),
            Route("/control/deactivate", deactivate, methods=["POST"]),
            Route("/control/backend-health", backend_health, methods=["GET"]),
            Route("/control/seed", seed_proxy, methods=["POST"]),
            Route("/control/artifacts", artifact_proxy, methods=["POST"]),
            Route("/control/artifacts/{artifact_id}", artifact_proxy, methods=["GET"]),
            Route("/control/{operation}", control_proxy, methods=["POST"]),
            Route("/mcp", mcp_proxy, methods=["GET", "POST", "DELETE"]),
            Route("/mcp/{path:path}", mcp_proxy, methods=["GET", "POST", "DELETE"]),
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
    app_id = os.environ.get("GATEWAY_APP_ID", "").strip()
    prefix = os.environ.get("GATEWAY_BACKEND_PREFIX", "").strip()
    if app_id != "kali-workstation":
        raise RuntimeError("GATEWAY_APP_ID must be kali-workstation")
    if not prefix or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-." for ch in prefix):
        raise RuntimeError("GATEWAY_BACKEND_PREFIX is invalid")
    state = GatewayState(app_id=app_id, backend_prefix=prefix, control_token=_token())
    import uvicorn

    uvicorn.run(
        create_app(state),
        host="0.0.0.0",
        port=8000,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()

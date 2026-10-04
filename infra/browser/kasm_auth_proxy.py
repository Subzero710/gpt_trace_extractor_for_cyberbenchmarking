#!/usr/bin/python3
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import html
import ipaddress
import os
import secrets
import ssl
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout, TCPConnector, WSMsgType, web
from multidict import CIMultiDict

COOKIE_NAME = "gpt_trace_teacher_session"
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 6901
DEFAULT_UPSTREAM = "https://127.0.0.1:6902"
DEFAULT_SESSION_TTL = 8 * 60 * 60
LOGIN_PATH = "/_auth/login"
LOGOUT_PATH = "/_auth/logout"
HEALTH_PATH = "/_auth/healthz"

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Teacher Browser</title>
<style>
:root { color-scheme: dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:#111318; color:#f4f6f8; }
main { width:min(92vw, 420px); background:#1b1f27; border:1px solid #303641; border-radius:16px; padding:32px; box-shadow:0 20px 60px #0008; }
h1 { margin:0 0 8px; font-size:1.6rem; }
p { color:#b7bec8; margin:0 0 24px; }
label { display:block; margin-bottom:8px; font-weight:600; }
input { box-sizing:border-box; width:100%; padding:12px 14px; border-radius:10px; border:1px solid #444b57; background:#0f1116; color:#fff; font-size:1rem; }
button { margin-top:16px; width:100%; padding:12px 14px; border:0; border-radius:10px; font-weight:700; font-size:1rem; cursor:pointer; }
.error { margin:0 0 16px; color:#ffb4ab; }
</style>
</head>
<body><main>
<h1>Teacher Browser</h1>
<p>Authenticate to open the persistent KasmVNC session.</p>
__ERROR__
<form method="post" action="/_auth/login" autocomplete="off">
<input type="hidden" name="next" value="__NEXT__">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Sign in</button>
</form>
</main></body></html>"""


class LoginLimiter:
    def __init__(self, *, attempts: int = 8, window_seconds: int = 60) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, key: str, now: float) -> deque[float]:
        bucket = self._failures[key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if not bucket:
            self._failures.pop(key, None)
            bucket = self._failures[key]
        return bucket

    def allowed(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return len(self._trim(key, now)) < self.attempts

    def fail(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._trim(key, now).append(now)

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)


class SessionSigner:
    def __init__(self, secret: bytes, ttl_seconds: int = DEFAULT_SESSION_TTL) -> None:
        if len(secret) < 32:
            raise ValueError("session secret must be at least 32 bytes")
        self.secret = secret
        self.ttl_seconds = ttl_seconds

    def mint(self, now: int | None = None) -> str:
        now = int(time.time()) if now is None else int(now)
        payload = f"v1.{now + self.ttl_seconds}.{secrets.token_urlsafe(18)}"
        sig = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def valid(self, token: str | None, now: int | None = None) -> bool:
        if not token:
            return False
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "v1":
            return False
        payload = ".".join(parts[:3])
        expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, parts[3]):
            return False
        try:
            expires = int(parts[1])
        except ValueError:
            return False
        now = int(time.time()) if now is None else int(now)
        return now <= expires


def _read_password(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not 12 <= len(value) <= 128:
        raise RuntimeError("teacher browser password must be 12..128 characters")
    return value


def _load_or_create_secret(path: Path) -> bytes:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"unsafe auth session secret path: {path}")
        raw = path.read_bytes()
        if len(raw) < 32:
            raise RuntimeError("auth session secret is too short")
        return raw
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    raw = secrets.token_bytes(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return raw


def _client_key(request: web.Request) -> str:
    forwarded = request.headers.get("CF-Connecting-IP", "").strip()
    if forwarded:
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return request.remote or "unknown"


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\r" in value or "\n" in value:
        return "/"
    return value


def _security_headers(response: web.StreamResponse) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )


def _login_response(*, next_path: str = "/", error: str = "", status: int = 200) -> web.Response:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    body = (
        LOGIN_PAGE.replace("__ERROR__", error_html).replace(
            "__NEXT__", html.escape(_safe_next(next_path), quote=True)
        )
    )
    response = web.Response(text=body, content_type="text/html", status=status)
    _security_headers(response)
    return response


def _copy_request_headers(request: web.Request, upstream_auth: str) -> CIMultiDict[str]:
    headers: CIMultiDict[str] = CIMultiDict()
    for name, value in request.headers.items():
        lower = name.lower()
        if (
            lower in HOP_BY_HOP
            or lower in {"host", "authorization", "cookie", "content-length"}
            or lower.startswith("sec-websocket-")
        ):
            continue
        headers.add(name, value)
    forwarded_cookies = [
        f"{name}={value}" for name, value in request.cookies.items() if name != COOKIE_NAME
    ]
    if forwarded_cookies:
        headers["Cookie"] = "; ".join(forwarded_cookies)
    headers["Authorization"] = upstream_auth
    return headers


def _copy_response_headers(source_response) -> CIMultiDict[str]:
    headers: CIMultiDict[str] = CIMultiDict()
    for raw_name, raw_value in source_response.raw_headers:
        name = raw_name.decode("latin-1")
        value = raw_value.decode("latin-1")
        lower = name.lower()
        if lower in HOP_BY_HOP or lower in {"content-length", "www-authenticate"}:
            continue
        headers.add(name, value)
    return headers


async def _pump_ws(source, target) -> None:
    async for msg in source:
        if msg.type == WSMsgType.TEXT:
            await target.send_str(msg.data)
        elif msg.type == WSMsgType.BINARY:
            await target.send_bytes(msg.data)
        elif msg.type == WSMsgType.PING:
            await target.ping(msg.data)
        elif msg.type == WSMsgType.PONG:
            await target.pong(msg.data)
        elif msg.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING, WSMsgType.ERROR}:
            break


class AuthProxy:
    def __init__(
        self,
        *,
        password: str,
        username: str,
        signer: SessionSigner,
        upstream: str,
    ) -> None:
        self.password = password
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        self.upstream_auth = f"Basic {token}"
        self.signer = signer
        self.upstream = upstream.rstrip("/")
        self.limiter = LoginLimiter()
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        self._ssl_context = ssl_context
        self.client: ClientSession | None = None

    async def start(self) -> None:
        if self.client is not None:
            return
        connector = TCPConnector(ssl=self._ssl_context, limit=32)
        self.client = ClientSession(
            connector=connector,
            timeout=ClientTimeout(total=None, sock_connect=5, sock_read=None),
        )

    def _client(self) -> ClientSession:
        if self.client is None:
            raise RuntimeError("auth proxy HTTP client is not started")
        return self.client

    async def close(self) -> None:
        if self.client is not None:
            await self.client.close()
            self.client = None

    def authenticated(self, request: web.Request) -> bool:
        return self.signer.valid(request.cookies.get(COOKIE_NAME))

    async def health(self, request: web.Request) -> web.Response:
        return web.Response(text="ok\n", content_type="text/plain")

    async def login_get(self, request: web.Request) -> web.Response:
        if self.authenticated(request):
            raise web.HTTPSeeOther(_safe_next(request.query.get("next")))
        return _login_response(next_path=request.query.get("next", "/"))

    async def login_post(self, request: web.Request) -> web.Response:
        key = _client_key(request)
        if not self.limiter.allowed(key):
            response = _login_response(error="Too many failed attempts. Try again shortly.", status=429)
            response.headers["Retry-After"] = str(self.limiter.window_seconds)
            return response
        data = await request.post()
        supplied = str(data.get("password", ""))
        next_path = _safe_next(str(data.get("next", "/")))
        if not hmac.compare_digest(supplied, self.password):
            self.limiter.fail(key)
            await asyncio.sleep(0.35)
            return _login_response(next_path=next_path, error="Invalid password.", status=401)
        self.limiter.clear(key)
        response = web.Response(status=303, headers={"Location": next_path})
        response.set_cookie(
            COOKIE_NAME,
            self.signer.mint(),
            max_age=self.signer.ttl_seconds,
            httponly=True,
            secure=True,
            samesite="Strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    async def logout(self, request: web.Request) -> web.Response:
        response = web.Response(status=303, headers={"Location": LOGIN_PATH})
        response.del_cookie(COOKIE_NAME, path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    async def proxy(self, request: web.Request) -> web.StreamResponse:
        if not self.authenticated(request):
            if request.headers.get("Upgrade", "").lower() == "websocket":
                return web.Response(status=401, text="authentication required\n")
            next_path = request.rel_url.path_qs
            raise web.HTTPSeeOther(f"{LOGIN_PATH}?next={quote(next_path, safe='/?=&%')}")

        target = f"{self.upstream}{request.rel_url.path_qs}"
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self.proxy_websocket(request, target)
        body = await request.read()
        async with self._client().request(
            request.method,
            target,
            headers=_copy_request_headers(request, self.upstream_auth),
            data=body if body else None,
            allow_redirects=False,
        ) as upstream_response:
            payload = await upstream_response.read()
            headers = _copy_response_headers(upstream_response)
            location = headers.get("Location")
            if location and location.startswith(self.upstream):
                headers["Location"] = location[len(self.upstream):] or "/"
            return web.Response(status=upstream_response.status, headers=headers, body=payload)

    async def proxy_websocket(self, request: web.Request, target: str) -> web.WebSocketResponse:
        protocols_header = request.headers.get("Sec-WebSocket-Protocol", "")
        protocols = [item.strip() for item in protocols_header.split(",") if item.strip()]
        upstream_ws = await self._client().ws_connect(
            target,
            headers=_copy_request_headers(request, self.upstream_auth),
            protocols=protocols,
            autoping=False,
            max_msg_size=0,
        )
        selected = [upstream_ws.protocol] if upstream_ws.protocol else []
        client_ws = web.WebSocketResponse(
            protocols=selected, autoping=False, max_msg_size=0
        )
        await client_ws.prepare(request)
        try:
            left = asyncio.create_task(_pump_ws(client_ws, upstream_ws))
            right = asyncio.create_task(_pump_ws(upstream_ws, client_ws))
            done, pending = await asyncio.wait({left, right}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(*done, return_exceptions=True)
        finally:
            await upstream_ws.close()
            await client_ws.close()
        return client_ws


def build_app(proxy: AuthProxy) -> web.Application:
    app = web.Application(client_max_size=32 * 1024 * 1024)
    app.router.add_get(HEALTH_PATH, proxy.health)
    app.router.add_get(LOGIN_PATH, proxy.login_get)
    app.router.add_post(LOGIN_PATH, proxy.login_post)
    app.router.add_route("*", LOGOUT_PATH, proxy.logout)
    app.router.add_route("*", "/{tail:.*}", proxy.proxy)

    async def startup(_: web.Application) -> None:
        await proxy.start()

    async def cleanup(_: web.Application) -> None:
        await proxy.close()

    app.on_startup.append(startup)
    app.on_cleanup.append(cleanup)
    return app


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--password-file", type=Path, default=Path("/run/secrets/teacher_browser_password"))
    parser.add_argument("--username", default=os.environ.get("BROWSER_KASM_USERNAME", "kasm_user"))
    parser.add_argument("--cert", type=Path, default=Path("/home/browser/.vnc/self.pem"))
    parser.add_argument("--session-secret", type=Path, default=Path("/home/browser/.vnc/auth-session-secret"))
    parser.add_argument("--session-ttl", type=int, default=DEFAULT_SESSION_TTL)
    args = parser.parse_args()

    password = _read_password(args.password_file)
    signer = SessionSigner(_load_or_create_secret(args.session_secret), args.session_ttl)
    proxy = AuthProxy(password=password, username=args.username, signer=signer, upstream=args.upstream)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(args.cert, args.cert)
    web.run_app(build_app(proxy), host=args.host, port=args.port, ssl_context=ssl_context, access_log=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

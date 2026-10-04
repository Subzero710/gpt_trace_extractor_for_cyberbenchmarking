from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
import unittest

from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

MODULE_PATH = Path(__file__).resolve().parents[1] / "kasm_auth_proxy.py"
spec = importlib.util.spec_from_file_location("kasm_auth_proxy", MODULE_PATH)
assert spec and spec.loader
proxy_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_module)


class SessionSignerTests(unittest.TestCase):
    def test_token_is_signed_and_expires(self) -> None:
        signer = proxy_module.SessionSigner(b"x" * 48, ttl_seconds=60)
        token = signer.mint(now=100)
        self.assertTrue(signer.valid(token, now=160))
        self.assertFalse(signer.valid(token, now=161))
        self.assertFalse(signer.valid(token + "x", now=101))

    def test_safe_next_rejects_external_redirect(self) -> None:
        self.assertEqual(proxy_module._safe_next("//evil.example"), "/")
        self.assertEqual(proxy_module._safe_next("https://evil.example"), "/")
        self.assertEqual(proxy_module._safe_next("/foo?bar=1"), "/foo?bar=1")


class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async def root(request: web.Request) -> web.Response:
            self.assertTrue(request.headers.get("Authorization", "").startswith("Basic "))
            return web.Response(text="upstream-ok", headers={"X-Upstream": "yes"})

        async def ws_handler(request: web.Request) -> web.WebSocketResponse:
            self.assertTrue(request.headers.get("Authorization", "").startswith("Basic "))
            ws = web.WebSocketResponse(protocols=["binary"])
            await ws.prepare(request)
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    await ws.send_bytes(msg.data[::-1])
                elif msg.type == WSMsgType.TEXT:
                    await ws.send_str(msg.data[::-1])
            return ws

        upstream_app = web.Application()
        upstream_app.router.add_get("/", root)
        upstream_app.router.add_get("/socket", ws_handler)
        self.upstream = TestServer(upstream_app)
        await self.upstream.start_server()

        self.proxy = proxy_module.AuthProxy(
            password="correct-horse-battery",
            username="kasm_user",
            signer=proxy_module.SessionSigner(b"s" * 48, ttl_seconds=3600),
            upstream=str(self.upstream.make_url("/")).rstrip("/"),
        )
        self.server = TestServer(proxy_module.build_app(self.proxy))
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.upstream.close()

    async def login(self) -> str:
        response = await self.client.post(
            "/_auth/login",
            data={"password": "correct-horse-battery", "next": "/"},
            allow_redirects=False,
        )
        self.assertEqual(response.status, 303)
        self.assertIn(proxy_module.COOKIE_NAME, response.cookies)
        return response.cookies[proxy_module.COOKIE_NAME].value

    async def test_anonymous_request_gets_html_login_not_basic_challenge(self) -> None:
        response = await self.client.get("/", allow_redirects=False)
        self.assertEqual(response.status, 303)
        self.assertTrue(response.headers["Location"].startswith("/_auth/login"))
        self.assertNotIn("WWW-Authenticate", response.headers)
        login = await self.client.get(response.headers["Location"])
        self.assertEqual(login.status, 200)
        text = await login.text()
        self.assertIn("Teacher Browser", text)
        self.assertNotIn("WWW-Authenticate", login.headers)

    async def test_bad_password_stays_html_without_basic_challenge(self) -> None:
        response = await self.client.post(
            "/_auth/login",
            data={"password": "wrong", "next": "/"},
            allow_redirects=False,
        )
        self.assertEqual(response.status, 401)
        self.assertNotIn("WWW-Authenticate", response.headers)
        self.assertIn("Invalid password", await response.text())

    async def test_authenticated_http_is_proxied(self) -> None:
        token = await self.login()
        response = await self.client.get(
            "/", headers={"Cookie": f"{proxy_module.COOKIE_NAME}={token}"}
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.text(), "upstream-ok")
        self.assertEqual(response.headers["X-Upstream"], "yes")

    async def test_authenticated_websocket_is_proxied(self) -> None:
        token = await self.login()
        ws = await self.client.ws_connect(
            "/socket",
            protocols=["binary"],
            headers={"Cookie": f"{proxy_module.COOKIE_NAME}={token}"},
        )
        await ws.send_bytes(b"abc")
        message = await ws.receive(timeout=2)
        self.assertEqual(message.type, WSMsgType.BINARY)
        self.assertEqual(message.data, b"cba")
        await ws.close()


if __name__ == "__main__":
    unittest.main()

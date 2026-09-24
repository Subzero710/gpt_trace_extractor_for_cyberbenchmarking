import httpx
import pytest

from mcp_gateway.server import GatewayState, create_app

TOKEN = "t" * 40
FP = "a" * 64
BACKEND = "http://gpt-trace-workspace-0123456789abcdef0123:8000"


class OneChunkStream(httpx.AsyncByteStream):
    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        yield self.data


def identity():
    return {
        "task_id": "task-1",
        "attempt": 2,
        "environment_id": "env-1",
        "task_fingerprint": FP,
    }


@pytest.mark.asyncio
async def test_gateway_binds_one_exact_backend_and_proxies_mcp_without_external_host() -> None:
    backend_calls = []

    async def backend_handler(request: httpx.Request):
        backend_calls.append(request)
        # Reproduce FastMCP's real behavior: /mcp redirects to /mcp/.
        # The gateway must canonicalize before the request reaches the backend.
        if request.url.path == "/mcp":
            return httpx.Response(
                307,
                headers={"location": f"{BACKEND}/mcp/"},
                request=request,
            )
        return httpx.Response(
            200,
            stream=OneChunkStream(b'{"jsonrpc":"2.0","result":{}}'),
            headers={"Mcp-Session-Id": "session-1"},
            request=request,
        )

    state = GatewayState(
        app_id="code-workspace",
        backend_prefix="gpt-trace-workspace-",
        control_token=TOKEN,
    )
    await state.client.aclose()
    state.client = httpx.AsyncClient(transport=httpx.MockTransport(backend_handler))
    app = create_app(state)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://public-gateway.example",
    ) as client:
        payload = {
            **identity(),
            "backend_url": BACKEND,
            "backend_token": "b" * 64,
        }
        response = await client.post(
            "/control/activate",
            json=payload,
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 200

        response = await client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0"}',
            headers={"host": "attacker.example", "x-test": "ok"},
        )
        assert response.status_code == 200
        assert response.headers["mcp-session-id"] == "session-1"

    assert len(backend_calls) == 1
    request = backend_calls[0]
    assert request.url == f"{BACKEND}/mcp/"
    assert request.headers["host"] == "gpt-trace-workspace-0123456789abcdef0123:8000"
    assert request.headers["x-test"] == "ok"
    assert request.headers["authorization"] == "Bearer " + "b" * 64


@pytest.mark.asyncio
async def test_control_proxy_uses_per_backend_token_and_identity() -> None:
    seen = []

    async def backend_handler(request: httpx.Request):
        seen.append(request)
        body = __import__("json").loads(request.content)
        return httpx.Response(200, json={**body, "status": "ready"}, request=request)

    state = GatewayState(
        app_id="code-workspace",
        backend_prefix="gpt-trace-workspace-",
        control_token=TOKEN,
    )
    await state.client.aclose()
    state.client = httpx.AsyncClient(transport=httpx.MockTransport(backend_handler))
    app = create_app(state)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway"
    ) as client:
        await client.post(
            "/control/activate",
            json={**identity(), "backend_url": BACKEND, "backend_token": "b" * 64},
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        response = await client.post(
            "/control/prepare",
            json={
                "task_id": "task-1",
                "environment_id": "env-1",
                "task_fingerprint": FP,
            },
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 200

    assert seen[0].headers["authorization"] == "Bearer " + "b" * 64
    assert seen[0].url == f"{BACKEND}/control/prepare"


@pytest.mark.asyncio
async def test_gateway_rejects_wrong_backend_name_and_conflicting_binding() -> None:
    state = GatewayState(
        app_id="code-workspace",
        backend_prefix="gpt-trace-workspace-",
        control_token=TOKEN,
    )
    app = create_app(state)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway"
    ) as client:
        bad = await client.post(
            "/control/activate",
            json={
                **identity(),
                "backend_url": "http://gpt-trace-workspace-evil.example:8000",
                "backend_token": "b" * 64,
            },
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert bad.status_code == 400

        first = await client.post(
            "/control/activate",
            json={**identity(), "backend_url": BACKEND, "backend_token": "b" * 64},
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert first.status_code == 200

        conflict = await client.post(
            "/control/activate",
            json={
                **identity(),
                "attempt": 3,
                "environment_id": "env-2",
                "backend_url": "http://gpt-trace-workspace-aaaaaaaaaaaaaaaaaaaa:8000",
                "backend_token": "c" * 64,
            },
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert conflict.status_code == 409


@pytest.mark.asyncio
async def test_gateway_accepts_private_task_backend_ip_and_rejects_public_or_loopback() -> None:
    state = GatewayState(
        app_id="code-workspace",
        backend_prefix="gpt-trace-workspace-",
        control_token=TOKEN,
    )
    app = create_app(state)
    headers = {"authorization": f"Bearer {TOKEN}"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://gateway",
    ) as client:
        accepted = await client.post(
            "/control/activate",
            json={
                **identity(),
                "backend_url": "http://172.30.0.17:8000",
                "backend_token": "b" * 64,
            },
            headers=headers,
        )
        assert accepted.status_code == 200

        await client.post(
            "/control/deactivate",
            json=identity(),
            headers=headers,
        )

        for forbidden in (
            "http://8.8.8.8:8000",
            "http://127.0.0.1:8000",
            "http://169.254.1.1:8000",
        ):
            rejected = await client.post(
                "/control/activate",
                json={
                    **identity(),
                    "backend_url": forbidden,
                    "backend_token": "b" * 64,
                },
                headers=headers,
            )
            assert rejected.status_code == 400


@pytest.mark.asyncio
async def test_mcp_proxy_uses_allowlisted_authority_for_private_ip_backend() -> None:
    backend_calls: list[httpx.Request] = []

    async def backend_handler(request: httpx.Request):
        backend_calls.append(request)
        # Reproduce MCP TransportSecurityMiddleware: the dynamic backend has
        # localhost:8000 in MCP_ALLOWED_HOSTS, but not its runtime-assigned IP.
        if request.headers.get("host") != "localhost:8000":
            return httpx.Response(
                421,
                text="Invalid Host header",
                request=request,
            )
        return httpx.Response(
            200,
            stream=OneChunkStream(b'{"jsonrpc":"2.0","result":{}}'),
            headers={"Mcp-Session-Id": "session-ip"},
            request=request,
        )

    state = GatewayState(
        app_id="code-workspace",
        backend_prefix="gpt-trace-workspace-",
        control_token=TOKEN,
    )
    await state.client.aclose()
    state.client = httpx.AsyncClient(transport=httpx.MockTransport(backend_handler))
    app = create_app(state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://workspace-gateway:8000",
    ) as client:
        activated = await client.post(
            "/control/activate",
            json={
                **identity(),
                "backend_url": "http://172.30.0.17:8000",
                "backend_token": "b" * 64,
            },
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        assert activated.status_code == 200

        response = await client.post(
            "/mcp",
            content=b'{"jsonrpc":"2.0"}',
            headers={"host": "workspace-gateway:8000", "x-test": "ok"},
        )
        assert response.status_code == 200
        assert response.headers["mcp-session-id"] == "session-ip"

    assert len(backend_calls) == 1
    request = backend_calls[0]
    assert request.url == "http://172.30.0.17:8000/mcp/"
    assert request.headers["host"] == "localhost:8000"
    assert request.headers["x-test"] == "ok"

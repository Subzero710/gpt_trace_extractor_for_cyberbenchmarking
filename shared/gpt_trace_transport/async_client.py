from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import httpx

from .wire import Endpoint, WireClient, TransportFailure


async def await_runtime(request, ident, operation, args, *, poll_interval, communication_error):
    operation_id = uuid.uuid4().hex
    query = {**ident, "operation": operation, "operation_id": operation_id}
    expected = {"identity": ident, "operation": operation, "operation_id": operation_id}

    def verify(response):
        if any(response.get(key) != value for key, value in expected.items()):
            raise RuntimeError("broker runtime operation identity mismatch")

    acknowledgement_error = None
    try:
        acknowledgement = await request("begin_runtime", {**query, "args": args})
    except communication_error as exc:
        acknowledgement_error = exc
    else:
        verify(acknowledgement)
        if acknowledgement.get("state") != "accepted":
            raise RuntimeError("invalid runtime operation acknowledgement")
    while True:
        try:
            status = await request("poll_runtime", query)
        except communication_error as exc:
            raise TransportFailure(f"runtime {operation} {operation_id} status unavailable") from exc
        verify(status)
        state = status.get("state")
        if state == "complete" and isinstance(status.get("result"), dict):
            return status["result"]
        if state == "failed":
            raise RuntimeError(f"runtime {operation} failed: {status.get('detail', '')[:1000]}")
        if state != "pending":
            raise TransportFailure(f"runtime {operation} {operation_id} outcome unconfirmed") from acknowledgement_error
        await asyncio.sleep(poll_interval)


def distributed() -> bool:
    mode = os.environ.get("WORKSTATION_BROKER_TRANSPORT", "unix")
    if mode not in {"unix", "mtls", "https"}:
        raise RuntimeError("unknown explicit broker transport")
    return mode != "unix"


class BrokerHTTPTransport(httpx.AsyncBaseTransport):
    def __init__(self, endpoint: Endpoint):
        self.wire = WireClient(endpoint)
        self.slots = asyncio.Semaphore(8)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        operation = request.extensions.get("timeout", {}).get("read")
        async with self.slots:
            try:
                status, raw = await asyncio.to_thread(self.wire.exchange, request.method,
                    request.url.raw_path.decode("ascii"), body, request.headers.get("authorization", ""), timeout=operation)
            except TransportFailure as exc:
                raise httpx.TransportError(str(exc), request=request) from exc
        return httpx.Response(status, content=raw, headers={"content-type": "application/json"}, request=request)


def make_client(socket_path: Path) -> httpx.AsyncClient:
    endpoint = Endpoint.from_env(socket_path)
    timeout = httpx.Timeout(endpoint.operation_timeout, connect=endpoint.connect_timeout)
    if endpoint.mode == "unix":
        return httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(socket_path)),
            base_url="http://broker", timeout=timeout, trust_env=False)
    if endpoint.mode == "https":
        transport = httpx.AsyncHTTPTransport(verify=endpoint.client_context(), trust_env=False,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=0))
        return httpx.AsyncClient(transport=transport, base_url=endpoint.url,
            timeout=timeout,
            trust_env=False, follow_redirects=False)
    return httpx.AsyncClient(transport=BrokerHTTPTransport(endpoint), base_url=endpoint.url,
        timeout=timeout, trust_env=False, follow_redirects=False)

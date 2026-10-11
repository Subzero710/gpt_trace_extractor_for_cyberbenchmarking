from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx

from .wire import Endpoint, WireClient, TransportFailure


def distributed() -> bool:
    mode = os.environ.get("WORKSTATION_BROKER_TRANSPORT", "unix")
    if mode not in {"unix", "mtls"}:
        raise RuntimeError("unknown explicit broker transport")
    return mode == "mtls"


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
    if endpoint.mode == "unix":
        return httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(socket_path)),
            base_url="http://broker", timeout=httpx.Timeout(1900, connect=10), trust_env=False)
    return httpx.AsyncClient(transport=BrokerHTTPTransport(endpoint), base_url=endpoint.url,
        timeout=httpx.Timeout(1900, connect=10), trust_env=False, follow_redirects=False)

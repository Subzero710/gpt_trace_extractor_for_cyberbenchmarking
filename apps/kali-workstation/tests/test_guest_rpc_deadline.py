from __future__ import annotations

import asyncio
import json
import socket
import struct
from types import SimpleNamespace

import pytest

from kali_workstation.guest.agent import Agent, handle, read_exact


async def exchange(agent, method):
    client, server = socket.socketpair()
    client.setblocking(False)
    server.setblocking(False)
    loop = asyncio.get_running_loop()
    payload = json.dumps({"method": method}).encode()
    task = asyncio.create_task(handle(server, agent))
    try:
        await loop.sock_sendall(client, struct.pack("!I", len(payload)) + payload)
        header = await asyncio.wait_for(read_exact(loop, client, 4), 1)
        size = struct.unpack("!I", header)[0]
        reply = await asyncio.wait_for(read_exact(loop, client, size), 1)
        return json.loads(reply)
    finally:
        client.close()
        await asyncio.wait_for(task, 1)


@pytest.mark.asyncio
async def test_guest_timeout_returns_structured_error(caplog):
    async def call(_payload):
        await asyncio.sleep(0.25)
        return {"status": "ready"}
    agent = SimpleNamespace(frame_timeout=0.2, response_reserve=0.15, call=call)
    reply = await exchange(agent, "prepare")
    assert reply == {"ok": False, "error": "TimeoutError: guest RPC prepare exceeded deadline"}
    assert "guest RPC prepare exceeded" in caplog.text


@pytest.mark.asyncio
async def test_unexpected_guest_rpc_exception_is_reported(caplog):
    async def call(_payload):
        raise LookupError("failure detail")
    agent = SimpleNamespace(frame_timeout=0.2, response_reserve=0.05, call=call)
    reply = await exchange(agent, "prepare")
    assert reply == {"ok": False, "error": "LookupError: failure detail"}
    assert "guest RPC prepare failed" in caplog.text


def test_guest_deadline_reserve_is_validated_from_broker_identity():
    limits = {"guest_agent_timeout_seconds": 60, "guest_poll_interval_seconds": 60}
    identity = {"task_id": "task", "attempt": 1, "environment_id": "env",
                "fingerprint": "a" * 64, "secret": "b" * 64, "limits": limits}
    with pytest.raises(ValueError, match="response deadline"):
        Agent(identity)

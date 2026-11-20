import asyncio
import json
import struct
from types import SimpleNamespace

import httpx
import pytest

from workstation_broker import server


def test_guest_exchange_uses_one_monotonic_deadline_for_connect_send_and_full_reply(monkeypatch):
    now = 0.0
    timeouts = []
    payload = json.dumps({"ok": True, "result": {"verified": True}}).encode()
    header = struct.pack("!I", len(payload))
    chunks = iter([header[:2], header[2:], payload])

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def settimeout(self, seconds):
            timeouts.append(seconds)

        def connect(self, address):
            nonlocal now
            assert address == (1234, server.PORT)
            now += 1

        def sendall(self, _request):
            nonlocal now
            now += 1

        def recv(self, _length):
            nonlocal now
            now += 1
            return next(chunks)

    monkeypatch.setattr(server.time, "monotonic", lambda: now)
    monkeypatch.setattr(server.socket, "socket", lambda *_args: Connection())
    broker = object.__new__(server.Broker)
    data = {"metadata": {"cid": 1234}, "secret": "secret"}
    with pytest.raises(TimeoutError, match="bounded deadline"):
        broker._guest_exchange(data, {}, "health", {}, deadline=None)
    with pytest.raises(TimeoutError, match="socket deadline"):
        broker._guest_exchange(data, {}, "health", {}, deadline=4.0)
    assert timeouts == [4, 3, 2, 1]


@pytest.mark.asyncio
@pytest.mark.parametrize("known", [True, False])
async def test_lost_guest_execution_acknowledgement_is_resolved_without_resubmitting(monkeypatch, known):
    broker = object.__new__(server.Broker)
    broker.guest_poll_interval_seconds = 0
    monkeypatch.setattr(broker, "_read", lambda identity: identity)
    messages = []

    async def request(data, ident, method, args):
        assert data == ident
        messages.append((method, args["operation_id"]))
        if method == "_exec_begin":
            raise TimeoutError("acknowledgement lost")
        if not known:
            return {"operation_id": args["operation_id"], "state": "unknown"}
        if len(messages) == 2:
            return {"operation_id": args["operation_id"], "state": "pending"}
        return {"operation_id": args["operation_id"], "state": "complete", "result": {"exit_code": 0}}

    monkeypatch.setattr(broker, "_guest_request", request)
    if known:
        assert await broker.rpc({}, "exec_command", {"command": "true"}) == {"exit_code": 0}
        assert [row[0] for row in messages] == ["_exec_begin", "_exec_status", "_exec_status"]
    else:
        with pytest.raises(TimeoutError, match="outcome unconfirmed"):
            await broker.rpc({}, "exec_command", {"command": "true"})
        assert [row[0] for row in messages] == ["_exec_begin", "_exec_status"]
    assert len({row[1] for row in messages}) == 1


@pytest.mark.asyncio
async def test_runtime_admission_persists_exact_result_and_does_not_cross_roles(tmp_path):
    admitted = asyncio.Event()
    proceed = asyncio.Event()
    calls = []

    async def rpc(ident, method, args, *, operation_id):
        calls.append((ident, method, args, operation_id))
        admitted.set()
        await proceed.wait()
        return {"exit_code": 0}

    broker = SimpleNamespace(root=tmp_path / "broker", admin_token="admin", controller_token="controller", rpc=rpc)
    origin = "http://broker"
    admin = {"authorization": "Bearer admin"}
    controller = {"authorization": "Bearer controller"}
    ident = {"task_id": "task", "attempt": 1, "environment_id": "env", "fingerprint": "a" * 64}
    operation_id = "b" * 32
    query = {**ident, "operation": "exec_command", "operation_id": operation_id}
    args = {"command": "printf '%s' verification"}
    payload = {**query, "args": args}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.create_app(broker)), base_url=origin) as client:
        accepted = await client.post("/v1/begin_runtime", json=payload, headers=admin)
        await asyncio.wait_for(admitted.wait(), 1)
        assert accepted.status_code == 200
        assert (await client.post("/v1/begin_runtime", json=payload, headers=admin)).json() == accepted.json()
        status = await client.post("/v1/poll_runtime", json=query, headers=admin)
        assert status.json()["state"] == "pending"
        assert (await client.post("/v1/poll_runtime", json=query, headers=controller)).status_code == 409
        evaluator = {**query, "purpose": "evaluator", "evaluator_retry": "c" * 32}
        assert (await client.post("/v1/poll_runtime", json=evaluator, headers=controller)).status_code == 403
        proceed.set()
        await asyncio.sleep(0)
        complete = await client.post("/v1/poll_runtime", json=query, headers=admin)
        assert complete.json()["result"] == {"exit_code": 0}
        assert complete.json()["state"] == "complete"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.create_app(broker)), base_url=origin) as client:
        assert (await client.post("/v1/poll_runtime", json=query, headers=admin)).json() == complete.json()
        changed = await client.post("/v1/begin_runtime", json={**payload, "args": {"command": "false"}}, headers=admin)
        assert changed.status_code == 409
    assert calls == [(ident, "exec_command", args, operation_id)]
    record = (tmp_path / "broker-runtime-operations" / (operation_id + ".json")).read_text()
    assert args["command"] not in record


@pytest.mark.asyncio
async def test_admin_cleanup_remains_observable_while_native_destroy_runs(tmp_path):
    from threading import Event

    entered = Event()
    finish = Event()
    calls = []

    def destroy(ident):
        calls.append(ident)
        entered.set()
        assert finish.wait(5)

    broker = SimpleNamespace(root=tmp_path / "broker", admin_token="admin", controller_token="controller",
                             draining=True, destroy=destroy)
    ident = {"task_id": "task", "attempt": 1, "environment_id": "env", "fingerprint": "a" * 64}
    query = {**ident, "operation": "destroy_attempt", "operation_id": "b" * 32}
    payload = {**query, "args": {}}
    admin = {"authorization": "Bearer admin"}
    controller = {"authorization": "Bearer controller"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.create_app(broker)),
                                 base_url="http://broker") as client:
        try:
            assert (await client.post("/v1/begin_runtime", json=payload, headers=controller)).status_code == 403
            accepted = await client.post("/v1/begin_runtime", json=payload, headers=admin)
            assert accepted.json()["state"] == "accepted"
            assert await asyncio.to_thread(entered.wait, 2)
            assert (await client.post("/v1/poll_runtime", json=query, headers=controller)).status_code == 403
            assert (await client.post("/v1/poll_runtime", json=query, headers=admin)).json()["state"] == "pending"
            duplicate = await client.post("/v1/begin_runtime", json=payload, headers=admin)
            assert duplicate.json() == accepted.json()
        finally:
            finish.set()
        async with asyncio.timeout(5):
            while (status := (await client.post("/v1/poll_runtime", json=query, headers=admin)).json())["state"] == "pending":
                await asyncio.sleep(0.01)
        assert status["state"] == "complete" and status["result"] == {"destroyed": True}
    assert calls == [ident]

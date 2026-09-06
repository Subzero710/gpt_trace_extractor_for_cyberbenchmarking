import json

import pytest

from gpt_trace_runner.traffic import TrafficMonitor


class FakePage:
    def __init__(self) -> None:
        self.handlers = {}

    def on(self, name, callback):
        self.handlers[name] = callback


class FakeRequest:
    def __init__(self, url: str, method: str = "GET") -> None:
        self.url = url
        self.method = method


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status: int = 200,
        method: str = "GET",
        payload=None,
    ) -> None:
        self.url = url
        self.status = status
        self.request = FakeRequest(url, method)
        self._payload = payload or {}

    async def body(self):
        return json.dumps(self._payload).encode()


@pytest.mark.asyncio
async def test_natural_snapshot_is_reused_without_new_request() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    response = FakeResponse(
        "https://chatgpt.com/backend-api/conversations/conv-1?num_turns=100",
        payload={"messages": [{"id": "m1"}]},
    )
    page.handlers["request"](response.request)
    page.handlers["response"](response)

    payload = await monitor.natural_snapshot("conv-1", wait_seconds=0)
    assert payload == {"messages": [{"id": "m1"}]}
    meta = monitor.runtime_metadata()
    assert meta["natural_snapshot_used"] is True
    assert meta["fallback_snapshot_used"] is False


def test_backend_403_and_429_are_recorded() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    page.handlers["response"](
        FakeResponse("https://chatgpt.com/backend-api/foo", status=403)
    )
    page.handlers["response"](
        FakeResponse("https://chatgpt.com/backend-api/bar", status=429)
    )
    assert monitor.saw_backend_403 is True
    assert monitor.saw_backend_429 is True
    meta = monitor.runtime_metadata()
    assert meta["responses_403"] == 1
    assert meta["responses_429"] == 1

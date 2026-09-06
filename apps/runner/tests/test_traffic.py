import json

import pytest

from gpt_trace_runner.exceptions import AmbiguousSubmission
from gpt_trace_runner.traffic import TrafficMonitor


class FakePage:
    def __init__(self) -> None:
        self.handlers = {}
    def on(self, name, callback):
        self.handlers[name] = callback


class FakeRequest:
    def __init__(self, url: str, method: str = "GET", payload=None) -> None:
        self.url = url
        self.method = method
        self.post_data_json = payload


class FakeResponse:
    def __init__(self, url: str, *, status: int = 200, method: str = "GET", payload=None, request=None) -> None:
        self.url = url
        self.status = status
        self.request = request or FakeRequest(url, method)
        self._payload = payload or {}
    async def body(self):
        return json.dumps(self._payload).encode()


@pytest.mark.asyncio
async def test_natural_snapshot_is_observed_without_marking_used_until_validated() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/conversations/conv-1?num_turns=100")
    response = FakeResponse(request.url, payload={"messages": [{"id": "m1"}]}, request=request)
    page.handlers["request"](request)
    page.handlers["response"](response)
    payload = await monitor.natural_snapshot("conv-1", wait_seconds=0)
    assert payload == {"messages": [{"id": "m1"}]}
    assert monitor.runtime_metadata()["natural_snapshot_used"] is False
    monitor.mark_natural_snapshot_used()
    assert monitor.runtime_metadata()["natural_snapshot_used"] is True


def test_429_is_sticky_across_task_boundaries() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/foo")
    page.handlers["request"](request)
    page.handlers["response"](FakeResponse(request.url, status=429, request=request))
    assert monitor.saw_backend_429 is True
    monitor.begin_task()
    assert monitor.saw_backend_429 is True


def test_late_response_is_not_counted_in_next_task() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/foo")
    page.handlers["request"](request)
    monitor.begin_task()
    page.handlers["response"](FakeResponse(request.url, status=403, request=request))
    assert monitor.runtime_metadata()["responses_403"] == 0


def test_conversation_post_extracts_model_and_timezone_only() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest(
        "https://chatgpt.com/backend-api/f/conversation",
        "POST",
        {"model": "gpt-5-6-thinking", "timezone": "Europe/Zurich", "timezone_offset_min": 120, "secret": "not-kept"},
    )
    page.handlers["request"](request)
    meta = monitor.runtime_metadata()
    assert meta["submitted_model"] == "gpt-5-6-thinking"
    assert meta["submitted_timezone"] == "Europe/Zurich"
    assert "secret" not in meta


def test_exactly_one_conversation_post_required() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    with pytest.raises(AmbiguousSubmission):
        monitor.validate_single_stream_request()
    for _ in range(2):
        page.handlers["request"](FakeRequest("https://chatgpt.com/backend-api/f/conversation", "POST", {}))
    with pytest.raises(AmbiguousSubmission):
        monitor.validate_single_stream_request()


def test_failed_request_is_cleaned_and_counted() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/foo")
    page.handlers["request"](request)
    page.handlers["requestfailed"](request)
    assert monitor.runtime_metadata()["requests_failed"] == 1


def test_conversation_post_prompt_with_app_mention_matches_benchmark():
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest(
        "https://chatgpt.com/backend-api/f/conversation",
        "POST",
        {
            "model": "gpt-5-6-thinking",
            "timezone": "Europe/Zurich",
            "timezone_offset_min": -120,
            "messages": [
                {
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["@Github (mosaic) inspect repo"]},
                    "metadata": {
                        "serialization_metadata": {
                            "custom_symbol_offsets": [
                                {"symbol": "ecosystemMention", "startIndex": 0, "endIndex": 16}
                            ]
                        }
                    },
                }
            ],
        },
    )
    page.handlers["request"](request)
    assert monitor.submitted_prompt_matches("inspect repo") is True
    assert monitor.submitted_prompt_matches("inspect  repo") is False
    assert monitor.submitted_timezone_offset_min == -120

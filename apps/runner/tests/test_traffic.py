import asyncio
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
    def __init__(self, url: str, *, status: int = 200, method: str = "GET", payload=None, request=None, headers=None) -> None:
        self.url = url
        self.status = status
        self.request = request or FakeRequest(url, method)
        self._payload = payload or {}
        self.headers = headers or {}

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


@pytest.mark.asyncio
async def test_backend_quiet_returns_immediately_without_request_history(monkeypatch) -> None:
    import gpt_trace_runner.traffic as traffic_module

    monkeypatch.setattr(traffic_module, "_PROCESS_LAST_BACKEND_REQUEST_AT", None)
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")

    async def unexpected_wait_for(*_args, **_kwargs):
        raise AssertionError("no wait expected")

    monkeypatch.setattr(asyncio, "wait_for", unexpected_wait_for)

    await monitor.wait_for_backend_quiet(quiet_seconds=1.25)


@pytest.mark.asyncio
async def test_backend_quiet_waits_only_for_remaining_gap(monkeypatch) -> None:
    import time
    import gpt_trace_runner.traffic as traffic_module

    monkeypatch.setattr(traffic_module, "_PROCESS_LAST_BACKEND_REQUEST_AT", None)
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    last = time.monotonic() - 0.4
    monitor._last_backend_request_at = last
    monkeypatch.setattr(traffic_module, "_PROCESS_LAST_BACKEND_REQUEST_AT", last)

    observed_timeouts = []

    async def fake_wait_for(awaitable, timeout):
        awaitable.close()
        observed_timeouts.append(timeout)
        raise TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    await monitor.wait_for_backend_quiet(quiet_seconds=1.0)

    assert len(observed_timeouts) == 1
    assert 0.45 <= observed_timeouts[0] <= 0.70


@pytest.mark.asyncio
async def test_backend_quiet_restarts_from_new_observed_request(monkeypatch) -> None:
    import gpt_trace_runner.traffic as traffic_module

    monkeypatch.setattr(traffic_module, "_PROCESS_LAST_BACKEND_REQUEST_AT", None)
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    quiet = 0.03
    page.handlers["request"](FakeRequest("https://chatgpt.com/backend-api/me"))
    loop = asyncio.get_running_loop()

    async def emit_request() -> None:
        await asyncio.sleep(0.01)
        page.handlers["request"](
            FakeRequest("https://chatgpt.com/backend-api/me")
        )

    start = loop.time()
    await asyncio.gather(
        monitor.wait_for_backend_quiet(quiet_seconds=quiet),
        emit_request(),
    )
    elapsed = loop.time() - start

    assert elapsed >= 0.035


def test_new_monitor_inherits_process_backend_request_time(monkeypatch) -> None:
    import gpt_trace_runner.traffic as traffic_module

    monkeypatch.setattr(traffic_module, "_PROCESS_LAST_BACKEND_REQUEST_AT", None)
    first_page = FakePage()
    first = TrafficMonitor(first_page, base_url="https://chatgpt.com")
    first_page.handlers["request"](
        FakeRequest("https://chatgpt.com/backend-api/me")
    )

    second = TrafficMonitor(FakePage(), base_url="https://chatgpt.com")

    assert first._last_backend_request_at is not None
    assert second._last_backend_request_at == first._last_backend_request_at


def test_begin_task_keeps_global_backend_pacing_state() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    request = FakeRequest("https://chatgpt.com/backend-api/me")
    page.handlers["request"](request)
    last = monitor._last_backend_request_at

    monitor.begin_task()

    assert last is not None
    assert monitor._last_backend_request_at == last


def test_429_is_task_scoped_and_does_not_poison_next_task() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/foo")
    page.handlers["request"](request)
    page.handlers["response"](FakeResponse(request.url, status=429, request=request))
    assert monitor.saw_backend_429 is True
    monitor.begin_task()
    assert monitor.saw_backend_429 is False


@pytest.mark.asyncio
async def test_auth_session_429_is_visible_and_not_misreported_as_auth_loss() -> None:
    from gpt_trace_runner.exceptions import RateLimited
    from gpt_trace_runner.site_guard import SiteGuard

    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    request = FakeRequest("https://chatgpt.com/api/auth/session")
    page.handlers["request"](request)
    page.handlers["response"](FakeResponse(
        request.url, request=request, status=429, headers={"retry-after": "120"},
    ))
    assert monitor.runtime_metadata()["responses_429"] == 1
    assert monitor.saw_backend_429 is False
    with pytest.raises(RateLimited) as raised:
        await monitor.wait_for_authenticated_user(timeout_seconds=0.01)
    assert raised.value.retry_after_seconds == 120.0

    guard = SiteGuard(page, interaction=object(), traffic=monitor,
                      ready_timeout_seconds=0.01, challenge_timeout_seconds=0.01)
    with pytest.raises(RateLimited):
        await guard.wait_ready()

    request2 = FakeRequest(request.url)
    page.handlers["request"](request2)
    page.handlers["response"](FakeResponse(request.url, request=request2, status=200))
    assert monitor.auth_session_rate_limit is None


def test_late_response_is_not_counted_in_next_task() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest("https://chatgpt.com/backend-api/foo")
    page.handlers["request"](request)
    monitor.begin_task()
    page.handlers["response"](FakeResponse(request.url, status=403, request=request))
    assert monitor.runtime_metadata()["responses_403"] == 0


def test_conversation_post_extracts_only_audited_runtime_fields() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()
    request = FakeRequest(
        "https://chatgpt.com/backend-api/f/conversation",
        "POST",
        {
            "model": "gpt-5-6-thinking",
            "timezone": "Europe/Zurich",
            "timezone_offset_min": 120,
            "secret": "not-kept",
        },
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


def test_conversation_post_captures_user_message_id_without_parsing_ui_text() -> None:
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
                    "id": "user-message-123",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["arbitrary serialized UI"]},
                    "metadata": {
                        "serialization_metadata": {
                            "custom_symbol_offsets": [
                                {"symbol": "futureUnknownSymbol", "startIndex": 0, "endIndex": 4}
                            ]
                        }
                    },
                }
            ],
        },
    )
    page.handlers["request"](request)
    assert monitor.submitted_user_message_id() == "user-message-123"
    assert monitor.submitted_timezone_offset_min == -120


def test_conversation_post_user_message_identity_is_fail_closed() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")

    monitor.begin_task()
    page.handlers["request"](
        FakeRequest(
            "https://chatgpt.com/backend-api/f/conversation",
            "POST",
            {"messages": [{"author": {"role": "user"}, "content": {"parts": ["x"]}}]},
        )
    )
    with pytest.raises(AmbiguousSubmission, match="no stable id"):
        monitor.submitted_user_message_id()

    monitor.begin_task()
    page.handlers["request"](
        FakeRequest(
            "https://chatgpt.com/backend-api/f/conversation",
            "POST",
            {
                "messages": [
                    {"id": "u1", "author": {"role": "user"}},
                    {"id": "u2", "author": {"role": "user"}},
                ]
            },
        )
    )
    with pytest.raises(AmbiguousSubmission, match="exactly one frontend user message"):
        monitor.submitted_user_message_id()


@pytest.mark.asyncio
async def test_backend_me_200_valid_user_is_authentication_oracle() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.reset_auth_probe()
    request = FakeRequest("https://chatgpt.com/backend-api/me")
    response = FakeResponse(
        request.url,
        status=200,
        request=request,
        payload={"object": "user", "id": "user-123"},
    )
    page.handlers["request"](request)
    page.handlers["response"](response)
    await monitor.wait_for_authenticated_user(timeout_seconds=0.1)
    assert monitor.auth_me_last_status == 200


@pytest.mark.asyncio
async def test_backend_me_rejects_invalid_identity_and_untrusted_subdomain() -> None:
    from gpt_trace_runner.exceptions import AuthenticationRequired

    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")

    monitor.reset_auth_probe()
    request = FakeRequest("https://chatgpt.com/backend-api/me")
    page.handlers["request"](request)
    page.handlers["response"](
        FakeResponse(
            request.url,
            status=200,
            request=request,
            payload={"object": "user", "id": ""},
        )
    )
    with pytest.raises(AuthenticationRequired, match="without a valid user identity"):
        await monitor.wait_for_authenticated_user(timeout_seconds=0.1)

    monitor.reset_auth_probe()
    evil = FakeRequest("https://evil.chatgpt.com/backend-api/me")
    page.handlers["request"](evil)
    page.handlers["response"](
        FakeResponse(
            evil.url,
            status=200,
            request=evil,
            payload={"object": "user", "id": "not-trusted"},
        )
    )
    with pytest.raises(AuthenticationRequired, match="no /backend-api/me response observed"):
        await monitor.wait_for_authenticated_user(timeout_seconds=0.01)


@pytest.mark.asyncio
async def test_backend_me_401_can_be_replaced_by_later_success() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.reset_auth_probe()

    first = FakeRequest("https://chatgpt.com/backend-api/me")
    page.handlers["request"](first)
    page.handlers["response"](
        FakeResponse(first.url, status=401, request=first, payload={})
    )
    assert monitor.auth_me_last_status == 401

    second = FakeRequest("https://chatgpt.com/backend-api/me")
    page.handlers["request"](second)
    page.handlers["response"](
        FakeResponse(
            second.url,
            status=200,
            request=second,
            payload={"object": "user", "id": "user-after-login"},
        )
    )
    await monitor.wait_for_authenticated_user(timeout_seconds=0.1)
    assert monitor.auth_me_last_status == 200


def test_app_system_hints_are_captured_from_init_and_prepare() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()

    page.handlers["request"](
        FakeRequest(
            "https://chatgpt.com/backend-api/conversation/init",
            "POST",
            {
                "system_hints": [
                    "plugin:asdk_app_workspace",
                    "unrelated:hint",
                ]
            },
        )
    )
    page.handlers["request"](
        FakeRequest(
            "https://chatgpt.com/backend-api/f/conversation/prepare",
            "POST",
            {
                "system_hints": [
                    "plugin:asdk_app_workspace",
                    "plugin:asdk_app_browser",
                ]
            },
        )
    )

    assert monitor.app_system_hints == (
        "plugin:asdk_app_browser",
        "plugin:asdk_app_workspace",
    )
    assert monitor.runtime_metadata()["app_system_hints"] == (
        "plugin:asdk_app_browser",
        "plugin:asdk_app_workspace",
    )

def test_conversation_readback_429_is_counted_but_not_sticky() -> None:
    page = FakePage()
    monitor = TrafficMonitor(page, base_url="https://chatgpt.com")
    monitor.begin_task()

    request = FakeRequest(
        "https://chatgpt.com/backend-api/conversations/conv-1?num_turns=100"
    )
    page.handlers["request"](request)
    page.handlers["response"](
        FakeResponse(request.url, status=429, request=request)
    )

    assert monitor.runtime_metadata()["responses_429"] == 1
    assert monitor.saw_backend_429 is False

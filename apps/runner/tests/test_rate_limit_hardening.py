from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from gpt_trace_runner.chatgpt import ChatGPTClient
from gpt_trace_runner.conversation import ConversationClient, _parse_retry_after
from gpt_trace_runner.exceptions import ConversationError, ConversationNotFound, ConversationStreamAborted, RateLimited
from gpt_trace_runner.stream import ConversationStream
from gpt_trace_runner.superbench.execution import _persist_rate_limit_defer, _raise_if_recovery_deferred
from gpt_trace_runner.journal import JournalStore, SubmissionJournal
from gpt_trace_runner.traffic import TrafficMonitor


@pytest.mark.asyncio
async def test_conversation_session_429_is_rate_limit_not_auth_failure() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={
            "sessionStatus": 429,
            "sessionRetryAfter": "7",
            "sessionRequestId": "req-session",
            "tokenPresent": False,
            "status": 0,
            "ok": False,
            "statusText": "",
            "text": "",
        }
    )
    client = ConversationClient(page)

    with pytest.raises(RateLimited) as raised:
        await client.recent_conversation_ids(limit=5)

    assert raised.value.endpoint == "/api/auth/session"
    assert raised.value.method == "GET"
    assert raised.value.retry_after_seconds == 7.0
    assert raised.value.request_id == "req-session"


@pytest.mark.asyncio
async def test_recent_resolution_caps_fetches_and_never_refetches_known_negatives() -> None:
    client = object.__new__(ConversationClient)
    client.recent_conversation_ids = AsyncMock(return_value=("old-1", "old-2", "new"))
    payloads = {
        "old-1": {"messages": [{"id": "other-1", "author": {"role": "user"}}]},
        "old-2": {"messages": [{"id": "other-2", "author": {"role": "user"}}]},
        "new": {"messages": [{"id": "wanted", "author": {"role": "user"}}]},
    }
    client.fetch = AsyncMock(side_effect=lambda cid: payloads[cid])
    rejected: set[str] = set()

    first = await client.find_recent_conversation_id_by_user_message_id(
        "wanted",
        exclude_ids=rejected,
        max_candidate_fetches=2,
    )
    second = await client.find_recent_conversation_id_by_user_message_id(
        "wanted",
        exclude_ids=rejected,
        max_candidate_fetches=2,
    )

    assert first is None
    assert second == "new"
    assert rejected == {"old-1", "old-2"}
    assert [call.args[0] for call in client.fetch.await_args_list] == [
        "old-1", "old-2", "new"
    ]


@pytest.mark.asyncio
async def test_recent_resolution_paces_list_before_candidate_fetch(monkeypatch) -> None:
    client = object.__new__(ConversationClient)
    client.recent_conversation_ids = AsyncMock(return_value=("wanted",))
    client.fetch = AsyncMock(
        return_value={"messages": [{"id": "user-wanted", "author": {"role": "user"}}]}
    )
    sleep = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep)

    resolved = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted",
        max_candidate_fetches=1,
        candidate_fetch_delay_seconds=1.0,
    )

    assert resolved == "wanted"
    sleep.assert_awaited_once_with(1.0)


def test_explicit_conversation_http_pairs_use_configured_gap() -> None:
    source = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "src"
        / "gpt_trace_runner"
        / "conversation.py"
    ).read_text(encoding="utf-8")

    assert "setTimeout(resolve, 1000)" not in source
    assert source.count("setTimeout(resolve, delayMs)") >= 3
    assert "_inter_request_gap_ms" in source


@pytest.mark.asyncio
async def test_conversation_id_resolver_backs_off_429_and_recovers() -> None:
    class Page:
        url = "https://chatgpt.com/c/local-chatgpt%3Atemporary"

    class Conversation:
        def __init__(self) -> None:
            self.calls = 0

        async def find_recent_conversation_id_by_user_message_id(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise RateLimited(
                    "list 429",
                    retry_after_seconds=0.001,
                    endpoint="/backend-api/conversations",
                    method="GET",
                )
            return "durable-1"

        async def fetch(self, _conversation_id):
            raise AssertionError("transient route must not be fetched")

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._conversation = Conversation()
    client._stream_start_timeout = 1.0
    client._conversation_id_route_grace_seconds = 0.0
    client._conversation_id_poll_initial_seconds = 0.001
    client._conversation_id_poll_max_seconds = 0.01
    client._conversation_id_rate_limit_backoff_seconds = 0.001

    resolved = await client._wait_for_conversation_id("user-1")

    assert resolved == "durable-1"
    assert client._conversation.calls == 2


@pytest.mark.asyncio
async def test_delete_retries_429_and_honors_retry_after() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        side_effect=[
            {
                "sessionStatus": 200,
                "tokenPresent": True,
                "status": 429,
                "ok": False,
                "statusText": "Too Many Requests",
                "retryAfter": "0",
                "requestId": "req-delete",
            },
            {
                "sessionStatus": 200,
                "tokenPresent": True,
                "status": 204,
                "ok": True,
                "statusText": "No Content",
            },
        ]
    )
    client = ConversationClient(page)
    client._delete_rate_limit_backoff_seconds = 0.0
    client._delete_rate_limit_backoff_max_seconds = 0.0

    await client.delete("conv")

    assert page.evaluate.await_count == 2


@pytest.mark.asyncio
async def test_backend_me_429_is_not_reported_as_authentication_loss() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/"
    page.evaluate = AsyncMock(return_value={"status": 429, "object": None, "id": None})
    client = object.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"

    with pytest.raises(RateLimited, match="/backend-api/me"):
        await client.assert_authenticated_current_page()


@pytest.mark.asyncio
async def test_auth_monitor_wakes_and_classifies_backend_me_429() -> None:
    monitor = object.__new__(TrafficMonitor)
    monitor._auth_me_response = None
    monitor._auth_me_last_status = 429
    monitor._auth_me_event = asyncio.Event()

    with pytest.raises(RateLimited, match="/backend-api/me"):
        await monitor.wait_for_authenticated_user(timeout_seconds=0.1)

@pytest.mark.asyncio
async def test_route_snapshot_429_does_not_immediately_fall_through_to_list_poll() -> None:
    class Page:
        url = "https://chatgpt.com/c/durable-route"

    class Conversation:
        def __init__(self) -> None:
            self.route_calls = 0
            self.list_calls = 0

        async def fetch(self, _conversation_id):
            self.route_calls += 1
            raise RateLimited(
                "route snapshot 429",
                retry_after_seconds=0.01,
                endpoint="/backend-api/conversations/durable-route",
                method="GET",
            )

        async def find_recent_conversation_id_by_user_message_id(self, *args, **kwargs):
            self.list_calls += 1
            return None

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._conversation = Conversation()
    client._stream_start_timeout = 0.02
    client._durable_error_recovery_seconds = 0.0
    client._conversation_id_route_grace_seconds = 0.0
    client._conversation_id_poll_initial_seconds = 0.01
    client._conversation_id_poll_max_seconds = 0.01
    client._conversation_id_rate_limit_backoff_seconds = 0.01

    with pytest.raises(RateLimited):
        await client._wait_for_conversation_id("user-1")

    assert client._conversation.route_calls >= 1
    assert client._conversation.list_calls == 0


def test_retry_after_is_never_capped_by_local_backoff_maximum() -> None:
    exc = RateLimited("429", retry_after_seconds=120.0)
    assert exc.retry_delay(1.0, maximum_seconds=8.0) == 120.0


@pytest.mark.asyncio
async def test_delete_does_not_retry_before_long_server_retry_after() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={
            "sessionStatus": 200,
            "tokenPresent": True,
            "status": 429,
            "ok": False,
            "statusText": "Too Many Requests",
            "retryAfter": "120",
            "requestId": "req-delete-long",
        }
    )
    client = ConversationClient(page)
    client._delete_rate_limit_backoff_seconds = 1.0
    client._delete_rate_limit_backoff_max_seconds = 8.0
    client._delete_rate_limit_recovery_seconds = 8.0

    with pytest.raises(RateLimited) as raised:
        await client.delete("conv")

    assert raised.value.retry_after_seconds == 120.0
    assert page.evaluate.await_count == 1


@pytest.mark.asyncio
async def test_recent_resolution_advances_past_two_404s_on_next_poll() -> None:
    from gpt_trace_runner.exceptions import ConversationNotFound

    client = object.__new__(ConversationClient)
    client.recent_conversation_ids = AsyncMock(return_value=("gone-1", "gone-2", "wanted"))

    async def fetch(candidate):
        if candidate in {"gone-1", "gone-2"}:
            raise ConversationNotFound(f"{candidate} 404")
        return {"messages": [{"id": "user-wanted", "author": {"role": "user"}}]}

    client.fetch = AsyncMock(side_effect=fetch)
    rejected: set[str] = set()
    attempts: dict[str, int] = {}

    first = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted",
        exclude_ids=rejected,
        candidate_attempts=attempts,
        max_candidate_fetches=2,
    )
    second = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted",
        exclude_ids=rejected,
        candidate_attempts=attempts,
        max_candidate_fetches=2,
    )

    assert first is None
    assert second == "wanted"
    assert rejected == set()
    assert [call.args[0] for call in client.fetch.await_args_list] == [
        "gone-1", "gone-2", "wanted"
    ]


@pytest.mark.asyncio
async def test_recent_resolution_rotates_transient_errors_and_retries_404() -> None:
    client = object.__new__(ConversationClient)
    client.recent_conversation_ids = AsyncMock(return_value=("first", "second", "third"))
    first_calls = 0

    async def fetch(candidate):
        nonlocal first_calls
        if candidate == "first":
            first_calls += 1
            if first_calls == 1:
                raise ConversationNotFound("not visible yet")
            return {"messages": [{"id": "wanted", "author": {"role": "user"}}]}
        if candidate == "second":
            raise ConversationError("temporary invalid JSON")
        return {"messages": [{"id": "other", "author": {"role": "user"}}]}

    client.fetch = AsyncMock(side_effect=fetch)
    rejected: set[str] = set()
    attempts: dict[str, int] = {}
    calls = [
        await client.find_recent_conversation_id_by_user_message_id(
            "wanted", exclude_ids=rejected, candidate_attempts=attempts,
            max_candidate_fetches=2,
        )
        for _ in range(2)
    ]
    assert calls == [None, "first"]
    assert [call.args[0] for call in client.fetch.await_args_list] == [
        "first", "second", "third", "first"
    ]


@pytest.mark.asyncio
async def test_recent_resolution_reaches_later_candidate_after_repeated_errors() -> None:
    client = object.__new__(ConversationClient)
    client.recent_conversation_ids = AsyncMock(return_value=("broken-1", "broken-2", "wanted"))

    async def fetch(candidate):
        if candidate != "wanted":
            raise ConversationError("temporary read failure")
        return {"messages": [{"id": "user-wanted", "author": {"role": "user"}}]}

    client.fetch = AsyncMock(side_effect=fetch)
    attempts: dict[str, int] = {}
    first = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted", candidate_attempts=attempts, max_candidate_fetches=2,
    )
    second = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted", candidate_attempts=attempts, max_candidate_fetches=2,
    )
    assert first is None
    assert second == "wanted"
    assert [call.args[0] for call in client.fetch.await_args_list] == [
        "broken-1", "broken-2", "wanted"
    ]


def test_retry_after_rejects_nonfinite_values() -> None:
    assert _parse_retry_after("NaN") is None
    assert _parse_retry_after("Infinity") is None


@pytest.mark.asyncio
async def test_recovery_snapshot_does_not_poll_before_retry_after() -> None:
    client = object.__new__(ChatGPTClient)
    client._conversation = SimpleNamespace(fetch=AsyncMock(side_effect=RateLimited(
        "snapshot 429", retry_after_seconds=120.0,
    )))
    client._durable_error_recovery_seconds = 0.02
    client._durable_poll_rate_limit_backoff_seconds = 0.01
    with pytest.raises(RateLimited):
        await client._fetch_recovery_snapshot("conv")
    assert client._conversation.fetch.await_count == 1


@pytest.mark.asyncio
async def test_active_stream_readback_observes_retry_after() -> None:
    class Stream:
        async def wait(self):
            await asyncio.Event().wait()

    client = object.__new__(ChatGPTClient)
    client._conversation = SimpleNamespace(fetch=AsyncMock(side_effect=RateLimited(
        "snapshot 429", retry_after_seconds=120.0,
    )))
    client._traffic = SimpleNamespace(
        natural_snapshot=AsyncMock(return_value=None),
        mark_fallback_snapshot=lambda: None,
    )
    client._turn_timeout = 0.05
    client._durable_poll_initial_seconds = 0.001
    client._durable_poll_max_seconds = 0.01
    client._durable_poll_rate_limit_backoff_seconds = 0.001
    submitted = SimpleNamespace(stream=Stream(), conversation_id="conv", user_message_id="wanted")
    with pytest.raises(RateLimited):
        await client._wait_stream_or_durable_completion(submitted)
    assert client._conversation.fetch.await_count == 1


@pytest.mark.asyncio
async def test_aborted_stream_readback_429_preserves_submitted_turn() -> None:
    class Stream:
        async def wait(self):
            raise ConversationStreamAborted("transport aborted")

    client = object.__new__(ChatGPTClient)
    client._conversation = SimpleNamespace(fetch=AsyncMock(side_effect=RateLimited(
        "snapshot 429", retry_after_seconds=120.0,
    )))
    client._traffic = SimpleNamespace(
        natural_snapshot=AsyncMock(return_value=None),
        mark_fallback_snapshot=lambda: None,
    )
    client._turn_timeout = 1.0
    client._durable_error_recovery_seconds = 0.02
    client._durable_poll_rate_limit_backoff_seconds = 0.001
    submitted = SimpleNamespace(stream=Stream(), conversation_id="conv", user_message_id="wanted")
    with pytest.raises(RateLimited):
        await client._wait_stream_or_durable_completion(submitted)
    assert client._conversation.fetch.await_count == 1


@pytest.mark.asyncio
async def test_stream_429_preserves_retry_after_and_request_id() -> None:
    class Response:
        status = 429

        async def header_value(self, name):
            return {"retry-after": "120", "x-request-id": "req-stream"}.get(name)

    with pytest.raises(RateLimited) as raised:
        await ConversationStream(Response(), timeout_seconds=1).wait()
    assert raised.value.retry_after_seconds == 120.0
    assert raised.value.request_id == "req-stream"
    assert raised.value.method == "POST"


def test_recovery_journal_persists_backoff_without_server_hint(tmp_path) -> None:
    journal = JournalStore(tmp_path / "journal.json")
    pending = SubmissionJournal(task_id="task", runner_id="runner", attempt=1, phase="cleanup_pending")
    journal.write(pending)
    _persist_rate_limit_defer(journal, pending, RateLimited("429"))
    assert journal.load().retry_not_before is not None
    with pytest.raises(RateLimited):
        _raise_if_recovery_deferred(journal.load())


@pytest.mark.asyncio
async def test_conversation_id_resolver_does_not_truncate_long_retry_after() -> None:
    class Page:
        url = "https://chatgpt.com/c/local-chatgpt%3Atemporary"

    class Conversation:
        def __init__(self) -> None:
            self.calls = 0

        async def find_recent_conversation_id_by_user_message_id(self, *args, **kwargs):
            self.calls += 1
            raise RateLimited(
                "list 429",
                retry_after_seconds=120.0,
                endpoint="/backend-api/conversations",
                method="GET",
            )

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._conversation = Conversation()
    client._stream_start_timeout = 1.0
    client._durable_error_recovery_seconds = 2.0
    client._conversation_id_route_grace_seconds = 0.0
    client._conversation_id_poll_initial_seconds = 0.01
    client._conversation_id_poll_max_seconds = 0.01
    client._conversation_id_rate_limit_backoff_seconds = 0.01

    with pytest.raises(RateLimited) as raised:
        await client._wait_for_conversation_id("user-1")

    assert raised.value.retry_after_seconds == 120.0
    assert client._conversation.calls == 1


@pytest.mark.asyncio
async def test_submit_429_is_raised_before_conversation_id_readback() -> None:
    class Response:
        status = 429

        async def header_value(self, name):
            return {
                "retry-after": "120",
                "x-request-id": "req-submit",
            }.get(name)

    class ResponseInfo:
        def __init__(self, response):
            loop = asyncio.get_running_loop()
            self.value = loop.create_future()
            self.value.set_result(response)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    class Page:
        def expect_response(self, *_args, **_kwargs):
            return ResponseInfo(Response())

    class Traffic:
        saw_backend_429 = True
        saw_backend_403 = False
        submitted_model = None
        submitted_timezone = None
        submitted_timezone_offset_min = None
        app_system_hints = ()

        def validate_single_stream_request(self):
            return None

        def submitted_user_message_id(self):
            return "user-1"

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._traffic = Traffic()
    client._turn_timeout = 10.0
    client._stream_start_timeout = 1.0
    client._thinking_effort_observer_error = None
    client._validate_thinking_effort_observation = lambda: None
    client._validate_requested_app_transport = lambda _task: None
    client._validate_submitted_model = lambda: None
    client._click_send = AsyncMock()
    client._wait_for_conversation_id = AsyncMock(
        side_effect=AssertionError("429 submit must not trigger conversation readback")
    )

    persisted = []
    prepared = type("Prepared", (), {"task": type("Task", (), {"tools": ()})()})()

    with pytest.raises(RateLimited) as raised:
        await client.submit_task(
            prepared,
            before_send=lambda: None,
            on_user_message_id=persisted.append,
        )

    assert persisted == ["user-1"]
    assert raised.value.endpoint == "/backend-api/f/conversation"
    assert raised.value.method == "POST"
    assert raised.value.retry_after_seconds == 120.0
    assert raised.value.request_id == "req-submit"
    client._wait_for_conversation_id.assert_not_awaited()


@pytest.mark.asyncio
async def test_durable_route_retries_without_same_cycle_list_fallback() -> None:
    class Page:
        url = "https://chatgpt.com/c/route-candidate"

    class Conversation:
        def __init__(self) -> None:
            self.route_calls = 0
            self.list_calls = 0

        async def fetch(self, conversation_id):
            assert conversation_id == "route-candidate"
            self.route_calls += 1
            if self.route_calls == 1:
                raise ConversationNotFound("route candidate not populated yet")
            return {"messages": [{"id": "user-1", "author": {"role": "user"}}]}

        async def find_recent_conversation_id_by_user_message_id(
            self, _user_message_id, **_kwargs
        ):
            self.list_calls += 1
            raise AssertionError("durable route must be retried before list fallback")

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._conversation = Conversation()
    client._stream_start_timeout = 1.0
    client._durable_error_recovery_seconds = 0.0
    client._conversation_id_route_grace_seconds = 0.0
    client._conversation_id_poll_initial_seconds = 0.01
    client._conversation_id_poll_max_seconds = 0.01
    client._conversation_id_rate_limit_backoff_seconds = 0.01

    resolved = await client._wait_for_conversation_id("user-1")

    assert resolved == "route-candidate"
    assert client._conversation.route_calls == 2
    assert client._conversation.list_calls == 0


@pytest.mark.asyncio
async def test_transient_route_fallback_is_single_candidate_and_paced() -> None:
    class Page:
        url = "https://chatgpt.com/c/local-chatgpt%3Atemporary"

    class Conversation:
        def __init__(self) -> None:
            self.kwargs = None

        async def fetch(self, _conversation_id):
            raise AssertionError("transient route must not be fetched")

        async def find_recent_conversation_id_by_user_message_id(
            self, _user_message_id, **kwargs
        ):
            self.kwargs = kwargs
            return "durable-1"

    client = object.__new__(ChatGPTClient)
    client._page = Page()
    client._conversation = Conversation()
    client._stream_start_timeout = 1.0
    client._durable_error_recovery_seconds = 0.0
    client._conversation_id_route_grace_seconds = 0.0
    client._conversation_id_poll_initial_seconds = 0.01
    client._conversation_id_poll_max_seconds = 0.01
    client._conversation_id_rate_limit_backoff_seconds = 0.01

    resolved = await client._wait_for_conversation_id("user-1")

    assert resolved == "durable-1"
    assert client._conversation.kwargs["max_candidate_fetches"] == 1
    assert client._conversation.kwargs["candidate_fetch_delay_seconds"] == pytest.approx(0.0)


def test_successful_journal_recovery_arms_inter_task_pause() -> None:
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "gpt_trace_runner"
        / "superbench"
        / "execution.py"
    ).read_text(encoding="utf-8")

    recovery = source.split("await _recover_pending_journal(", 1)[1].split(
        "if control_store is not None:", 1
    )[0]
    assert "pending_before_recovery is not None" in recovery
    assert "last_completed_task_at = asyncio.get_running_loop().time()" in recovery

def test_all_runner_chatgpt_control_paths_are_paced() -> None:
    from pathlib import Path

    package = Path(__file__).resolve().parents[1] / "src" / "gpt_trace_runner"
    chatgpt = (package / "chatgpt.py").read_text(encoding="utf-8")
    conversation = (package / "conversation.py").read_text(encoding="utf-8")
    tools = (package / "tools.py").read_text(encoding="utf-8")
    execution = (
        package / "superbench" / "execution.py"
    ).read_text(encoding="utf-8")

    navigate = chatgpt.split("async def _navigate(", 1)[1].split(
        "async def goto_home", 1
    )[0]
    auth = chatgpt.split("async def assert_authenticated_current_page", 1)[1].split(
        "async def wait_until_authenticated", 1
    )[0]
    auth_wait = chatgpt.split("async def wait_until_authenticated", 1)[1].split(
        "async def _new_chat_if_needed", 1
    )[0]
    send = chatgpt.split("async def _click_send", 1)[1].split(
        "@staticmethod", 1
    )[0]
    recover = chatgpt.split("async def recover(", 1)[1].split(
        "async def recover_current_candidate", 1
    )[0]
    connect = execution.split("async def _connect_chatgpt(", 1)[1].split(
        "async def _cleanup_task", 1
    )[0]

    assert "await self._wait_for_backend_quiet()" in navigate
    assert "await self._wait_for_backend_quiet()" in auth
    assert ".reload(" not in auth_wait
    assert "assert_authenticated_current_page()" in auth_wait
    assert "await self._wait_for_backend_quiet()" in send
    assert "self._navigate(" not in recover
    assert "await chatgpt.goto_home()" not in connect

    assert "before_backend_request=self._wait_for_backend_quiet" in chatgpt
    assert chatgpt.count("network_quiet=self._wait_for_backend_quiet") == 2
    assert conversation.count("await self._pace_backend_request()") == 3
    assert conversation.count("setTimeout(resolve, delayMs)") == 3
    assert "network_quiet: NetworkQuiet | None = None" in tools

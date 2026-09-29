from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from gpt_trace_runner.chatgpt import ChatGPTClient
from gpt_trace_runner.conversation import ConversationClient
from gpt_trace_runner.exceptions import RateLimited
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

    first = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted",
        exclude_ids=rejected,
        max_candidate_fetches=2,
    )
    second = await client.find_recent_conversation_id_by_user_message_id(
        "user-wanted",
        exclude_ids=rejected,
        max_candidate_fetches=2,
    )

    assert first is None
    assert second == "wanted"
    assert rejected == {"gone-1", "gone-2"}
    assert [call.args[0] for call in client.fetch.await_args_list] == [
        "gone-1", "gone-2", "wanted"
    ]


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

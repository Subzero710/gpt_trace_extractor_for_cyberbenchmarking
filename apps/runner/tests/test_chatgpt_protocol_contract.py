from __future__ import annotations

import asyncio
import json

import pytest

from gpt_trace_runner.chatgpt import (
    REQUIRED_THINKING_EFFORT,
    ChatGPTClient,
    SubmittedTurn,
)
from gpt_trace_runner.conversation import (
    conversation_id_from_url,
    is_transient_conversation_id,
)
from gpt_trace_runner.exceptions import ConversationStreamAborted
from gpt_trace_runner.models import BenchmarkTask


def test_conversation_url_decodes_local_chatgpt_route() -> None:
    value = conversation_id_from_url(
        "https://chatgpt.com/c/local-chatgpt%3A133c75a0-5498-4aff-a5dc-4bd6007ea9e1"
    )
    assert value == "local-chatgpt:133c75a0-5498-4aff-a5dc-4bd6007ea9e1"
    assert is_transient_conversation_id(value) is True
    assert is_transient_conversation_id("6ab97601-700c-83eb-9513-5982fd98bce3") is False


class _AbortedStream:
    async def wait(self):
        raise ConversationStreamAborted("conversation SSE failed: net::ERR_ABORTED")


class _FakeConversationClient:
    def __init__(self):
        self.fetches = 0

    async def fetch(self, conversation_id: str):
        self.fetches += 1
        return {
            "messages": [
                {
                    "id": "user-1",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["x"]},
                },
                {
                    "id": "assistant-1",
                    "author": {"role": "assistant"},
                    "channel": "final",
                    "end_turn": True,
                    "metadata": {"model_slug": "gpt-5-6-thinking"},
                    "content": {"content_type": "text", "parts": ["done"]},
                },
            ]
        }


class _FakeTraffic:
    def __init__(self):
        self.fallback_snapshots = 0

    def mark_fallback_snapshot(self):
        self.fallback_snapshots += 1


@pytest.mark.asyncio
async def test_err_aborted_stream_can_complete_from_verified_durable_snapshot() -> None:
    client = object.__new__(ChatGPTClient)
    client._conversation = _FakeConversationClient()
    client._traffic = _FakeTraffic()
    client._turn_timeout = 2.0
    client._expected_model = "gpt-5-6-thinking"

    submitted = SubmittedTurn(
        conversation_id="6ab97601-700c-83eb-9513-5982fd98bce3",
        user_message_id="user-1",
        stream=_AbortedStream(),
        task=BenchmarkTask("task", "question", ()),
    )

    result, stream_error, conversation, messages = await asyncio.wait_for(
        client._wait_stream_or_durable_completion(submitted),
        timeout=1.0,
    )

    assert result is None
    assert isinstance(stream_error, ConversationStreamAborted)
    assert conversation is not None
    assert messages[-1]["end_turn"] is True
    assert client._traffic.fallback_snapshots == 1


def test_protocol_source_enforces_both_contracts() -> None:
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")

    assert 'rewritten["thinking_effort"] = REQUIRED_THINKING_EFFORT' in source
    assert "ensure_extended_thinking_effort_setting" in source
    assert "self._validate_thinking_effort_enforcement()" in source
    assert "is_transient_conversation_id(candidate)" in source
    assert "await self._conversation.fetch(candidate)" in source
    assert "ConversationStreamAborted" in source

class _ProtocolRoutePage:
    def __init__(self) -> None:
        self.registered = []

    async def route(self, pattern, handler):
        self.registered.append((pattern, handler))


def test_chatgpt_protocol_contracts_execute_runtime_regex() -> None:
    from gpt_trace_runner.chatgpt import check_chatgpt_protocol_contracts

    check_chatgpt_protocol_contracts("https://chatgpt.com")


@pytest.mark.asyncio
async def test_thinking_effort_enforcer_installs_runtime_route() -> None:
    page = _ProtocolRoutePage()
    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"
    client._thinking_effort_route_installed = False

    await client._ensure_thinking_effort_enforcer()

    assert client._thinking_effort_route_installed is True
    assert len(page.registered) == 1
    pattern, _handler = page.registered[0]
    assert pattern.fullmatch(
        "https://chatgpt.com/backend-api/f/conversation"
    )
    assert pattern.fullmatch(
        "https://chatgpt.com/backend-api/f/conversation/prepare"
    )

@pytest.mark.asyncio
async def test_recovery_snapshot_retries_readback_429() -> None:
    from gpt_trace_runner.exceptions import RateLimited

    class RateLimitedOnce:
        def __init__(self):
            self.calls = 0

        async def fetch(self, conversation_id):
            self.calls += 1
            if self.calls == 1:
                raise RateLimited("snapshot 429")
            return {"messages": []}

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._conversation = RateLimitedOnce()
    client._durable_poll_rate_limit_backoff_seconds = 0.01
    client._durable_error_recovery_seconds = 1.0

    payload = await client._fetch_recovery_snapshot("conv-1")

    assert payload == {"messages": []}
    assert client._conversation.calls == 2

class _ThinkingSettingPage:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def evaluate(self, script, arg):
        self.calls.append((script, arg))
        return self.result


@pytest.mark.asyncio
async def test_high_setting_uses_har_observed_backend_contract() -> None:
    page = _ThinkingSettingPage({"ok": True, "status": 200, "statusText": "OK"})
    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._expected_model = "gpt-5-6-thinking"

    await client.ensure_extended_thinking_effort_setting()

    assert len(page.calls) == 1
    script, arg = page.calls[0]
    assert "/backend-api/settings/user_last_used_model_config" in script
    assert "method: 'PATCH'" in script
    assert "thinking_effort" in script
    assert arg == ["gpt-5-6-thinking", "extended"]


def test_submit_requires_app_transport_hint_for_requested_app() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")
    submit = source.split("async def submit_task(", 1)[1].split(
        "def _validate_message_models(", 1
    )[0]
    assert "self._validate_requested_app_transport(prepared.task)" in submit

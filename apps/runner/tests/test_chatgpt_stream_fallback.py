from __future__ import annotations

import pytest

from gpt_trace_runner.chatgpt import ChatGPTClient, SubmittedTurn
from gpt_trace_runner.exceptions import ConversationStreamIncomplete
from gpt_trace_runner.models import BenchmarkTask


class IncompleteStream:
    async def wait(self):
        raise ConversationStreamIncomplete(
            "SSE ended without a final assistant end_turn=true"
        )


class FakeTraffic:
    submitted_model = None
    submitted_timezone = None
    submitted_timezone_offset_min = None
    saw_backend_429 = False

    def __init__(self):
        self.fallback_snapshots = 0
        self.natural_snapshots = 0

    def validate_single_stream_request(self):
        return None

    async def natural_snapshot(self, _conversation_id, *, wait_seconds):
        assert wait_seconds == 0
        return None

    def mark_natural_snapshot_used(self):
        self.natural_snapshots += 1

    def mark_fallback_snapshot(self):
        self.fallback_snapshots += 1

    def runtime_metadata(self):
        return {"traffic_test": True}


class FakeConversation:
    def __init__(self, payload):
        self.payload = payload
        self.fetches = 0

    async def fetch(self, conversation_id):
        assert conversation_id == "conv-1"
        self.fetches += 1
        return self.payload


def conversation(*, complete: bool):
    return {
        "messages": [
            {
                "id": "user-1",
                "author": {"role": "user"},
                "content": {"parts": ["question"]},
            },
            {
                "id": "assistant-1",
                "author": {"role": "assistant"},
                "content": {"parts": ["FINAL ANSWER: 2"]},
                "metadata": {},
                "end_turn": complete,
            },
        ]
    }


def make_client(payload):
    client = object.__new__(ChatGPTClient)
    client._traffic = FakeTraffic()
    client._conversation = FakeConversation(payload)
    client._natural_snapshot_wait = 0
    client._expected_model = ""
    client._environment_baseline = None
    client._environment_hash = "env"
    return client


def submitted_turn():
    return SubmittedTurn(
        conversation_id="conv-1",
        user_message_id="user-1",
        stream=IncompleteStream(),
        task=BenchmarkTask("task", "question", ()),
    )


@pytest.mark.asyncio
async def test_incomplete_sse_uses_complete_durable_conversation_without_manual_resume():
    client = make_client(conversation(complete=True))
    submitted = submitted_turn()
    client._active_turn = submitted

    async def stable_environment():
        return None

    client._check_environment = stable_environment

    captured = await client.wait_for_completion(submitted)

    assert captured.conversation_id == "conv-1"
    assert captured.messages[-1]["end_turn"] is True
    assert captured.runtime_metadata["stream_recovered_from_incomplete"] is True
    assert captured.runtime_metadata["stream_error_type"] == "ConversationStreamIncomplete"
    assert captured.runtime_metadata["recovered"] is False
    assert client._conversation.fetches == 1
    assert client._traffic.fallback_snapshots == 1
    assert client._active_turn is None


@pytest.mark.asyncio
async def test_incomplete_sse_still_requires_durable_end_turn_proof():
    client = make_client(conversation(complete=False))
    submitted = submitted_turn()
    client._active_turn = submitted

    async def stable_environment():
        return None

    client._check_environment = stable_environment

    with pytest.raises(
        ConversationStreamIncomplete,
        match="SSE ended without a final assistant end_turn=true",
    ):
        await client.wait_for_completion(submitted)

    assert client._conversation.fetches == 1
    assert client._traffic.fallback_snapshots == 1
    assert client._active_turn is None

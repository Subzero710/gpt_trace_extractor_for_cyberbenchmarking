from __future__ import annotations

from pathlib import Path

import pytest

from gpt_trace_runner.exceptions import (
    ConversationStreamIncomplete,
)
from gpt_trace_runner.stream import (
    inspect_conversation_stream,
    is_conversation_stream_response,
)


FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_simple_stream_is_complete() -> None:
    result = inspect_conversation_stream(
        read_fixture("simple_turn.sse")
    )
    assert result.conversation_id == "conv-simple"
    assert result.final_end_turn is True
    assert result.message_stream_complete is True
    assert result.done is True
    assert result.last_token is True
    assert result.request_id == "req-simple"
    assert result.turn_exchange_id == "turn-simple"
    assert result.tool_invoked is False


def test_tool_stream_ignores_intermediate_end_turn_false() -> None:
    result = inspect_conversation_stream(
        read_fixture("tool_turn.sse")
    )
    assert result.conversation_id == "conv-tool"
    assert result.final_end_turn is True
    assert result.tool_invoked is True
    assert result.tool_name == "CodeModeTool"


@pytest.mark.parametrize(
    "fixture",
    [
        "missing_end_turn.sse",
        "missing_stream_complete.sse",
        "truncated_turn.sse",
    ],
)
def test_incomplete_streams_are_rejected(fixture: str) -> None:
    with pytest.raises(ConversationStreamIncomplete):
        inspect_conversation_stream(read_fixture(fixture))


class FakeRequest:
    def __init__(self, method: str) -> None:
        self.method = method


class FakeResponse:
    def __init__(self, url: str, method: str = "POST") -> None:
        self.url = url
        self.request = FakeRequest(method)


def test_stream_response_predicate_is_exact() -> None:
    assert is_conversation_stream_response(
        FakeResponse(
            "https://chatgpt.com/backend-api/f/conversation"
        )
    )
    assert not is_conversation_stream_response(
        FakeResponse(
            "https://chatgpt.com/backend-api/f/conversation/prepare"
        )
    )
    assert not is_conversation_stream_response(
        FakeResponse(
            "https://chatgpt.com/backend-api/f/conversation",
            method="GET",
        )
    )


class FakeFinishedResponse:
    def __init__(
        self,
        body: bytes,
        *,
        content_type: str = "text/event-stream; charset=utf-8",
        status: int = 200,
    ) -> None:
        self.url = "https://chatgpt.com/backend-api/f/conversation"
        self.request = FakeRequest("POST")
        self.ok = 200 <= status < 300
        self.status = status
        self.status_text = "OK" if self.ok else "ERROR"
        self._content_type = content_type
        self._body = body

    async def header_value(self, name: str) -> str | None:
        if name.lower() == "content-type":
            return self._content_type
        return None

    async def finished(self):
        return None

    async def body(self) -> bytes:
        return self._body


@pytest.mark.asyncio
async def test_conversation_stream_wait_reads_body_after_finish() -> None:
    from gpt_trace_runner.stream import ConversationStream

    response = FakeFinishedResponse(
        read_fixture("simple_turn.sse").encode("utf-8")
    )
    result = await ConversationStream(
        response,
        timeout_seconds=1,
    ).wait()

    assert result.conversation_id == "conv-simple"
    assert result.http_status == 200
    assert "text/event-stream" in result.content_type
    assert result.stream_started_at
    assert result.stream_completed_at


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, expected",
    [
        (403, "AccessDenied"),
        (429, "RateLimited"),
    ],
)
async def test_stream_protection_statuses_are_batch_breakers(status, expected) -> None:
    from gpt_trace_runner import exceptions
    from gpt_trace_runner.stream import ConversationStream

    response = FakeFinishedResponse(
        b"blocked",
        content_type="text/html",
        status=status,
    )
    error_type = getattr(exceptions, expected)
    with pytest.raises(error_type):
        await ConversationStream(response, timeout_seconds=1).wait()


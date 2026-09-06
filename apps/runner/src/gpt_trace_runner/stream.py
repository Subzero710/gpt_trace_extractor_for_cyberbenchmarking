from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urlparse

from playwright.async_api import Response

from .exceptions import (
    ConversationStreamAborted,
    ConversationStreamIncomplete,
    ConversationStreamProtocolError,
    ConversationStreamTimeout,
)


@dataclass(frozen=True, slots=True)
class SSEEvent:
    event: str | None
    data: str


@dataclass(frozen=True, slots=True)
class ConversationStreamResult:
    conversation_id: str
    final_end_turn: bool
    message_stream_complete: bool
    done: bool
    last_token: bool
    request_id: str | None
    turn_exchange_id: str | None
    tool_invoked: bool | None
    tool_name: str | None
    event_count: int
    http_status: int
    content_type: str
    stream_started_at: str
    stream_completed_at: str

    def runtime_metadata(self) -> dict[str, Any]:
        return {
            "stream_protocol": "sse",
            "conversation_id": self.conversation_id,
            "final_end_turn": self.final_end_turn,
            "message_stream_complete": self.message_stream_complete,
            "done": self.done,
            "last_token": self.last_token,
            "request_id": self.request_id,
            "turn_exchange_id": self.turn_exchange_id,
            "tool_invoked": self.tool_invoked,
            "tool_name": self.tool_name,
            "event_count": self.event_count,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "stream_started_at": self.stream_started_at,
            "stream_completed_at": self.stream_completed_at,
        }


def is_conversation_stream_response(response: Response) -> bool:
    path = urlparse(response.url).path.rstrip("/")
    return (
        response.request.method.upper() == "POST"
        and path == "/backend-api/f/conversation"
    )


def parse_sse(text: str) -> Iterator[SSEEvent]:
    event_name: str | None = None
    data_lines: list[str] = []

    def flush() -> SSEEvent | None:
        nonlocal event_name, data_lines
        if event_name is None and not data_lines:
            return None
        item = SSEEvent(event=event_name, data="\n".join(data_lines))
        event_name = None
        data_lines = []
        return item

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for line in normalized.split("\n"):
        if line == "":
            item = flush()
            if item is not None:
                yield item
            continue
        if line.startswith(":"):
            continue

        field, separator, value = line.partition(":")
        if not separator:
            value = ""
        elif value.startswith(" "):
            value = value[1:]

        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)

    item = flush()
    if item is not None:
        yield item


def _message_from_delta(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    message = value.get("message")
    if isinstance(message, dict):
        return message

    nested = value.get("v")
    if isinstance(nested, dict):
        message = nested.get("message")
        if isinstance(message, dict):
            return message

    return None


def inspect_conversation_stream(text: str) -> ConversationStreamResult:
    conversation_ids: set[str] = set()
    final_end_turn = False
    stream_complete = False
    done = False
    last_token = False
    request_id: str | None = None
    turn_exchange_id: str | None = None
    tool_invoked: bool | None = None
    tool_name: str | None = None
    active_final_assistant = False
    event_count = 0

    for event in parse_sse(text):
        event_count += 1

        if event.data == "[DONE]":
            done = True
            continue

        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError as exc:
            raise ConversationStreamProtocolError(
                f"invalid JSON in SSE event #{event_count}: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            continue

        cid = payload.get("conversation_id")
        if isinstance(cid, str) and cid:
            conversation_ids.add(cid)

        event_type = payload.get("type")
        if event_type == "resume_conversation_token":
            cid = payload.get("conversation_id")
            if isinstance(cid, str) and cid:
                conversation_ids.add(cid)

        if event_type == "message_marker":
            if (
                payload.get("marker") == "last_token"
                and payload.get("event") == "last"
            ):
                last_token = True

        if event_type == "message_stream_complete":
            stream_complete = True

        if event_type == "server_ste_metadata":
            metadata = payload.get("metadata")
            if isinstance(metadata, dict):
                value = metadata.get("request_id")
                if isinstance(value, str) and value:
                    request_id = value
                value = metadata.get("turn_exchange_id")
                if isinstance(value, str) and value:
                    turn_exchange_id = value
                value = metadata.get("tool_invoked")
                if isinstance(value, bool):
                    tool_invoked = value
                value = metadata.get("tool_name")
                if isinstance(value, str) and value:
                    tool_name = value

        message = _message_from_delta(payload)
        if message is not None:
            author = message.get("author")
            role = author.get("role") if isinstance(author, dict) else None
            active_final_assistant = (
                role == "assistant" and message.get("channel") == "final"
            )
            if active_final_assistant and message.get("end_turn") is True:
                final_end_turn = True

        if payload.get("o") == "patch" and active_final_assistant:
            operations = payload.get("v")
            if isinstance(operations, list):
                for operation in operations:
                    if not isinstance(operation, dict):
                        continue
                    if (
                        operation.get("p") == "/message/end_turn"
                        and operation.get("v") is True
                    ):
                        final_end_turn = True

    if len(conversation_ids) != 1:
        raise ConversationStreamProtocolError(
            "expected exactly one conversation_id in the stream, got "
            f"{sorted(conversation_ids)!r}"
        )

    conversation_id = next(iter(conversation_ids))

    if not final_end_turn:
        raise ConversationStreamIncomplete(
            "SSE ended without a final assistant end_turn=true"
        )
    if not stream_complete:
        raise ConversationStreamIncomplete(
            "SSE ended without message_stream_complete"
        )
    if not done:
        raise ConversationStreamIncomplete("SSE ended without [DONE]")

    return ConversationStreamResult(
        conversation_id=conversation_id,
        final_end_turn=final_end_turn,
        message_stream_complete=stream_complete,
        done=done,
        last_token=last_token,
        request_id=request_id,
        turn_exchange_id=turn_exchange_id,
        tool_invoked=tool_invoked,
        tool_name=tool_name,
        event_count=event_count,
        http_status=0,
        content_type="",
        stream_started_at="",
        stream_completed_at="",
    )


class ConversationStream:
    def __init__(
        self,
        response: Response,
        *,
        timeout_seconds: float,
    ) -> None:
        self._response = response
        self._timeout_seconds = timeout_seconds
        self._started_at = datetime.now(timezone.utc)

    async def wait(self) -> ConversationStreamResult:
        content_type = (
            await self._response.header_value("content-type") or ""
        )
        if "text/event-stream" not in content_type.lower():
            raise ConversationStreamProtocolError(
                "conversation response is not text/event-stream: "
                f"{content_type!r}"
            )
        if not self._response.ok:
            raise ConversationStreamProtocolError(
                "conversation stream returned HTTP "
                f"{self._response.status} {self._response.status_text}"
            )

        try:
            finished_error = await asyncio.wait_for(
                self._response.finished(),
                timeout=self._timeout_seconds,
            )
        except TimeoutError as exc:
            raise ConversationStreamTimeout(
                "conversation SSE did not finish within "
                f"{self._timeout_seconds:.0f}s"
            ) from exc

        if finished_error:
            raise ConversationStreamAborted(
                f"conversation SSE failed: {finished_error}"
            )

        try:
            body = await self._response.body()
        except Exception as exc:
            raise ConversationStreamAborted(
                f"could not read completed SSE body: {exc}"
            ) from exc

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConversationStreamProtocolError(
                "conversation SSE body was not valid UTF-8"
            ) from exc

        completed_at = datetime.now(timezone.utc)
        result = inspect_conversation_stream(text)
        return replace(
            result,
            http_status=self._response.status,
            content_type=content_type,
            stream_started_at=self._started_at.isoformat(),
            stream_completed_at=completed_at.isoformat(),
        )

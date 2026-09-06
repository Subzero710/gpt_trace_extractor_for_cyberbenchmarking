from __future__ import annotations

import json
from typing import Any

from playwright.async_api import Page

from .exceptions import AccessDenied, ConversationError, RateLimited


def conversation_id_from_url(url: str) -> str | None:
    if "/c/" not in url:
        return None
    value = url.split("/c/", 1)[1].split("?", 1)[0].split("/", 1)[0].strip()
    return value or None


def _hidden_raw_cot(message: dict[str, Any]) -> bool:
    metadata = message.get("metadata")
    return isinstance(metadata, dict) and metadata.get("summary_type") == "raw_cot"


def extract_dataset_messages(conversation: dict[str, Any]) -> list[dict[str, Any]]:
    messages = conversation.get("messages")
    if not isinstance(messages, list):
        raise ConversationError("conversation JSON has no messages[]")
    return [m for m in messages if isinstance(m, dict) and not _hidden_raw_cot(m)]


def is_complete(messages: list[dict[str, Any]]) -> bool:
    for message in reversed(messages):
        author = message.get("author")
        if isinstance(author, dict) and author.get("role") == "assistant":
            return message.get("end_turn") is True
    return False


def _part_text(part: Any) -> str:
    if isinstance(part, str):
        return part
    if not isinstance(part, dict):
        return ""
    kind = str(part.get("type", ""))
    if kind in {"ecosystemMention", "ecosystem_mention", "app_mention"}:
        return ""
    text = part.get("text")
    if isinstance(text, str):
        return text
    content = part.get("content")
    if isinstance(content, str):
        return content
    return ""


def message_plain_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if isinstance(parts, list):
        return "".join(_part_text(part) for part in parts)
    text = content.get("text")
    return text if isinstance(text, str) else ""


def _mention_stripped_text(message: dict[str, Any]) -> tuple[str, set[int]]:
    """Remove frontend-owned ecosystemMention spans and mark separator positions.

    Returns the remaining text plus indexes of ASCII spaces that sit exactly at
    a removed mention boundary.  Only those spaces may be ignored when matching
    the original benchmark prompt.
    """
    text = message_plain_text(message)
    metadata = message.get("metadata")
    if not isinstance(metadata, dict):
        return text, set()
    serialization = metadata.get("serialization_metadata")
    if not isinstance(serialization, dict):
        return text, set()
    offsets = serialization.get("custom_symbol_offsets")
    if not isinstance(offsets, list):
        return text, set()

    spans: list[tuple[int, int]] = []
    for item in offsets:
        if not isinstance(item, dict) or item.get("symbol") != "ecosystemMention":
            continue
        start = item.get("startIndex")
        end = item.get("endIndex")
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and 0 <= start < end <= len(text)
        ):
            spans.append((start, end))
    if not spans:
        return text, set()

    spans.sort()
    for (_, previous_end), (next_start, _) in zip(spans, spans[1:]):
        if next_start < previous_end:
            raise ConversationError("overlapping ecosystemMention offsets")

    pieces: list[str] = []
    boundaries: list[int] = []
    cursor = 0
    output_len = 0
    for start, end in spans:
        piece = text[cursor:start]
        pieces.append(piece)
        output_len += len(piece)
        boundaries.append(output_len)
        cursor = end
    pieces.append(text[cursor:])
    candidate = "".join(pieces)

    deletable: set[int] = set()
    for boundary in boundaries:
        if boundary < len(candidate) and candidate[boundary] == " ":
            deletable.add(boundary)
        if boundary > 0 and candidate[boundary - 1] == " ":
            deletable.add(boundary - 1)
    return candidate, deletable


def message_benchmark_text(message: dict[str, Any]) -> str:
    return _mention_stripped_text(message)[0]


def benchmark_text_matches(message: dict[str, Any], prompt: str) -> bool:
    candidate, deletable = _mention_stripped_text(message)
    i = 0
    j = 0
    while i < len(candidate):
        if j < len(prompt) and candidate[i] == prompt[j]:
            i += 1
            j += 1
            continue
        if i in deletable and candidate[i] == " ":
            i += 1
            continue
        return False
    return j == len(prompt)


def conversation_matches_task(messages: list[dict[str, Any]], prompt: str) -> bool:
    for message in messages:
        author = message.get("author")
        if isinstance(author, dict) and author.get("role") == "user":
            return benchmark_text_matches(message, prompt)
    return False


def validate_task_conversation(messages: list[dict[str, Any]], prompt: str) -> None:
    if not conversation_matches_task(messages, prompt):
        raise ConversationError("conversation does not contain the exact benchmark prompt")
    if not is_complete(messages):
        raise ConversationError("conversation has no assistant end_turn=true")


def assistant_model_slugs(messages: list[dict[str, Any]]) -> set[str]:
    slugs: set[str] = set()
    for message in messages:
        author = message.get("author")
        if not isinstance(author, dict) or author.get("role") != "assistant":
            continue
        metadata = message.get("metadata")
        if not isinstance(metadata, dict):
            continue
        slug = metadata.get("model_slug")
        if isinstance(slug, str) and slug.strip():
            slugs.add(slug.strip())
    return slugs


def invoked_app_names(messages: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for message in messages:
        metadata = message.get("metadata")
        if not isinstance(metadata, dict):
            continue
        resource = metadata.get("invoked_resource")
        if isinstance(resource, dict):
            app_name = resource.get("app_name")
            if isinstance(app_name, str) and app_name.strip():
                names.add(app_name.strip())
    return names


class ConversationClient:
    def __init__(self, page: Page, turns: int = 100) -> None:
        self._page = page
        self._turns = turns

    async def fetch(self, conversation_id: str) -> dict[str, Any]:
        endpoint = (
            f"/backend-api/conversations/{conversation_id}"
            f"?include_has_versions=true&num_turns={self._turns}"
        )
        try:
            result = await self._page.evaluate(
                """async (endpoint) => {
                    const r = await fetch(endpoint, {credentials:'include', cache:'no-store'});
                    return {status:r.status, ok:r.ok, statusText:r.statusText, text:await r.text()};
                }""",
                endpoint,
            )
        except Exception as exc:
            raise ConversationError(f"fetch {conversation_id} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ConversationError("conversation fetch returned invalid result")
        status = int(result.get("status", 0))
        if status == 429:
            raise RateLimited("conversation snapshot returned HTTP 429")
        if status == 403:
            raise AccessDenied("conversation snapshot returned HTTP 403")
        if not result.get("ok"):
            raise ConversationError(
                f"conversation snapshot HTTP {status} {result.get('statusText', '')}"
            )
        try:
            payload = json.loads(str(result.get("text", "")))
        except json.JSONDecodeError as exc:
            raise ConversationError("conversation endpoint returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ConversationError("conversation endpoint returned non-object JSON")
        return payload

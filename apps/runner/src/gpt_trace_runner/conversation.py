from __future__ import annotations
from typing import Any
from playwright.async_api import Page
from .exceptions import ConversationError

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

class ConversationClient:
    def __init__(self, page: Page, turns: int = 100) -> None:
        self._page = page
        self._turns = turns

    async def fetch(self, conversation_id: str) -> dict[str, Any]:
        endpoint = f"/backend-api/conversations/{conversation_id}?include_has_versions=true&num_turns={self._turns}"
        try:
            result = await self._page.evaluate(
                """async (endpoint) => {
                    const r = await fetch(endpoint, {credentials: 'include', cache: 'no-store'});
                    const text = await r.text();
                    if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${text.slice(0,500)}`);
                    return JSON.parse(text);
                }""",
                endpoint,
            )
        except Exception as exc:
            raise ConversationError(f"fetch {conversation_id} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ConversationError("conversation endpoint returned non-object JSON")
        return result

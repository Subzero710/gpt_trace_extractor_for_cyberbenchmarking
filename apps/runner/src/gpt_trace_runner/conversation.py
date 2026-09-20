from __future__ import annotations

import json
from typing import Any

from playwright.async_api import Page

from .exceptions import (
    AccessDenied,
    AuthenticationRequired,
    ConversationError,
    ConversationNotFound,
    RateLimited,
)


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


def validate_conversation_identity(
    messages: list[dict[str, Any]],
    user_message_id: str,
) -> None:
    if not isinstance(user_message_id, str) or not user_message_id.strip():
        raise ConversationError("expected user_message_id is missing")

    user_messages = []
    for message in messages:
        author = message.get("author")
        if isinstance(author, dict) and author.get("role") == "user":
            user_messages.append(message)

    if len(user_messages) != 1:
        raise ConversationError(
            "conversation must contain exactly one user message for a benchmark task"
        )

    observed_id = user_messages[0].get("id")
    if observed_id != user_message_id:
        raise ConversationError(
            "conversation user message ID does not match the submitted message ID"
        )
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
                    // Current ChatGPT backend conversation reads use a short-lived
                    // bearer token in addition to the browser session cookie.
                    // Keep that token entirely in page JavaScript: never return it
                    // to Python, logs, storage, or artifacts.
                    const session = await fetch(
                        '/api/auth/session',
                        {credentials:'include', cache:'no-store'}
                    );

                    let accessToken = null;
                    if (session.ok) {
                        try {
                            const payload = await session.json();
                            if (
                                payload &&
                                typeof payload.accessToken === 'string' &&
                                payload.accessToken.trim()
                            ) {
                                accessToken = payload.accessToken;
                            }
                        } catch (_) {
                        }
                    }

                    if (!accessToken) {
                        return {
                            sessionStatus: session.status,
                            tokenPresent: false,
                            status: 0,
                            ok: false,
                            statusText: '',
                            text: ''
                        };
                    }

                    const r = await fetch(endpoint, {
                        credentials: 'include',
                        cache: 'no-store',
                        headers: {
                            authorization: `Bearer ${accessToken}`
                        }
                    });
                    return {
                        sessionStatus: session.status,
                        tokenPresent: true,
                        status: r.status,
                        ok: r.ok,
                        statusText: r.statusText,
                        text: await r.text()
                    };
                }""",
                endpoint,
            )
        except Exception as exc:
            raise ConversationError(f"fetch {conversation_id} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ConversationError("conversation fetch returned invalid result")

        session_status = int(result.get("sessionStatus", 0))
        token_present = result.get("tokenPresent") is True
        if not token_present:
            raise AuthenticationRequired(
                "ChatGPT browser session did not yield a backend access token "
                f"(session HTTP {session_status})"
            )

        status = int(result.get("status", 0))
        if status == 401:
            raise AuthenticationRequired(
                "conversation snapshot rejected the authenticated backend token "
                "(HTTP 401)"
            )
        if status == 403:
            raise AccessDenied("conversation snapshot returned HTTP 403")
        if status == 404:
            raise ConversationNotFound(
                f"conversation {conversation_id!r} was not found (HTTP 404)"
            )
        if status == 429:
            raise RateLimited("conversation snapshot returned HTTP 429")
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

    async def delete(self, conversation_id: str) -> None:
        endpoint = f"/backend-api/conversation/id/{conversation_id}"
        try:
            result = await self._page.evaluate(
                """async (endpoint) => {
                    const session = await fetch(
                        '/api/auth/session',
                        {credentials:'include', cache:'no-store'}
                    );

                    let accessToken = null;
                    if (session.ok) {
                        try {
                            const payload = await session.json();
                            if (
                                payload &&
                                typeof payload.accessToken === 'string' &&
                                payload.accessToken.trim()
                            ) {
                                accessToken = payload.accessToken;
                            }
                        } catch (_) {
                        }
                    }

                    if (!accessToken) {
                        return {
                            sessionStatus: session.status,
                            tokenPresent: false,
                            status: 0,
                            ok: false,
                            statusText: ''
                        };
                    }

                    const r = await fetch(endpoint, {
                        method: 'DELETE',
                        credentials: 'include',
                        cache: 'no-store',
                        headers: {
                            authorization: `Bearer ${accessToken}`
                        }
                    });
                    return {
                        sessionStatus: session.status,
                        tokenPresent: true,
                        status: r.status,
                        ok: r.ok,
                        statusText: r.statusText
                    };
                }""",
                endpoint,
            )
        except Exception as exc:
            raise ConversationError(
                f"delete conversation {conversation_id} failed: {exc}"
            ) from exc

        if not isinstance(result, dict):
            raise ConversationError("conversation delete returned invalid result")

        session_status = int(result.get("sessionStatus", 0))
        token_present = result.get("tokenPresent") is True
        if not token_present:
            raise AuthenticationRequired(
                "ChatGPT browser session did not yield a backend access token "
                f"(session HTTP {session_status})"
            )

        status = int(result.get("status", 0))
        # DELETE is intentionally idempotent for crash cleanup: a prior cleanup
        # may already have removed the conversation before the process stopped.
        if status in {200, 204, 404}:
            return
        if status == 401:
            raise AuthenticationRequired(
                "conversation delete rejected the authenticated backend token "
                "(HTTP 401)"
            )
        if status == 403:
            raise AccessDenied("conversation delete returned HTTP 403")
        if status == 429:
            raise RateLimited("conversation delete returned HTTP 429")
        raise ConversationError(
            f"conversation delete HTTP {status} {result.get('statusText', '')}"
        )


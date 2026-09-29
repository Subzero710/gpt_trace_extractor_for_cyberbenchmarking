from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import unquote

from playwright.async_api import Page

from .exceptions import (
    AccessDenied,
    AuthenticationRequired,
    ConversationError,
    ConversationNotFound,
    RateLimited,
)


def _parse_retry_after(value: object) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _rate_limited(
    message: str,
    *,
    result: dict[str, Any],
    endpoint: str,
    method: str,
    retry_key: str = "retryAfter",
    request_id_key: str = "requestId",
) -> RateLimited:
    retry_after = _parse_retry_after(result.get(retry_key))
    request_id_raw = result.get(request_id_key)
    request_id = (
        request_id_raw.strip()
        if isinstance(request_id_raw, str) and request_id_raw.strip()
        else None
    )
    details = message
    if retry_after is not None:
        details += f"; retry_after={retry_after:.3f}s"
    if request_id is not None:
        details += f"; request_id={request_id}"
    return RateLimited(
        details,
        retry_after_seconds=retry_after,
        endpoint=endpoint,
        method=method,
        request_id=request_id,
    )


def _check_session_rate_limit(result: dict[str, Any]) -> None:
    session_status = int(result.get("sessionStatus", 0))
    if session_status == 429:
        raise _rate_limited(
            "ChatGPT auth session returned HTTP 429",
            result=result,
            endpoint="/api/auth/session",
            method="GET",
            retry_key="sessionRetryAfter",
            request_id_key="sessionRequestId",
        )


def conversation_id_from_url(url: str) -> str | None:
    if "/c/" not in url:
        return None
    value = url.split("/c/", 1)[1].split("?", 1)[0].split("/", 1)[0].strip()
    value = unquote(value).strip()
    return value or None


def is_transient_conversation_id(value: str | None) -> bool:
    if not isinstance(value, str) or not value.strip():
        return True
    normalized = unquote(value).strip().casefold()
    return normalized.startswith("web:") or normalized.startswith("local-chatgpt:")

def extract_dataset_messages(conversation: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep the complete durable message trajectory, including exposed reasoning summaries.

    ChatGPT currently marks user-visible reasoning progress messages with
    metadata.summary_type == "raw_cot". They are not treated as hidden/internal
    chain-of-thought here: the backend explicitly returned them in messages[], and
    the ML normalizer decides which useful fields to retain.
    """
    messages = conversation.get("messages")
    if not isinstance(messages, list):
        raise ConversationError("conversation JSON has no messages[]")
    return [m for m in messages if isinstance(m, dict)]


def is_complete(messages: list[dict[str, Any]]) -> bool:
    # Reasoning/tool messages may occur around the final answer and have
    # end_turn=false/null. Completion therefore means that *some* assistant
    # message in the durable trajectory is the terminal end_turn=true message.
    for message in reversed(messages):
        author = message.get("author")
        if (
            isinstance(author, dict)
            and author.get("role") == "assistant"
            and message.get("end_turn") is True
        ):
            return True
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


    async def recent_conversation_ids(self, *, limit: int = 5) -> tuple[str, ...]:
        """Return only recent durable backend IDs; never expose the bearer token."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        endpoint = f"/backend-api/conversations?offset=0&limit={limit}&order=updated"
        try:
            result = await self._page.evaluate(
                """async (endpoint) => {
                    const session = await fetch(
                        '/api/auth/session',
                        {credentials:'include', cache:'no-store'}
                    );
                    const sessionRetryAfter = session.headers.get('retry-after');
                    const sessionRequestId =
                        session.headers.get('x-request-id') ||
                        session.headers.get('openai-request-id') || null;
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
                            sessionRetryAfter,
                            sessionRequestId,
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
                        headers: {authorization: `Bearer ${accessToken}`}
                    });
                    return {
                        sessionStatus: session.status,
                        tokenPresent: true,
                        status: r.status,
                        ok: r.ok,
                        statusText: r.statusText,
                        retryAfter: r.headers.get('retry-after'),
                        requestId:
                            r.headers.get('x-request-id') ||
                            r.headers.get('openai-request-id') || null,
                        text: await r.text()
                    };
                }""",
                endpoint,
            )
        except Exception as exc:
            raise ConversationError(f"conversation list fetch failed: {exc}") from exc
        if not isinstance(result, dict):
            raise ConversationError("conversation list fetch returned invalid result")

        session_status = int(result.get("sessionStatus", 0))
        _check_session_rate_limit(result)
        if result.get("tokenPresent") is not True:
            raise AuthenticationRequired(
                "ChatGPT browser session did not yield a backend access token "
                f"(session HTTP {session_status})"
            )
        status = int(result.get("status", 0))
        if status == 401:
            raise AuthenticationRequired("conversation list rejected the backend token (HTTP 401)")
        if status == 403:
            raise AccessDenied("conversation list returned HTTP 403")
        if status == 429:
            raise _rate_limited(
                "conversation list returned HTTP 429",
                result=result,
                endpoint=endpoint,
                method="GET",
            )
        if not result.get("ok"):
            raise ConversationError(
                f"conversation list HTTP {status} {result.get('statusText', '')}"
            )
        try:
            payload = json.loads(str(result.get("text", "")))
        except json.JSONDecodeError as exc:
            raise ConversationError("conversation list returned invalid JSON") from exc
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise ConversationError("conversation list JSON has no items[]")
        ids: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            value = item.get("id")
            if isinstance(value, str) and value.strip() and not is_transient_conversation_id(value):
                ids.append(value.strip())
        return tuple(ids)

    async def find_recent_conversation_id_by_user_message_id(
        self,
        user_message_id: str,
        *,
        limit: int = 5,
        exclude_ids: set[str] | None = None,
        max_candidate_fetches: int | None = None,
    ) -> str | None:
        """Resolve a submitted message while avoiding repeated candidate snapshots."""
        if not isinstance(user_message_id, str) or not user_message_id.strip():
            raise ConversationError("expected user_message_id is missing")
        if max_candidate_fetches is not None and max_candidate_fetches < 1:
            raise ValueError("max_candidate_fetches must be >= 1")

        rejected = exclude_ids if exclude_ids is not None else set()
        fetched = 0
        for conversation_id in await self.recent_conversation_ids(limit=limit):
            if conversation_id in rejected:
                continue
            if max_candidate_fetches is not None and fetched >= max_candidate_fetches:
                break
            fetched += 1
            try:
                payload = await self.fetch(conversation_id)
                messages = extract_dataset_messages(payload)
            except ConversationNotFound:
                # A 404 is a stable negative for this list entry. Mark it rejected
                # so the next bounded poll advances to later candidates instead
                # of spending its whole budget on the same missing IDs forever.
                rejected.add(conversation_id)
                continue
            except ConversationError:
                # Other read errors may be transient; do not permanently exclude
                # the candidate from a later poll.
                continue
            user_ids = [
                message.get("id")
                for message in messages
                if isinstance(message.get("author"), dict)
                and message["author"].get("role") == "user"
            ]
            if len(user_ids) == 1 and user_ids[0] == user_message_id:
                return conversation_id
            # Existing conversations with user messages are stable negatives for
            # this fresh benchmark submit. Do not refetch them on every poll.
            if user_ids:
                rejected.add(conversation_id)
        return None


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
                    const sessionRetryAfter = session.headers.get('retry-after');
                    const sessionRequestId =
                        session.headers.get('x-request-id') ||
                        session.headers.get('openai-request-id') || null;

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
                            sessionRetryAfter,
                            sessionRequestId,
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
                        retryAfter: r.headers.get('retry-after'),
                        requestId:
                            r.headers.get('x-request-id') ||
                            r.headers.get('openai-request-id') || null,
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
        _check_session_rate_limit(result)
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
            raise _rate_limited(
                "conversation snapshot returned HTTP 429",
                result=result,
                endpoint=endpoint,
                method="GET",
            )
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
        max_attempts = max(1, int(getattr(self, "_delete_rate_limit_max_attempts", 3)))
        base_delay = max(0.0, float(getattr(self, "_delete_rate_limit_backoff_seconds", 1.0)))
        max_delay = max(base_delay, float(getattr(self, "_delete_rate_limit_backoff_max_seconds", 8.0)))
        recovery_window = max(
            0.0,
            float(getattr(self, "_delete_rate_limit_recovery_seconds", max_delay)),
        )
        retry_deadline = asyncio.get_running_loop().time() + recovery_window

        async def wait_before_retry(exc: RateLimited, fallback: float) -> None:
            delay = exc.retry_delay(fallback, maximum_seconds=max_delay)
            remaining = retry_deadline - asyncio.get_running_loop().time()
            # Never truncate Retry-After merely to fit our local recovery window.
            # Bubble the rate limit so the durable recovery journal can preserve
            # the attempt instead of calling the server before its requested time.
            if delay > 0 and delay > remaining:
                raise exc
            if delay > 0:
                await asyncio.sleep(delay)

        for attempt in range(max_attempts):
            try:
                result = await self._page.evaluate(
                    """async (endpoint) => {
                        const session = await fetch(
                            '/api/auth/session',
                            {credentials:'include', cache:'no-store'}
                        );
                        const sessionRetryAfter = session.headers.get('retry-after');
                        const sessionRequestId =
                            session.headers.get('x-request-id') ||
                            session.headers.get('openai-request-id') || null;

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
                                sessionRetryAfter,
                                sessionRequestId,
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
                            statusText: r.statusText,
                            retryAfter: r.headers.get('retry-after'),
                            requestId:
                                r.headers.get('x-request-id') ||
                                r.headers.get('openai-request-id') || null
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
            try:
                _check_session_rate_limit(result)
            except RateLimited as exc:
                if attempt + 1 >= max_attempts:
                    raise
                await wait_before_retry(exc, base_delay * (2 ** attempt))
                continue

            token_present = result.get("tokenPresent") is True
            if not token_present:
                raise AuthenticationRequired(
                    "ChatGPT browser session did not yield a backend access token "
                    f"(session HTTP {session_status})"
                )

            status = int(result.get("status", 0))
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
                exc = _rate_limited(
                    "conversation delete returned HTTP 429",
                    result=result,
                    endpoint=endpoint,
                    method="DELETE",
                )
                if attempt + 1 >= max_attempts:
                    raise exc
                await wait_before_retry(exc, base_delay * (2 ** attempt))
                continue
            raise ConversationError(
                f"conversation delete HTTP {status} {result.get('statusText', '')}"
            )

        raise AssertionError("unreachable conversation delete retry state")

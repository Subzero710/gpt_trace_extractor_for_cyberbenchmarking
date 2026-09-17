from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Page, Response

from .conversation import benchmark_text_matches


_CONVERSATION_SNAPSHOT = re.compile(r"^/backend-api/conversations/([^/]+)$")


@dataclass(slots=True)
class TrafficStats:
    chatgpt_requests: int = 0
    backend_requests: int = 0
    sentinel_requests: int = 0
    conversation_requests: int = 0
    conversation_prepare_requests: int = 0
    conversation_stream_requests: int = 0
    requests_failed: int = 0
    responses_403: int = 0
    responses_429: int = 0
    responses_5xx: int = 0
    challenge_seen: bool = False
    challenge_resolved: bool = False
    natural_snapshot_used: bool = False
    fallback_snapshot_used: bool = False
    submitted_model: str | None = None
    submitted_timezone: str | None = None
    submitted_timezone_offset_min: int | None = None


class TrafficMonitor:
    """Count browser traffic without retaining security headers, cookies, or bodies."""

    def __init__(self, page: Page, *, base_url: str) -> None:
        self._base_host = urlparse(base_url).hostname or "chatgpt.com"
        self._generation = 0
        self._stats = TrafficStats()
        self._snapshots: dict[str, Response] = {}
        self._snapshot_events: dict[str, asyncio.Event] = {}
        self._request_generation: dict[int, int] = {}
        self._task_403 = False
        self._sticky_429 = False
        self._submitted_user_message: dict[str, Any] | None = None
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfailed", self._on_request_failed)

    def begin_task(self) -> None:
        self._generation += 1
        self._stats = TrafficStats()
        self._snapshots = {}
        self._snapshot_events = {}
        self._task_403 = False
        self._submitted_user_message = None
        # sticky 429 intentionally survives task boundaries.

    def _is_chatgpt_host(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return (
            host == self._base_host
            or host.endswith("." + self._base_host)
            or host == "openai.com"
            or host.endswith(".openai.com")
        )

    @staticmethod
    def _is_backend_path(path: str) -> bool:
        return path.startswith("/backend-api/") or path.startswith("/backend-anon/")

    def _on_request(self, request) -> None:
        if not self._is_chatgpt_host(request.url):
            return
        self._request_generation[id(request)] = self._generation
        path = urlparse(request.url).path.rstrip("/")
        self._stats.chatgpt_requests += 1
        if self._is_backend_path(path):
            self._stats.backend_requests += 1
        if "/sentinel/" in path:
            self._stats.sentinel_requests += 1
        if "/conversation" in path:
            self._stats.conversation_requests += 1
        if path == "/backend-api/f/conversation/prepare":
            self._stats.conversation_prepare_requests += 1
        if path == "/backend-api/f/conversation" and request.method.upper() == "POST":
            self._stats.conversation_stream_requests += 1
            try:
                payload = request.post_data_json
                if isinstance(payload, dict):
                    model = payload.get("model")
                    if isinstance(model, str):
                        self._stats.submitted_model = model
                    timezone = payload.get("timezone")
                    if isinstance(timezone, str):
                        self._stats.submitted_timezone = timezone
                    offset = payload.get("timezone_offset_min")
                    if isinstance(offset, int):
                        self._stats.submitted_timezone_offset_min = offset
                    messages = payload.get("messages")
                    if isinstance(messages, list):
                        for message in messages:
                            if not isinstance(message, dict):
                                continue
                            author = message.get("author")
                            if isinstance(author, dict) and author.get("role") == "user":
                                self._submitted_user_message = message
                                break
            except Exception:
                pass

    def _belongs_to_current(self, request) -> bool:
        return self._request_generation.get(id(request), self._generation) == self._generation

    def _on_response(self, response: Response) -> None:
        if not self._is_chatgpt_host(response.url):
            return
        current = self._belongs_to_current(response.request)
        path = urlparse(response.url).path.rstrip("/")
        if self._is_backend_path(path):
            if response.status == 429:
                self._sticky_429 = True
                if current:
                    self._stats.responses_429 += 1
            elif response.status == 403 and current:
                self._task_403 = True
                self._stats.responses_403 += 1
            elif response.status >= 500 and current:
                self._stats.responses_5xx += 1

        if current:
            match = _CONVERSATION_SNAPSHOT.match(path)
            if match and response.request.method.upper() == "GET" and 200 <= response.status < 300:
                conversation_id = match.group(1)
                self._snapshots[conversation_id] = response
                event = self._snapshot_events.get(conversation_id)
                if event is not None:
                    event.set()
        self._request_generation.pop(id(response.request), None)

    def _on_request_failed(self, request) -> None:
        if self._is_chatgpt_host(request.url) and self._belongs_to_current(request):
            self._stats.requests_failed += 1
        self._request_generation.pop(id(request), None)

    @property
    def saw_backend_403(self) -> bool:
        return self._task_403

    @property
    def saw_backend_429(self) -> bool:
        return self._sticky_429

    @property
    def submitted_model(self) -> str | None:
        return self._stats.submitted_model

    @property
    def submitted_timezone(self) -> str | None:
        return self._stats.submitted_timezone

    @property
    def submitted_timezone_offset_min(self) -> int | None:
        return self._stats.submitted_timezone_offset_min

    def submitted_prompt_matches(self, prompt: str) -> bool:
        message = self._submitted_user_message
        return isinstance(message, dict) and benchmark_text_matches(message, prompt)

    @property
    def conversation_stream_requests(self) -> int:
        return self._stats.conversation_stream_requests

    def mark_challenge_seen(self) -> None:
        self._stats.challenge_seen = True

    def mark_challenge_resolved(self) -> None:
        self._stats.challenge_seen = True
        self._stats.challenge_resolved = True

    def mark_natural_snapshot_used(self) -> None:
        self._stats.natural_snapshot_used = True

    def mark_fallback_snapshot(self) -> None:
        self._stats.fallback_snapshot_used = True

    def validate_single_stream_request(self) -> None:
        if self._stats.conversation_stream_requests != 1:
            from .exceptions import AmbiguousSubmission
            raise AmbiguousSubmission(
                "expected exactly one frontend POST /backend-api/f/conversation; "
                f"observed {self._stats.conversation_stream_requests}"
            )

    async def natural_snapshot(self, conversation_id: str, *, wait_seconds: float) -> dict[str, Any] | None:
        response = self._snapshots.get(conversation_id)
        if response is None and wait_seconds > 0:
            event = self._snapshot_events.setdefault(conversation_id, asyncio.Event())
            try:
                await asyncio.wait_for(event.wait(), timeout=wait_seconds)
            except TimeoutError:
                return None
            response = self._snapshots.get(conversation_id)
        if response is None:
            return None
        try:
            payload = json.loads((await response.body()).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            return None
        return payload

    def runtime_metadata(self) -> dict[str, Any]:
        return asdict(self._stats)

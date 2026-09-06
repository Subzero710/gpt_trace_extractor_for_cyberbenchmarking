from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Page, Response


_CONVERSATION_SNAPSHOT = re.compile(r"^/backend-api/conversations/([^/]+)$")


@dataclass(slots=True)
class TrafficStats:
    chatgpt_requests: int = 0
    backend_requests: int = 0
    sentinel_requests: int = 0
    conversation_requests: int = 0
    conversation_prepare_requests: int = 0
    conversation_stream_requests: int = 0
    responses_403: int = 0
    responses_429: int = 0
    responses_5xx: int = 0
    challenge_seen: bool = False
    challenge_resolved: bool = False
    natural_snapshot_used: bool = False
    fallback_snapshot_used: bool = False


class TrafficMonitor:
    """Count observable ChatGPT traffic without logging credentials or tokens."""

    def __init__(self, page: Page, *, base_url: str) -> None:
        self._page = page
        self._base_host = urlparse(base_url).hostname or "chatgpt.com"
        self._stats = TrafficStats()
        self._snapshots: dict[str, Response] = {}
        self._snapshot_events: dict[str, asyncio.Event] = {}
        self._saw_backend_403 = False
        self._saw_backend_429 = False
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def begin_task(self) -> None:
        self._stats = TrafficStats()
        self._snapshots = {}
        self._snapshot_events = {}
        self._saw_backend_403 = False
        self._saw_backend_429 = False

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
        self._stats.chatgpt_requests += 1
        path = urlparse(request.url).path.rstrip("/")
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

    def _on_response(self, response: Response) -> None:
        if not self._is_chatgpt_host(response.url):
            return
        path = urlparse(response.url).path.rstrip("/")
        if self._is_backend_path(path):
            if response.status == 403:
                self._stats.responses_403 += 1
                self._saw_backend_403 = True
            elif response.status == 429:
                self._stats.responses_429 += 1
                self._saw_backend_429 = True
            elif response.status >= 500:
                self._stats.responses_5xx += 1

        match = _CONVERSATION_SNAPSHOT.match(path)
        if (
            match
            and response.request.method.upper() == "GET"
            and 200 <= response.status < 300
        ):
            conversation_id = match.group(1)
            self._snapshots[conversation_id] = response
            event = self._snapshot_events.get(conversation_id)
            if event is not None:
                event.set()

    @property
    def saw_backend_403(self) -> bool:
        return self._saw_backend_403

    @property
    def saw_backend_429(self) -> bool:
        return self._saw_backend_429

    def mark_challenge_seen(self) -> None:
        self._stats.challenge_seen = True

    def mark_challenge_resolved(self) -> None:
        self._stats.challenge_seen = True
        self._stats.challenge_resolved = True

    def mark_fallback_snapshot(self) -> None:
        self._stats.fallback_snapshot_used = True

    async def natural_snapshot(
        self,
        conversation_id: str,
        *,
        wait_seconds: float,
    ) -> dict[str, Any] | None:
        response = self._snapshots.get(conversation_id)
        if response is None and wait_seconds > 0:
            event = self._snapshot_events.setdefault(
                conversation_id,
                asyncio.Event(),
            )
            try:
                await asyncio.wait_for(event.wait(), timeout=wait_seconds)
            except TimeoutError:
                return None
            response = self._snapshots.get(conversation_id)

        if response is None:
            return None

        try:
            body = await response.body()
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return None

        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            return None

        self._stats.natural_snapshot_used = True
        return payload

    def runtime_metadata(self) -> dict[str, Any]:
        return asdict(self._stats)

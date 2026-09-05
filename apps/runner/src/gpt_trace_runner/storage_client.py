from __future__ import annotations
from pathlib import Path
from typing import Any
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from .exceptions import StorageError
from .models import CapturedConversation, StoredRun

class StorageClient:
    def __init__(self, base_url: str) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=30.0)

    async def close(self) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=.5, min=.5, max=5), reraise=True)
    async def health(self) -> None:
        r = await self._client.get("/healthz")
        r.raise_for_status()

    async def get(self, task_id: str) -> StoredRun | None:
        r = await self._client.get(f"/v1/runs/{task_id}")
        if r.status_code == 404:
            return None
        if r.is_error:
            raise StorageError(f"GET run failed: {r.status_code} {r.text}")
        p = r.json()
        return StoredRun(p["task_id"], p["status"], p.get("conversation_id"), p.get("attempt", 0), p.get("error_type"), p.get("error_message"))

    async def start(self, task_id: str, runner_id: str) -> StoredRun:
        r = await self._client.post("/v1/runs/start", json={"task_id": task_id, "runner_id": runner_id})
        if r.is_error:
            raise StorageError(f"start failed: {r.status_code} {r.text}")
        p = r.json()
        return StoredRun(p["task_id"], p["status"], p.get("conversation_id"), p.get("attempt", 0))

    async def set_conversation(self, task_id: str, conversation_id: str) -> None:
        r = await self._client.patch(f"/v1/runs/{task_id}/conversation", json={"conversation_id": conversation_id})
        if r.is_error:
            raise StorageError(f"set conversation failed: {r.status_code} {r.text}")

    async def complete(self, task_id: str, captured: CapturedConversation) -> None:
        r = await self._client.post(f"/v1/runs/{task_id}/complete", json={"conversation_id": captured.conversation_id, "messages": captured.messages})
        if r.is_error:
            raise StorageError(f"complete failed: {r.status_code} {r.text}")

    async def fail(self, task_id: str, error: Exception) -> None:
        r = await self._client.post(f"/v1/runs/{task_id}/fail", json={"error_type": type(error).__name__, "error_message": str(error)[:8000]})
        if r.is_error:
            raise StorageError(f"fail update failed: {r.status_code} {r.text}")

    async def stats(self) -> dict[str, Any]:
        r = await self._client.get("/v1/stats")
        if r.is_error:
            raise StorageError(f"stats failed: {r.status_code} {r.text}")
        return r.json()

    async def export(self, output: Path) -> int:
        r = await self._client.get("/v1/export.jsonl")
        if r.is_error:
            raise StorageError(f"export failed: {r.status_code} {r.text}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(r.content)
        return sum(bool(line.strip()) for line in r.text.splitlines())

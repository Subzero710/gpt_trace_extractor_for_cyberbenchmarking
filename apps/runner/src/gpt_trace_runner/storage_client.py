from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .exceptions import StorageError
from .models import CapturedConversation, StoredRun


def _stored_run(payload: dict[str, Any]) -> StoredRun:
    return StoredRun(
        task_id=payload["task_id"],
        status=payload["status"],
        conversation_id=payload.get("conversation_id"),
        attempt=payload.get("attempt", 0),
        error_type=payload.get("error_type"),
        error_message=payload.get("error_message"),
        runtime_metadata=payload.get("runtime_metadata"),
    )


class StorageClient:
    def __init__(self, base_url: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=30.0,
        )

    async def close(self) -> None:
        await self._client.aclose()

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(
            multiplier=0.5,
            min=0.5,
            max=5,
        ),
        reraise=True,
    )
    async def health(self) -> None:
        response = await self._client.get("/healthz")
        response.raise_for_status()

    async def get(self, task_id: str) -> StoredRun | None:
        response = await self._client.get(f"/v1/runs/{task_id}")
        if response.status_code == 404:
            return None
        if response.is_error:
            raise StorageError(
                f"GET run failed: {response.status_code} {response.text}"
            )
        return _stored_run(response.json())

    async def start(self, task_id: str, runner_id: str) -> StoredRun:
        response = await self._client.post(
            "/v1/runs/start",
            json={"task_id": task_id, "runner_id": runner_id},
        )
        if response.is_error:
            raise StorageError(
                f"start failed: {response.status_code} {response.text}"
            )
        return _stored_run(response.json())

    async def set_conversation(
        self,
        task_id: str,
        conversation_id: str,
    ) -> None:
        response = await self._client.patch(
            f"/v1/runs/{task_id}/conversation",
            json={"conversation_id": conversation_id},
        )
        if response.is_error:
            raise StorageError(
                "set conversation failed: "
                f"{response.status_code} {response.text}"
            )

    async def complete(
        self,
        task_id: str,
        captured: CapturedConversation,
    ) -> None:
        response = await self._client.post(
            f"/v1/runs/{task_id}/complete",
            json={
                "conversation_id": captured.conversation_id,
                "messages": captured.messages,
                "runtime_metadata": captured.runtime_metadata,
            },
        )
        if response.is_error:
            raise StorageError(
                f"complete failed: {response.status_code} {response.text}"
            )

    async def fail(self, task_id: str, error: Exception) -> None:
        response = await self._client.post(
            f"/v1/runs/{task_id}/fail",
            json={
                "error_type": type(error).__name__,
                "error_message": str(error)[:8000],
            },
        )
        if response.is_error:
            raise StorageError(
                "fail update failed: "
                f"{response.status_code} {response.text}"
            )

    async def stats(self) -> dict[str, Any]:
        response = await self._client.get("/v1/stats")
        if response.is_error:
            raise StorageError(
                f"stats failed: {response.status_code} {response.text}"
            )
        return response.json()

    async def export(self, output: Path) -> int:
        response = await self._client.get("/v1/export.jsonl")
        if response.is_error:
            raise StorageError(
                f"export failed: {response.status_code} {response.text}"
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(response.content)
        return sum(
            bool(line.strip())
            for line in response.text.splitlines()
        )

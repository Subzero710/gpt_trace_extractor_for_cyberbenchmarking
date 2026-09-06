from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import httpx

from .exceptions import StorageConflict, StorageError
from .models import CapturedConversation, StoredRun


def _stored_run(payload: dict[str, Any]) -> StoredRun:
    return StoredRun(
        task_id=payload["task_id"],
        status=payload["status"],
        conversation_id=payload.get("conversation_id"),
        attempt=payload.get("attempt", 0),
        runner_id=payload.get("runner_id"),
        task_fingerprint=payload.get("task_fingerprint"),
        error_type=payload.get("error_type"),
        error_message=payload.get("error_message"),
        runtime_metadata=payload.get("runtime_metadata"),
    )


class StorageClient:
    def __init__(self, base_url: str) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=30.0)

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, url: str, *, json: dict | None = None,
                       safe_retry: bool = False) -> httpx.Response:
        attempts = 2 if safe_retry else 1
        last: Exception | None = None
        for index in range(attempts):
            try:
                response = await self._client.request(method, url, json=json)
            except httpx.HTTPError as exc:
                last = exc
                if index + 1 < attempts:
                    await asyncio.sleep(0.2)
                    continue
                raise StorageError(f"storage transport failed for {method} {url}: {exc}") from exc
            if response.status_code == 409:
                raise StorageConflict(f"storage conflict: {response.text}")
            if response.is_error:
                raise StorageError(
                    f"storage {method} {url} failed: {response.status_code} {response.text}"
                )
            return response
        raise StorageError(f"storage request failed: {last}")

    async def health(self) -> None:
        last: Exception | None = None
        for attempt in range(5):
            try:
                await self._request("GET", "/healthz")
                return
            except StorageError as exc:
                last = exc
                if attempt < 4:
                    await asyncio.sleep(min(0.5 * (2 ** attempt), 3.0))
        raise StorageError(f"storage health check failed: {last}")

    async def get(self, task_id: str) -> StoredRun | None:
        try:
            response = await self._client.get(f"/v1/runs/{task_id}")
        except httpx.HTTPError as exc:
            raise StorageError(f"storage GET failed: {exc}") from exc
        if response.status_code == 404:
            return None
        if response.status_code == 409:
            raise StorageConflict(response.text)
        if response.is_error:
            raise StorageError(f"GET run failed: {response.status_code} {response.text}")
        return _stored_run(response.json())

    async def start(self, task_id: str, runner_id: str, expected_attempt: int, task_fingerprint: str) -> StoredRun:
        response = await self._request(
            "POST", "/v1/runs/start",
            json={"task_id": task_id, "runner_id": runner_id, "expected_attempt": expected_attempt, "task_fingerprint": task_fingerprint},
            safe_retry=True,
        )
        return _stored_run(response.json())

    async def set_conversation(self, task_id: str, conversation_id: str,
                               *, attempt: int, runner_id: str) -> StoredRun:
        response = await self._request(
            "PATCH", f"/v1/runs/{task_id}/conversation",
            json={"conversation_id": conversation_id, "attempt": attempt, "runner_id": runner_id},
            safe_retry=True,
        )
        return _stored_run(response.json())

    async def complete(self, task_id: str, captured: CapturedConversation,
                       *, attempt: int, runner_id: str) -> StoredRun:
        response = await self._request(
            "POST", f"/v1/runs/{task_id}/complete",
            json={
                "conversation_id": captured.conversation_id,
                "messages": captured.messages,
                "runtime_metadata": captured.runtime_metadata,
                "attempt": attempt,
                "runner_id": runner_id,
            },
            safe_retry=True,
        )
        return _stored_run(response.json())

    async def fail(self, task_id: str, error: Exception,
                   *, attempt: int, runner_id: str) -> StoredRun:
        response = await self._request(
            "POST", f"/v1/runs/{task_id}/fail",
            json={
                "error_type": type(error).__name__,
                "error_message": str(error)[:8000],
                "attempt": attempt,
                "runner_id": runner_id,
            },
            safe_retry=True,
        )
        return _stored_run(response.json())

    async def stats(self) -> dict[str, Any]:
        return (await self._request("GET", "/v1/stats")).json()

    async def export(self, output: Path) -> int:
        output.parent.mkdir(parents=True, exist_ok=True)
        tmp = output.with_suffix(output.suffix + ".tmp")
        count = 0
        pending = b""
        try:
            async with self._client.stream("GET", "/v1/export.jsonl") as response:
                if response.status_code == 409:
                    body = (await response.aread()).decode("utf-8", errors="replace")
                    raise StorageConflict(f"storage export conflict: {body}")
                if response.is_error:
                    body = (await response.aread()).decode("utf-8", errors="replace")
                    raise StorageError(
                        f"export failed: {response.status_code} {body}"
                    )
                with tmp.open("wb") as handle:
                    async for chunk in response.aiter_bytes():
                        handle.write(chunk)
                        data = pending + chunk
                        lines = data.split(b"\n")
                        pending = lines.pop()
                        count += sum(bool(line.strip()) for line in lines)
                    if pending.strip():
                        count += 1
                    handle.flush()
                    os.fsync(handle.fileno())
        except (StorageError, StorageConflict):
            if tmp.exists():
                tmp.unlink()
            raise
        except httpx.HTTPError as exc:
            if tmp.exists():
                tmp.unlink()
            raise StorageError(f"export transport failed: {exc}") from exc
        os.replace(tmp, output)
        dir_fd = os.open(output.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return count


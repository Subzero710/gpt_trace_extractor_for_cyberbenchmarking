from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .exceptions import AppInfrastructureError
from .models import BenchmarkTask

MAX_ATTACHMENTS_BYTES = 128 * 1024 * 1024


class AppLifecycle:
    def __init__(self, token_file: Path, *, client: httpx.AsyncClient | None = None) -> None:
        self.token_file = token_file
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(180.0, connect=10.0),
            trust_env=False,
        )
        self._owns_client = client is None
        self._token: str | None = None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _read_token(self) -> str:
        if self._token is not None:
            return self._token
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AppInfrastructureError(f"cannot read local App control token: {self.token_file}") from exc
        if len(token) < 32:
            raise AppInfrastructureError("local App control token is missing or too short")
        self._token = token
        return token

    @staticmethod
    def environment_ids(task: BenchmarkTask, *, attempt: int, fingerprint: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for tool in task.tools:
            if tool.kind != "local_mcp":
                continue
            raw = f"{task.task_id}\0{attempt}\0{fingerprint}\0{tool.app_id}".encode("utf-8")
            result[tool.app_id] = f"{task.task_id[:80]}-{attempt}-{hashlib.sha256(raw).hexdigest()[:24]}"
        return result

    @staticmethod
    def _attachments(task: BenchmarkTask) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        names: set[str] = set()
        total = 0
        for path in task.attachments:
            if path.name in names:
                raise AppInfrastructureError(f"duplicate attachment basename for workspace: {path.name}")
            content = path.read_bytes()
            total += len(content)
            if total > MAX_ATTACHMENTS_BYTES:
                raise AppInfrastructureError("task attachments exceed local App transfer limit")
            output.append({
                "path": f"attachments/{path.name}",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "content_base64": base64.b64encode(content).decode("ascii"),
            })
            names.add(path.name)
        return output

    async def _operation(
        self,
        task: BenchmarkTask,
        tool,
        environment_id: str,
        fingerprint: str,
        operation: str,
    ) -> dict[str, Any]:
        if not tool.control_endpoint:
            raise AppInfrastructureError(f"local App {tool.app_id!r} has no control endpoint")
        self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
        payload: dict[str, Any] = {
            "task_id": task.task_id,
            "environment_id": environment_id,
            "task_fingerprint": fingerprint,
        }
        if operation == "prepare" and tool.attachment_mode == "copy":
            payload["attachments"] = self._attachments(task)
        try:
            response = await self._client.post(
                f"{tool.control_endpoint.rstrip('/')}/control/{operation}",
                json=payload,
                headers={"authorization": f"Bearer {self._read_token()}"},
            )
        except httpx.HTTPError as exc:
            raise AppInfrastructureError(f"{tool.app_id} control transport failed during {operation}") from exc
        if response.status_code != 200:
            detail = response.text[:1000]
            raise AppInfrastructureError(f"{tool.app_id} {operation} failed: HTTP {response.status_code}: {detail}")
        try:
            value = response.json()
        except ValueError as exc:
            raise AppInfrastructureError(f"{tool.app_id} {operation} returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise AppInfrastructureError(f"{tool.app_id} {operation} returned a non-object")
        for key, expected in payload.items():
            if key == "attachments":
                continue
            if value.get(key) != expected:
                raise AppInfrastructureError(f"{tool.app_id} {operation} identity response mismatch")
        return value

    @staticmethod
    def _validate_control_endpoint(app_id: str, value: str) -> None:
        try:
            parsed = urlparse(value)
            port = parsed.port
            hostname = parsed.hostname
        except ValueError as exc:
            raise AppInfrastructureError(f"local App {app_id!r} has an invalid control endpoint") from exc
        if (
            parsed.scheme != "http"
            or hostname != f"app-{app_id}"
            or port != 8000
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise AppInfrastructureError(
                f"local App {app_id!r} control endpoint must be internal http://app-{app_id}:8000"
            )

    async def prepare(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str) -> None:
        for tool in task.tools:
            if tool.kind == "local_mcp":
                await self._operation(task, tool, environments[tool.app_id], fingerprint, "prepare")

    async def assert_resume(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str) -> None:
        for tool in task.tools:
            if tool.kind == "local_mcp":
                await self._operation(task, tool, environments[tool.app_id], fingerprint, "resume")

    async def reset(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str) -> None:
        errors: list[str] = []
        for tool in reversed(task.tools):
            if tool.kind != "local_mcp":
                continue
            try:
                await self._operation(task, tool, environments[tool.app_id], fingerprint, "reset")
            except AppInfrastructureError as exc:
                errors.append(str(exc))
        if errors:
            raise AppInfrastructureError("; ".join(errors))

    async def health(self, task: BenchmarkTask) -> None:
        headers = {"authorization": f"Bearer {self._read_token()}"}
        for tool in task.tools:
            if tool.kind != "local_mcp" or not tool.control_endpoint:
                continue
            self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
            try:
                response = await self._client.get(f"{tool.control_endpoint.rstrip('/')}/healthz", headers=headers)
            except httpx.HTTPError as exc:
                raise AppInfrastructureError(f"{tool.app_id} health request failed") from exc
            if response.status_code != 200:
                raise AppInfrastructureError(f"{tool.app_id} is unhealthy: HTTP {response.status_code}")

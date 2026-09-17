from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .docker_runtime import AttemptRuntime, DockerRuntime, RuntimeResource
from .exceptions import AppInfrastructureError
from .models import BenchmarkTask


class AppLifecycle:
    def __init__(
        self,
        token_file: Path,
        *,
        runtime: DockerRuntime,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.token_file = token_file
        self.runtime = runtime
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(180.0, connect=10.0),
            trust_env=False,
        )
        self._owns_client = client is None
        self._token: str | None = None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
        await self.runtime.close()

    def _read_token(self) -> str:
        if self._token is not None:
            return self._token
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AppInfrastructureError(
                f"cannot read local App control token: {self.token_file}"
            ) from exc
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
            result[tool.app_id] = (
                f"{task.task_id[:80]}-{attempt}-{hashlib.sha256(raw).hexdigest()[:24]}"
            )
        return result

    @staticmethod
    def _expected_gateway_host(app_id: str) -> str:
        if app_id == "code-workspace":
            return "workspace-gateway"
        if app_id == "browser":
            return "browser-gateway"
        raise AppInfrastructureError(f"unsupported local App gateway: {app_id!r}")

    @classmethod
    def _validate_control_endpoint(cls, app_id: str, value: str) -> None:
        try:
            parsed = urlparse(value)
            port = parsed.port
            hostname = parsed.hostname
        except ValueError as exc:
            raise AppInfrastructureError(
                f"local App {app_id!r} has an invalid control endpoint"
            ) from exc
        expected_host = cls._expected_gateway_host(app_id)
        if (
            parsed.scheme != "http"
            or hostname != expected_host
            or port != 8000
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise AppInfrastructureError(
                f"local App {app_id!r} control endpoint must be internal "
                f"http://{expected_host}:8000"
            )

    def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self._read_token()}"}

    async def _post_gateway(
        self,
        tool,
        path: str,
        payload: dict[str, Any],
        *,
        expected: set[int] = {200},
    ) -> dict[str, Any]:
        if not tool.control_endpoint:
            raise AppInfrastructureError(f"local App {tool.app_id!r} has no control endpoint")
        self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
        try:
            response = await self._client.post(
                f"{tool.control_endpoint.rstrip('/')}{path}",
                json=payload,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise AppInfrastructureError(
                f"{tool.app_id} gateway transport failed for {path}"
            ) from exc
        if response.status_code not in expected:
            raise AppInfrastructureError(
                f"{tool.app_id} gateway {path} failed: HTTP {response.status_code}: "
                f"{response.text[:1000]}"
            )
        try:
            value = response.json()
        except ValueError as exc:
            raise AppInfrastructureError(
                f"{tool.app_id} gateway {path} returned invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise AppInfrastructureError(
                f"{tool.app_id} gateway {path} returned a non-object"
            )
        return value

    async def _activate(
        self,
        task: BenchmarkTask,
        tool,
        resource: RuntimeResource,
        fingerprint: str,
        *,
        attempt: int,
    ) -> None:
        payload = {
            "task_id": task.task_id,
            "attempt": attempt,
            "environment_id": resource.environment_id,
            "task_fingerprint": fingerprint,
            "backend_url": resource.backend_url,
            "backend_token": resource.backend_token,
        }
        value = await self._post_gateway(tool, "/control/activate", payload)
        for key in ("task_id", "attempt", "environment_id", "task_fingerprint"):
            if value.get(key) != payload[key]:
                raise AppInfrastructureError(
                    f"{tool.app_id} gateway activation identity mismatch"
                )

    async def _deactivate(
        self,
        task: BenchmarkTask,
        tool,
        environment_id: str,
        fingerprint: str,
        *,
        attempt: int,
    ) -> None:
        await self._post_gateway(
            tool,
            "/control/deactivate",
            {
                "task_id": task.task_id,
                "attempt": attempt,
                "environment_id": environment_id,
                "task_fingerprint": fingerprint,
            },
        )

    async def _wait_backend(self, tool, *, timeout_seconds: float = 90.0) -> None:
        if not tool.control_endpoint:
            raise AppInfrastructureError(f"local App {tool.app_id!r} has no control endpoint")
        self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        last_detail = "backend did not answer"
        while True:
            try:
                response = await self._client.get(
                    f"{tool.control_endpoint.rstrip('/')}/control/backend-health",
                    headers=self._headers(),
                )
                if response.status_code == 200:
                    return
                last_detail = f"HTTP {response.status_code}: {response.text[:400]}"
            except httpx.HTTPError as exc:
                last_detail = str(exc)
            if asyncio.get_running_loop().time() >= deadline:
                raise AppInfrastructureError(
                    f"{tool.app_id} backend did not become healthy: {last_detail}"
                )
            await asyncio.sleep(0.5)

    async def _operation(
        self,
        task: BenchmarkTask,
        tool,
        environment_id: str,
        fingerprint: str,
        operation: str,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "task_id": task.task_id,
            "environment_id": environment_id,
            "task_fingerprint": fingerprint,
        }
        value = await self._post_gateway(tool, f"/control/{operation}", payload)
        for key, expected in payload.items():
            if value.get(key) != expected:
                raise AppInfrastructureError(
                    f"{tool.app_id} {operation} identity response mismatch"
                )
        return value

    async def prepare(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> AttemptRuntime:
        control_token = self._read_token()
        runtime = await self.runtime.create(
            task,
            environments,
            fingerprint,
            attempt=attempt,
            control_token=control_token,
        )
        activated: list[Any] = []
        try:
            for tool in task.tools:
                if tool.kind != "local_mcp":
                    continue
                resource = runtime.resources[tool.app_id]
                await self._activate(
                    task,
                    tool,
                    resource,
                    fingerprint,
                    attempt=attempt,
                )
                activated.append(tool)
                await self._wait_backend(tool)
                await self._operation(
                    task,
                    tool,
                    resource.environment_id,
                    fingerprint,
                    "prepare",
                )
            return runtime
        except Exception:
            for tool in reversed(activated):
                try:
                    await self._deactivate(
                        task,
                        tool,
                        environments[tool.app_id],
                        fingerprint,
                        attempt=attempt,
                    )
                except Exception:
                    pass
            try:
                await self.runtime.destroy(
                    task,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
            except Exception:
                pass
            raise

    async def assert_resume(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> AttemptRuntime:
        control_token = self._read_token()
        runtime = await self.runtime.discover(
            task,
            environments,
            fingerprint,
            attempt=attempt,
            control_token=control_token,
        )
        for tool in task.tools:
            if tool.kind != "local_mcp":
                continue
            resource = runtime.resources[tool.app_id]
            await self._activate(
                task,
                tool,
                resource,
                fingerprint,
                attempt=attempt,
            )
            await self._wait_backend(tool)
            await self._operation(
                task,
                tool,
                resource.environment_id,
                fingerprint,
                "resume",
            )
        return runtime

    async def runtime_metadata(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> dict[str, Any]:
        return await self.runtime.snapshot(
            task,
            environments,
            fingerprint,
            attempt=attempt,
            control_token=self._read_token(),
        )

    async def reset(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> None:
        errors: list[str] = []
        for tool in reversed(task.tools):
            if tool.kind != "local_mcp":
                continue
            try:
                await self._deactivate(
                    task,
                    tool,
                    environments[tool.app_id],
                    fingerprint,
                    attempt=attempt,
                )
            except AppInfrastructureError as exc:
                errors.append(str(exc))
        try:
            await self.runtime.destroy(
                task,
                environments,
                fingerprint,
                attempt=attempt,
            )
        except AppInfrastructureError as exc:
            errors.append(str(exc))
        if errors:
            raise AppInfrastructureError("; ".join(errors))

    async def health(self, task: BenchmarkTask) -> None:
        for tool in task.tools:
            if tool.kind != "local_mcp" or not tool.control_endpoint:
                continue
            self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
            try:
                response = await self._client.get(
                    f"{tool.control_endpoint.rstrip('/')}/healthz",
                    headers=self._headers(),
                )
            except httpx.HTTPError as exc:
                raise AppInfrastructureError(
                    f"{tool.app_id} gateway health request failed"
                ) from exc
            if response.status_code != 200:
                raise AppInfrastructureError(
                    f"{tool.app_id} gateway is unhealthy: HTTP {response.status_code}"
                )

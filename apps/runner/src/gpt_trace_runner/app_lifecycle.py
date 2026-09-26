from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .workstation_provider import AttemptRuntime, WorkstationProvider, RuntimeResource
from .exceptions import AppInfrastructureError
from .models import BenchmarkTask
from .workspace_seed import build_workspace_archive


class AppLifecycle:
    def __init__(
        self,
        token_file: Path,
        *,
        runtime: WorkstationProvider,
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
        if app_id == "kali-workstation":
            return "workstation-gateway"
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

    async def _seed_workspace(self, task: BenchmarkTask, tool) -> None:
        if tool.app_id != "kali-workstation":
            return
        if task.initial_workspace is None and not task.attachments:
            return
        if not tool.control_endpoint:
            raise AppInfrastructureError("local App 'kali-workstation' has no control endpoint")
        self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
        archive = build_workspace_archive(task.initial_workspace, task.attachments)
        digest = hashlib.sha256(archive).hexdigest()
        try:
            response = await self._client.post(
                f"{tool.control_endpoint.rstrip('/')}/control/seed",
                content=archive,
                headers={**self._headers(), "content-type": "application/x-tar"},
                timeout=180.0,
            )
        except httpx.HTTPError as exc:
            raise AppInfrastructureError("kali-workstation gateway transport failed for /control/seed") from exc
        if response.status_code != 200:
            raise AppInfrastructureError(
                f"kali-workstation gateway /control/seed failed: HTTP {response.status_code}: "
                f"{response.text[:1000]}"
            )
        try:
            value = response.json()
        except ValueError as exc:
            raise AppInfrastructureError("kali-workstation seed returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise AppInfrastructureError("kali-workstation seed returned a non-object")
        if (
            value.get("status") != "seeded"
            or value.get("archive_bytes") != len(archive)
            or value.get("sha256") != digest
        ):
            raise AppInfrastructureError("kali-workstation seed integrity response mismatch")

    async def _operation(
        self,
        task: BenchmarkTask,
        tool,
        environment_id: str,
        fingerprint: str,
        operation: str,
        attempt: int,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "task_id": task.task_id,
            "environment_id": environment_id,
            "task_fingerprint": fingerprint,
            "attempt": attempt,
        }
        value = await self._post_gateway(tool, f"/control/{operation}", payload)
        for key in ("task_id", "environment_id", "task_fingerprint"):
            if value.get(key) != payload[key]:
                raise AppInfrastructureError(f"{tool.app_id} {operation} identity response mismatch")
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
                    attempt,
                )
                await self._seed_workspace(task, tool)
            return runtime
        except Exception as prepare_error:
            cleanup_errors: list[str] = []
            for tool in reversed(activated):
                try:
                    await self._operation(task, tool, environments[tool.app_id],
                                          fingerprint, "reset", attempt)
                except Exception as exc:
                    cleanup_errors.append(f"{tool.app_id} controller reset: {exc}")
                try:
                    await self._deactivate(
                        task,
                        tool,
                        environments[tool.app_id],
                        fingerprint,
                        attempt=attempt,
                    )
                except Exception as exc:
                    cleanup_errors.append(f"{tool.app_id} gateway deactivation: {exc}")
            try:
                await self.runtime.destroy(
                    task,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
            except Exception as exc:
                cleanup_errors.append(f"workstation destroy: {exc}")
            if cleanup_errors:
                raise AppInfrastructureError(
                    f"prepare failed: {prepare_error}; cleanup incomplete: {'; '.join(cleanup_errors)}"
                ) from prepare_error
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
                attempt,
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
        metadata = await self.runtime.snapshot(task, environments, fingerprint, attempt=attempt, control_token=self._read_token())
        return metadata

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
                await self._operation(task, tool, environments[tool.app_id], fingerprint, "reset", attempt)
            except AppInfrastructureError as exc:
                errors.append(str(exc))
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

    async def assert_clean(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> None:
        errors: list[str] = []
        for tool in task.tools:
            if tool.kind != "local_mcp" or not tool.control_endpoint:
                continue
            self._validate_control_endpoint(tool.app_id, tool.control_endpoint)
            try:
                response = await self._client.get(
                    f"{tool.control_endpoint.rstrip('/')}/control/status",
                    headers=self._headers(),
                )
            except httpx.HTTPError as exc:
                errors.append(f"{tool.app_id} gateway status failed: {exc}")
                continue
            if response.status_code != 200:
                errors.append(f"{tool.app_id} gateway status returned HTTP {response.status_code}")
                continue
            try:
                value = response.json()
            except ValueError:
                errors.append(f"{tool.app_id} gateway status returned invalid JSON")
                continue
            if not isinstance(value, dict) or value.get("active") is not None:
                errors.append(f"{tool.app_id} gateway remained bound after reset")
        try:
            await self.runtime.assert_absent(task, environments, fingerprint, attempt=attempt)
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

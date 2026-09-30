from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from .exceptions import AppInfrastructureError
from .models import BenchmarkTask

APP_ID = "kali-workstation"


@dataclass(frozen=True)
class RuntimeResource:
    app_id: str
    environment_id: str
    backend_url: str
    backend_token: str
    details: dict[str, Any]

    def metadata(self) -> dict[str, Any]:
        return {"environment_id": self.environment_id, **self.details}


@dataclass(frozen=True)
class AttemptRuntime:
    resources: dict[str, RuntimeResource]

    def metadata(self) -> dict[str, Any]:
        return {"provider": "libvirt", "apps": {key: value.metadata() for key, value in self.resources.items()}}


class WorkstationProvider(Protocol):
    async def create(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str, *, attempt: int, control_token: str) -> AttemptRuntime: ...
    async def discover(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str, *, attempt: int, control_token: str) -> AttemptRuntime: ...
    async def snapshot(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str, *, attempt: int, control_token: str) -> dict: ...
    async def destroy(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str, *, attempt: int) -> None: ...
    async def assert_absent(self, task: BenchmarkTask, environments: dict[str, str], fingerprint: str, *, attempt: int) -> None: ...
    async def close(self) -> None: ...


class LibvirtWorkstationProvider:
    def __init__(self, socket: Path, token_file: Path, *, client: httpx.AsyncClient | None = None):
        self.socket = socket
        self.token_file = token_file
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(socket)),
                                                   base_url="http://broker", timeout=httpx.Timeout(200, connect=10), trust_env=False)

    async def close(self) -> None:
        if self._owns_client: await self.client.aclose()

    def _identity(self, task, environments, fingerprint, attempt):
        local = [tool for tool in task.tools if tool.kind == "local_mcp"]
        if not local: return None
        if len(local) != 1 or local[0].app_id != APP_ID or set(environments) != {APP_ID}:
            raise AppInfrastructureError("exactly one kali-workstation environment is required")
        return {"task_id": task.task_id, "attempt": attempt,
                "environment_id": environments[APP_ID], "fingerprint": fingerprint}

    async def _request(self, name: str, identity: dict) -> dict:
        token = self.token_file.read_text().strip()
        response = await self.client.post(f"/v1/{name}", json=identity,
                                          headers={"authorization": f"Bearer {token}"})
        if response.status_code != 200:
            raise AppInfrastructureError(f"broker {name}: HTTP {response.status_code}: {response.text[:1000]}")
        data = response.json()
        if not isinstance(data, dict): raise AppInfrastructureError("invalid broker response")
        return data

    async def _resource(self, name, task, environments, fingerprint, attempt, control_token):
        identity = self._identity(task, environments, fingerprint, attempt)
        if identity is None: return AttemptRuntime({})
        details = await self._request(name, identity)
        if details.get("identity") != identity or details.get("provider") != "libvirt":
            raise AppInfrastructureError("broker attempt identity mismatch")
        token = hmac.new(control_token.encode(),
                         f"backend\0{APP_ID}\0{identity['environment_id']}".encode(), hashlib.sha256).hexdigest()
        return AttemptRuntime({APP_ID: RuntimeResource(APP_ID, identity["environment_id"],
            "http://kali-workstation-controller:8000", token, details)})

    async def create(self, task, environments, fingerprint, *, attempt, control_token):
        return await self._resource("create_attempt", task, environments, fingerprint, attempt, control_token)

    async def discover(self, task, environments, fingerprint, *, attempt, control_token):
        return await self._resource("inspect_attempt", task, environments, fingerprint, attempt, control_token)

    async def snapshot(self, task, environments, fingerprint, *, attempt, control_token):
        return (await self.discover(task, environments, fingerprint, attempt=attempt, control_token=control_token)).metadata()

    async def destroy(self, task, environments, fingerprint, *, attempt):
        identity = self._identity(task, environments, fingerprint, attempt)
        if identity is not None: await self._request("destroy_attempt", identity)

    async def assert_absent(self, task, environments, fingerprint, *, attempt):
        identity = self._identity(task, environments, fingerprint, attempt)
        if identity is not None:
            result = await self._request("assert_absent", identity)
            if result != {"absent": True}: raise AppInfrastructureError("broker cleanup mismatch")

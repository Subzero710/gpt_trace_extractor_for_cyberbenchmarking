from __future__ import annotations

import hashlib
import hmac
import base64
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from .exceptions import AppInfrastructureError
from .models import BenchmarkTask
from .workstation_template import validate_template_id

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
    async def preflight(self, template_ids: list[str]) -> dict: ...
    async def call(self, task, environments, fingerprint, *, attempt, method, args) -> dict: ...
    async def export(self, task, environments, fingerprint, *, attempt, path, destination) -> dict: ...
    async def import_bytes(self, task, environments, fingerprint, *, attempt, data, path) -> dict: ...
    async def abandon(self, task, environments, fingerprint, *, attempt) -> None: ...
    async def materialize_template_artifact(self, task, environments, fingerprint, *, attempt, artifact_id) -> dict: ...
    async def create_evaluator(self, task, environments, fingerprint, *, attempt, abandon_stale=False) -> dict: ...


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
                                          headers={"authorization": f"Bearer {token}"}, timeout=1850)
        if response.status_code != 200:
            raise AppInfrastructureError(f"broker {name}: HTTP {response.status_code}: {response.text[:1000]}")
        data = response.json()
        if not isinstance(data, dict): raise AppInfrastructureError("invalid broker response")
        return data

    async def _resource(self, name, task, environments, fingerprint, attempt, control_token):
        identity = self._identity(task, environments, fingerprint, attempt)
        if identity is None: return AttemptRuntime({})
        payload = dict(identity)
        if name == "create_attempt" and task.workstation_template is not None:
            payload["template_id"] = validate_template_id(task.workstation_template)
            payload["logical_task_id"] = task.template_task_id
        details = await self._request(name, payload)
        if details.get("identity") != identity or details.get("provider") != "libvirt":
            raise AppInfrastructureError("broker attempt identity mismatch")
        if task.workstation_template is not None:
            if details.get("template_id") != task.workstation_template or any(
                not isinstance(details.get(key), str) or not details[key]
                for key in ("backing_path", "backing_sha256", "template_generation", "template_source_fingerprint")
            ):
                raise AppInfrastructureError("broker workstation template identity mismatch")
        elif details.get("template_id") is not None:
            raise AppInfrastructureError("unexpected template for default Kali attempt")
        if task.template_task_id is not None and details.get("logical_task_id") != task.template_task_id:
            raise AppInfrastructureError("broker template source scope mismatch")
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

    async def preflight(self, template_ids):
        values = sorted({validate_template_id(value) for value in template_ids})
        if not values:
            return {"templates": {}}
        result = await self._request("preflight_templates", {"template_ids": values})
        if set(result.get("templates", {})) != set(values):
            raise AppInfrastructureError("template preflight selection mismatch")
        return result

    async def call(self, task, environments, fingerprint, *, attempt, method, args):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is None:
            raise AppInfrastructureError("internal guest RPC requires a workstation")
        return await self._request("rpc", {**ident, "method": method, "args": args})

    async def export(self, task, environments, fingerprint, *, attempt, path, destination):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is None:
            raise AppInfrastructureError("internal export requires a workstation")
        return await self._export(ident, path, destination)

    async def _export(self, ident, path, destination, prefix=""):
        info = await self._request(prefix + "artifact_export", {**ident, "args": {"path": path}})
        size, sha = info.get("size"), info.get("sha256")
        if type(size) is not int or not 0 <= size <= 268435456 or info.get("artifact_id") != sha:
            raise AppInfrastructureError("invalid exported artifact record")
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".export-")
        temporary = Path(temporary)
        digest = hashlib.sha256()
        try:
            with os.fdopen(fd, "wb") as output:
                offset = 0
                while offset < size:
                    chunk = await self._request(prefix + "artifact_read", {**ident, "args": {"artifact_id": sha, "offset": offset}})
                    raw = base64.b64decode(chunk["content_base64"], validate=True)
                    if chunk.get("sha256") != sha or chunk.get("size") != size or not raw or len(raw) > min(1048576, size-offset):
                        raise AppInfrastructureError("artifact changed while downloading")
                    output.write(raw)
                    digest.update(raw)
                    offset += len(raw)
                output.flush()
                os.fsync(output.fileno())
            if digest.hexdigest() != sha:
                raise AppInfrastructureError("exported artifact SHA256 mismatch")
            os.replace(temporary, destination)
            fd = os.open(destination.parent, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)
        return {**info, "local_path": str(destination)}

    async def import_bytes(self, task, environments, fingerprint, *, attempt, data, path):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is None or len(data) > 268435456:
            raise AppInfrastructureError("invalid internal artifact import")
        return await self._import(ident, data, path)

    async def _import(self, ident, data, path, prefix=""):
        if len(data) > 268435456:
            raise AppInfrastructureError("invalid internal artifact import")
        upload = await self._request(prefix + "artifact_stage_begin", ident)
        try:
            for offset in range(0, len(data), 1048576):
                await self._request(prefix + "artifact_stage_chunk", {**ident, "args": {"upload_id": upload["upload_id"],
                    "content_base64": base64.b64encode(data[offset:offset+1048576]).decode()}})
            info = await self._request(prefix + "artifact_stage_end", {**ident, "args": {"upload_id": upload["upload_id"],
                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}})
            result = await self._request(prefix + "artifact_import", {**ident, "args": {"artifact_id": info["artifact_id"],
                                                                              "path": path, "overwrite": True}})
            if result.get("sha256") != hashlib.sha256(data).hexdigest() or result.get("size") != len(data) or result.get("path") != path:
                raise AppInfrastructureError("guest import did not preserve exact candidate bytes")
            return result
        except BaseException:
            await self._request(prefix + "artifact_stage_abort", {**ident, "args": {"upload_id": upload["upload_id"]}})
            raise

    async def materialize_template_artifact(self, task, environments, fingerprint, *, attempt, artifact_id):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is None:
            raise AppInfrastructureError("template artifact requires an attempt")
        return await self._request("materialize_template_artifact", {**ident, "artifact_id": artifact_id})

    async def create_evaluator(self, task, environments, fingerprint, *, attempt, abandon_stale=False):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is None or task.workstation_template is None:
            raise AppInfrastructureError("isolated evaluation requires an immutable workstation template")
        result = await self._request("create_evaluator", {**ident, "abandon_stale": abandon_stale})
        evaluator = result.get("identity", {})
        if any(evaluator.get(key) != value for key, value in ident.items()) or evaluator.get("purpose") != "evaluator" or result.get("template_id") != task.workstation_template or result.get("network") is not None:
            raise AppInfrastructureError("isolated evaluator identity/template/network mismatch")
        return result

    async def abandon(self, task, environments, fingerprint, *, attempt):
        ident = self._identity(task, environments, fingerprint, attempt)
        if ident is not None:
            if task.workstation_template is not None:
                await self._request("abandon_evaluators", ident)
            await self._request("abandon_attempt", ident)


@dataclass(frozen=True)
class InternalRuntime:
    """Attempt-bound runner access. This is never part of the MCP manifest."""
    provider: WorkstationProvider
    task: BenchmarkTask
    environments: dict[str, str]
    fingerprint: str
    attempt: int
    artifact_root: Path
    explicit_recovery: bool = False
    journal: Any = None

    async def call(self, method, args):
        return await self.provider.call(self.task, self.environments, self.fingerprint,
                                        attempt=self.attempt, method=method, args=args)

    async def export(self, path, name):
        if Path(name).name != name or name in {"", ".", ".."}:
            raise AppInfrastructureError("invalid internal artifact filename")
        return await self.provider.export(self.task, self.environments, self.fingerprint,
                                          attempt=self.attempt, path=path, destination=self.artifact_root / name)

    async def import_bytes(self, data, path):
        return await self.provider.import_bytes(self.task, self.environments, self.fingerprint,
                                                attempt=self.attempt, data=data, path=path)

    async def materialize_template_artifact(self, artifact_id):
        return await self.provider.materialize_template_artifact(self.task, self.environments, self.fingerprint,
                                                                attempt=self.attempt, artifact_id=artifact_id)

    async def create_evaluator(self):
        record = await self.provider.create_evaluator(self.task, self.environments, self.fingerprint,
                                                     attempt=self.attempt, abandon_stale=self.explicit_recovery)
        if self.journal is not None:
            self.journal.record_evaluator(record)
        return EvaluatorRuntime(self, record)


@dataclass(frozen=True)
class EvaluatorRuntime:
    """Runner-only control; no App resource, gateway, browser, or MCP endpoint."""
    teacher: InternalRuntime
    record: dict

    @property
    def artifact_root(self):
        return self.teacher.artifact_root / "evaluators" / self.record["identity"]["evaluator_retry"]

    @property
    def request_identity(self):
        teacher = self.teacher
        ident = teacher.provider._identity(teacher.task, teacher.environments, teacher.fingerprint, teacher.attempt)
        return {**ident, "evaluator_retry": self.record["identity"]["evaluator_retry"]}

    async def call(self, method, args):
        return await self.teacher.provider._request("evaluator_rpc", {**self.request_identity, "method": method, "args": args})

    async def materialize_template_artifact(self, artifact_id):
        return await self.teacher.provider._request("evaluator_materialize_template_artifact", {**self.request_identity, "artifact_id": artifact_id})

    async def import_bytes(self, data, path):
        return await self.teacher.provider._import(self.request_identity, data, path, prefix="evaluator_")

    async def export(self, path, name):
        if Path(name).name != name or name in {"", ".", ".."}:
            raise AppInfrastructureError("invalid evaluator artifact filename")
        return await self.teacher.provider._export(self.request_identity, path, self.artifact_root / name, prefix="evaluator_")

    async def destroy(self):
        return await self.teacher.provider._request("destroy_evaluator", self.request_identity)

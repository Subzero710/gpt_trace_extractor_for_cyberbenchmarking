from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from .exceptions import AppInfrastructureError
from .models import BenchmarkTask
from .workspace_seed import build_workspace_archive

MANAGED_LABEL = "gpttrace.managed"
TASK_LABEL = "gpttrace.task_id"
ATTEMPT_LABEL = "gpttrace.attempt"
APP_LABEL = "gpttrace.app_id"
ENVIRONMENT_LABEL = "gpttrace.environment_id"
FINGERPRINT_LABEL = "gpttrace.task_fingerprint"


@dataclass(frozen=True, slots=True)
class RuntimeResource:
    app_id: str
    environment_id: str
    container_name: str
    container_id: str
    image: str
    image_id: str
    backend_url: str
    backend_token: str

    def metadata(self) -> dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "container_name": self.container_name,
            "container_id": self.container_id,
            "image": self.image,
            "image_id": self.image_id,
        }


@dataclass(frozen=True, slots=True)
class AttemptRuntime:
    network_name: str | None
    network_id: str | None
    egress_network_name: str | None
    egress_network_id: str | None
    resources: dict[str, RuntimeResource]

    def metadata(self) -> dict[str, Any]:
        return {
            "network": (
                {"name": self.network_name, "id": self.network_id}
                if self.network_name is not None
                else None
            ),
            "egress_network": (
                {"name": self.egress_network_name, "id": self.egress_network_id}
                if self.egress_network_name is not None
                else None
            ),
            "apps": {
                app_id: resource.metadata()
                for app_id, resource in sorted(self.resources.items())
            },
        }


class DockerRuntime:
    """Owns per-attempt execution containers. Model-facing containers never see Docker."""

    def __init__(
        self,
        socket_path: Path,
        *,
        workspace_image: str,
        browser_image: str,
        workspace_gateway_container: str,
        browser_gateway_container: str,
        browser_environment: dict[str, str],
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.workspace_image = workspace_image
        self.browser_image = browser_image
        self.workspace_gateway_container = workspace_gateway_container
        self.browser_gateway_container = browser_gateway_container
        self.browser_environment = dict(browser_environment)
        if client is None:
            transport = httpx.AsyncHTTPTransport(uds=str(socket_path))
            client = httpx.AsyncClient(
                transport=transport,
                base_url="http://docker",
                timeout=httpx.Timeout(180.0, connect=10.0),
                trust_env=False,
            )
            self._owns_client = True
        else:
            self._owns_client = False
        self._client = client

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        expected: set[int],
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            response = await self._client.request(
                method,
                path,
                json=json_body,
                content=content,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise AppInfrastructureError(f"Docker API transport failed for {method} {path}") from exc
        if response.status_code not in expected:
            detail = response.text[:1200]
            raise AppInfrastructureError(
                f"Docker API {method} {path} failed: HTTP {response.status_code}: {detail}"
            )
        return response

    async def ping(self) -> None:
        await self._request("GET", "/_ping", expected={200})

    @staticmethod
    def _suffix(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]

    @classmethod
    def _container_name(cls, app_id: str, environment_id: str) -> str:
        role = "workspace" if app_id == "code-workspace" else "browser"
        return f"gpt-trace-{role}-{cls._suffix(environment_id)}"

    @classmethod
    def _network_name(cls, task: BenchmarkTask, attempt: int, fingerprint: str) -> str:
        raw = f"{task.task_id}\0{attempt}\0{fingerprint}"
        return f"gpt-trace-task-{cls._suffix(raw)}"

    @classmethod
    def _egress_network_name(cls, task: BenchmarkTask, attempt: int, fingerprint: str) -> str:
        raw = f"egress\0{task.task_id}\0{attempt}\0{fingerprint}"
        return f"gpt-trace-egress-{cls._suffix(raw)}"

    @staticmethod
    def backend_token(control_token: str, app_id: str, environment_id: str) -> str:
        message = f"backend\0{app_id}\0{environment_id}".encode("utf-8")
        return hmac.new(control_token.encode("utf-8"), message, hashlib.sha256).hexdigest()

    def _gateway_container(self, app_id: str) -> str:
        if app_id == "code-workspace":
            return self.workspace_gateway_container
        if app_id == "browser":
            return self.browser_gateway_container
        raise AppInfrastructureError(f"unsupported local App runtime: {app_id}")

    def _image(self, app_id: str) -> str:
        if app_id == "code-workspace":
            return self.workspace_image
        if app_id == "browser":
            return self.browser_image
        raise AppInfrastructureError(f"unsupported local App runtime: {app_id}")

    def _labels(
        self,
        task: BenchmarkTask,
        *,
        app_id: str,
        attempt: int,
        environment_id: str,
        fingerprint: str,
    ) -> dict[str, str]:
        return {
            MANAGED_LABEL: "true",
            TASK_LABEL: task.task_id,
            ATTEMPT_LABEL: str(attempt),
            APP_LABEL: app_id,
            ENVIRONMENT_LABEL: environment_id,
            FINGERPRINT_LABEL: fingerprint,
        }

    def _container_config(
        self,
        task: BenchmarkTask,
        *,
        app_id: str,
        attempt: int,
        environment_id: str,
        fingerprint: str,
        network_name: str,
        egress_network_name: str | None,
        backend_token: str,
        container_name: str,
    ) -> dict[str, Any]:
        env = [
            f"APP_CONTROL_TOKEN={backend_token}",
            f"MCP_ALLOWED_HOSTS={container_name}:8000,localhost:8000",
        ]
        if app_id == "code-workspace":
            env += [
                "CODE_WORKSPACE_ROOT=/workspace",
                "CODE_WORKSPACE_STATE_ROOT=/state",
            ]
            host_config: dict[str, Any] = {
                "ReadonlyRootfs": True,
                "Init": True,
                "CapDrop": ["ALL"],
                "CapAdd": ["CHOWN", "KILL", "SETGID", "SETUID"],
                "SecurityOpt": ["no-new-privileges"],
                "PidsLimit": 160,
                "Memory": 2 * 1024 * 1024 * 1024,
                "NanoCpus": 2_000_000_000,
                "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
                "Tmpfs": {
                    "/workspace": "rw,nosuid,nodev,size=2147483648,mode=0770",
                    "/state": "rw,nosuid,nodev,noexec,size=16777216,mode=0700",
                    "/tmp": "rw,nosuid,nodev,noexec,size=268435456,mode=1777",
                },
                "NetworkMode": network_name,
            }
        else:
            for key, value in sorted(self.browser_environment.items()):
                if value != "":
                    env.append(f"{key}={value}")
            env.append("APP_BROWSER_STATE_ROOT=/browser-state")
            host_config = {
                "ReadonlyRootfs": True,
                "Init": True,
                "CapDrop": ["AUDIT_WRITE", "MKNOD", "NET_RAW"],
                "SecurityOpt": ["no-new-privileges"],
                "PidsLimit": 512,
                "Memory": 4 * 1024 * 1024 * 1024,
                "NanoCpus": 2_000_000_000,
                "ShmSize": 2 * 1024 * 1024 * 1024,
                "Tmpfs": {
                    "/browser-state": "rw,nosuid,nodev,size=2147483648,mode=0700",
                    "/tmp": "rw,nosuid,nodev,size=1073741824,mode=1777",
                },
                "NetworkMode": network_name,
            }
        if app_id == "browser":
            if egress_network_name is None:
                raise AppInfrastructureError("browser runtime requires a per-attempt egress network")
            primary_network = egress_network_name
        else:
            primary_network = network_name
        host_config["NetworkMode"] = primary_network
        return {
            "Image": self._image(app_id),
            "Env": env,
            "Labels": self._labels(
                task,
                app_id=app_id,
                attempt=attempt,
                environment_id=environment_id,
                fingerprint=fingerprint,
            ),
            "ExposedPorts": {"8000/tcp": {}},
            "HostConfig": host_config,
            "NetworkingConfig": {"EndpointsConfig": {primary_network: {}}},
        }

    async def _inspect_container(self, name_or_id: str) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            f"/containers/{quote(name_or_id, safe='')}/json",
            expected={200, 404},
        )
        if response.status_code == 404:
            return None
        try:
            value = response.json()
        except ValueError as exc:
            raise AppInfrastructureError("Docker container inspect returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise AppInfrastructureError("Docker container inspect returned a non-object")
        return value

    async def _inspect_network(self, name_or_id: str) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            f"/networks/{quote(name_or_id, safe='')}",
            expected={200, 404},
        )
        if response.status_code == 404:
            return None
        value = response.json()
        if not isinstance(value, dict):
            raise AppInfrastructureError("Docker network inspect returned a non-object")
        return value

    async def _connect(self, network_name: str, container: str) -> None:
        response = await self._request(
            "POST",
            f"/networks/{quote(network_name, safe='')}/connect",
            expected={200, 403, 404},
            json_body={"Container": container},
        )
        if response.status_code == 404:
            raise AppInfrastructureError(f"Docker network not found while connecting {container}: {network_name}")
        if response.status_code == 403:
            message = response.text.casefold()
            if "already exists" not in message and "already connected" not in message:
                raise AppInfrastructureError(
                    f"Docker refused network connection for {container}: {response.text[:1000]}"
                )

    async def _disconnect(self, network_name: str, container: str) -> None:
        response = await self._request(
            "POST",
            f"/networks/{quote(network_name, safe='')}/disconnect",
            expected={200, 403, 404},
            json_body={"Container": container, "Force": True},
        )
        if response.status_code == 403:
            message = response.text.casefold()
            if "not connected" not in message and "is not connected" not in message:
                raise AppInfrastructureError(
                    f"Docker refused network disconnect for {container}: {response.text[:1000]}"
                )

    async def _remove_container(self, name_or_id: str) -> None:
        await self._request(
            "DELETE",
            f"/containers/{quote(name_or_id, safe='')}?force=true&v=true",
            expected={204, 404},
        )

    async def _remove_network(self, network_name: str) -> None:
        await self._request(
            "DELETE",
            f"/networks/{quote(network_name, safe='')}",
            expected={204, 404},
        )

    async def _create_network(
        self,
        task: BenchmarkTask,
        *,
        attempt: int,
        fingerprint: str,
        network_name: str,
        internal: bool,
        role: str,
    ) -> str:
        labels = {
            MANAGED_LABEL: "true",
            TASK_LABEL: task.task_id,
            ATTEMPT_LABEL: str(attempt),
            FINGERPRINT_LABEL: fingerprint,
        }
        response = await self._request(
            "POST",
            "/networks/create",
            expected={201},
            json_body={
                "Name": network_name,
                "CheckDuplicate": True,
                "Internal": internal,
                "Attachable": False,
                "Labels": {**labels, "gpttrace.network_role": role},
            },
        )
        value = response.json()
        network_id = value.get("Id") if isinstance(value, dict) else None
        if not isinstance(network_id, str) or not network_id:
            raise AppInfrastructureError("Docker network create returned no id")
        return network_id

    @staticmethod
    def _verify_labels(
        inspect: dict[str, Any],
        *,
        task: BenchmarkTask,
        app_id: str,
        attempt: int,
        environment_id: str,
        fingerprint: str,
    ) -> None:
        config = inspect.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        expected = {
            MANAGED_LABEL: "true",
            TASK_LABEL: task.task_id,
            ATTEMPT_LABEL: str(attempt),
            APP_LABEL: app_id,
            ENVIRONMENT_LABEL: environment_id,
            FINGERPRINT_LABEL: fingerprint,
        }
        if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected.items()):
            raise AppInfrastructureError(f"Docker runtime identity mismatch for {app_id}")

    async def create(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
        control_token: str,
    ) -> AttemptRuntime:
        local_tools = [tool for tool in task.tools if tool.kind == "local_mcp"]
        if not local_tools:
            return AttemptRuntime(None, None, None, None, {})
        await self.ping()
        has_browser = any(tool.app_id == "browser" for tool in local_tools)
        network_name = self._network_name(task, attempt, fingerprint)
        egress_network_name = (
            self._egress_network_name(task, attempt, fingerprint) if has_browser else None
        )
        if await self._inspect_network(network_name) is not None:
            raise AppInfrastructureError(f"task network already exists before prepare: {network_name}")
        network_id = await self._create_network(
            task,
            attempt=attempt,
            fingerprint=fingerprint,
            network_name=network_name,
            internal=True,
            role="task",
        )
        egress_network_id: str | None = None
        if egress_network_name is not None:
            if await self._inspect_network(egress_network_name) is not None:
                await self._remove_network(network_name)
                raise AppInfrastructureError(
                    f"task egress network already exists before prepare: {egress_network_name}"
                )
            egress_network_id = await self._create_network(
                task,
                attempt=attempt,
                fingerprint=fingerprint,
                network_name=egress_network_name,
                internal=False,
                role="egress",
            )
        resources: dict[str, RuntimeResource] = {}
        connected_gateways: list[str] = []
        created_containers: list[str] = []
        try:
            for tool in local_tools:
                environment_id = environments[tool.app_id]
                container_name = self._container_name(tool.app_id, environment_id)
                if await self._inspect_container(container_name) is not None:
                    raise AppInfrastructureError(
                        f"task container already exists before prepare: {container_name}"
                    )
                backend_token = self.backend_token(control_token, tool.app_id, environment_id)
                config = self._container_config(
                    task,
                    app_id=tool.app_id,
                    attempt=attempt,
                    environment_id=environment_id,
                    fingerprint=fingerprint,
                    network_name=network_name,
                    egress_network_name=egress_network_name,
                    backend_token=backend_token,
                    container_name=container_name,
                )
                response = await self._request(
                    "POST",
                    f"/containers/create?name={quote(container_name, safe='')}",
                    expected={201},
                    json_body=config,
                )
                value = response.json()
                container_id = value.get("Id") if isinstance(value, dict) else None
                if not isinstance(container_id, str) or not container_id:
                    raise AppInfrastructureError("Docker container create returned no id")
                created_containers.append(container_name)
                if tool.app_id == "browser":
                    await self._connect(network_name, container_id)
                await self._request(
                    "POST",
                    f"/containers/{quote(container_id, safe='')}/start",
                    expected={204, 304},
                )
                if tool.app_id == "code-workspace":
                    archive = build_workspace_archive(task.initial_workspace, task.attachments)
                    if archive:
                        await self._request(
                            "PUT",
                            f"/containers/{quote(container_id, safe='')}/archive?path=%2Fworkspace",
                            expected={200},
                            content=archive,
                            headers={"content-type": "application/x-tar"},
                        )
                gateway = self._gateway_container(tool.app_id)
                await self._connect(network_name, gateway)
                connected_gateways.append(gateway)
                inspected = await self._inspect_container(container_id)
                if inspected is None:
                    raise AppInfrastructureError(f"created container disappeared: {container_name}")
                image_id = inspected.get("Image")
                config_inspect = inspected.get("Config")
                image = config_inspect.get("Image") if isinstance(config_inspect, dict) else None
                if not isinstance(image_id, str) or not isinstance(image, str):
                    raise AppInfrastructureError("Docker inspect omitted image provenance")
                resources[tool.app_id] = RuntimeResource(
                    tool.app_id,
                    environment_id,
                    container_name,
                    container_id,
                    image,
                    image_id,
                    f"http://{container_name}:8000",
                    backend_token,
                )
            return AttemptRuntime(
                network_name,
                network_id,
                egress_network_name,
                egress_network_id,
                resources,
            )
        except Exception:
            for container in reversed(created_containers):
                try:
                    await self._remove_container(container)
                except Exception:
                    pass
            for gateway in reversed(connected_gateways):
                try:
                    await self._disconnect(network_name, gateway)
                except Exception:
                    pass
            try:
                await self._remove_network(network_name)
            except Exception:
                pass
            if egress_network_name is not None:
                try:
                    await self._remove_network(egress_network_name)
                except Exception:
                    pass
            raise

    async def discover(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
        control_token: str,
    ) -> AttemptRuntime:
        local_tools = [tool for tool in task.tools if tool.kind == "local_mcp"]
        if not local_tools:
            return AttemptRuntime(None, None, None, None, {})
        await self.ping()
        has_browser = any(tool.app_id == "browser" for tool in local_tools)
        network_name = self._network_name(task, attempt, fingerprint)
        egress_network_name = (
            self._egress_network_name(task, attempt, fingerprint) if has_browser else None
        )
        network = await self._inspect_network(network_name)
        if network is None:
            raise AppInfrastructureError("the exact task network is unavailable for recovery")
        network_id = network.get("Id")
        if not isinstance(network_id, str) or not network_id:
            raise AppInfrastructureError("Docker network inspect omitted id")
        egress_network_id: str | None = None
        if egress_network_name is not None:
            egress_network = await self._inspect_network(egress_network_name)
            if egress_network is None:
                raise AppInfrastructureError(
                    "the exact task egress network is unavailable for recovery"
                )
            value = egress_network.get("Id")
            if not isinstance(value, str) or not value:
                raise AppInfrastructureError("Docker egress network inspect omitted id")
            egress_network_id = value
        resources: dict[str, RuntimeResource] = {}
        for tool in local_tools:
            environment_id = environments[tool.app_id]
            container_name = self._container_name(tool.app_id, environment_id)
            inspected = await self._inspect_container(container_name)
            if inspected is None:
                raise AppInfrastructureError(
                    f"the exact {tool.app_id} container is unavailable for recovery"
                )
            self._verify_labels(
                inspected,
                task=task,
                app_id=tool.app_id,
                attempt=attempt,
                environment_id=environment_id,
                fingerprint=fingerprint,
            )
            state = inspected.get("State")
            if not isinstance(state, dict) or not state.get("Running"):
                raise AppInfrastructureError(f"recovery container is not running: {container_name}")
            networks = inspected.get("NetworkSettings", {}).get("Networks", {})
            if not isinstance(networks, dict) or network_name not in networks:
                raise AppInfrastructureError(f"recovery container is detached from task network: {container_name}")
            if (
                tool.app_id == "browser"
                and (egress_network_name is None or egress_network_name not in networks)
            ):
                raise AppInfrastructureError("recovery browser container lost its task egress network")
            await self._connect(network_name, self._gateway_container(tool.app_id))
            image_id = inspected.get("Image")
            config_inspect = inspected.get("Config")
            image = config_inspect.get("Image") if isinstance(config_inspect, dict) else None
            if not isinstance(image_id, str) or not isinstance(image, str):
                raise AppInfrastructureError("Docker inspect omitted image provenance")
            resources[tool.app_id] = RuntimeResource(
                tool.app_id,
                environment_id,
                container_name,
                str(inspected.get("Id", container_name)),
                image,
                image_id,
                f"http://{container_name}:8000",
                self.backend_token(control_token, tool.app_id, environment_id),
            )
        return AttemptRuntime(
            network_name,
            network_id,
            egress_network_name,
            egress_network_id,
            resources,
        )

    async def snapshot(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
        control_token: str,
    ) -> dict[str, Any]:
        runtime = await self.discover(
            task,
            environments,
            fingerprint,
            attempt=attempt,
            control_token=control_token,
        )
        return runtime.metadata()

    async def destroy(
        self,
        task: BenchmarkTask,
        environments: dict[str, str],
        fingerprint: str,
        *,
        attempt: int,
    ) -> None:
        local_tools = [tool for tool in task.tools if tool.kind == "local_mcp"]
        if not local_tools:
            return
        network_name = self._network_name(task, attempt, fingerprint)
        has_browser = any(tool.app_id == "browser" for tool in local_tools)
        egress_network_name = (
            self._egress_network_name(task, attempt, fingerprint) if has_browser else None
        )
        errors: list[str] = []
        for tool in reversed(local_tools):
            container_name = self._container_name(tool.app_id, environments[tool.app_id])
            try:
                await self._remove_container(container_name)
            except AppInfrastructureError as exc:
                errors.append(str(exc))
        for tool in reversed(local_tools):
            try:
                await self._disconnect(network_name, self._gateway_container(tool.app_id))
            except AppInfrastructureError as exc:
                errors.append(str(exc))
        try:
            await self._remove_network(network_name)
        except AppInfrastructureError as exc:
            errors.append(str(exc))
        if egress_network_name is not None:
            try:
                await self._remove_network(egress_network_name)
            except AppInfrastructureError as exc:
                errors.append(str(exc))
        if errors:
            raise AppInfrastructureError("; ".join(errors))

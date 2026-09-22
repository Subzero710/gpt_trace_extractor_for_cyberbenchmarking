from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from .exceptions import AppInfrastructureError
from .models import BenchmarkTask

MANAGED_LABEL = "gpttrace.managed"
TASK_LABEL = "gpttrace.task_id"
ATTEMPT_LABEL = "gpttrace.attempt"
APP_LABEL = "gpttrace.app_id"
ENVIRONMENT_LABEL = "gpttrace.environment_id"
FINGERPRINT_LABEL = "gpttrace.task_fingerprint"
ROLE_LABEL = "gpttrace.role"


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
    browser_control_network_name: str | None = None
    browser_control_network_id: str | None = None
    relay_workspace_network_name: str | None = None
    relay_workspace_network_id: str | None = None
    relay_browser_network_name: str | None = None
    relay_browser_network_id: str | None = None
    relay: dict[str, Any] | None = None

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
            "browser_control_network": ({"name": self.browser_control_network_name, "id": self.browser_control_network_id} if self.browser_control_network_name else None),
            "relay_workspace_network": ({"name": self.relay_workspace_network_name, "id": self.relay_workspace_network_id} if self.relay_workspace_network_name else None),
            "relay_browser_network": ({"name": self.relay_browser_network_name, "id": self.relay_browser_network_id} if self.relay_browser_network_name else None),
            "relay": self.relay,
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
        file_relay_image: str = "gpt-trace-file-relay:latest",
        file_transfer_limits: dict[str, int] | None = None,
        workspace_gateway_container: str,
        browser_gateway_container: str,
        browser_environment: dict[str, str],
        browser_blocked_hosts: tuple[str, ...] = (),
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.workspace_image = workspace_image
        self.browser_image = browser_image
        self.file_relay_image = file_relay_image
        self.file_transfer_limits = dict(file_transfer_limits or {})
        self.workspace_gateway_container = workspace_gateway_container
        self.browser_gateway_container = browser_gateway_container
        self.browser_environment = dict(browser_environment)
        self.browser_blocked_hosts = tuple(
            sorted({host.casefold().rstrip(".") for host in browser_blocked_hosts if host.strip(".")})
        )
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

    @classmethod
    def _browser_control_network_name(cls, task: BenchmarkTask, attempt: int, fingerprint: str) -> str:
        return f"gpt-trace-browser-control-{cls._suffix(f'browser-control{chr(0)}{task.task_id}{chr(0)}{attempt}{chr(0)}{fingerprint}')}"

    @classmethod
    def _relay_network_name(cls, side: str, task: BenchmarkTask, attempt: int, fingerprint: str) -> str:
        return f"gpt-trace-relay-{side}-{cls._suffix(f'relay{chr(0)}{side}{chr(0)}{task.task_id}{chr(0)}{attempt}{chr(0)}{fingerprint}')}"

    @classmethod
    def _relay_container_name(cls, task: BenchmarkTask, attempt: int, fingerprint: str) -> str:
        return f"gpt-trace-file-relay-{cls._suffix(f'relay{chr(0)}{task.task_id}{chr(0)}{attempt}{chr(0)}{fingerprint}')}"

    @staticmethod
    def relay_token(control_token: str, task: BenchmarkTask, attempt: int, fingerprint: str, app_id: str, environment_id: str) -> str:
        message=f"file-relay\0{task.task_id}\0{attempt}\0{fingerprint}\0{app_id}\0{environment_id}".encode()
        return hmac.new(control_token.encode(),message,hashlib.sha256).hexdigest()

    @staticmethod
    def backend_token(control_token: str, app_id: str, environment_id: str) -> str:
        message = f"backend\0{app_id}\0{environment_id}".encode("utf-8")
        return hmac.new(control_token.encode("utf-8"), message, hashlib.sha256).hexdigest()

    @staticmethod
    def _browser_fingerprint_seed(
        task: BenchmarkTask,
        attempt: int,
        fingerprint: str,
    ) -> int:
        raw = f"browser-fingerprint\0{task.task_id}\0{attempt}\0{fingerprint}"
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % 2_000_000_000 + 1

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
        relay_url: str | None = None,
        relay_token: str | None = None,
    ) -> dict[str, Any]:
        env = [
            f"APP_CONTROL_TOKEN={backend_token}",
            f"MCP_ALLOWED_HOSTS={container_name}:8000,localhost:8000",
        ]
        if relay_url and relay_token:
            env += [f"FILE_RELAY_URL={relay_url}",f"FILE_RELAY_TOKEN={relay_token}",f"FILE_RELAY_APP_ID={app_id}",f"FILE_RELAY_MAX_FILE_BYTES={self.file_transfer_limits.get('max_file_bytes',134217728)}"]
        if app_id == "code-workspace":
            env += [
                "CODE_WORKSPACE_ROOT=/workspace",
                "CODE_WORKSPACE_STATE_ROOT=/state",
            ]
            host_config: dict[str, Any] = {
                "ReadonlyRootfs": False,
                "Init": True,
                "Privileged": False,
                "CapDrop": ["AUDIT_WRITE", "MKNOD", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"],
                "SecurityOpt": ["no-new-privileges"],
                "PidsLimit": 160,
                "Memory": 2 * 1024 * 1024 * 1024,
                "NanoCpus": 2_000_000_000,
                "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
                "Tmpfs": {
                    "/workspace": "rw,nosuid,nodev,size=2147483648,mode=0770,uid=0,gid=0",
                    "/state": "rw,nosuid,nodev,noexec,size=16777216,mode=0700,uid=0,gid=0",
                    "/tmp": "rw,nosuid,nodev,noexec,size=268435456,mode=1777,uid=0,gid=0",
                },
                "NetworkMode": network_name,
            }
        else:
            env.append(
                f"APP_BROWSER_FINGERPRINT_SEED={self._browser_fingerprint_seed(task, attempt, fingerprint)}"
            )
            for key, value in sorted(self.browser_environment.items()):
                if key == "APP_BROWSER_FINGERPRINT_SEED":
                    continue
                if value != "":
                    env.append(f"{key}={value}")
            if self.browser_blocked_hosts:
                env.append(
                    "APP_BROWSER_BLOCKED_HOSTS=" + ",".join(self.browser_blocked_hosts)
                )
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
        config: dict[str, Any] = {
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
            "NetworkingConfig": {
                "EndpointsConfig": {
                    primary_network: (
                        {"GwPriority": 1}
                        if app_id == "browser"
                        else {}
                    )
                }
            },
        }
        if app_id == "code-workspace":
            config["User"] = "0:0"
        return config

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

    @staticmethod
    def _backend_url_from_inspect(
        inspected: dict[str, Any],
        *,
        network_name: str,
        container_name: str,
    ) -> str:
        network_settings = inspected.get("NetworkSettings")
        networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        endpoint = networks.get(network_name) if isinstance(networks, dict) else None
        address = endpoint.get("IPAddress") if isinstance(endpoint, dict) else None
        if not isinstance(address, str) or not address:
            raise AppInfrastructureError(
                "Docker inspect omitted the task-network backend IP: "
                f"{container_name} on {network_name}"
            )
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise AppInfrastructureError(
                "Docker inspect returned an invalid task-network backend IP: "
                f"{container_name} -> {address!r}"
            ) from exc
        if parsed.version != 4:
            raise AppInfrastructureError(
                "task backend must currently have an IPv4 address: "
                f"{container_name} -> {address!r}"
            )
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            raise AppInfrastructureError(
                "Docker inspect returned an unusable task-network backend IP: "
                f"{container_name} -> {address!r}"
            )
        return f"http://{parsed.compressed}:8000"

    async def _connect(
        self,
        network_name: str,
        container: str,
        *,
        aliases: list[str] | None = None,
        gw_priority: int | None = None,
    ) -> None:
        body: dict[str, Any] = {"Container": container}
        endpoint: dict[str, Any] = {}
        if aliases:
            endpoint["Aliases"] = aliases
        if gw_priority is not None:
            endpoint["GwPriority"] = gw_priority
        if endpoint:
            body["EndpointConfig"] = endpoint
        response = await self._request(
            "POST",
            f"/networks/{quote(network_name, safe='')}/connect",
            expected={200, 403, 404},
            json_body=body,
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
            expected={200, 403, 404, 500},
            json_body={"Container": container, "Force": True},
        )
        if response.status_code in {403, 500}:
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

    async def _wait_healthy(self, container: str, timeout_seconds: float = 25.0) -> None:
        deadline=asyncio.get_running_loop().time()+timeout_seconds
        while True:
            info=await self._inspect_container(container)
            if info is None or not info.get("State",{}).get("Running"):
                raise AppInfrastructureError("file relay exited during readiness")
            status=info.get("State",{}).get("Health",{}).get("Status")
            if status=="healthy":return
            if status=="unhealthy":raise AppInfrastructureError("file relay healthcheck failed")
            if asyncio.get_running_loop().time()>=deadline:raise AppInfrastructureError("file relay readiness timed out")
            await asyncio.sleep(.25)

    async def create(
        self, task: BenchmarkTask, environments: dict[str,str], fingerprint: str, *,
        attempt: int, control_token: str,
    ) -> AttemptRuntime:
        local_tools=[t for t in task.tools if t.kind=="local_mcp"]
        if not local_tools:return AttemptRuntime(None,None,None,None,{})
        await self.ping()
        ids={t.app_id for t in local_tools}; has_browser="browser" in ids; transfer=ids=={"browser","code-workspace"}
        workspace_net=self._network_name(task,attempt,fingerprint)
        browser_net=self._browser_control_network_name(task,attempt,fingerprint) if has_browser else None
        egress=self._egress_network_name(task,attempt,fingerprint) if has_browser else None
        relay_w=self._relay_network_name("workspace",task,attempt,fingerprint) if transfer else None
        relay_b=self._relay_network_name("browser",task,attempt,fingerprint) if transfer else None
        names=[n for n in (workspace_net,browser_net,egress,relay_w,relay_b) if n]
        for n in names:
            if await self._inspect_network(n) is not None:raise AppInfrastructureError(f"attempt network already exists before prepare: {n}")
        made=[]; connected=[]; containers=[]
        async def mk(name,internal,role):
            nid=await self._create_network(task,attempt=attempt,fingerprint=fingerprint,network_name=name,internal=internal,role=role);made.append(name);return nid
        try:
            workspace_id=await mk(workspace_net,False,"workspace-control")
            browser_id=await mk(browser_net,True,"browser-control") if browser_net else None
            egress_id=await mk(egress,False,"egress") if egress else None
            relay_w_id=await mk(relay_w,True,"relay-workspace") if relay_w else None
            relay_b_id=await mk(relay_b,True,"relay-browser") if relay_b else None
            relay_meta=None
            if transfer:
                relay_name=self._relay_container_name(task,attempt,fingerprint)
                wt=self.relay_token(control_token,task,attempt,fingerprint,"code-workspace",environments["code-workspace"])
                bt=self.relay_token(control_token,task,attempt,fingerprint,"browser",environments["browser"])
                env=[f"FILE_RELAY_TASK_ID={task.task_id}",f"FILE_RELAY_ATTEMPT={attempt}",
                     f"FILE_RELAY_WORKSPACE_TOKEN={wt}",f"FILE_RELAY_BROWSER_TOKEN={bt}"]
                mapping={"max_file_bytes":"MAX_FILE_BYTES","max_total_bytes":"MAX_TOTAL_BYTES","max_objects":"MAX_OBJECTS",
                         "max_concurrent_uploads":"MAX_CONCURRENT_UPLOADS","max_concurrent_downloads":"MAX_CONCURRENT_DOWNLOADS","ttl_seconds":"TTL_SECONDS"}
                for k,suffix in mapping.items():
                    if k in self.file_transfer_limits:env.append(f"FILE_RELAY_{suffix}={self.file_transfer_limits[k]}")
                relay_quota=int(self.file_transfer_limits.get("max_total_bytes",268435456))
                relay_tmpfs=relay_quota+67108864
                relay_memory=relay_tmpfs+268435456
                cfg={"Image":self.file_relay_image,"User":"65532:65532","Env":env,
                     "Labels":{MANAGED_LABEL:"true",TASK_LABEL:task.task_id,ATTEMPT_LABEL:str(attempt),FINGERPRINT_LABEL:fingerprint,ROLE_LABEL:"file-relay"},
                     "ExposedPorts":{"8080/tcp":{}},"HostConfig":{"ReadonlyRootfs":True,"Init":True,"CapDrop":["ALL"],
                       "SecurityOpt":["no-new-privileges"],"PidsLimit":64,"Memory":relay_memory,"NanoCpus":500000000,
                       "Ulimits":[{"Name":"nofile","Soft":256,"Hard":256}],
                       "Tmpfs":{"/data":f"rw,nosuid,nodev,noexec,size={relay_tmpfs},mode=0700,uid=65532,gid=65532",
                                "/tmp":"rw,nosuid,nodev,noexec,size=16777216,mode=1777"},
                       "NetworkMode":relay_w},
                     "NetworkingConfig":{"EndpointsConfig":{relay_w:{"Aliases":["file-relay"]}}}}
                resp=await self._request("POST",f"/containers/create?name={quote(relay_name,safe='')}",expected={201},json_body=cfg)
                rid=resp.json().get("Id");containers.append(relay_name)
                await self._request("POST",f"/containers/{quote(rid,safe='')}/start",expected={204,304})
                await self._connect(relay_b,relay_name,aliases=["file-relay"],gw_priority=0)
                await self._wait_healthy(relay_name)
                ri=await self._inspect_container(relay_name)
                relay_meta={"container_name":relay_name,"container_id":rid,"image":self.file_relay_image,"image_id":ri.get("Image") if ri else None}
            resources={}
            for tool in local_tools:
                app=tool.app_id; env_id=environments[app]; cname=self._container_name(app,env_id)
                if await self._inspect_container(cname) is not None:raise AppInfrastructureError(f"task container already exists before prepare: {cname}")
                app_net=browser_net if app=="browser" else workspace_net
                token=self.backend_token(control_token,app,env_id)
                relay_url="http://file-relay:8080" if transfer else None
                rtok=self.relay_token(control_token,task,attempt,fingerprint,app,env_id) if transfer else None
                cfg=self._container_config(task,app_id=app,attempt=attempt,environment_id=env_id,fingerprint=fingerprint,
                    network_name=app_net,egress_network_name=egress if app=="browser" else None,backend_token=token,container_name=cname,
                    relay_url=relay_url,relay_token=rtok)
                resp=await self._request("POST",f"/containers/create?name={quote(cname,safe='')}",expected={201},json_body=cfg)
                cid=resp.json().get("Id");containers.append(cname)
                await self._request("POST",f"/containers/{quote(cid,safe='')}/start",expected={204,304})
                if app=="browser":await self._connect(browser_net,cname,aliases=[cname],gw_priority=0)
                if transfer:await self._connect(relay_b if app=="browser" else relay_w,cname,gw_priority=0)
                gateway=self._gateway_container(app);await self._connect(app_net,gateway);connected.append((app_net,gateway))
                inspected=await self._inspect_container(cid)
                image_id=inspected.get("Image"); image=inspected.get("Config",{}).get("Image")
                backend=self._backend_url_from_inspect(inspected,network_name=app_net,container_name=cname)
                resources[app]=RuntimeResource(app,env_id,cname,cid,image,image_id,backend,token)
            return AttemptRuntime(workspace_net,workspace_id,egress,egress_id,resources,browser_net,browser_id,relay_w,relay_w_id,relay_b,relay_b_id,relay_meta)
        except Exception:
            for c in reversed(containers):
                try:await self._remove_container(c)
                except Exception:pass
            for n,g in reversed(connected):
                try:await self._disconnect(n,g)
                except Exception:pass
            for n in reversed(made):
                try:await self._remove_network(n)
                except Exception:pass
            raise

    async def discover(self,task:BenchmarkTask,environments:dict[str,str],fingerprint:str,*,attempt:int,control_token:str)->AttemptRuntime:
        local=[t for t in task.tools if t.kind=="local_mcp"]
        if not local:return AttemptRuntime(None,None,None,None,{})
        await self.ping();ids={t.app_id for t in local};has_browser="browser" in ids;transfer=ids=={"browser","code-workspace"}
        wn=self._network_name(task,attempt,fingerprint);bn=self._browser_control_network_name(task,attempt,fingerprint) if has_browser else None
        en=self._egress_network_name(task,attempt,fingerprint) if has_browser else None
        rw=self._relay_network_name("workspace",task,attempt,fingerprint) if transfer else None;rb=self._relay_network_name("browser",task,attempt,fingerprint) if transfer else None
        async def net(name):
            if not name:return None,None
            x=await self._inspect_network(name)
            if x is None:raise AppInfrastructureError(f"recovery network unavailable: {name}")
            return name,x.get("Id")
        _,wid=await net(wn);_,bid=await net(bn);_,eid=await net(en);_,rwid=await net(rw);_,rbid=await net(rb)
        relay_meta=None
        if transfer:
            rn=self._relay_container_name(task,attempt,fingerprint);ri=await self._inspect_container(rn)
            if ri is None or not ri.get("State",{}).get("Running"):raise AppInfrastructureError("recovery file relay is unavailable")
            if ri.get("State",{}).get("Health",{}).get("Status")!="healthy":raise AppInfrastructureError("recovery file relay is unhealthy")
            labels=ri.get("Config",{}).get("Labels",{})
            expected={MANAGED_LABEL:"true",TASK_LABEL:task.task_id,ATTEMPT_LABEL:str(attempt),FINGERPRINT_LABEL:fingerprint,ROLE_LABEL:"file-relay"}
            if any(labels.get(k)!=v for k,v in expected.items()):raise AppInfrastructureError("file relay identity mismatch")
            nets=ri.get("NetworkSettings",{}).get("Networks",{})
            if rw not in nets or rb not in nets:raise AppInfrastructureError("file relay lost transfer network")
            relay_meta={"container_name":rn,"container_id":ri.get("Id"),"image":ri.get("Config",{}).get("Image"),"image_id":ri.get("Image")}
        resources={}
        for tool in local:
            app=tool.app_id;env_id=environments[app];cname=self._container_name(app,env_id);ins=await self._inspect_container(cname)
            if ins is None:raise AppInfrastructureError(f"the exact {app} container is unavailable for recovery")
            self._verify_labels(ins,task=task,app_id=app,attempt=attempt,environment_id=env_id,fingerprint=fingerprint)
            if not ins.get("State",{}).get("Running"):raise AppInfrastructureError(f"recovery container is not running: {cname}")
            appnet=bn if app=="browser" else wn;nets=ins.get("NetworkSettings",{}).get("Networks",{})
            if appnet not in nets:raise AppInfrastructureError(f"recovery container lost control network: {cname}")
            if app=="browser" and en not in nets:raise AppInfrastructureError("recovery browser lost egress network")
            if transfer and (rb if app=="browser" else rw) not in nets:raise AppInfrastructureError("recovery runtime lost relay network")
            await self._connect(appnet,self._gateway_container(app))
            resources[app]=RuntimeResource(app,env_id,cname,str(ins.get("Id",cname)),ins.get("Config",{}).get("Image"),ins.get("Image"),
              self._backend_url_from_inspect(ins,network_name=appnet,container_name=cname),self.backend_token(control_token,app,env_id))
        return AttemptRuntime(wn,wid,en,eid,resources,bn,bid,rw,rwid,rb,rbid,relay_meta)

    async def assert_absent(self,task:BenchmarkTask,environments:dict[str,str],fingerprint:str,*,attempt:int)->None:
        residue=[];ids={t.app_id for t in task.tools if t.kind=="local_mcp"};has_browser="browser" in ids;transfer=ids=={"browser","code-workspace"}
        nets=[self._network_name(task,attempt,fingerprint)]
        if has_browser:nets += [self._browser_control_network_name(task,attempt,fingerprint),self._egress_network_name(task,attempt,fingerprint)]
        if transfer:nets += [self._relay_network_name("workspace",task,attempt,fingerprint),self._relay_network_name("browser",task,attempt,fingerprint)]
        for n in nets:
            if await self._inspect_network(n) is not None:residue.append("network:"+n)
        for t in task.tools:
            if t.kind=="local_mcp":
                n=self._container_name(t.app_id,environments[t.app_id])
                if await self._inspect_container(n) is not None:residue.append("container:"+n)
        if transfer:
            n=self._relay_container_name(task,attempt,fingerprint)
            if await self._inspect_container(n) is not None:residue.append("container:"+n)
        if residue:raise AppInfrastructureError("runtime cleanup residue remains after reset: "+", ".join(residue))

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

    async def destroy(self,task:BenchmarkTask,environments:dict[str,str],fingerprint:str,*,attempt:int)->None:
        local=[t for t in task.tools if t.kind=="local_mcp"]
        if not local:return
        ids={t.app_id for t in local};has_browser="browser" in ids;transfer=ids=={"browser","code-workspace"};errors=[]
        wn=self._network_name(task,attempt,fingerprint);bn=self._browser_control_network_name(task,attempt,fingerprint) if has_browser else None
        en=self._egress_network_name(task,attempt,fingerprint) if has_browser else None
        rw=self._relay_network_name("workspace",task,attempt,fingerprint) if transfer else None;rb=self._relay_network_name("browser",task,attempt,fingerprint) if transfer else None
        for t in reversed(local):
            try:await self._remove_container(self._container_name(t.app_id,environments[t.app_id]))
            except AppInfrastructureError as e:errors.append(str(e))
        if transfer:
            try:await self._remove_container(self._relay_container_name(task,attempt,fingerprint))
            except AppInfrastructureError as e:errors.append(str(e))
        for t in reversed(local):
            try:await self._disconnect(bn if t.app_id=="browser" else wn,self._gateway_container(t.app_id))
            except AppInfrastructureError as e:errors.append(str(e))
        for n in (rw,rb,bn,wn,en):
            if n:
                try:await self._remove_network(n)
                except AppInfrastructureError as e:errors.append(str(e))
        if errors:raise AppInfrastructureError("; ".join(errors))

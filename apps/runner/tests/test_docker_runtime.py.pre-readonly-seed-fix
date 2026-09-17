import io
import json
import tarfile
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from gpt_trace_runner.docker_runtime import DockerRuntime
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool


class DockerMock:
    def __init__(self):
        self.networks = {}
        self.containers = {}
        self.ids = {}
        self.created_configs = {}
        self.archives = {}
        self.gateway_connects = []
        self.deleted_containers = []
        self.deleted_networks = []

    def _container(self, value):
        name = self.ids.get(value, value)
        return self.containers.get(name)

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path
        if method == "GET" and path == "/_ping":
            return httpx.Response(200, text="OK", request=request)

        if path.startswith("/networks/") and method == "GET":
            name = path.split("/", 2)[2]
            item = self.networks.get(name)
            return httpx.Response(200, json=item, request=request) if item else httpx.Response(404, request=request)

        if path == "/networks/create" and method == "POST":
            body = json.loads(request.content)
            name = body["Name"]
            if name in self.networks:
                return httpx.Response(409, text="exists", request=request)
            item = {
                "Id": f"net-{len(self.networks)+1}",
                "Name": name,
                "Internal": body["Internal"],
                "Labels": body.get("Labels", {}),
            }
            self.networks[name] = item
            return httpx.Response(201, json={"Id": item["Id"]}, request=request)

        if path.startswith("/networks/") and path.endswith("/connect") and method == "POST":
            name = path.split("/")[2]
            body = json.loads(request.content)
            container = body["Container"]
            item = self._container(container)
            if item is not None:
                item["NetworkSettings"]["Networks"][name] = {}
            else:
                self.gateway_connects.append((name, container))
            return httpx.Response(200, request=request)

        if path.startswith("/networks/") and path.endswith("/disconnect") and method == "POST":
            name = path.split("/")[2]
            body = json.loads(request.content)
            self.gateway_connects.append((f"disconnect:{name}", body["Container"]))
            return httpx.Response(200, request=request)

        if path.startswith("/networks/") and method == "DELETE":
            name = path.split("/", 2)[2]
            self.networks.pop(name, None)
            self.deleted_networks.append(name)
            return httpx.Response(204, request=request)

        if path == "/containers/create" and method == "POST":
            name = request.url.params["name"]
            config = json.loads(request.content)
            cid = f"cid-{len(self.containers)+1}"
            primary = config["HostConfig"]["NetworkMode"]
            item = {
                "Id": cid,
                "Image": f"sha256:{name}",
                "Config": {"Image": config["Image"], "Labels": config["Labels"]},
                "State": {"Running": False},
                "NetworkSettings": {"Networks": {primary: {}}},
            }
            self.containers[name] = item
            self.ids[cid] = name
            self.created_configs[name] = config
            return httpx.Response(201, json={"Id": cid}, request=request)

        if path.startswith("/containers/") and path.endswith("/start") and method == "POST":
            cid = path.split("/")[2]
            item = self._container(cid)
            item["State"]["Running"] = True
            return httpx.Response(204, request=request)

        if path.startswith("/containers/") and path.endswith("/archive") and method == "PUT":
            cid = path.split("/")[2]
            self.archives[cid] = request.content
            return httpx.Response(200, request=request)

        if path.startswith("/containers/") and path.endswith("/json") and method == "GET":
            cid = path.split("/")[2]
            item = self._container(cid)
            return httpx.Response(200, json=item, request=request) if item else httpx.Response(404, request=request)

        if path.startswith("/containers/") and method == "DELETE":
            cid = path.split("/")[2]
            item = self._container(cid)
            if item is None:
                return httpx.Response(404, request=request)
            name = self.ids.get(cid, cid)
            if cid in self.ids:
                name = self.ids.pop(cid)
            else:
                # delete by name
                for key, val in list(self.ids.items()):
                    if val == cid:
                        self.ids.pop(key, None)
                name = cid
            self.containers.pop(name, None)
            self.deleted_containers.append((name, request.url.query.decode() if isinstance(request.url.query, bytes) else request.url.query))
            return httpx.Response(204, request=request)

        raise AssertionError(f"unhandled Docker request: {method} {request.url}")


def tool(app_id: str) -> BenchmarkTool:
    return BenchmarkTool(
        type="app",
        app_id=app_id,
        ui_name="Code Workspace" if app_id == "code-workspace" else "Browser",
        required=True,
        kind="local_mcp",
        version="1.0.0",
        manifest_sha256="m" * 64,
        tool_manifest={"app_id": app_id, "version": "1.0.0", "tools": []},
        mcp_endpoint=(
            "http://workspace-gateway:8000/mcp"
            if app_id == "code-workspace"
            else "http://browser-gateway:8000/mcp"
        ),
        control_endpoint=(
            "http://workspace-gateway:8000"
            if app_id == "code-workspace"
            else "http://browser-gateway:8000"
        ),
    )


def runtime(mock: DockerMock) -> DockerRuntime:
    client = httpx.AsyncClient(transport=httpx.MockTransport(mock), base_url="http://docker")
    return DockerRuntime(
        Path("/var/run/docker.sock"),
        workspace_image="gpt-trace-code-workspace:latest",
        browser_image="gpt-trace-browser:latest",
        workspace_gateway_container="gpt-trace-workspace-gateway",
        browser_gateway_container="gpt-trace-browser-gateway",
        browser_environment={"APP_BROWSER_FINGERPRINT_SEED": "123"},
        client=client,
    )


@pytest.mark.asyncio
async def test_attempt_creates_fresh_containers_and_private_networks_then_destroys_everything(tmp_path: Path) -> None:
    initial = tmp_path / "initial_workspace"
    initial.mkdir()
    (initial / "Cargo.toml").write_text("[package]\nname='x'\nversion='0.1.0'\n")
    attachment = tmp_path / "input.txt"
    attachment.write_text("hello")
    task = BenchmarkTask(
        "task-a", "prompt", (attachment,), (tool("code-workspace"), tool("browser")), initial
    )
    environments = {"code-workspace": "env-w", "browser": "env-b"}
    fp = "f" * 64
    mock = DockerMock()
    rt = runtime(mock)

    attempt = await rt.create(task, environments, fp, attempt=1, control_token="s" * 40)

    assert len(mock.containers) == 2
    assert attempt.network_name in mock.networks
    assert attempt.egress_network_name in mock.networks
    assert mock.networks[attempt.network_name]["Internal"] is True
    assert mock.networks[attempt.egress_network_name]["Internal"] is False

    workspace_name = rt._container_name("code-workspace", "env-w")
    browser_name = rt._container_name("browser", "env-b")
    workspace_cfg = mock.created_configs[workspace_name]
    browser_cfg = mock.created_configs[browser_name]
    assert workspace_cfg["HostConfig"]["NetworkMode"] == attempt.network_name
    assert browser_cfg["HostConfig"]["NetworkMode"] == attempt.egress_network_name
    assert attempt.network_name in mock.containers[browser_name]["NetworkSettings"]["Networks"]
    assert "Binds" not in workspace_cfg["HostConfig"]
    assert "Binds" not in browser_cfg["HostConfig"]
    assert "/var/run/docker.sock" not in json.dumps(workspace_cfg)
    assert "/var/run/docker.sock" not in json.dumps(browser_cfg)

    assert (attempt.network_name, "gpt-trace-workspace-gateway") in mock.gateway_connects
    assert (attempt.network_name, "gpt-trace-browser-gateway") in mock.gateway_connects

    workspace_id = attempt.resources["code-workspace"].container_id
    archive = mock.archives[workspace_id]
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
        names = sorted(member.name for member in tf.getmembers())
    assert "Cargo.toml" in names
    assert "attachments/input.txt" in names

    assert attempt.resources["code-workspace"].image_id.startswith("sha256:")
    assert attempt.resources["browser"].image_id.startswith("sha256:")

    await rt.destroy(task, environments, fp, attempt=1)
    assert mock.containers == {}
    assert attempt.network_name not in mock.networks
    assert attempt.egress_network_name not in mock.networks
    assert len(mock.deleted_containers) == 2
    assert all("force=true" in query and "v=true" in query for _, query in mock.deleted_containers)


@pytest.mark.asyncio
async def test_workspace_only_attempt_has_no_egress_network(tmp_path: Path) -> None:
    task = BenchmarkTask("task-w", "prompt", (), (tool("code-workspace"),), None)
    environments = {"code-workspace": "env-w"}
    mock = DockerMock()
    rt = runtime(mock)
    attempt = await rt.create(task, environments, "e" * 64, attempt=1, control_token="s" * 40)
    assert attempt.egress_network_name is None
    assert len(mock.networks) == 1
    assert next(iter(mock.networks.values()))["Internal"] is True


@pytest.mark.asyncio
async def test_recovery_requires_exact_existing_container_and_networks(tmp_path: Path) -> None:
    task = BenchmarkTask("task-b", "prompt", (), (tool("browser"),), None)
    environments = {"browser": "env-b"}
    fp = "d" * 64
    mock = DockerMock()
    rt = runtime(mock)
    created = await rt.create(task, environments, fp, attempt=3, control_token="s" * 40)
    recovered = await rt.discover(task, environments, fp, attempt=3, control_token="s" * 40)
    assert recovered.resources["browser"].container_id == created.resources["browser"].container_id

    mock.containers.clear()
    with pytest.raises(Exception, match="exact browser container"):
        await rt.discover(task, environments, fp, attempt=3, control_token="s" * 40)

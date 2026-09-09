import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from gpt_trace_runner.app_lifecycle import AppLifecycle
from gpt_trace_runner.benchmark import load_benchmark
from gpt_trace_runner.docker_runtime import AttemptRuntime, RuntimeResource
from gpt_trace_runner.exceptions import AppInfrastructureError
from gpt_trace_runner.models import task_fingerprint
from registry_helpers import make_registry


def task(tmp_path: Path):
    attachment = tmp_path / "repo.zip"
    attachment.write_bytes(b"zip")
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({
        "task_id": "t", "prompt": "x", "attachments": ["repo.zip"],
        "tools": [{"id": "code-workspace", "required": True}, {"id": "browser"}],
    }) + "\n")
    return load_benchmark(manifest, tasks_root=tmp_path, registry=make_registry(tmp_path))[0]


class Runtime:
    def __init__(self):
        self.calls = []

    async def close(self):
        self.calls.append(("close",))

    async def create(self, task, environments, fingerprint, *, attempt, control_token):
        self.calls.append(("create", attempt, dict(environments), fingerprint, control_token))
        resources = {
            "code-workspace": RuntimeResource(
                "code-workspace", environments["code-workspace"], "gpt-trace-workspace-1",
                "cid-w", "workspace:latest", "sha256:w", "http://gpt-trace-workspace-1:8000", "b" * 64,
            ),
            "browser": RuntimeResource(
                "browser", environments["browser"], "gpt-trace-browser-1",
                "cid-b", "browser:latest", "sha256:b", "http://gpt-trace-browser-1:8000", "c" * 64,
            ),
        }
        return AttemptRuntime("task-net", "nid", "egress-net", "eid", resources)

    async def discover(self, task, environments, fingerprint, *, attempt, control_token):
        self.calls.append(("discover", attempt, dict(environments), fingerprint, control_token))
        return await self.create(task, environments, fingerprint, attempt=attempt, control_token=control_token)

    async def snapshot(self, task, environments, fingerprint, *, attempt, control_token):
        self.calls.append(("snapshot", attempt))
        return {"apps": {"code-workspace": {"image_id": "sha256:w"}}}

    async def destroy(self, task, environments, fingerprint, *, attempt):
        self.calls.append(("destroy", attempt, dict(environments), fingerprint))


@pytest.mark.asyncio
async def test_prepare_resume_reset_bind_gateways_to_exact_attempt_runtime(tmp_path: Path) -> None:
    item = task(tmp_path)
    calls = []

    async def handler(request: httpx.Request):
        body = json.loads(request.content) if request.content else {}
        calls.append((request.url.host, request.url.path, body, request.headers.get("authorization")))
        if request.url.path.endswith("backend-health"):
            return httpx.Response(200, json={"status": "ok"}, request=request)
        if request.url.path == "/control/activate":
            return httpx.Response(200, json={
                "task_id": body["task_id"],
                "attempt": body["attempt"],
                "environment_id": body["environment_id"],
                "task_fingerprint": body["task_fingerprint"],
                "backend_url": body["backend_url"],
            }, request=request)
        if request.url.path == "/control/deactivate":
            return httpx.Response(200, json={**body, "status": "idle"}, request=request)
        return httpx.Response(200, json={
            "task_id": body["task_id"],
            "environment_id": body["environment_id"],
            "task_fingerprint": body["task_fingerprint"],
            "status": "ready",
        }, request=request)

    token = tmp_path / "token"
    token.write_text("s" * 40)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = Runtime()
    lifecycle = AppLifecycle(token, runtime=runtime, client=client)
    fingerprint = task_fingerprint(item)
    environments = lifecycle.environment_ids(item, attempt=2, fingerprint=fingerprint)

    await lifecycle.prepare(item, environments, fingerprint, attempt=2)
    await lifecycle.assert_resume(item, environments, fingerprint, attempt=2)
    metadata = await lifecycle.runtime_metadata(item, environments, fingerprint, attempt=2)
    await lifecycle.reset(item, environments, fingerprint, attempt=2)
    await client.aclose()

    assert list(environments) == ["code-workspace", "browser"]
    assert metadata["apps"]["code-workspace"]["image_id"] == "sha256:w"
    assert any(call[0] == "workspace-gateway" and call[1] == "/control/activate" for call in calls)
    assert any(call[0] == "browser-gateway" and call[1] == "/control/activate" for call in calls)
    assert all(call[3] == "Bearer " + "s" * 40 for call in calls)
    assert ("destroy", 2, environments, fingerprint) in runtime.calls


@pytest.mark.asyncio
async def test_gateway_failure_destroys_fresh_attempt_runtime(tmp_path: Path) -> None:
    item = task(tmp_path)
    token = tmp_path / "token"
    token.write_text("s" * 40)

    async def handler(request):
        return httpx.Response(409, text="already bound", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = Runtime()
    lifecycle = AppLifecycle(token, runtime=runtime, client=client)
    fingerprint = task_fingerprint(item)
    environments = lifecycle.environment_ids(item, attempt=1, fingerprint=fingerprint)
    with pytest.raises(AppInfrastructureError, match="409"):
        await lifecycle.prepare(item, environments, fingerprint, attempt=1)
    assert any(call[0] == "destroy" for call in runtime.calls)
    await client.aclose()


@pytest.mark.asyncio
async def test_control_token_is_never_sent_to_an_external_endpoint(tmp_path: Path) -> None:
    item = task(tmp_path)
    token = tmp_path / "token"
    token.write_text("s" * 40)
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={}, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lifecycle = AppLifecycle(token, runtime=Runtime(), client=client)
    changed = replace(item.tools[0], control_endpoint="https://attacker.example")
    with pytest.raises(AppInfrastructureError, match="internal"):
        await lifecycle._operation(item, changed, "env", task_fingerprint(item), "prepare")
    assert calls == 0
    await client.aclose()


def test_malformed_control_endpoint_is_rejected_as_infrastructure_error() -> None:
    with pytest.raises(AppInfrastructureError, match="invalid control endpoint"):
        AppLifecycle._validate_control_endpoint("browser", "http://[broken:8000")

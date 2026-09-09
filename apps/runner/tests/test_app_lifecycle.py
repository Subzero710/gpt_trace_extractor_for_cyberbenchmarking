import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from gpt_trace_runner.app_lifecycle import AppLifecycle
from gpt_trace_runner.benchmark import load_benchmark
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


@pytest.mark.asyncio
async def test_prepare_resume_reset_use_exact_environment_and_copy_only_to_workspace(tmp_path: Path) -> None:
    item = task(tmp_path)
    calls = []

    async def handler(request: httpx.Request):
        body = json.loads(request.content)
        calls.append((request.url.host, request.url.path, body, request.headers.get("authorization")))
        status = "idle" if request.url.path.endswith("/reset") else "ready"
        return httpx.Response(200, json={
            "task_id": body["task_id"],
            "environment_id": body["environment_id"],
            "task_fingerprint": body["task_fingerprint"],
            "status": status,
        }, request=request)

    token = tmp_path / "token"
    token.write_text("s" * 40)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lifecycle = AppLifecycle(token, client=client)
    fingerprint = task_fingerprint(item)
    environments = lifecycle.environment_ids(item, attempt=2, fingerprint=fingerprint)
    await lifecycle.prepare(item, environments, fingerprint)
    await lifecycle.assert_resume(item, environments, fingerprint)
    await lifecycle.reset(item, environments, fingerprint)
    await client.aclose()
    assert list(environments) == ["code-workspace", "browser"]
    workspace_prepare = next(call for call in calls if call[0] == "app-code-workspace" and call[1].endswith("prepare"))
    browser_prepare = next(call for call in calls if call[0] == "app-browser" and call[1].endswith("prepare"))
    assert workspace_prepare[2]["attachments"][0]["path"] == "attachments/repo.zip"
    assert "attachments" not in browser_prepare[2]
    assert all(call[3] == "Bearer " + "s" * 40 for call in calls)
    assert [call[0] for call in calls if call[1].endswith("reset")] == ["app-browser", "app-code-workspace"]


@pytest.mark.asyncio
async def test_control_failure_is_a_batch_circuit_breaker(tmp_path: Path) -> None:
    item = task(tmp_path)
    token = tmp_path / "token"
    token.write_text("s" * 40)
    async def handler(request):
        return httpx.Response(409, text="owned by another task", request=request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lifecycle = AppLifecycle(token, client=client)
    fingerprint = task_fingerprint(item)
    with pytest.raises(AppInfrastructureError, match="409"):
        await lifecycle.prepare(item, lifecycle.environment_ids(item, attempt=1, fingerprint=fingerprint), fingerprint)
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
    lifecycle = AppLifecycle(token, client=client)
    changed = replace(item.tools[0], control_endpoint="https://attacker.example")
    with pytest.raises(AppInfrastructureError, match="internal"):
        await lifecycle._operation(item, changed, "env", task_fingerprint(item), "prepare")
    assert calls == 0
    await client.aclose()


def test_malformed_control_endpoint_is_rejected_as_infrastructure_error() -> None:
    with pytest.raises(AppInfrastructureError, match="invalid control endpoint"):
        AppLifecycle._validate_control_endpoint("browser", "http://[broken:8000")

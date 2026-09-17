from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import AppInfrastructureError
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool
from gpt_trace_runner.runtime_preflight import preflight_tasks


def _tool() -> BenchmarkTool:
    return BenchmarkTool(
        type="app",
        app_id="code-workspace",
        ui_name="Code Workspace",
        required=True,
        kind="local_mcp",
        version="1.0.0",
        manifest_sha256="m" * 64,
        tool_manifest={"app_id": "code-workspace", "version": "1.0.0", "tools": []},
        mcp_endpoint="http://workspace-gateway:8000/mcp",
        control_endpoint="http://workspace-gateway:8000",
    )


class FakeLifecycle:
    def __init__(self, *, fail_prepare: bool = False) -> None:
        self.fail_prepare = fail_prepare
        self.calls: list[tuple] = []

    @staticmethod
    def environment_ids(task, *, attempt, fingerprint):
        return {"code-workspace": f"{task.task_id}-{attempt}-{fingerprint[:8]}"}

    async def health(self, task):
        self.calls.append(("health", task.task_id))

    async def prepare(self, task, environments, fingerprint, *, attempt):
        self.calls.append(("prepare", task.task_id, attempt, dict(environments)))
        if self.fail_prepare:
            raise AppInfrastructureError("prepare exploded")

    async def reset(self, task, environments, fingerprint, *, attempt):
        self.calls.append(("reset", task.task_id, attempt, dict(environments)))


@pytest.mark.asyncio
async def test_preflight_exercises_prepare_and_cleanup_without_chatgpt(tmp_path: Path) -> None:
    task = BenchmarkTask("real-task", "prompt", (), (_tool(),), None)
    lifecycle = FakeLifecycle()

    await preflight_tasks(lifecycle, [task], console=Console())

    names = [call[0] for call in lifecycle.calls]
    assert names == ["health", "prepare", "reset"]
    probe_ids = {call[1] for call in lifecycle.calls}
    assert len(probe_ids) == 1
    probe_id = next(iter(probe_ids))
    assert probe_id.startswith("doctor-1-")
    assert probe_id != task.task_id


@pytest.mark.asyncio
async def test_preflight_failure_still_cleans_up_and_fails(tmp_path: Path) -> None:
    task = BenchmarkTask("real-task", "prompt", (), (_tool(),), None)
    lifecycle = FakeLifecycle(fail_prepare=True)

    with pytest.raises(AppInfrastructureError, match="prepare exploded"):
        await preflight_tasks(lifecycle, [task], console=Console())

    assert [call[0] for call in lifecycle.calls] == ["health", "prepare", "reset"]

from __future__ import annotations

import os

from .models import TaskSpec, TeacherCampaign, run_task_id
from ..models import BenchmarkTask, BenchmarkTool


def campaign(settings) -> TeacherCampaign:
    build_id = os.environ.get("GPT_TRACE_RUNNER_BUILD_ID", "").strip()
    if not build_id:
        raise RuntimeError(
            "GPT_TRACE_RUNNER_BUILD_ID is required for Superbench campaign identity"
        )
    return TeacherCampaign(
        settings.chatgpt_expected_model_slug,
        {
            "conversation_turns": settings.chatgpt_conversation_turns,
            "turn_timeout_seconds": settings.chatgpt_turn_timeout_seconds,
        },
        build_id,
    )


def benchmark_tool(registry, app_id: str) -> BenchmarkTool:
    resolved = registry.resolve_id(app_id)
    return BenchmarkTool(
        type="app",
        app_id=resolved.app_id,
        ui_name=resolved.ui_name,
        # Superbench makes tools available; correctness belongs to the native
        # evaluator, not to a generic "must have called every app" rule.
        required=False,
        kind=resolved.kind,
        version=resolved.version,
        manifest_sha256=resolved.manifest_sha256,
        tool_manifest=resolved.manifest,
        mcp_endpoint=resolved.mcp_endpoint,
        control_endpoint=resolved.control_endpoint,
        attachment_mode=resolved.attachment_mode,
    )


def to_benchmark_task(task: TaskSpec, registry, campaign_id: str) -> BenchmarkTask:
    return BenchmarkTask(
        task_id=run_task_id(task.task_id, campaign_id),
        prompt=task.prompt,
        attachments=task.attachments,
        tools=tuple(benchmark_tool(registry, app_id) for app_id in task.tools),
        initial_workspace=task.initial_workspace,
    )


def storage_context(task: TaskSpec, camp: TeacherCampaign, adapter) -> dict:
    return {
        "logical_task_id": task.task_id,
        "dataset_metadata": {
            "task": dict(task.metadata),
            "teacher": {
                "expected_model": camp.expected_model,
                "configuration": camp.teacher_configuration,
                "runner_commit": camp.runner_commit,
            },
            "adapter": {
                "id": adapter.adapter_id,
                "version": adapter.adapter_version,
            },
            "campaign_id": camp.campaign_id,
        },
    }

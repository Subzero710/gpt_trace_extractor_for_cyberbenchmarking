from __future__ import annotations

import hashlib
import os

from .models import TaskSpec, TeacherCampaign, run_task_id, task_spec_fingerprint
from ..models import BenchmarkTask, BenchmarkTool, task_fingerprint


def campaign(settings) -> TeacherCampaign:
    # Keep execution settings and commit for provenance, but deliberately keep
    # them out of campaign identity. A timeout tweak or documentation commit
    # must not cause the same benchmark task to be collected again.
    return TeacherCampaign(
        settings.chatgpt_expected_model_slug,
        {
            "conversation_turns": settings.chatgpt_conversation_turns,
            "turn_timeout_seconds": settings.chatgpt_turn_timeout_seconds,
        },
        os.environ.get("GPT_TRACE_RUNNER_BUILD_ID", "").strip(),
    )


def benchmark_tool(registry, app_id: str) -> BenchmarkTool:
    resolved = registry.resolve_id(app_id)
    return BenchmarkTool(
        type="app",
        app_id=resolved.app_id,
        ui_name=resolved.ui_name,
        kind=resolved.kind,
        version=resolved.version,
        manifest_sha256=resolved.manifest_sha256,
        tool_manifest=resolved.manifest,
        mcp_endpoint=resolved.mcp_endpoint,
        control_endpoint=resolved.control_endpoint,
        attachment_mode=resolved.attachment_mode,
    )


def to_benchmark_task(task: TaskSpec, registry, camp: TeacherCampaign, adapter) -> BenchmarkTask:
    return BenchmarkTask(
        task_id=run_task_id(
            task.task_id,
            camp.campaign_id,
            adapter.adapter_id,
            adapter.adapter_version,
        ),
        prompt=task.prompt,
        attachments=task.attachments,
        tools=tuple(benchmark_tool(registry, app_id) for app_id in task.tools),
        initial_workspace=task.initial_workspace,
    )


def storage_context(task: TaskSpec, camp: TeacherCampaign, adapter, registry) -> dict:
    preview = to_benchmark_task(task, registry, camp, adapter)
    contract_fingerprint = hashlib.sha256(
        (task_spec_fingerprint(task) + ":" + task_fingerprint(preview)).encode("ascii")
    ).hexdigest()
    return {
        "logical_task_id": task.task_id,
        "dataset_metadata": {
            "task_contract_fingerprint": contract_fingerprint,
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

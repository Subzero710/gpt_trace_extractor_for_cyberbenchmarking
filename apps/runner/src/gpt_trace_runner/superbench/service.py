from __future__ import annotations
import os
from .models import TeacherCampaign, run_task_id
from ..models import BenchmarkTask, BenchmarkTool

def campaign(settings) -> TeacherCampaign:
    build_id=os.environ.get("GPT_TRACE_RUNNER_BUILD_ID","").strip()
    if not build_id: raise RuntimeError("GPT_TRACE_RUNNER_BUILD_ID is required for Superbench campaign identity")
    return TeacherCampaign(settings.chatgpt_expected_model_slug,{"conversation_turns":settings.chatgpt_conversation_turns,"turn_timeout_seconds":settings.chatgpt_turn_timeout_seconds},build_id)
def benchmark_tool(registry,app_id):
    a=registry.resolve_id(app_id); return BenchmarkTool(type="app",app_id=a.app_id,ui_name=a.ui_name,required=True,kind=a.kind,version=a.version,manifest_sha256=a.manifest_sha256,tool_manifest=a.manifest,mcp_endpoint=a.mcp_endpoint,control_endpoint=a.control_endpoint,attachment_mode=a.attachment_mode)
def to_benchmark_task(task,registry,campaign_id):
    return BenchmarkTask(task_id=run_task_id(task.canonical_task_id,campaign_id),prompt=task.prompt,attachments=task.attachments,tools=tuple(benchmark_tool(registry,x) for x in task.required_apps),initial_workspace=task.initial_workspace)
def start_metadata(task,camp):
    return {**task.provenance(),"campaign_id":camp.campaign_id,"teacher_metadata":{"expected_model":camp.expected_model,"configuration":camp.teacher_configuration,"runner_commit":camp.runner_commit},"adapter_id":task.adapter_id,"adapter_version":task.adapter_version}

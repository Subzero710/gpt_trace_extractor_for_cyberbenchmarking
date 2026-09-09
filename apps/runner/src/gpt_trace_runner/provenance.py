from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import BenchmarkTask, CapturedConversation, task_app_provenance


def invoked_tool_calls(
    messages: list[dict[str, Any]],
    *,
    task: BenchmarkTask | None = None,
) -> list[dict[str, str | None]]:
    by_ui_name = {
        tool.ui_name.casefold(): tool
        for tool in task.tools
    } if task is not None else {}
    calls: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, str | None, str | None, str | None]] = set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        metadata = message.get("metadata")
        resource = metadata.get("invoked_resource") if isinstance(metadata, dict) else None
        app_name = resource.get("app_name") if isinstance(resource, dict) else None
        tool_name = None
        if isinstance(resource, dict):
            for key in ("tool_name", "name", "operation"):
                value = resource.get(key)
                if isinstance(value, str) and value.strip():
                    tool_name = value.strip()
                    break
        if tool_name is None and isinstance(metadata, dict):
            value = metadata.get("tool_name")
            if isinstance(value, str) and value.strip():
                tool_name = value.strip()
        recipient = message.get("recipient")
        recipient = recipient.strip() if isinstance(recipient, str) and recipient.strip() else None
        app_name = app_name.strip() if isinstance(app_name, str) and app_name.strip() else None
        if app_name is None and tool_name is None and recipient is None:
            continue
        requested = by_ui_name.get(app_name.casefold()) if app_name is not None else None
        app_id = requested.app_id if requested is not None else None
        canonical_names = {
            item.get("name")
            for item in requested.tool_manifest.get("tools", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        } if requested is not None else set()
        canonical_name = tool_name if tool_name in canonical_names else None
        identity = (app_id, app_name, tool_name, recipient)
        if identity not in seen:
            calls.append({
                "app_id": app_id,
                "canonical_tool_name": canonical_name,
                "ui_app_name": app_name,
                "runtime_tool_name": tool_name,
                "recipient": recipient,
            })
            seen.add(identity)
    return calls


def enrich_capture(
    captured: CapturedConversation,
    *,
    task: BenchmarkTask,
    app_environments: dict[str, str],
) -> CapturedConversation:
    metadata = deepcopy(captured.runtime_metadata)
    metadata["requested_tools"] = [
        {
            "type": "app",
            "app_id": tool.app_id,
            "ui_name": tool.ui_name,
            "required": tool.required,
            "version": tool.version,
            "tool_manifest_sha256": tool.manifest_sha256,
        }
        for tool in task.tools
    ]
    metadata["app_provenance"] = task_app_provenance(task)
    metadata["app_environments"] = dict(sorted(app_environments.items()))
    metadata["used_tool_calls"] = invoked_tool_calls(captured.messages, task=task)
    return CapturedConversation(captured.conversation_id, captured.messages, metadata)

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import BenchmarkTask, CapturedConversation, task_app_provenance
from .workspace_seed import snapshot as workspace_snapshot


def _message_role(message: dict[str, Any]) -> str:
    author = message.get("author")
    role = author.get("role") if isinstance(author, dict) else message.get("role")
    return str(role or "")


def _alias(value: str | None) -> str:
    return "_".join(
        part for part in "".join(
            ch.lower() if ch.isalnum() else "_" for ch in str(value or "")
        ).split("_") if part
    )


def _manifest_names(tool: Any) -> set[str]:
    return {
        item["name"]
        for item in tool.tool_manifest.get("tools", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
    }


def _resolve_requested_identity(
    task: BenchmarkTask | None,
    *,
    app_name: str | None = None,
    tool_name: str | None = None,
    recipient: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    if task is None:
        return None, None, app_name

    requested = None
    if app_name:
        folded = app_name.casefold()
        for candidate in task.tools:
            if candidate.ui_name.casefold() == folded or candidate.app_id.casefold() == folded:
                requested = candidate
                break

    canonical_name = None
    if requested is not None and tool_name in _manifest_names(requested):
        canonical_name = tool_name

    if requested is None and tool_name:
        matches = [candidate for candidate in task.tools if tool_name in _manifest_names(candidate)]
        if len(matches) == 1:
            requested = matches[0]
            canonical_name = tool_name

    if recipient:
        head, separator, tail = recipient.rpartition(".")
        if separator:
            head_alias = _alias(head)
            matches: list[tuple[Any, str]] = []
            for candidate in task.tools:
                aliases = {_alias(candidate.app_id), _alias(candidate.ui_name)}
                if not any(
                    head_alias == alias or head_alias.endswith("_" + alias)
                    for alias in aliases if alias
                ):
                    continue
                for manifest_name in _manifest_names(candidate):
                    if tail == manifest_name:
                        matches.append((candidate, manifest_name))
            if len(matches) == 1:
                requested, canonical_name = matches[0]

    return (
        requested.app_id if requested is not None else None,
        canonical_name,
        requested.ui_name if requested is not None else app_name,
    )


def _resource_observation(
    message: dict[str, Any],
    *,
    task: BenchmarkTask | None,
) -> dict[str, str | None]:
    metadata = message.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    resource = metadata.get("invoked_resource")
    resource = resource if isinstance(resource, dict) else {}

    app_name = resource.get("app_name")
    app_name = app_name.strip() if isinstance(app_name, str) and app_name.strip() else None
    tool_name = None
    for key in ("tool_name", "name", "operation"):
        value = resource.get(key)
        if isinstance(value, str) and value.strip():
            tool_name = value.strip()
            break
    if tool_name is None:
        value = metadata.get("tool_name")
        if isinstance(value, str) and value.strip():
            tool_name = value.strip()

    recipient = message.get("recipient")
    recipient = recipient.strip() if isinstance(recipient, str) and recipient.strip() else None
    app_id, canonical_name, resolved_ui_name = _resolve_requested_identity(
        task, app_name=app_name, tool_name=tool_name, recipient=recipient
    )
    return {
        "app_id": app_id,
        "canonical_tool_name": canonical_name,
        "ui_app_name": resolved_ui_name or app_name,
        "runtime_tool_name": tool_name,
        "recipient": recipient,
    }


def _merge_call(call: dict[str, str | None], observation: dict[str, str | None]) -> None:
    for key in (
        "app_id", "canonical_tool_name", "ui_app_name", "runtime_tool_name", "recipient"
    ):
        value = observation.get(key)
        if value and not call.get(key):
            call[key] = value


def _compatible(call: dict[str, str | None], observation: dict[str, str | None]) -> bool:
    for key in ("app_id", "canonical_tool_name"):
        left, right = call.get(key), observation.get(key)
        if left and right and left != right:
            return False
    runtime = observation.get("runtime_tool_name")
    recipient = call.get("recipient")
    if runtime and recipient and "." in recipient and recipient.rsplit(".", 1)[-1] != runtime:
        canonical = call.get("canonical_tool_name")
        if canonical != runtime:
            return False
    return True


def invoked_tool_calls(
    messages: list[dict[str, Any]],
    *,
    task: BenchmarkTask | None = None,
) -> list[dict[str, str | None]]:
    """Return call-level App provenance, joining assistant calls to tool results.

    Each logical call retains the assistant recipient and the canonical App/tool
    identity learned from task contracts or the corresponding tool-result metadata.
    This makes the runtime provenance usable as a deterministic alias table during
    SFT normalization.
    """
    calls: list[dict[str, str | None]] = []
    pending: list[dict[str, str | None]] = []

    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        role = _message_role(message)
        metadata = message.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        message_id = message.get("id")
        message_id = str(message_id) if message_id not in (None, "") else None
        recipient = message.get("recipient")
        recipient = recipient.strip() if isinstance(recipient, str) and recipient.strip() else None

        explicit_calls = message.get("tool_calls") or metadata.get("tool_calls") or []
        created: list[dict[str, str | None]] = []
        if role == "assistant" and isinstance(explicit_calls, list):
            for offset, raw_call in enumerate(explicit_calls):
                if not isinstance(raw_call, dict):
                    continue
                function = raw_call.get("function")
                function = function if isinstance(function, dict) else {}
                runtime_name = raw_call.get("name") or function.get("name")
                runtime_name = str(runtime_name) if runtime_name not in (None, "") else None
                call_id = raw_call.get("id") or f"{message_id or f'message:{index}'}:{offset}"
                app_id, canonical_name, ui_name = _resolve_requested_identity(
                    task,
                    tool_name=runtime_name,
                    recipient=recipient or runtime_name,
                )
                created.append({
                    "call_id": str(call_id),
                    "call_message_id": message_id,
                    "result_message_id": None,
                    "app_id": app_id,
                    "canonical_tool_name": canonical_name,
                    "ui_app_name": ui_name,
                    "runtime_tool_name": runtime_name,
                    "recipient": recipient or (runtime_name if runtime_name and "." in runtime_name else None),
                })

        if role == "assistant" and not created and recipient and recipient != "all":
            app_id, canonical_name, ui_name = _resolve_requested_identity(
                task, recipient=recipient
            )
            created.append({
                "call_id": message_id or f"message:{index}",
                "call_message_id": message_id,
                "result_message_id": None,
                "app_id": app_id,
                "canonical_tool_name": canonical_name,
                "ui_app_name": ui_name,
                "runtime_tool_name": None,
                "recipient": recipient,
            })

        for call in created:
            calls.append(call)
            pending.append(call)

        observation = _resource_observation(message, task=task)
        has_observation = any(observation.values())
        if role == "assistant" and created and has_observation:
            for call in created:
                if _compatible(call, observation):
                    _merge_call(call, observation)
            continue
        if not has_observation:
            continue

        explicit_link = metadata.get("tool_call_id") or metadata.get("parent_id") or message.get("tool_call_id")
        matched = None
        if explicit_link not in (None, ""):
            link = str(explicit_link)
            for call in reversed(pending):
                if (
                    call.get("result_message_id") is None
                    and (call.get("call_id") == link or call.get("call_message_id") == link)
                    and _compatible(call, observation)
                ):
                    matched = call
                    break
        if matched is None:
            for call in reversed(pending):
                if call.get("result_message_id") is None and _compatible(call, observation):
                    matched = call
                    break

        if matched is None:
            synthetic_id = str(explicit_link or message_id or f"observed:{index}")
            matched = {
                "call_id": synthetic_id,
                "call_message_id": str(explicit_link) if explicit_link not in (None, "") else None,
                "result_message_id": message_id if role == "tool" else None,
                "app_id": None,
                "canonical_tool_name": None,
                "ui_app_name": None,
                "runtime_tool_name": None,
                "recipient": None,
            }
            calls.append(matched)

        _merge_call(matched, observation)
        if role == "tool":
            matched["result_message_id"] = message_id
            if matched in pending:
                pending.remove(matched)

    return calls


def enrich_capture(
    captured: CapturedConversation,
    *,
    task: BenchmarkTask,
    app_environments: dict[str, str],
    app_runtime: dict[str, Any] | None = None,
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
    workspace = workspace_snapshot(task.initial_workspace)
    metadata["initial_workspace"] = {
        "sha256": workspace.sha256,
        "files": workspace.files,
        "bytes": workspace.bytes,
    }
    metadata["app_runtime"] = deepcopy(app_runtime or {})
    metadata["used_tool_calls"] = invoked_tool_calls(captured.messages, task=task)
    return CapturedConversation(captured.conversation_id, captured.messages, metadata)

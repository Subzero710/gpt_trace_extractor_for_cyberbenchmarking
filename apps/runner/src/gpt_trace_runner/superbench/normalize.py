from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from ..tool_identity import stable_tool_name


def _role(raw: dict) -> str:
    author = raw.get("author")
    role = author.get("role") if isinstance(author, dict) else raw.get("role")
    role = str(role or "assistant")
    return role if role in {"user", "assistant", "tool", "system"} else "assistant"


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(part for part in (_text(item) for item in value) if part)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        if "parts" in value:
            return _text(value.get("parts"))
        if isinstance(value.get("content"), str):
            return value["content"]
        return ""
    return str(value)


def _identity_maps(used_tool_calls, app_provenance):
    aliases: dict[str, set[str]] = defaultdict(set)
    call_names: dict[str, str] = {}
    result_to_call: dict[str, str] = {}
    message_to_calls: dict[str, list[str]] = defaultdict(list)

    for app in app_provenance or []:
        if not isinstance(app, dict):
            continue
        app_id = str(app.get("app_id") or "")
        manifest = app.get("tool_manifest") if isinstance(app.get("tool_manifest"), dict) else {}
        for tool in manifest.get("tools", []):
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            canonical = str(tool["name"])
            stable = stable_tool_name(app_id, canonical)
            aliases[canonical].add(stable)

    for call in used_tool_calls or []:
        if not isinstance(call, dict):
            continue
        app_id = str(call.get("app_id") or "")
        canonical = str(call.get("canonical_tool_name") or "")
        call_id = str(call.get("call_id") or "")
        if not app_id or not canonical:
            continue
        stable = stable_tool_name(app_id, canonical)
        if call_id:
            call_names[call_id] = stable
        call_message_id = str(call.get("call_message_id") or "")
        if call_message_id and call_id and call_id not in message_to_calls[call_message_id]:
            message_to_calls[call_message_id].append(call_id)
        result_message_id = str(call.get("result_message_id") or "")
        if result_message_id and call_id:
            result_to_call[result_message_id] = call_id
        for alias in (
            canonical,
            call.get("runtime_tool_name"),
            call.get("recipient"),
        ):
            if isinstance(alias, str) and alias:
                aliases[alias].add(stable)

    def resolve(alias: Any) -> str:
        value = str(alias or "")
        candidates = aliases.get(value, set())
        return next(iter(candidates)) if len(candidates) == 1 else value

    return call_names, result_to_call, message_to_calls, resolve


def normalize_messages(
    messages: list[dict],
    *,
    used_tool_calls=None,
    app_provenance=None,
):
    call_names, result_to_call, message_to_calls, resolve_alias = _identity_maps(
        used_tool_calls,
        app_provenance,
    )

    calls_by_index: dict[int, list[dict[str, str]]] = {}
    calls_by_message: dict[str, list[str]] = defaultdict(list)

    for index, raw in enumerate(messages):
        if not isinstance(raw, dict):
            continue
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        content = raw.get("content")
        calls: list[dict[str, str]] = []
        raw_calls = raw.get("tool_calls") or metadata.get("tool_calls") or []

        if isinstance(raw_calls, list):
            for offset, call in enumerate(raw_calls):
                if not isinstance(call, dict):
                    continue
                function = call.get("function") if isinstance(call.get("function"), dict) else {}
                arguments = call.get("arguments", function.get("arguments"))
                if not isinstance(arguments, str):
                    arguments = json.dumps(
                        arguments,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                call_id = str(
                    call.get("id")
                    or f"{raw.get('id') or f'message:{index}'}:{offset}"
                )
                raw_name = call.get("name") or function.get("name")
                stable_name = call_names.get(call_id) or resolve_alias(raw_name)
                call_names.setdefault(call_id, stable_name)
                calls.append(
                    {"id": call_id, "name": stable_name, "arguments": arguments}
                )

        recipient = raw.get("recipient")
        content_type = content.get("content_type") if isinstance(content, dict) else None
        if (
            not calls
            and _role(raw) == "assistant"
            and content_type == "code"
            and isinstance(recipient, str)
            and recipient
            and recipient != "all"
        ):
            call_id = str(raw.get("id") or f"message:{index}")
            stable_name = call_names.get(call_id) or resolve_alias(recipient)
            call_names.setdefault(call_id, stable_name)
            calls.append(
                {"id": call_id, "name": stable_name, "arguments": _text(content)}
            )

        if calls:
            calls_by_index[index] = calls
            message_id = str(raw.get("id") or "")
            if message_id:
                calls_by_message[message_id].extend(call["id"] for call in calls)

    # Provenance may know assistant-message membership even when the raw message
    # format did not expose a standard tool_calls array.
    for message_id, call_ids in message_to_calls.items():
        for call_id in call_ids:
            if call_id not in calls_by_message[message_id]:
                calls_by_message[message_id].append(call_id)

    out = []
    unmatched: list[tuple[str, str, int]] = []
    consumed: set[str] = set()

    for index, raw in enumerate(messages):
        if not isinstance(raw, dict):
            continue
        author = raw.get("author") if isinstance(raw.get("author"), dict) else {}
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        role = _role(raw)
        calls = calls_by_index.get(index, [])
        for call in calls:
            unmatched.append((call["id"], call["name"], index))

        raw_name = author.get("name") or raw.get("name")
        tool_call_id = raw.get("tool_call_id") or metadata.get("tool_call_id")

        if role == "tool":
            result_message_id = str(raw.get("id") or "")
            if not tool_call_id and result_message_id:
                tool_call_id = result_to_call.get(result_message_id)

            if not tool_call_id:
                parent_id = str(metadata.get("parent_id") or "")
                candidates = [
                    cid
                    for cid in calls_by_message.get(parent_id, [])
                    if cid not in consumed
                ]
                resolved_result_name = resolve_alias(raw_name)
                same_name = [
                    cid
                    for cid in candidates
                    if call_names.get(cid) == resolved_result_name
                ]
                if len(same_name) == 1:
                    tool_call_id = same_name[0]
                elif len(candidates) == 1:
                    tool_call_id = candidates[0]

            if not tool_call_id:
                resolved_result_name = resolve_alias(raw_name)
                for pos in range(len(unmatched) - 1, -1, -1):
                    cid, name, call_index = unmatched[pos]
                    if (
                        call_index < index
                        and cid not in consumed
                        and (not resolved_result_name or name == resolved_result_name)
                    ):
                        tool_call_id = cid
                        break

            if tool_call_id:
                tool_call_id = str(tool_call_id)
                consumed.add(tool_call_id)
                unmatched = [item for item in unmatched if item[0] != tool_call_id]

        normalized_name = None
        if role == "tool" and tool_call_id:
            normalized_name = call_names.get(str(tool_call_id))
        if normalized_name is None and raw_name:
            normalized_name = resolve_alias(raw_name)

        out.append(
            {
                "role": role,
                "content": _text(raw.get("content")),
                "name": normalized_name or None,
                "tool_call_id": str(tool_call_id) if tool_call_id else None,
                "tool_calls": calls,
            }
        )

    return out


def tools_from_provenance(apps: list[dict]):
    out = []
    for app in apps or []:
        if not isinstance(app, dict):
            continue
        app_id = str(app.get("app_id") or "")
        manifest = app.get("tool_manifest") if isinstance(app.get("tool_manifest"), dict) else {}
        for tool in manifest.get("tools", []):
            if not isinstance(tool, dict):
                continue
            canonical = str(tool.get("name") or "")
            if not canonical:
                continue
            out.append(
                {
                    "app_id": app_id,
                    "name": stable_tool_name(app_id, canonical),
                    "description": str(tool.get("description") or ""),
                    "input_schema": json.dumps(
                        tool.get("inputSchema") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "output_schema": json.dumps(
                        tool.get("outputSchema") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
            )
    return out

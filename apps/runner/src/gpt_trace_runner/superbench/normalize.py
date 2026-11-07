from __future__ import annotations

import json
from collections import Counter, defaultdict
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


def _reasoning_summary_text(content: Any) -> str:
    """Extract only non-empty raw_cot thoughts[].content text."""
    if not isinstance(content, dict):
        return ""
    thoughts = content.get("thoughts")
    if not isinstance(thoughts, list):
        return ""
    parts: list[str] = []
    for thought in thoughts:
        if not isinstance(thought, dict):
            continue
        value = thought.get("content")
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    return "\n".join(parts)


def _reasoning_title(metadata: dict[str, Any]) -> str | None:
    value = metadata.get("reasoning_title")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _message_kind(
    raw: dict[str, Any],
    *,
    role: str,
    calls: list[dict[str, str]],
) -> str:
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    content = raw.get("content")
    content_type = content.get("content_type") if isinstance(content, dict) else None

    if (
        role == "assistant"
        and metadata.get("summary_type") == "raw_cot"
        and content_type == "thoughts"
    ):
        return "reasoning_summary"
    if role == "user":
        return "user_prompt"
    if role == "tool":
        return "tool_result"
    if role == "system":
        return "system"
    if role == "assistant" and calls:
        return "assistant_tool_call"
    if role == "assistant" and (
        raw.get("channel") == "final" or raw.get("end_turn") is True
    ):
        return "assistant_final"
    return "assistant_message"


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

    # Preserve insertion order without repeatedly scanning the entire message.
    # The historical behavior keeps the first occurrence of a call identity.
    for message_id, call_ids in message_to_calls.items():
        members = set(calls_by_message[message_id])
        for call_id in call_ids:
            if call_id not in members:
                calls_by_message[message_id].append(call_id)
                members.add(call_id)

    # Build an index of still-unused calls for parent-linked results. Each call
    # is removed from its parent indexes at most once; repeated results no
    # longer rescan every call belonging to a large assistant message.
    parent_unconsumed = {
        parent: Counter(call_ids)
        for parent, call_ids in calls_by_message.items()
    }
    parent_by_name: dict[str, dict[str | None, int]] = {}
    parents_for_call: dict[str, list[str]] = defaultdict(list)
    parent_sizes: dict[str, int] = {}
    for parent, call_counts in parent_unconsumed.items():
        by_name: dict[str | None, int] = defaultdict(int)
        for call_id, count in call_counts.items():
            by_name[call_names.get(call_id)] += count
            parents_for_call[call_id].append(parent)
        parent_by_name[parent] = by_name
        parent_sizes[parent] = sum(call_counts.values())

    out = []
    # Two append-only stacks replace the O(n) reverse scan and O(n) list
    # reconstruction performed for every tool result. Stale consumed entries
    # are discarded lazily, so an identity present in multiple call records
    # can never be reused. Each stack entry is pushed and popped once.
    unmatched_all: list[tuple[str, str]] = []
    unmatched_by_name: dict[str, list[str]] = defaultdict(list)
    consumed: set[str] = set()

    def latest_unmatched(name: str) -> str | None:
        stack = unmatched_by_name[name] if name else unmatched_all
        while stack and stack[-1][0] in consumed:
            stack.pop()
        return stack[-1][0] if stack else None

    for index, raw in enumerate(messages):
        if not isinstance(raw, dict):
            continue
        author = raw.get("author") if isinstance(raw.get("author"), dict) else {}
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        role = _role(raw)
        calls = calls_by_index.get(index, [])
        # Calls belonging to the current message become eligible only after
        # its result has been resolved; the old scan required call_index < index.
        raw_name = author.get("name") or raw.get("name")
        tool_call_id = raw.get("tool_call_id") or metadata.get("tool_call_id")

        if role == "tool":
            result_message_id = str(raw.get("id") or "")
            if not tool_call_id and result_message_id:
                tool_call_id = result_to_call.get(result_message_id)

            if not tool_call_id:
                parent_id = str(metadata.get("parent_id") or "")
                remaining = parent_unconsumed.get(parent_id, {})
                resolved_result_name = resolve_alias(raw_name)
                if parent_by_name.get(parent_id, {}).get(resolved_result_name, 0) == 1:
                    tool_call_id = next(
                        cid for cid in remaining
                        if call_names.get(cid) == resolved_result_name
                    )
                elif parent_sizes.get(parent_id, 0) == 1:
                    tool_call_id = next(iter(remaining))

            if not tool_call_id:
                resolved_result_name = resolve_alias(raw_name)
                tool_call_id = latest_unmatched(resolved_result_name)

            if tool_call_id:
                tool_call_id = str(tool_call_id)
                consumed.add(tool_call_id)
                for parent in parents_for_call.get(tool_call_id, ()):
                    count = parent_unconsumed[parent].pop(tool_call_id, 0)
                    parent_sizes[parent] -= count
                    parent_by_name[parent][call_names.get(tool_call_id)] -= count

        for call in calls:
            entry = (call["id"], call["name"])
            unmatched_all.append(entry)
            unmatched_by_name[call["name"]].append(entry)

        normalized_name = None
        if role == "tool" and tool_call_id:
            normalized_name = call_names.get(str(tool_call_id))
        if normalized_name is None and raw_name:
            normalized_name = resolve_alias(raw_name)

        kind = _message_kind(raw, role=role, calls=calls)
        if kind == "reasoning_summary":
            normalized_content = _reasoning_summary_text(raw.get("content"))
            # raw_cot sometimes contains a closing thought with content="" only.
            # It carries no training signal, so omit that normalized message.
            if not normalized_content:
                continue
        else:
            normalized_content = _text(raw.get("content"))

        out.append(
            {
                "role": role,
                "kind": kind,
                "content": normalized_content,
                "reasoning_title": _reasoning_title(metadata),
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

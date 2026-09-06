from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .exceptions import BenchmarkError
from .models import BenchmarkTask, BenchmarkTool


def _resolve_attachment(
    value: object,
    *,
    tasks_root: Path,
    manifest: Path,
    line_number: int,
) -> Path:
    root = tasks_root.expanduser().resolve()
    raw = Path(str(value))

    if raw.is_absolute():
        candidate = raw.expanduser().resolve()
    else:
        parts = raw.parts
        if parts and parts[0] == "tasks":
            raw = Path(*parts[1:])
        candidate = (root / raw).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise BenchmarkError(
            f"{manifest}:{line_number}: attachment escapes TASKS_ROOT: {candidate}"
        ) from exc

    if not candidate.is_file():
        raise BenchmarkError(
            f"{manifest}:{line_number}: attachment not found: {candidate}"
        )

    return candidate


def _parse_tool(
    value: Any,
    *,
    manifest: Path,
    line_number: int,
) -> BenchmarkTool:
    if isinstance(value, str):
        tool_type = "app"
        name = value.strip()
        required = False
    elif isinstance(value, dict):
        tool_type = str(value.get("type", "app")).strip().lower()
        name = str(value.get("name", "")).strip()
        required_value = value.get("required", False)
        if not isinstance(required_value, bool):
            raise BenchmarkError(
                f"{manifest}:{line_number}: tool.required must be a boolean"
            )
        required = required_value
    else:
        raise BenchmarkError(
            f"{manifest}:{line_number}: each tool must be a string or object"
        )

    if tool_type != "app":
        raise BenchmarkError(
            f"{manifest}:{line_number}: unsupported tool type {tool_type!r}; "
            "the ChatGPT UI runner supports installed ChatGPT apps only"
        )
    if not name:
        raise BenchmarkError(f"{manifest}:{line_number}: tool name is required")

    return BenchmarkTool(type="app", name=name, required=required)


def load_benchmark(
    path: Path,
    *,
    tasks_root: Path | None = None,
) -> list[BenchmarkTask]:
    if not path.is_file():
        raise BenchmarkError(f"benchmark manifest not found: {path}")

    artifact_root = (tasks_root or path.parent).expanduser().resolve()
    tasks: list[BenchmarkTask] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue

            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise BenchmarkError(
                    f"{path}:{line_number}: invalid JSON: {exc}"
                ) from exc

            if not isinstance(item, dict):
                raise BenchmarkError(f"{path}:{line_number}: expected object")

            task_id = str(item.get("task_id", "")).strip()
            prompt = str(item.get("prompt", "")).strip()

            if not task_id:
                raise BenchmarkError(f"{path}:{line_number}: missing task_id")
            if task_id in seen:
                raise BenchmarkError(
                    f"{path}:{line_number}: duplicate task_id {task_id!r}"
                )
            if not prompt:
                raise BenchmarkError(f"{path}:{line_number}: missing prompt")

            raw_attachments = item.get("attachments", [])
            if not isinstance(raw_attachments, list):
                raise BenchmarkError(
                    f"{path}:{line_number}: attachments must be a list"
                )
            attachments = tuple(
                _resolve_attachment(
                    value,
                    tasks_root=artifact_root,
                    manifest=path,
                    line_number=line_number,
                )
                for value in raw_attachments
            )

            raw_tools = item.get("tools", [])
            if not isinstance(raw_tools, list):
                raise BenchmarkError(
                    f"{path}:{line_number}: tools must be a list"
                )
            tools = tuple(
                _parse_tool(
                    value,
                    manifest=path,
                    line_number=line_number,
                )
                for value in raw_tools
            )

            tasks.append(
                BenchmarkTask(
                    task_id=task_id,
                    prompt=prompt,
                    attachments=attachments,
                    tools=tools,
                )
            )
            seen.add(task_id)

    return tasks

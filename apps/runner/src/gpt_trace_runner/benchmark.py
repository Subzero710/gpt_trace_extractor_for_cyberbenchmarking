from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .exceptions import BenchmarkError
from .models import BenchmarkTask, BenchmarkTool
from .registry import AppRegistry, ResolvedApp

MAX_PROMPT_BYTES = 8 * 1024 * 1024


def _resolve_attachment(value: object, *, tasks_root: Path, manifest: Path, line_number: int) -> Path:
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
        raise BenchmarkError(f"{manifest}:{line_number}: attachment escapes TASKS_ROOT: {candidate}") from exc
    if not candidate.is_file():
        raise BenchmarkError(f"{manifest}:{line_number}: attachment not found: {candidate}")
    return candidate


def _benchmark_tool(app: ResolvedApp, *, required: bool) -> BenchmarkTool:
    return BenchmarkTool(
        type="app",
        app_id=app.app_id,
        ui_name=app.ui_name,
        required=required,
        kind=app.kind,
        version=app.version,
        manifest_sha256=app.manifest_sha256,
        tool_manifest=app.manifest,
        mcp_endpoint=app.mcp_endpoint,
        control_endpoint=app.control_endpoint,
        attachment_mode=app.attachment_mode,
    )


def _parse_tool(value: Any, *, manifest: Path, line_number: int, registry: AppRegistry | None) -> BenchmarkTool:
    if registry is None:
        raise BenchmarkError(f"{manifest}:{line_number}: an App registry is required when tools are requested")
    if isinstance(value, str):
        selector_type = "name"
        selector = value.strip()
        required = False
        supplied_name: str | None = None
    elif isinstance(value, dict):
        tool_type = value.get("type", "app")
        if not isinstance(tool_type, str) or tool_type.strip().lower() != "app":
            raise BenchmarkError(
                f"{manifest}:{line_number}: unsupported tool type {tool_type!r}; "
                "the ChatGPT UI runner accepts logical Apps only"
            )
        required_value = value.get("required", False)
        if not isinstance(required_value, bool):
            raise BenchmarkError(f"{manifest}:{line_number}: tool.required must be a boolean")
        required = required_value
        app_id = value.get("id")
        supplied_name_value = value.get("name")
        if app_id is not None:
            if not isinstance(app_id, str) or not app_id.strip():
                raise BenchmarkError(f"{manifest}:{line_number}: tool.id must be a non-empty string")
            selector_type = "id"
            selector = app_id.strip()
            if supplied_name_value is not None and not isinstance(supplied_name_value, str):
                raise BenchmarkError(f"{manifest}:{line_number}: tool.name must be a string")
            supplied_name = supplied_name_value.strip() if isinstance(supplied_name_value, str) else None
        else:
            if not isinstance(supplied_name_value, str) or not supplied_name_value.strip():
                raise BenchmarkError(f"{manifest}:{line_number}: tool id or name is required")
            selector_type = "name"
            selector = supplied_name_value.strip()
            supplied_name = None
    else:
        raise BenchmarkError(f"{manifest}:{line_number}: each tool must be a string or object")

    if not selector or len(selector) > 255:
        raise BenchmarkError(f"{manifest}:{line_number}: tool selector is invalid")
    app = registry.resolve_id(selector) if selector_type == "id" else registry.resolve_name(selector)
    if supplied_name is not None and supplied_name.casefold() not in {app.ui_name.casefold(), app.app_id.casefold()}:
        raise BenchmarkError(
            f"{manifest}:{line_number}: supplied tool.name does not match the configured UI name for {app.app_id!r}"
        )
    return _benchmark_tool(app, required=required)


def load_benchmark(path: Path, *, tasks_root: Path | None = None, registry: AppRegistry | None = None) -> list[BenchmarkTask]:
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
                raise BenchmarkError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise BenchmarkError(f"{path}:{line_number}: expected object")
            task_id_value = item.get("task_id")
            if not isinstance(task_id_value, str):
                raise BenchmarkError(f"{path}:{line_number}: task_id must be a string")
            task_id = task_id_value.strip()
            prompt = item.get("prompt")
            if not isinstance(prompt, str):
                raise BenchmarkError(f"{path}:{line_number}: prompt must be a string")
            if not task_id:
                raise BenchmarkError(f"{path}:{line_number}: missing task_id")
            if task_id in {".", ".."}:
                raise BenchmarkError(f"{path}:{line_number}: reserved task_id {task_id!r}")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", task_id):
                raise BenchmarkError(f"{path}:{line_number}: task_id contains unsupported characters")
            if task_id in seen:
                raise BenchmarkError(f"{path}:{line_number}: duplicate task_id {task_id!r}")
            if prompt.strip() == "":
                raise BenchmarkError(f"{path}:{line_number}: missing prompt")
            if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
                raise BenchmarkError(f"{path}:{line_number}: prompt exceeds {MAX_PROMPT_BYTES} byte clipboard limit")
            raw_attachments = item.get("attachments", [])
            if not isinstance(raw_attachments, list):
                raise BenchmarkError(f"{path}:{line_number}: attachments must be a list")
            attachments = tuple(
                _resolve_attachment(value, tasks_root=artifact_root, manifest=path, line_number=line_number)
                for value in raw_attachments
            )
            if len(set(attachments)) != len(attachments):
                raise BenchmarkError(f"{path}:{line_number}: duplicate attachment")
            basenames = [attachment.name for attachment in attachments]
            if len(set(basenames)) != len(basenames):
                raise BenchmarkError(f"{path}:{line_number}: attachment basenames must be unique")
            raw_tools = item.get("tools", [])
            if not isinstance(raw_tools, list):
                raise BenchmarkError(f"{path}:{line_number}: tools must be a list")
            tools = tuple(
                _parse_tool(value, manifest=path, line_number=line_number, registry=registry)
                for value in raw_tools
            )
            app_ids = [tool.app_id for tool in tools]
            if len(set(app_ids)) != len(app_ids):
                raise BenchmarkError(f"{path}:{line_number}: duplicate logical App")
            ui_names = [tool.ui_name.casefold() for tool in tools]
            if len(set(ui_names)) != len(ui_names):
                raise BenchmarkError(f"{path}:{line_number}: requested Apps resolve to a duplicate UI name")
            tasks.append(BenchmarkTask(task_id=task_id, prompt=prompt, attachments=attachments, tools=tools))
            seen.add(task_id)
    if not tasks:
        raise BenchmarkError(f"benchmark manifest is empty: {path}")
    return tasks

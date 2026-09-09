from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from .workspace_seed import snapshot as workspace_snapshot


@dataclass(frozen=True, slots=True)
class BenchmarkTool:
    type: Literal["app"]
    app_id: str
    ui_name: str
    required: bool
    kind: str
    version: str
    manifest_sha256: str
    tool_manifest: dict[str, Any]
    mcp_endpoint: str | None = None
    control_endpoint: str | None = None
    attachment_mode: str = "none"

    @property
    def name(self) -> str:
        """Compatibility name used only by the ChatGPT UI adapter."""
        return self.ui_name

    def provenance(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "ui_name": self.ui_name,
            "kind": self.kind,
            "version": self.version,
            "tool_manifest_sha256": self.manifest_sha256,
            "tool_manifest": deepcopy(self.tool_manifest),
        }


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    task_id: str
    prompt: str
    attachments: tuple[Path, ...]
    tools: tuple[BenchmarkTool, ...] = ()
    initial_workspace: Path | None = None


@dataclass(frozen=True, slots=True)
class StoredRun:
    task_id: str
    status: str
    conversation_id: str | None = None
    attempt: int = 0
    runner_id: str | None = None
    task_fingerprint: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    runtime_metadata: dict[str, Any] | None = None
    app_provenance: list[dict[str, Any]] | None = None


@dataclass(frozen=True, slots=True)
class CapturedConversation:
    conversation_id: str
    messages: list[dict[str, Any]]
    runtime_metadata: dict[str, Any] = field(default_factory=dict)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def task_app_provenance(task: BenchmarkTask) -> list[dict[str, Any]]:
    return [tool.provenance() for tool in task.tools]


def task_fingerprint(task: BenchmarkTask) -> str:
    attachments = [
        {"name": path.name, "sha256": _file_sha256(path)}
        for path in task.attachments
    ]
    workspace = workspace_snapshot(task.initial_workspace)
    payload = {
        "task_id": task.task_id,
        "prompt": task.prompt,
        "attachments": attachments,
        "initial_workspace": {
            "sha256": workspace.sha256,
            "files": workspace.files,
            "bytes": workspace.bytes,
        },
        "apps": [
            {
                "type": tool.type,
                "app_id": tool.app_id,
                "required": tool.required,
                "version": tool.version,
                "tool_manifest_sha256": tool.manifest_sha256,
            }
            for tool in task.tools
        ],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def task_with_stored_ui_names(task: BenchmarkTask, provenance: list[dict[str, Any]]) -> BenchmarkTask:
    by_id = {item.get("app_id"): item for item in provenance if isinstance(item, dict)}
    if len(by_id) != len(provenance) or set(by_id) != {tool.app_id for tool in task.tools}:
        raise ValueError("stored App provenance does not match requested logical Apps")
    tools: list[BenchmarkTool] = []
    for tool in task.tools:
        item = by_id[tool.app_id]
        if (
            item.get("kind") != tool.kind
            or item.get("app_id") != tool.app_id
            or item.get("version") != tool.version
            or item.get("tool_manifest_sha256") != tool.manifest_sha256
            or item.get("tool_manifest") != tool.tool_manifest
        ):
            raise ValueError(f"stored App contract differs for {tool.app_id}")
        ui_name = item.get("ui_name")
        if not isinstance(ui_name, str) or not ui_name:
            raise ValueError(f"stored UI name is missing for {tool.app_id}")
        tools.append(replace(tool, ui_name=ui_name))
    return replace(task, tools=tuple(tools))

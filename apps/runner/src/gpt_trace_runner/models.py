from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class BenchmarkTool:
    type: Literal["app"]
    name: str
    required: bool = False


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    task_id: str
    prompt: str
    attachments: tuple[Path, ...]
    tools: tuple[BenchmarkTool, ...] = ()


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


def task_fingerprint(task: BenchmarkTask) -> str:
    attachments = []
    for path in task.attachments:
        attachments.append({"name": path.name, "sha256": _file_sha256(path)})
    payload = {
        "task_id": task.task_id,
        "prompt": task.prompt,
        "attachments": attachments,
        "tools": [
            {"type": tool.type, "name": tool.name, "required": tool.required}
            for tool in task.tools
        ],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

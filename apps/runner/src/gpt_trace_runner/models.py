from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    task_id: str
    prompt: str
    attachments: tuple[Path, ...]

@dataclass(frozen=True, slots=True)
class StoredRun:
    task_id: str
    status: str
    conversation_id: str | None = None
    attempt: int = 0
    error_type: str | None = None
    error_message: str | None = None

@dataclass(frozen=True, slots=True)
class CapturedConversation:
    conversation_id: str
    messages: list[dict[str, Any]]

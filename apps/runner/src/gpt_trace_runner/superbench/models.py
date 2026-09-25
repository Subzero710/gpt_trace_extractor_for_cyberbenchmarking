from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from ..workspace_seed import snapshot as workspace_snapshot


def _stable(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Optional native benchmark verdict."""

    verdict: Literal["pass", "fail"]
    score: float | None = None
    details: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "details": self.details,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """Runtime-facing task contract exposed by benchmark adapters."""

    task_id: str
    prompt: str
    tools: tuple[str, ...] = ()
    attachments: tuple[Path, ...] = ()
    initial_workspace: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id.strip() or len(self.task_id) > 255:
            raise ValueError("task_id must contain 1..255 non-whitespace characters")
        if not self.prompt.strip():
            raise ValueError("prompt must not be empty")
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("duplicate tool app")
        if any(not str(app_id).strip() for app_id in self.tools):
            raise ValueError("tool app id must not be empty")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def task_spec_fingerprint(task: "TaskSpec") -> str:
    """Hash the adapter-visible source task before runtime materialization."""
    attachments = [
        {"name": path.name, "sha256": _file_sha256(path)}
        for path in task.attachments
    ]
    workspace = workspace_snapshot(task.initial_workspace)
    payload = {
        "task_id": task.task_id,
        "prompt": task.prompt,
        "tools": list(task.tools),
        "attachments": attachments,
        "initial_workspace": {
            "sha256": workspace.sha256,
            "files": workspace.files,
            "bytes": workspace.bytes,
        },
        "metadata": task.metadata,
    }
    return hashlib.sha256(_stable(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class TeacherCampaign:
    expected_model: str
    teacher_configuration: dict[str, Any]
    runner_commit: str = ""

    def __post_init__(self) -> None:
        if not self.expected_model.strip():
            raise ValueError("expected_model must not be empty")

    @property
    def campaign_id(self) -> str:
        # Runtime timeouts, fetch limits and the runner git SHA are provenance,
        # not dataset identity. They must not duplicate the same source task.
        return hashlib.sha256(
            _stable({"expected_model": self.expected_model})
        ).hexdigest()


def run_task_id(
    task_id: str,
    campaign_id: str,
    adapter_id: str,
    adapter_version: str,
) -> str:
    source = hashlib.sha256(
        _stable(
            {
                "task_id": task_id,
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
            }
        )
    ).hexdigest()[:32]
    return f"sb:{campaign_id[:16]}:{source}"

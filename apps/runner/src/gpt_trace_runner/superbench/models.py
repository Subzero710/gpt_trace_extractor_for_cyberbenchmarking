from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Literal


def _stable(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Optional benchmark verdict.

    A task that has no reliable native evaluator simply returns ``None`` from the
    adapter. When an evaluator exists it returns pass/fail plus optional native
    score/details. Superbench does not invent a verdict.
    """

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
    """Minimal runtime-facing task contract.

    ``metadata`` is deliberately opaque. It may contain benchmark/source
    provenance for later filtering/auditing, but neither the runner nor the
    training conversation depends on a benchmark-specific metadata schema.
    """

    task_id: str
    prompt: str
    tools: tuple[str, ...] = ()
    attachments: tuple[Path, ...] = ()
    initial_workspace: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    environment_spec: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id.strip() or len(self.task_id) > 255:
            raise ValueError("task_id must contain 1..255 non-whitespace characters")
        if not self.prompt.strip():
            raise ValueError("prompt must not be empty")
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("duplicate tool app")
        if any(not str(app_id).strip() for app_id in self.tools):
            raise ValueError("tool app id must not be empty")




@dataclass(frozen=True, slots=True)
class TeacherCampaign:
    expected_model: str
    teacher_configuration: dict[str, Any]
    runner_commit: str

    def __post_init__(self) -> None:
        if not self.expected_model.strip() or not self.runner_commit.strip():
            raise ValueError("campaign identity is incomplete")

    @property
    def campaign_id(self) -> str:
        return hashlib.sha256(
            _stable(
                {
                    "expected_model": self.expected_model,
                    "teacher_configuration": self.teacher_configuration,
                    "runner_commit": self.runner_commit,
                }
            )
        ).hexdigest()


def run_task_id(task_id: str, campaign_id: str) -> str:
    return (
        f"sb:{campaign_id[:16]}:"
        f"{hashlib.sha256(task_id.encode('utf-8')).hexdigest()[:32]}"
    )

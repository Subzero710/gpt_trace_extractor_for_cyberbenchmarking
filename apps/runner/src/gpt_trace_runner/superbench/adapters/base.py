from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from ..models import CanonicalTask, EvaluationResult
from ...models import CapturedConversation

@dataclass(frozen=True, slots=True)
class PreparedBenchmarkContext:
    workspace: Path | None = None
    environment: dict[str, Any] = field(default_factory=dict)
    evaluator_state: dict[str, Any] = field(default_factory=dict)

class BenchmarkAdapter(ABC):
    adapter_id: str
    adapter_version: str
    @abstractmethod
    def discover_tasks(self) -> list[CanonicalTask]: ...
    def materialize_task(self, task: CanonicalTask, staging_root: Path) -> CanonicalTask: return task
    async def prepare(self, task: CanonicalTask) -> PreparedBenchmarkContext:
        return PreparedBenchmarkContext(workspace=task.initial_workspace)
    @abstractmethod
    async def evaluate(self, task: CanonicalTask, *, prepared: PreparedBenchmarkContext, captured: CapturedConversation) -> EvaluationResult: ...
    async def cleanup(self, task: CanonicalTask, *, prepared: PreparedBenchmarkContext) -> None: return None
    def validate_environment(self) -> None: return None

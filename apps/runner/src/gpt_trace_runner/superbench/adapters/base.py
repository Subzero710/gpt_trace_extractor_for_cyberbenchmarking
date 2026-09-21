from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import EvaluationResult, TaskSpec
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
    def discover_tasks(self) -> list[TaskSpec]: ...

    def materialize_task(self, task: TaskSpec, staging_root: Path) -> TaskSpec:
        return task

    async def prepare(self, task: TaskSpec) -> PreparedBenchmarkContext:
        return PreparedBenchmarkContext(workspace=task.initial_workspace)

    async def recover(
        self,
        task: TaskSpec,
        *,
        attempt: int,
        app_environments: dict[str, str],
    ) -> PreparedBenchmarkContext:
        return await self.prepare(task)

    async def evaluate(
        self,
        task: TaskSpec,
        *,
        prepared: PreparedBenchmarkContext,
        captured: CapturedConversation,
    ) -> EvaluationResult | None:
        """Return a native verdict when the benchmark has one, otherwise None."""
        return None

    async def cleanup(
        self,
        task: TaskSpec,
        *,
        prepared: PreparedBenchmarkContext,
    ) -> None:
        return None

    def validate_environment(self) -> None:
        return None

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import os
from pathlib import Path

from ..models import EvaluationResult, TaskSpec
from ...models import CapturedConversation


@dataclass(frozen=True, slots=True)
class PreparedBenchmarkContext:
    """Opaque marker for adapter-owned preparation state."""

    pass


class BenchmarkAdapter(ABC):
    adapter_id: str
    adapter_version: str

    @property
    def source_root(self) -> Path:
        base = Path(
            os.environ.get(
                "GPT_TRACE_SUPERBENCH_SOURCE_ROOT",
                "/data/state/superbench/sources",
            )
        )
        return base / self.adapter_id

    def fetch(self) -> None:
        """Fetch/pin upstream source material required by this adapter, if any."""
        return None

    @abstractmethod
    def discover_tasks(self) -> list[TaskSpec]: ...

    def task_order_key(self, task: TaskSpec) -> str:
        """Stable campaign selection order; default adapters retain task-ID order."""
        return task.task_id

    def materialize_task(self, task: TaskSpec, staging_root: Path) -> TaskSpec:
        return task

    async def prepare(self, task: TaskSpec) -> PreparedBenchmarkContext:
        return PreparedBenchmarkContext()

    async def recover(
        self,
        task: TaskSpec,
        *,
        attempt: int,
        app_environments: dict[str, str],
    ) -> PreparedBenchmarkContext:
        return await self.prepare(task)

    @property
    def uses_runtime_hooks(self) -> bool:
        return False

    async def prepare_runtime(self, task, *, prepared, runtime) -> None:
        """Trusted setup after VM boot, before teacher interaction."""
        return None

    async def capture_candidate(self, task, *, prepared, captured, runtime) -> dict:
        """Export a candidate before the durable grading checkpoint."""
        return {}

    async def evaluate_runtime(self, task, *, prepared, captured, candidate, runtime):
        return await self.evaluate(task, prepared=prepared, captured=captured)

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
        prepared: PreparedBenchmarkContext | None,
    ) -> None:
        return None

from __future__ import annotations

from dataclasses import dataclass

from .models import TaskSpec
from .registry import AdapterRegistry


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    task: TaskSpec
    adapter_id: str


class SuperbenchCatalog:
    def __init__(self, registry: AdapterRegistry):
        self.registry = registry

    def discover(self, only: tuple[str, ...] = ()) -> list[CatalogEntry]:
        tasks: list[CatalogEntry] = []
        seen: dict[str, str] = {}
        for adapter_id, adapter in sorted(self.registry.adapters.items()):
            if only and adapter_id not in only:
                continue
            for task in adapter.discover_tasks():
                if task.task_id in seen:
                    raise ValueError(
                        f"duplicate task_id {task.task_id!r}: "
                        f"{seen[task.task_id]!r} and {adapter_id!r}"
                    )
                seen[task.task_id] = adapter_id
                tasks.append(CatalogEntry(task=task, adapter_id=adapter_id))
        return sorted(tasks, key=lambda item: item.task.task_id)

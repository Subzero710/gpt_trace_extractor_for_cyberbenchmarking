from __future__ import annotations
from dataclasses import dataclass
from .models import CanonicalTask
from .registry import AdapterRegistry
@dataclass(frozen=True,slots=True)
class CatalogEntry: task:CanonicalTask; adapter_id:str
class SuperbenchCatalog:
    def __init__(self,registry:AdapterRegistry): self.registry=registry
    def discover(self,only:tuple[str,...]=()):
        tasks=[]; ids={}; groups={}
        for aid,adapter in sorted(self.registry.adapters.items()):
            if only and aid not in only: continue
            for task in adapter.discover_tasks():
                if task.adapter_id!=aid: raise ValueError(f'adapter identity mismatch for {task.canonical_task_id}')
                if task.canonical_task_id in ids: raise ValueError(f'duplicate canonical_task_id: {task.canonical_task_id}')
                ids[task.canonical_task_id]=aid
                if task.dedup_group:
                    key=task.dedup_group.strip().lower()
                    if key in groups: raise ValueError(f'cross-source duplicate origin {task.dedup_group!r}: {groups[key]} and {task.canonical_task_id}')
                    groups[key]=task.canonical_task_id
                tasks.append(CatalogEntry(task,aid))
        return sorted(tasks,key=lambda x:x.task.canonical_task_id)

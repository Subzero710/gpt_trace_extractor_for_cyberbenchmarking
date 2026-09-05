from __future__ import annotations
import json
from pathlib import Path
from .exceptions import BenchmarkError
from .models import BenchmarkTask

def load_benchmark(path: Path) -> list[BenchmarkTask]:
    if not path.is_file():
        raise BenchmarkError(f"benchmark manifest not found: {path}")
    tasks: list[BenchmarkTask] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise BenchmarkError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise BenchmarkError(f"{path}:{line_number}: expected object")
            task_id = str(item.get("task_id", "")).strip()
            prompt = str(item.get("prompt", "")).strip()
            if not task_id:
                raise BenchmarkError(f"{path}:{line_number}: missing task_id")
            if task_id in seen:
                raise BenchmarkError(f"{path}:{line_number}: duplicate task_id {task_id!r}")
            if not prompt:
                raise BenchmarkError(f"{path}:{line_number}: missing prompt")
            raw_attachments = item.get("attachments", [])
            if not isinstance(raw_attachments, list):
                raise BenchmarkError(f"{path}:{line_number}: attachments must be a list")
            attachments: list[Path] = []
            for value in raw_attachments:
                p = Path(str(value))
                p = p.resolve() if p.is_absolute() else (path.parent / p).resolve()
                if not p.is_file():
                    raise BenchmarkError(f"{path}:{line_number}: attachment not found: {p}")
                attachments.append(p)
            tasks.append(BenchmarkTask(task_id, prompt, tuple(attachments)))
            seen.add(task_id)
    return tasks

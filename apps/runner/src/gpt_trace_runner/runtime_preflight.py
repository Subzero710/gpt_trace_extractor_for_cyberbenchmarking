from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from rich.console import Console

from .app_lifecycle import AppLifecycle
from .exceptions import AppInfrastructureError
from .models import BenchmarkTask, task_fingerprint


async def preflight_tasks(
    lifecycle: AppLifecycle,
    tasks: Sequence[BenchmarkTask],
    *,
    console: Console,
) -> None:
    """Exercise the complete local-App lifecycle without ChatGPT/auth/storage writes."""
    if not tasks:
        raise AppInfrastructureError("runtime preflight selection is empty")

    for index, task in enumerate(tasks, 1):
        source_fingerprint = task_fingerprint(task)
        probe = replace(
            task,
            task_id=f"doctor-{index}-{source_fingerprint[:16]}",
        )
        fingerprint = task_fingerprint(probe)
        attempt = 1
        environments = lifecycle.environment_ids(
            probe,
            attempt=attempt,
            fingerprint=fingerprint,
        )

        console.print(
            f"[dim]runtime preflight {index}/{len(tasks)}: {task.task_id}[/]"
        )

        primary_error: Exception | None = None
        try:
            await lifecycle.health(probe)
            await lifecycle.prepare(
                probe,
                environments,
                fingerprint,
                attempt=attempt,
            )
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            try:
                await lifecycle.reset(
                    probe,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
            except Exception as cleanup_exc:
                if primary_error is None:
                    raise
                raise AppInfrastructureError(
                    f"runtime preflight for {task.task_id!r} failed with "
                    f"{type(primary_error).__name__}: {primary_error}; "
                    f"cleanup also failed with "
                    f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                ) from primary_error

        console.print(f"[green]runtime preflight: {task.task_id}: ok[/]")

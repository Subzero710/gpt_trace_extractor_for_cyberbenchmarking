from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run


class RunConflict(RuntimeError):
    pass


async def get_run(session: AsyncSession, task_id: str, *, for_update: bool = False) -> Run | None:
    stmt = select(Run).where(Run.task_id == task_id)
    if for_update:
        stmt = stmt.with_for_update()
    return await session.scalar(stmt)


async def _check_identity(run: Run, *, attempt: int, runner_id: str) -> None:
    if run.attempt != attempt or run.runner_id != runner_id:
        raise RunConflict(
            f"stale mutation: expected attempt={run.attempt} runner={run.runner_id!r}, "
            f"got attempt={attempt} runner={runner_id!r}"
        )


async def start_run(
    session: AsyncSession,
    *,
    task_id: str,
    runner_id: str,
    expected_attempt: int,
    task_fingerprint: str,
    app_provenance: list[dict],
    superbench: dict | None = None,
) -> Run:
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext('gpt_trace_single_runner'))"))
    other = await session.scalar(select(Run).where(Run.status == "running", Run.task_id != task_id).limit(1))
    if other is not None:
        raise RunConflict(f"another task is already running: {other.task_id}")
    run = await get_run(session, task_id, for_update=True)
    now = datetime.now(timezone.utc)
    if run is None:
        if expected_attempt != 1:
            raise RunConflict(f"new task must start at attempt 1, got {expected_attempt}")
        run = Run(
            task_id=task_id,
            status="running",
            runner_id=runner_id,
            attempt=1,
            task_fingerprint=task_fingerprint,
            app_provenance=app_provenance,
            started_at=now,
            **({k: v for k, v in (superbench or {}).items() if k in {"canonical_task_id","campaign_id","source_benchmark","source_benchmark_version","source_task_id","upstream_repository","upstream_commit","source_license","source_metadata","teacher_metadata","adapter_id","adapter_version"}}),
        )
        session.add(run)
    elif run.task_fingerprint is None:
        raise RunConflict("legacy run has no task fingerprint; migrate/reset it explicitly before resume")
    elif run.task_fingerprint != task_fingerprint:
        raise RunConflict("task specification changed for an existing task_id")
    elif run.status == "completed":
        raise RunConflict("completed run is immutable")
    elif run.status == "running":
        if run.attempt == expected_attempt and run.runner_id == runner_id:
            if run.app_provenance is None or run.app_provenance != app_provenance:
                raise RunConflict("idempotent start App provenance differs")
            await session.commit()
            await session.refresh(run)
            return run
        raise RunConflict(f"task already running at attempt={run.attempt} runner={run.runner_id!r}")
    else:
        if expected_attempt != run.attempt + 1:
            raise RunConflict(f"expected next attempt {run.attempt + 1}, got {expected_attempt}")
        run.status = "running"
        run.runner_id = runner_id
        run.attempt = expected_attempt
        run.started_at = now
        run.completed_at = None
        run.conversation_id = None
        run.messages = None
        run.runtime_metadata = None
        run.app_provenance = app_provenance
        run.error_type = None
        run.error_message = None
        if superbench:
            for k, v in superbench.items():
                if k in {"canonical_task_id","campaign_id","source_benchmark","source_benchmark_version","source_task_id","upstream_repository","upstream_commit","source_license","source_metadata","teacher_metadata","adapter_id","adapter_version"}: setattr(run,k,v)
        run.run_status = None; run.success = None; run.reward = None; run.native_result = None; run.evaluator_metadata = None
    await session.commit()
    await session.refresh(run)
    return run


async def set_conversation(
    session: AsyncSession,
    *,
    task_id: str,
    conversation_id: str,
    attempt: int,
    runner_id: str,
) -> Run | None:
    run = await get_run(session, task_id, for_update=True)
    if run is None:
        return None
    await _check_identity(run, attempt=attempt, runner_id=runner_id)
    if run.status == "completed":
        if run.conversation_id == conversation_id:
            return run
        raise RunConflict("completed run cannot change conversation_id")
    if run.status != "running":
        raise RunConflict(f"cannot set conversation on status={run.status}")
    if run.conversation_id and run.conversation_id != conversation_id:
        raise RunConflict("running attempt already has a different conversation_id")
    run.conversation_id = conversation_id
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise RunConflict("conversation_id is already assigned to another task") from exc
    await session.refresh(run)
    return run


async def complete_run(
    session: AsyncSession, *, task_id: str, conversation_id: str, messages: list[dict],
    runtime_metadata: dict, attempt: int, runner_id: str, evaluation: dict | None = None,
) -> Run | None:
    run = await get_run(session, task_id, for_update=True)
    if run is None: return None
    await _check_identity(run, attempt=attempt, runner_id=runner_id)
    if run.app_provenance is None: raise RunConflict("cannot complete a run without App provenance")
    if run.canonical_task_id is not None and evaluation is None:
        raise RunConflict("Superbench completion requires an evaluation result")
    if evaluation is not None and not isinstance(evaluation.get("success"), bool):
        raise RunConflict("evaluated completion requires boolean success")
    if run.status == "completed":
        if not (run.conversation_id == conversation_id and run.messages == messages and (run.runtime_metadata or {}) == runtime_metadata):
            raise RunConflict("completed run is immutable")
        if evaluation is not None and not (
            run.success is evaluation["success"] and run.reward == evaluation.get("reward")
            and (run.native_result or {}) == (evaluation.get("native_result") or {})
            and (run.evaluator_metadata or {}) == (evaluation.get("evaluator_metadata") or {})
        ):
            raise RunConflict("completed run evaluation differs from immutable label")
        return run
    if run.status != "running": raise RunConflict(f"cannot complete status={run.status}")
    if run.conversation_id and run.conversation_id != conversation_id:
        raise RunConflict("completion conversation_id differs from running attempt")
    run.status="completed"; run.conversation_id=conversation_id; run.messages=messages; run.runtime_metadata=runtime_metadata
    run.error_type=None; run.error_message=None; run.run_status="completed"
    if evaluation is not None:
        run.success=evaluation["success"]; run.reward=evaluation.get("reward")
        run.native_result=evaluation.get("native_result") or {}; run.evaluator_metadata=evaluation.get("evaluator_metadata") or {}
    run.completed_at=datetime.now(timezone.utc)
    try: await session.commit()
    except IntegrityError as exc:
        await session.rollback(); raise RunConflict("conversation_id is already assigned to another task") from exc
    await session.refresh(run); return run


async def fail_run(
    session: AsyncSession,
    *,
    task_id: str,
    error_type: str,
    error_message: str,
    attempt: int,
    runner_id: str,
) -> Run | None:
    run = await get_run(session, task_id, for_update=True)
    if run is None:
        return None
    await _check_identity(run, attempt=attempt, runner_id=runner_id)
    if run.status == "completed":
        return run
    if run.status == "failed":
        if run.error_type == error_type and run.error_message == error_message:
            return run
        raise RunConflict("failed run is immutable until a new attempt is started")
    if run.status != "running":
        raise RunConflict(f"cannot fail status={run.status}")
    run.status = "failed"
    run.run_status = "infra_failed"
    run.success = None
    run.error_type = error_type
    run.error_message = error_message
    await session.commit()
    await session.refresh(run)
    return run


async def reset_run(
    session: AsyncSession,
    *,
    task_id: str,
    expected_task_fingerprint: str,
) -> bool:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('gpt_trace_single_runner'))")
    )
    run = await get_run(session, task_id, for_update=True)
    if run is None:
        return False
    if run.task_fingerprint != expected_task_fingerprint:
        raise RunConflict("stale reset fingerprint differs from stored run")
    if run.status == "running":
        raise RunConflict("running run cannot be reset; recover or stop it explicitly first")
    await session.delete(run)
    await session.commit()
    return True


async def stats(session: AsyncSession) -> dict[str, int]:
    rows = (await session.execute(select(Run.status, func.count(Run.id)).group_by(Run.status))).all()
    output = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "total": 0}
    for status, count in rows:
        if status in output:
            output[status] = int(count)
        output["total"] += int(count)
    return output

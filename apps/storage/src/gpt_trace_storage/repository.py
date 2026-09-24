from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run


class RunConflict(RuntimeError):
    pass


async def get_run(
    session: AsyncSession,
    task_id: str,
    *,
    for_update: bool = False,
) -> Run | None:
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


def _validated_evaluation(evaluation: dict[str, Any] | None) -> dict[str, Any] | None:
    if evaluation is None:
        return None
    if not isinstance(evaluation, dict):
        raise RunConflict("evaluation must be an object or null")
    unknown = set(evaluation) - {"verdict", "score", "details", "metadata"}
    if unknown:
        raise RunConflict(f"evaluation contains unsupported fields: {sorted(unknown)!r}")
    verdict = evaluation.get("verdict")
    if verdict not in {"pass", "fail"}:
        raise RunConflict("evaluation.verdict must be 'pass' or 'fail'")
    score = evaluation.get("score")
    if score is not None and (
        not isinstance(score, (int, float)) or isinstance(score, bool)
    ):
        raise RunConflict("evaluation.score must be numeric or null")
    details = evaluation.get("details", {})
    metadata = evaluation.get("metadata", {})
    if not isinstance(details, dict) or not isinstance(metadata, dict):
        raise RunConflict("evaluation details/metadata must be objects")
    return {
        "verdict": verdict,
        "score": float(score) if score is not None else None,
        "details": details,
        "metadata": metadata,
    }


async def start_run(
    session: AsyncSession,
    *,
    task_id: str,
    logical_task_id: str | None,
    runner_id: str,
    expected_attempt: int,
    task_fingerprint: str,
    app_provenance: list[dict],
    dataset_metadata: dict[str, Any] | None = None,
) -> Run:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('gpt_trace_single_runner'))")
    )
    other = await session.scalar(
        select(Run)
        .where(Run.status == "running", Run.task_id != task_id)
        .limit(1)
    )
    if other is not None:
        raise RunConflict(f"another task is already running: {other.task_id}")

    logical_id = logical_task_id or task_id
    metadata = dict(dataset_metadata or {})
    run = await get_run(session, task_id, for_update=True)
    now = datetime.now(timezone.utc)

    if run is None:
        if expected_attempt != 1:
            raise RunConflict(f"new task must start at attempt 1, got {expected_attempt}")
        run = Run(
            task_id=task_id,
            logical_task_id=logical_id,
            status="running",
            runner_id=runner_id,
            attempt=1,
            task_fingerprint=task_fingerprint,
            app_provenance=app_provenance,
            dataset_metadata=metadata,
            evaluation=None,
            started_at=now,
        )
        session.add(run)
    elif run.task_fingerprint is None:
        raise RunConflict(
            "stored run has no task fingerprint; migrate or delete it explicitly before resume"
        )
    elif run.task_fingerprint != task_fingerprint:
        raise RunConflict("task specification changed for an existing task_id")
    elif run.logical_task_id != logical_id:
        raise RunConflict("logical_task_id changed for an existing task_id")
    elif run.status == "completed":
        if (run.dataset_metadata or {}) != metadata:
            raise RunConflict("completed run dataset_metadata is immutable")
        raise RunConflict("completed run is immutable")
    elif run.status == "running":
        if (run.dataset_metadata or {}) != metadata:
            raise RunConflict("idempotent start dataset_metadata differs")
        if run.attempt == expected_attempt and run.runner_id == runner_id:
            if run.app_provenance is None or run.app_provenance != app_provenance:
                raise RunConflict("idempotent start App provenance differs")
            await session.commit()
            await session.refresh(run)
            return run
        raise RunConflict(
            f"task already running at attempt={run.attempt} runner={run.runner_id!r}"
        )
    elif run.status == "failed":
        if expected_attempt != run.attempt + 1:
            raise RunConflict(
                f"expected next attempt {run.attempt + 1}, got {expected_attempt}"
            )
        run.status = "running"
        run.runner_id = runner_id
        run.attempt = expected_attempt
        run.started_at = now
        run.completed_at = None
        run.conversation_id = None
        run.messages = None
        run.runtime_metadata = None
        run.app_provenance = app_provenance
        run.dataset_metadata = metadata
        run.evaluation = None
        run.error_type = None
        run.error_message = None
    else:
        raise RunConflict(f"cannot start run from status={run.status!r}")

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
        raise RunConflict(
            "conversation_id is already assigned to another task"
        ) from exc
    await session.refresh(run)
    return run


async def complete_run(
    session: AsyncSession,
    *,
    task_id: str,
    conversation_id: str,
    messages: list[dict],
    runtime_metadata: dict,
    attempt: int,
    runner_id: str,
    evaluation: dict[str, Any] | None = None,
) -> Run | None:
    run = await get_run(session, task_id, for_update=True)
    if run is None:
        return None
    await _check_identity(run, attempt=attempt, runner_id=runner_id)
    if run.app_provenance is None:
        raise RunConflict("cannot complete a run without App provenance")

    normalized_evaluation = _validated_evaluation(evaluation)

    if run.status == "completed":
        if not (
            run.conversation_id == conversation_id
            and run.messages == messages
            and (run.runtime_metadata or {}) == runtime_metadata
        ):
            raise RunConflict("completed run is immutable")
        if run.evaluation != normalized_evaluation:
            raise RunConflict("completed run evaluation differs from immutable label")
        return run

    if run.status != "running":
        raise RunConflict(f"cannot complete status={run.status}")
    if run.conversation_id and run.conversation_id != conversation_id:
        raise RunConflict(
            "completion conversation_id differs from running attempt"
        )

    run.status = "completed"
    run.conversation_id = conversation_id
    run.messages = messages
    run.runtime_metadata = runtime_metadata
    run.evaluation = normalized_evaluation
    run.error_type = None
    run.error_message = None
    run.completed_at = datetime.now(timezone.utc)

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise RunConflict(
            "conversation_id is already assigned to another task"
        ) from exc
    await session.refresh(run)
    return run


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
    run.evaluation = None
    run.error_type = error_type
    run.error_message = error_message
    await session.commit()
    await session.refresh(run)
    return run



async def stats(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(
            select(Run.status, func.count(Run.id)).group_by(Run.status)
        )
    ).all()
    output = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "total": 0}
    for status, count in rows:
        if status in output:
            output[status] = int(count)
        output["total"] += int(count)
    return output

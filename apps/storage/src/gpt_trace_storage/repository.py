from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from .models import Run

async def get_run(session: AsyncSession, task_id: str) -> Run | None:
    return await session.scalar(select(Run).where(Run.task_id == task_id))

async def start_run(session: AsyncSession, *, task_id: str, runner_id: str) -> Run:
    run = await get_run(session, task_id)
    now = datetime.now(timezone.utc)
    if run is None:
        run = Run(task_id=task_id, status="running", runner_id=runner_id, attempt=1, started_at=now)
        session.add(run)
    elif run.status != "completed":
        run.status = "running"; run.runner_id = runner_id; run.attempt += 1
        run.started_at = now; run.error_type = None; run.error_message = None
    await session.commit(); await session.refresh(run); return run

async def set_conversation(session: AsyncSession, *, task_id: str, conversation_id: str) -> Run | None:
    run = await get_run(session, task_id)
    if run is None: return None
    run.conversation_id = conversation_id
    await session.commit(); await session.refresh(run); return run

async def complete_run(session: AsyncSession, *, task_id: str, conversation_id: str, messages: list[dict]) -> Run | None:
    run = await get_run(session, task_id)
    if run is None: return None
    run.status = "completed"; run.conversation_id = conversation_id; run.messages = messages
    run.error_type = None; run.error_message = None; run.completed_at = datetime.now(timezone.utc)
    await session.commit(); await session.refresh(run); return run

async def fail_run(session: AsyncSession, *, task_id: str, error_type: str, error_message: str) -> Run | None:
    run = await get_run(session, task_id)
    if run is None: return None
    if run.status != "completed":
        run.status = "failed"; run.error_type = error_type; run.error_message = error_message
    await session.commit(); await session.refresh(run); return run

async def stats(session: AsyncSession) -> dict[str, int]:
    rows = (await session.execute(select(Run.status, func.count(Run.id)).group_by(Run.status))).all()
    out = {"pending":0,"running":0,"completed":0,"failed":0,"total":0}
    for status, count in rows:
        if status in out: out[status] = int(count)
        out["total"] += int(count)
    return out

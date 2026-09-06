from __future__ import annotations

import json

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .db import SessionFactory, get_session
from .models import Run
from .repository import RunConflict, complete_run, fail_run, get_run, set_conversation, start_run, stats
from .schemas import CompleteRunRequest, ConversationRequest, FailRunRequest, RunResponse, StartRunRequest, StatsResponse

app = FastAPI(title="GPT Trace Storage", version="0.3.0")


def conflict(exc: RunConflict) -> HTTPException:
    return HTTPException(409, str(exc))


@app.get("/healthz")
async def healthz(session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    await session.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.post("/v1/runs/start", response_model=RunResponse)
async def start(body: StartRunRequest, session: AsyncSession = Depends(get_session)):
    try:
        return await start_run(
            session, task_id=body.task_id, runner_id=body.runner_id,
            expected_attempt=body.expected_attempt, task_fingerprint=body.task_fingerprint,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc


@app.get("/v1/runs/{task_id}", response_model=RunResponse)
async def read_run(task_id: str, session: AsyncSession = Depends(get_session)):
    run = await get_run(session, task_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.patch("/v1/runs/{task_id}/conversation", response_model=RunResponse)
async def update_conversation(task_id: str, body: ConversationRequest,
                              session: AsyncSession = Depends(get_session)):
    try:
        run = await set_conversation(
            session, task_id=task_id, conversation_id=body.conversation_id,
            attempt=body.attempt, runner_id=body.runner_id,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.post("/v1/runs/{task_id}/complete", response_model=RunResponse)
async def complete(task_id: str, body: CompleteRunRequest,
                   session: AsyncSession = Depends(get_session)):
    try:
        run = await complete_run(
            session, task_id=task_id, conversation_id=body.conversation_id,
            messages=body.messages, runtime_metadata=body.runtime_metadata,
            attempt=body.attempt, runner_id=body.runner_id,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.post("/v1/runs/{task_id}/fail", response_model=RunResponse)
async def fail(task_id: str, body: FailRunRequest,
               session: AsyncSession = Depends(get_session)):
    try:
        run = await fail_run(
            session, task_id=task_id, error_type=body.error_type,
            error_message=body.error_message, attempt=body.attempt,
            runner_id=body.runner_id,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.get("/v1/stats", response_model=StatsResponse)
async def run_stats(session: AsyncSession = Depends(get_session)):
    return await stats(session)


@app.get("/v1/export.jsonl")
async def export_jsonl():
    async with SessionFactory() as check_session:
        invalid = await check_session.scalar(
            select(func.count(Run.id)).where(
                Run.status == "completed",
                or_(
                    Run.conversation_id.is_(None),
                    Run.messages.is_(None),
                    Run.completed_at.is_(None),
                ),
            )
        )
        if invalid:
            raise HTTPException(409, f"{invalid} completed run(s) have incomplete dataset state")

    async def rows():
        async with SessionFactory() as session:
            result = await session.stream_scalars(
                select(Run).where(Run.status == "completed").order_by(Run.task_id)
            )
            async for run in result:
                item = {
                    "task_id": run.task_id,
                    "conversation_id": run.conversation_id,
                    "captured_at": run.completed_at.isoformat() if run.completed_at else None,
                    "messages": run.messages or [],
                }
                yield json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
    return StreamingResponse(
        rows(), media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="dataset.jsonl"'},
    )

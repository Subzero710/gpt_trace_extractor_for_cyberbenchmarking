from __future__ import annotations

import json

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from . import __version__
from .db import SessionFactory, get_session
from .models import Run
from .repository import RunConflict, complete_run, fail_run, get_run, set_conversation, start_run, stats
from .schemas import CompleteRunRequest, ConversationRequest, FailRunRequest, RunResponse, StartRunRequest, StatsResponse

app = FastAPI(title="GPT Trace Storage", version=__version__)


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
            session,
            task_id=body.task_id,
            runner_id=body.runner_id,
            expected_attempt=body.expected_attempt,
            task_fingerprint=body.task_fingerprint,
            logical_task_id=body.logical_task_id,
            app_provenance=[item.model_dump(mode="json") for item in body.app_provenance],
            dataset_metadata=body.dataset_metadata,
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
async def update_conversation(task_id: str, body: ConversationRequest, session: AsyncSession = Depends(get_session)):
    try:
        run = await set_conversation(
            session,
            task_id=task_id,
            conversation_id=body.conversation_id,
            attempt=body.attempt,
            runner_id=body.runner_id,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.post("/v1/runs/{task_id}/complete", response_model=RunResponse)
async def complete(task_id: str, body: CompleteRunRequest, session: AsyncSession = Depends(get_session)):
    try:
        run = await complete_run(
            session,
            task_id=task_id,
            conversation_id=body.conversation_id,
            messages=body.messages,
            runtime_metadata=body.runtime_metadata,
            attempt=body.attempt,
            runner_id=body.runner_id,
            evaluation=body.evaluation.model_dump(mode="json") if body.evaluation else None,
        )
    except RunConflict as exc:
        raise conflict(exc) from exc
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.post("/v1/runs/{task_id}/fail", response_model=RunResponse)
async def fail(task_id: str, body: FailRunRequest, session: AsyncSession = Depends(get_session)):
    try:
        run = await fail_run(
            session,
            task_id=task_id,
            error_type=body.error_type,
            error_message=body.error_message,
            attempt=body.attempt,
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



def _export_item(run: Run) -> dict:
    return {
        "task_id": run.task_id,
        "logical_task_id": run.logical_task_id,
        "status": run.status,
        "conversation_id": run.conversation_id,
        "messages": run.messages,
        "runtime_metadata": {} if run.runtime_metadata is None else run.runtime_metadata,
        "app_provenance": [] if run.app_provenance is None else run.app_provenance,
        "dataset_metadata": run.dataset_metadata,
        "evaluation": run.evaluation,
        "captured_at": run.completed_at.isoformat() if run.completed_at else None,
        "attempt": run.attempt,
        "runner_id": run.runner_id,
        "task_fingerprint": run.task_fingerprint,
        "error_type": run.error_type,
        "error_message": run.error_message,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
    }


@app.get("/v1/export.jsonl")
async def export_jsonl():
    async def rows():
        async with SessionFactory() as session:
            # One repeatable-read snapshot: capture/evaluation updates cannot
            # split a trajectory or change the exported population mid-stream.
            await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            result = await session.stream_scalars(
                select(Run).where(Run.messages.is_not(None),
                    func.json_typeof(Run.messages) != "null").order_by(Run.task_id)
            )
            async for run in result:
                yield json.dumps(_export_item(run), ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")) + "\n"
    return StreamingResponse(rows(), media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="dataset.jsonl"'})

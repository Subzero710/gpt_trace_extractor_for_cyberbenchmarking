from unittest.mock import AsyncMock

import pytest

from gpt_trace_storage.models import Run
from gpt_trace_storage import repository


class FakeSession:
    def __init__(self):
        self.commit = AsyncMock()
        self.refresh = AsyncMock()
        self.rollback = AsyncMock()


def run(status="running", *, attempt=2, runner_id="r", conversation_id=None):
    return Run(
        task_id="t",
        status=status,
        attempt=attempt,
        runner_id=runner_id,
        conversation_id=conversation_id,
    )


@pytest.mark.asyncio
async def test_stale_attempt_cannot_set_conversation(monkeypatch) -> None:
    item = run()
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    with pytest.raises(repository.RunConflict, match="stale mutation"):
        await repository.set_conversation(
            FakeSession(), task_id="t", conversation_id="c",
            attempt=1, runner_id="r",
        )


@pytest.mark.asyncio
async def test_completed_run_cannot_change_conversation(monkeypatch) -> None:
    item = run("completed", conversation_id="a")
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    with pytest.raises(repository.RunConflict, match="cannot change"):
        await repository.set_conversation(
            FakeSession(), task_id="t", conversation_id="b",
            attempt=2, runner_id="r",
        )


@pytest.mark.asyncio
async def test_completed_run_exact_complete_retry_is_idempotent(monkeypatch) -> None:
    item = run("completed", conversation_id="c")
    item.messages = [{"id": "m"}]
    item.runtime_metadata = {"x": 1}
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    result = await repository.complete_run(
        FakeSession(), task_id="t", conversation_id="c",
        messages=[{"id": "m"}], runtime_metadata={"x": 1},
        attempt=2, runner_id="r",
    )
    assert result is item


@pytest.mark.asyncio
async def test_completed_run_is_not_changed_by_fail_retry(monkeypatch) -> None:
    item = run("completed", conversation_id="c")
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    result = await repository.fail_run(
        FakeSession(), task_id="t", error_type="X", error_message="x",
        attempt=2, runner_id="r",
    )
    assert result.status == "completed"


class StartSession(FakeSession):
    def __init__(self, other=None):
        super().__init__()
        self.other = other
        self.execute = AsyncMock()
        self.scalar = AsyncMock(return_value=other)
        self.added = []
    def add(self, obj):
        self.added.append(obj)


@pytest.mark.asyncio
async def test_start_refuses_another_running_task(monkeypatch) -> None:
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=None))
    session = StartSession(other=Run(task_id="other", status="running", attempt=1, runner_id="x", task_fingerprint="a"*64))
    with pytest.raises(repository.RunConflict, match="another task"):
        await repository.start_run(
            session, task_id="t", runner_id="r", expected_attempt=1,
            task_fingerprint="b" * 64,
        )


@pytest.mark.asyncio
async def test_start_retry_same_attempt_is_idempotent(monkeypatch) -> None:
    item = Run(task_id="t", status="running", attempt=2, runner_id="r", task_fingerprint="a"*64)
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    session = StartSession(other=None)
    result = await repository.start_run(
        session, task_id="t", runner_id="r", expected_attempt=2,
        task_fingerprint="a" * 64,
    )
    assert result is item


@pytest.mark.asyncio
async def test_start_rejects_changed_task_spec(monkeypatch) -> None:
    item = Run(task_id="t", status="failed", attempt=1, runner_id="old", task_fingerprint="a"*64)
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    session = StartSession(other=None)
    with pytest.raises(repository.RunConflict, match="specification changed"):
        await repository.start_run(
            session, task_id="t", runner_id="r", expected_attempt=2,
            task_fingerprint="b" * 64,
        )


@pytest.mark.asyncio
async def test_failed_run_is_immutable_for_same_attempt(monkeypatch):
    item = Run(
        task_id="x",
        status="failed",
        runner_id="runner",
        attempt=2,
        task_fingerprint="a" * 64,
        error_type="OldError",
        error_message="old",
    )
    monkeypatch.setattr(repository, "get_run", AsyncMock(return_value=item))
    session = FakeSession()
    same = await repository.fail_run(
        session,
        task_id="x",
        error_type="OldError",
        error_message="old",
        attempt=2,
        runner_id="runner",
    )
    assert same.error_message == "old"

    with pytest.raises(repository.RunConflict):
        await repository.fail_run(
            session,
            task_id="x",
            error_type="DifferentError",
            error_message="different",
            attempt=2,
            runner_id="runner",
        )

from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import RateLimited
from gpt_trace_runner.journal import JournalStore
from gpt_trace_runner.models import BenchmarkTask, StoredRun
from gpt_trace_runner.runner import BenchmarkRunner, RunOptions


class FakeChatGPT:
    def __init__(self) -> None:
        self.prepared: list[str] = []
    async def prepare_session(self, *, fresh_home=False):
        return None
    async def prepare_task(self, task):
        self.prepared.append(task.task_id)
        raise RateLimited("429")


class FakeStorage:
    def __init__(self) -> None:
        self.failed: list[str] = []
    async def get(self, task_id):
        return None
    async def start(self, task_id, runner_id, expected_attempt, task_fingerprint):
        return StoredRun(task_id, "running", attempt=expected_attempt, runner_id=runner_id)
    async def fail(self, task_id, error, *, attempt, runner_id):
        self.failed.append(task_id)
        return StoredRun(task_id, "failed", attempt=attempt, runner_id=runner_id)


@pytest.mark.asyncio
async def test_circuit_breaker_never_advances_to_next_task(tmp_path: Path) -> None:
    chatgpt = FakeChatGPT()
    storage = FakeStorage()
    runner = BenchmarkRunner(
        chatgpt=chatgpt,
        storage=storage,
        runner_id="test",
        recover_existing=True,
        console=Console(force_terminal=False),
        journal=JournalStore(tmp_path / "submission.json"),
    )
    tasks = [BenchmarkTask("one", "x", ()), BenchmarkTask("two", "y", ())]
    with pytest.raises(RateLimited):
        await runner.run(tasks, RunOptions(stop_on_error=False))
    assert chatgpt.prepared == ["one"]
    assert storage.failed == ["one"]  # known-safe pre-submit failure


@pytest.mark.asyncio
async def test_storage_start_conflict_does_not_touch_chatgpt(tmp_path: Path) -> None:
    from gpt_trace_runner.exceptions import StorageConflict

    class ConflictStorage(FakeStorage):
        async def start(self, task_id, runner_id, expected_attempt, task_fingerprint):
            raise StorageConflict("another task is running")

    class CountingChatGPT(FakeChatGPT):
        def __init__(self):
            super().__init__()
            self.session_calls = 0
        async def prepare_session(self, *, fresh_home=False):
            self.session_calls += 1

    chatgpt = CountingChatGPT()
    runner = BenchmarkRunner(
        chatgpt=chatgpt,
        storage=ConflictStorage(),
        runner_id="test",
        recover_existing=True,
        console=Console(force_terminal=False),
        journal=JournalStore(tmp_path / "submission.json"),
    )
    with pytest.raises(StorageConflict):
        await runner.run([BenchmarkTask("one", "x", ())], RunOptions())
    assert chatgpt.session_calls == 0

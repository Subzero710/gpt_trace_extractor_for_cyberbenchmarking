from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import RateLimited, StorageConflict
from gpt_trace_runner.journal import JournalStore
from gpt_trace_runner.models import BenchmarkTask, StoredRun
from gpt_trace_runner.runner import BenchmarkRunner


class Lifecycle:
    def __init__(self): self.calls = []
    def environment_ids(self, task, *, attempt, fingerprint): return {}
    async def prepare(self, task, environments, fingerprint, *, attempt): self.calls.append("prepare")
    async def assert_resume(self, task, environments, fingerprint, *, attempt): self.calls.append("resume")
    async def runtime_metadata(self, task, environments, fingerprint, *, attempt): return {}
    async def reset(self, task, environments, fingerprint, *, attempt): self.calls.append("reset")


class FakeChatGPT:
    def __init__(self): self.prepared = []
    async def prepare_session(self, *, fresh_home=False): pass
    async def prepare_task(self, task):
        self.prepared.append(task.task_id)
        raise RateLimited("429")


class FakeStorage:
    def __init__(self): self.failed = []
    async def get(self, task_id): return None
    async def start(
        self, task_id, runner_id, expected_attempt, task_fingerprint, app_provenance,
        logical_task_id=None, dataset_metadata=None,
    ):
        return StoredRun(
            task_id=task_id, logical_task_id=logical_task_id or task_id, status="running",
            attempt=expected_attempt, runner_id=runner_id, task_fingerprint=task_fingerprint,
            app_provenance=app_provenance, dataset_metadata=dataset_metadata or {},
        )
    async def fail(self, task_id, error, *, attempt, runner_id):
        self.failed.append(task_id)
        return StoredRun(task_id=task_id, logical_task_id=task_id, status="failed", attempt=attempt, runner_id=runner_id)


def make_runner(chatgpt, storage, lifecycle, path):
    return BenchmarkRunner(
        chatgpt=chatgpt, storage=storage, lifecycle=lifecycle,
        runner_id="test", recover_existing=True,
        console=Console(force_terminal=False), journal=JournalStore(path),
    )


@pytest.mark.asyncio
async def test_rate_limit_cleans_pre_submit_state_and_raises(tmp_path: Path) -> None:
    chatgpt = FakeChatGPT()
    storage = FakeStorage()
    lifecycle = Lifecycle()
    runner = make_runner(chatgpt, storage, lifecycle, tmp_path / "submission.json")
    with pytest.raises(RateLimited):
        await runner.run_task(BenchmarkTask("one", "x", ()), False)
    assert chatgpt.prepared == ["one"]
    assert storage.failed == ["one"]
    assert lifecycle.calls == ["prepare", "reset"]


@pytest.mark.asyncio
async def test_storage_start_conflict_does_not_touch_apps_or_chatgpt(tmp_path: Path) -> None:
    class ConflictStorage(FakeStorage):
        async def start(self, *args, **kwargs):
            raise StorageConflict("another task is running")
    chatgpt = FakeChatGPT()
    lifecycle = Lifecycle()
    runner = make_runner(chatgpt, ConflictStorage(), lifecycle, tmp_path / "submission.json")
    with pytest.raises(StorageConflict):
        await runner.run_task(BenchmarkTask("one", "x", ()), False)
    assert chatgpt.prepared == []
    assert lifecycle.calls == []

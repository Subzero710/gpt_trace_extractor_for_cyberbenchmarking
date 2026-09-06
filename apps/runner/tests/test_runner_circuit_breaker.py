from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import RateLimited
from gpt_trace_runner.models import BenchmarkTask
from gpt_trace_runner.runner import BenchmarkRunner, RunOptions


class FakeChatGPT:
    def __init__(self) -> None:
        self.started: list[str] = []

    async def start_task(self, task):
        self.started.append(task.task_id)
        raise RateLimited("429")


class FakeStorage:
    def __init__(self) -> None:
        self.failed: list[str] = []

    async def get(self, task_id):
        return None

    async def start(self, task_id, runner_id):
        return None

    async def fail(self, task_id, error):
        self.failed.append(task_id)


@pytest.mark.asyncio
async def test_circuit_breaker_never_advances_to_next_task() -> None:
    chatgpt = FakeChatGPT()
    storage = FakeStorage()
    runner = BenchmarkRunner(
        chatgpt=chatgpt,
        storage=storage,
        runner_id="test",
        recover_existing=True,
        console=Console(force_terminal=False),
    )
    tasks = [
        BenchmarkTask("one", "x", ()),
        BenchmarkTask("two", "y", ()),
    ]

    with pytest.raises(RateLimited):
        await runner.run(tasks, RunOptions(stop_on_error=False))

    assert chatgpt.started == ["one"]
    assert storage.failed == ["one"]

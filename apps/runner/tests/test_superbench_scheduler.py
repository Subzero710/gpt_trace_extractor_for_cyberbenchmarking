import pytest

from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
from gpt_trace_runner.superbench.catalog import CatalogEntry
from gpt_trace_runner.superbench.execution import _ordered_entries, run_pending
from gpt_trace_runner.superbench.models import EvaluationResult, TaskSpec
from gpt_trace_runner.superbench.registry import AdapterRegistry


class A(BenchmarkAdapter):
    adapter_id = "a"
    adapter_version = "1"

    def discover_tasks(self):
        return [TaskSpec("a:1", "prompt")]

    async def evaluate(self, task, *, prepared, captured):
        return EvaluationResult("pass", 1.0)


class State:
    def __init__(self, status):
        self.status = status
        self.attempt = 1


class Storage:
    def __init__(self, state):
        self.state = state

    async def health(self):
        pass

    async def get(self, _):
        return self.state


class Settings:
    chatgpt_expected_model_slug = "m"
    chatgpt_conversation_turns = 1
    chatgpt_turn_timeout_seconds = 1
    runner_lock_path = "/tmp/sb-v2-test.lock"


class Registry:
    def resolve_id(self, _):
        raise AssertionError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,expected",
    [(State("completed"), 0), (State("failed"), 1), (None, 1)],
)
async def test_run_pending_skips_completed_and_retries_failed(state, expected):
    calls = []

    async def execute(*args):
        calls.append(1)

    n, _ = await run_pending(
        settings=Settings(),
        registry=Registry(),
        make_lifecycle=None,
        make_chatgpt=None,
        console=None,
        adapters=AdapterRegistry([A()]),
        storage=Storage(state),
        executor=execute,
    )
    assert n == expected
    assert len(calls) == expected


def test_limit_prioritizes_required_app_coverage():
    entries = [
        CatalogEntry(TaskSpec("1", "p", tools=("browser",), required_tools=("browser",)), "a"),
        CatalogEntry(TaskSpec("2", "p", tools=("browser",), required_tools=("browser",)), "a"),
        CatalogEntry(TaskSpec("3", "p", tools=("code-workspace",), required_tools=("code-workspace",)), "a"),
    ]
    chosen = _ordered_entries(entries, 2)
    assert [entry.task.task_id for entry in chosen[:2]] == ["1", "3"]


class TwoTaskAdapter(A):
    def discover_tasks(self):
        return [TaskSpec(f"a:{n}", f"p{n}") for n in (1, 2)]


class PerTaskStorage(Storage):
    async def get(self, _):
        return None


@pytest.mark.asyncio
async def test_run_pending_continues_after_task_local_failure():
    seen = []

    async def execute(adapter, task, *args):
        seen.append(task.task_id)
        if len(seen) == 1:
            raise ValueError("task-local")

    n, _ = await run_pending(
        settings=Settings(),
        registry=Registry(),
        make_lifecycle=None,
        make_chatgpt=None,
        console=None,
        adapters=AdapterRegistry([TwoTaskAdapter()]),
        storage=PerTaskStorage(None),
        executor=execute,
    )
    assert n == 2
    assert seen == ["a:1", "a:2"]

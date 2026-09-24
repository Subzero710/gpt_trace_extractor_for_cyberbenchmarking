from pathlib import Path

import pytest

from gpt_trace_runner.exceptions import RecoveryIncomplete
from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
from gpt_trace_runner.superbench.catalog import CatalogEntry
from gpt_trace_runner.superbench.execution import (
    _ordered_entries,
    _record_pre_runner_failure,
    run_pending,
)
from gpt_trace_runner.superbench.models import EvaluationResult, TaskSpec
from gpt_trace_runner.superbench.registry import AdapterRegistry
from gpt_trace_runner.superbench.service import campaign, storage_context, to_benchmark_task


class A(BenchmarkAdapter):
    adapter_id = "a"
    adapter_version = "1"

    def __init__(self):
        self.materialized = []

    def discover_tasks(self):
        return [TaskSpec("a:1", "prompt")]

    def materialize_task(self, task, staging_root):
        self.materialized.append(task.task_id)
        return task

    async def evaluate(self, task, *, prepared, captured):
        return EvaluationResult("pass", 1.0)


class State:
    def __init__(self, status, *, dataset_metadata=None):
        self.status = status
        self.attempt = 1
        self.dataset_metadata = dataset_metadata or {}


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
    runner_lock_path = Path("/tmp/sb-v2-test.lock")


class Registry:
    def resolve_id(self, _):
        raise AssertionError


def completed_state(adapter):
    task = adapter.discover_tasks()[0]
    metadata = storage_context(task, campaign(Settings()), adapter, Registry())["dataset_metadata"]
    return State("completed", dataset_metadata=metadata)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [("failed", 1), (None, 1)])
async def test_run_pending_retries_failed_and_runs_new(status, expected):
    adapter = A()
    state = None if status is None else State(status)
    calls = []

    async def execute(*args):
        calls.append(1)

    n, _ = await run_pending(
        settings=Settings(), registry=Registry(), make_lifecycle=None, make_chatgpt=None,
        console=None, adapters=AdapterRegistry([adapter]), storage=Storage(state), executor=execute,
    )
    assert n == expected
    assert len(calls) == expected
    assert adapter.materialized == ["a:1"]


@pytest.mark.asyncio
async def test_completed_task_is_validated_and_skipped_without_materialization():
    adapter = A()
    state = completed_state(adapter)
    adapter.materialized.clear()
    calls = []

    async def execute(*args):
        calls.append(1)

    n, _ = await run_pending(
        settings=Settings(), registry=Registry(), make_lifecycle=None, make_chatgpt=None,
        console=None, adapters=AdapterRegistry([adapter]), storage=Storage(state), executor=execute,
    )
    assert n == 0
    assert calls == []
    assert adapter.materialized == []


@pytest.mark.asyncio
async def test_completed_task_with_changed_contract_is_not_silently_skipped():
    adapter = A()
    state = completed_state(adapter)
    state.dataset_metadata["task_contract_fingerprint"] = "0" * 64
    with pytest.raises(RecoveryIncomplete, match="task contract changed"):
        await run_pending(
            settings=Settings(), registry=Registry(), make_lifecycle=None, make_chatgpt=None,
            console=None, adapters=AdapterRegistry([adapter]), storage=Storage(state), executor=lambda *args: None,
        )
    assert adapter.materialized == []


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
async def test_run_pending_stops_after_task_local_technical_failure():
    seen = []

    async def execute(adapter, task, *args):
        seen.append(task.task_id)
        raise ValueError("task-local")

    with pytest.raises(ValueError, match="task-local"):
        await run_pending(
            settings=Settings(), registry=Registry(), make_lifecycle=None, make_chatgpt=None,
            console=None, adapters=AdapterRegistry([TwoTaskAdapter()]), storage=PerTaskStorage(None),
            executor=execute,
        )
    assert seen == ["a:1"]


@pytest.mark.asyncio
async def test_pre_runner_failure_uses_one_runner_identity():
    class ChangingSettings(Settings):
        def __init__(self):
            self.calls = 0

        def effective_runner_id(self):
            self.calls += 1
            return f"runner-{self.calls}"

    class FailureStorage:
        def __init__(self):
            self.started_runner = None
            self.failed_runner = None

        async def start(self, task_id, runner_id, expected_attempt, task_fingerprint, app_provenance, **kwargs):
            self.started_runner = runner_id
            return type("Started", (), {"attempt": expected_attempt})()

        async def fail(self, task_id, error, *, attempt, runner_id):
            self.failed_runner = runner_id

    adapter = A()
    source = adapter.discover_tasks()[0]
    settings = ChangingSettings()
    storage = FailureStorage()
    bt = to_benchmark_task(source, Registry(), campaign(settings), adapter)
    await _record_pre_runner_failure(
        storage=storage, settings=settings, source_task=source, adapter=adapter, bt=bt,
        camp=campaign(settings), registry=Registry(), state=None, error=ValueError("boom"),
    )
    assert settings.calls == 1
    assert storage.started_runner == storage.failed_runner == "runner-1"

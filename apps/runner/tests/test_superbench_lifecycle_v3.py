from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from pathlib import Path
import signal
from types import SimpleNamespace

import pytest
from rich.console import Console

import gpt_trace_runner.cli as cli_module
import gpt_trace_runner.storage_client as storage_client_module
import gpt_trace_runner.superbench.execution as execution_module
import gpt_trace_runner.superbench.lifecycle as lifecycle_module
from gpt_trace_runner.exceptions import RecoveryIncomplete
from gpt_trace_runner.journal import JournalStore
from gpt_trace_runner.models import (
    BenchmarkTask,
    CapturedConversation,
    StoredRun,
)
from gpt_trace_runner.runner import BenchmarkRunner
from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
from gpt_trace_runner.superbench.models import TaskSpec
from gpt_trace_runner.superbench.registry import AdapterRegistry
from gpt_trace_runner.superbench.run_control import (
    ActiveRun,
    PlannedTask,
    RunControlStore,
)


@dataclass
class V3Settings:
    superbench_active_run_path: Path
    runner_lock_path: Path
    storage_base_url: str = "http://storage"
    chatgpt_expected_model_slug: str = "m"
    chatgpt_conversation_turns: int = 1
    chatgpt_turn_timeout_seconds: int = 10
    chatgpt_stream_start_timeout_seconds: int = 10
    chatgpt_tool_select_timeout_seconds: int = 10
    chatgpt_upload_timeout_seconds: int = 10
    chatgpt_site_ready_timeout_seconds: int = 10
    chatgpt_challenge_timeout_seconds: int = 10
    chatgpt_natural_snapshot_wait_seconds: int = 1
    browser_humanize: bool = False
    browser_humanize_preset: str = "default"
    app_browser_humanize: bool = False
    app_browser_humanize_preset: str = "default"
    app_browser_timezone: str = "UTC"
    app_browser_locale: str = "en-US"
    app_browser_geoip: str = ""


class EmptyRegistry:
    def resolve_id(self, _app_id):
        raise AssertionError("these tests use tasks without Apps")


class MutableAdapter(BenchmarkAdapter):
    adapter_id = "a"
    adapter_version = "1"

    def __init__(self, tasks=None):
        self.tasks = list(
            tasks
            or [
                TaskSpec("a:1", "p1"),
                TaskSpec("a:2", "p2"),
            ]
        )

    def discover_tasks(self):
        return list(self.tasks)


def make_settings(tmp_path: Path) -> V3Settings:
    return V3Settings(
        superbench_active_run_path=tmp_path / "active-run.json",
        runner_lock_path=tmp_path / "runner.lock",
    )


def freeze(settings: V3Settings, adapter: MutableAdapter, *, limit=None):
    adapters = AdapterRegistry([adapter])
    camp, tasks = lifecycle_module.plan(
        settings,
        EmptyRegistry(),
        adapters,
        (),
        limit,
    )
    state = ActiveRun(
        schema_version=3,
        run_id="run",
        campaign_id=camp.campaign_id,
        status="running",
        selected_tasks=tasks,
        expected_model=settings.chatgpt_expected_model_slug,
        configuration_fingerprint=lifecycle_module.config_fp(settings),
    )
    return adapters, state


@pytest.mark.asyncio
async def test_frozen_limit_selection_is_identical_on_repeated_resume_execution(
    tmp_path,
    monkeypatch,
):
    settings = make_settings(tmp_path)
    adapter = MutableAdapter()
    adapters, state = freeze(settings, adapter, limit=1)
    selected = tuple(task.run_task_id for task in state.selected_tasks)
    assert len(selected) == 1

    original_path = execution_module.Path

    def path_factory(value):
        if str(value) == "/data/state/superbench/staging":
            return tmp_path / "staging"
        return original_path(value)

    monkeypatch.setattr(execution_module, "Path", path_factory)

    class MissingStorage:
        async def health(self):
            return None

        async def get(self, _task_id):
            return None

    seen = []

    async def execute(_adapter, task, *_args):
        seen.append(task.task_id)

    for _ in range(2):
        await execution_module.run_pending(
            settings=settings,
            registry=EmptyRegistry(),
            make_lifecycle=None,
            make_chatgpt=None,
            console=None,
            adapters=adapters,
            storage=MissingStorage(),
            executor=execute,
            selected_run_task_ids=selected,
        )

    assert seen == ["a:1", "a:1"]


def test_validate_frozen_rejects_configuration_drift(tmp_path):
    settings = make_settings(tmp_path)
    adapter = MutableAdapter()
    adapters, state = freeze(settings, adapter, limit=1)

    drifted = replace(
        settings,
        chatgpt_turn_timeout_seconds=settings.chatgpt_turn_timeout_seconds + 1,
    )

    with pytest.raises(
        RecoveryIncomplete,
        match="campaign/model/config drift",
    ):
        lifecycle_module.validate_frozen(
            state,
            drifted,
            EmptyRegistry(),
            adapters,
        )


def test_validate_frozen_rejects_task_spec_drift(tmp_path):
    settings = make_settings(tmp_path)
    adapter = MutableAdapter()
    adapters, state = freeze(settings, adapter, limit=1)

    adapter.tasks[0] = TaskSpec("a:1", "changed prompt")

    with pytest.raises(
        RecoveryIncomplete,
        match="task/adapter/App contract drift",
    ):
        lifecycle_module.validate_frozen(
            state,
            settings,
            EmptyRegistry(),
            adapters,
        )


def test_validate_frozen_rejects_adapter_version_drift(tmp_path):
    settings = make_settings(tmp_path)
    adapter = MutableAdapter()
    adapters, state = freeze(settings, adapter, limit=1)

    adapter.adapter_version = "2"

    with pytest.raises(
        RecoveryIncomplete,
        match="task/adapter/App contract drift",
    ):
        lifecycle_module.validate_frozen(
            state,
            settings,
            EmptyRegistry(),
            adapters,
        )


@pytest.mark.asyncio
async def test_status_separates_evaluator_fail_from_infrastructure_failure(
    tmp_path,
    monkeypatch,
):
    settings = make_settings(tmp_path)
    state = ActiveRun(
        schema_version=3,
        run_id="run",
        campaign_id="campaign",
        status="paused",
        selected_tasks=(
            PlannedTask("pass", "p", "a", "1", "s1", "c1"),
            PlannedTask("fail", "f", "a", "1", "s2", "c2"),
            PlannedTask("infra", "i", "a", "1", "s3", "c3"),
        ),
        expected_model="m",
        configuration_fingerprint="config",
        completed_run_task_ids=("pass", "fail"),
    )
    RunControlStore(settings.superbench_active_run_path).create(state)

    rows = {
        "pass": SimpleNamespace(
            status="completed",
            evaluation={"verdict": "pass"},
        ),
        "fail": SimpleNamespace(
            status="completed",
            evaluation={"verdict": "fail"},
        ),
        "infra": SimpleNamespace(
            status="failed",
            evaluation=None,
        ),
    }

    class FakeStorageClient:
        def __init__(self, _base_url):
            pass

        async def health(self):
            return None

        async def get(self, task_id):
            return rows.get(task_id)

        async def close(self):
            return None

    monkeypatch.setattr(
        storage_client_module,
        "StorageClient",
        FakeStorageClient,
    )

    payload = await lifecycle_module.status_payload(settings)

    assert payload["completed"] == 2
    assert payload["evaluated"] == 2
    assert payload["pass"] == 1
    assert payload["fail"] == 1
    assert payload["infra_failed"] == 1


def test_auth_refuses_while_an_unfinished_active_run_exists(
    tmp_path,
    monkeypatch,
):
    settings = make_settings(tmp_path)
    state = ActiveRun(
        schema_version=3,
        run_id="run",
        campaign_id="campaign",
        status="paused",
        selected_tasks=(
            PlannedTask("x", "logical", "a", "1", "spec", "contract"),
        ),
        expected_model="m",
        configuration_fingerprint="config",
    )
    RunControlStore(settings.superbench_active_run_path).create(state)

    monkeypatch.setattr(cli_module, "Settings", lambda: settings)

    with pytest.raises(
        RecoveryIncomplete,
        match="auth refused while active Superbench run",
    ):
        cli_module.superbench_auth()


@pytest.mark.asyncio
async def test_first_sigint_during_final_storage_proof_pauses_instead_of_completing(
    tmp_path,
    monkeypatch,
):
    settings = make_settings(tmp_path)
    store = RunControlStore(settings.superbench_active_run_path)
    state = ActiveRun(
        schema_version=3,
        run_id="run",
        campaign_id="campaign",
        status="running",
        selected_tasks=(
            PlannedTask("x", "logical", "a", "1", "spec", "contract"),
        ),
        expected_model="m",
        configuration_fingerprint="config",
        completed_run_task_ids=("x",),
    )
    store.create(state)

    handlers = {}
    monkeypatch.setattr(
        lifecycle_module.signal,
        "getsignal",
        lambda _sig: object(),
    )
    monkeypatch.setattr(
        lifecycle_module.signal,
        "signal",
        lambda sig, handler: handlers.__setitem__(sig, handler),
    )

    async def fake_run_pending(**_kwargs):
        return 1, "campaign"

    async def fake_storage_completed(_settings, _state):
        handlers[signal.SIGINT](signal.SIGINT, None)
        await asyncio.sleep(0)
        return frozenset({"x"})

    monkeypatch.setattr(lifecycle_module, "run_pending", fake_run_pending)
    monkeypatch.setattr(
        lifecycle_module,
        "_storage_completed_run_task_ids",
        fake_storage_completed,
    )

    attempted, campaign_id = await lifecycle_module._execute_locked(
        settings,
        EmptyRegistry(),
        AdapterRegistry([]),
        store,
        ("x",),
        None,
        None,
        None,
    )

    assert attempted == 1
    assert campaign_id == "campaign"
    assert store.load().status == "paused"


@pytest.mark.asyncio
async def test_external_pause_request_cancels_active_execution(
    tmp_path,
    monkeypatch,
):
    settings = make_settings(tmp_path)
    store = RunControlStore(settings.superbench_active_run_path)
    state = ActiveRun(
        schema_version=3,
        run_id="run",
        campaign_id="campaign",
        status="running",
        selected_tasks=(
            PlannedTask("x", "logical", "a", "1", "spec", "contract"),
        ),
        expected_model="m",
        configuration_fingerprint="config",
    )
    store.create(state)

    monkeypatch.setattr(
        lifecycle_module.signal,
        "getsignal",
        lambda _sig: object(),
    )
    monkeypatch.setattr(
        lifecycle_module.signal,
        "signal",
        lambda *_args: None,
    )

    async def fake_run_pending(**_kwargs):
        store.request_pause()
        await asyncio.Event().wait()

    monkeypatch.setattr(lifecycle_module, "run_pending", fake_run_pending)

    attempted, campaign_id = await asyncio.wait_for(
        lifecycle_module._execute_locked(
            settings,
            EmptyRegistry(),
            AdapterRegistry([]),
            store,
            ("x",),
            None,
            None,
            None,
        ),
        timeout=1,
    )

    assert attempted == 0
    assert campaign_id == "campaign"
    assert store.load().status == "paused"



class EvalLifecycle:
    def environment_ids(self, task, *, attempt, fingerprint):
        return {}

    async def prepare(self, task, environments, fingerprint, *, attempt):
        return None

    async def assert_resume(self, task, environments, fingerprint, *, attempt):
        return None

    async def runtime_metadata(
        self,
        task,
        environments,
        fingerprint,
        *,
        attempt,
    ):
        return {}

    async def reset(self, task, environments, fingerprint, *, attempt):
        return None


class EvalChatGPT:
    def __init__(self):
        self.prepared = []

    async def prepare_session(self, *, fresh_home=False):
        return None

    async def prepare_task(self, task):
        self.prepared.append(task.task_id)
        return task

    async def submit_task(
        self,
        prepared,
        *,
        before_send,
        on_user_message_id,
    ):
        before_send()
        user_message_id = f"user-{prepared.task_id}"
        on_user_message_id(user_message_id)
        return SimpleNamespace(
            conversation_id=f"conv-{prepared.task_id}",
            user_message_id=user_message_id,
        )

    async def wait_for_completion(self, submitted):
        return CapturedConversation(
            submitted.conversation_id,
            [{"id": f"assistant-{submitted.conversation_id}"}],
            {},
        )

    async def delete_completed_conversation(self, _conversation_id):
        return None


class EvalStorage:
    def __init__(self):
        self.rows = {}
        self.evaluations = []

    async def get(self, task_id):
        return self.rows.get(task_id)

    async def start(
        self,
        task_id,
        runner_id,
        expected_attempt,
        task_fingerprint,
        app_provenance,
        logical_task_id=None,
        dataset_metadata=None,
    ):
        row = StoredRun(
            task_id=task_id,
            logical_task_id=logical_task_id or task_id,
            status="running",
            attempt=expected_attempt,
            runner_id=runner_id,
            task_fingerprint=task_fingerprint,
            app_provenance=app_provenance,
            dataset_metadata=dataset_metadata or {},
        )
        self.rows[task_id] = row
        return row

    async def set_conversation(
        self,
        task_id,
        conversation_id,
        *,
        attempt,
        runner_id,
    ):
        row = replace(
            self.rows[task_id],
            conversation_id=conversation_id,
        )
        self.rows[task_id] = row
        return row

    async def complete(
        self,
        task_id,
        captured,
        *,
        attempt,
        runner_id,
        evaluation=None,
    ):
        row = replace(
            self.rows[task_id],
            status="completed",
            conversation_id=captured.conversation_id,
            evaluation=evaluation,
        )
        self.rows[task_id] = row
        self.evaluations.append((task_id, evaluation))
        return row

    async def fail(
        self,
        task_id,
        error,
        *,
        attempt,
        runner_id,
    ):
        row = replace(
            self.rows[task_id],
            status="failed",
            error_type=type(error).__name__,
            error_message=str(error),
        )
        self.rows[task_id] = row
        return row


@pytest.mark.asyncio
async def test_evaluator_fail_is_completed_and_batch_continues(tmp_path):
    chatgpt = EvalChatGPT()
    storage = EvalStorage()
    lifecycle = EvalLifecycle()

    async def fail_eval(_captured):
        return {"verdict": "fail", "score": 0.0}

    async def pass_eval(_captured):
        return {"verdict": "pass", "score": 1.0}

    runner = BenchmarkRunner(
        chatgpt=chatgpt,
        storage=storage,
        lifecycle=lifecycle,
        runner_id="runner",
        recover_existing=True,
        console=Console(force_terminal=False),
        journal=JournalStore(tmp_path / "submission.json"),
        evaluation_hooks={
            "one": fail_eval,
            "two": pass_eval,
        },
    )

    await runner.run_task(BenchmarkTask("one", "p1", ()), False)
    await runner.run_task(BenchmarkTask("two", "p2", ()), False)

    assert chatgpt.prepared == ["one", "two"]
    assert storage.rows["one"].status == "completed"
    assert storage.rows["two"].status == "completed"
    assert storage.evaluations == [
        ("one", {"verdict": "fail", "score": 0.0}),
        ("two", {"verdict": "pass", "score": 1.0}),
    ]

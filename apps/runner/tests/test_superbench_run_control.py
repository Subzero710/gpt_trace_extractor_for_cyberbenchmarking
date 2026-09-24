import json
import signal
from dataclasses import asdict, replace

import pytest

from gpt_trace_runner.exceptions import ConcurrentRunnerError, RecoveryIncomplete
from gpt_trace_runner.lock import RunnerLock
from gpt_trace_runner.superbench.lifecycle import SigintPause, classify_incident
from gpt_trace_runner.superbench.run_control import (
    ActiveRun,
    PlannedTask,
    RunControlStore,
)


def make_run() -> ActiveRun:
    return ActiveRun(
        schema_version=3,
        run_id="r",
        campaign_id="c",
        status="running",
        selected_tasks=(
            PlannedTask(
                run_task_id="x",
                logical_task_id="logical",
                adapter_id="a",
                adapter_version="1",
                task_spec_fingerprint="spec",
                task_contract_fingerprint="contract",
            ),
        ),
        expected_model="m",
        configuration_fingerprint="config",
    )


def test_pause_not_overwritten_by_finish(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    store.start_task("x")
    store.request_pause()
    store.finish_task("x")
    state = store.load()
    assert state.status == "pause_requested"
    assert state.completed_run_task_ids == ("x",)


def test_pause_not_overwritten_by_start(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    store.request_pause()
    store.start_task("x")
    state = store.load()
    assert state.status == "pause_requested"
    assert state.current_run_task_id is None


def test_signal_pause_during_transaction_is_not_lost(tmp_path, monkeypatch):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    original_write = store._write
    fired = False

    def write_with_signal(state):
        nonlocal fired
        if not fired and state.current_run_task_id == "x":
            fired = True
            store.request_pause_from_signal()
        original_write(state)

    monkeypatch.setattr(store, "_write", write_with_signal)
    store.start_task("x")

    state = store.load()
    assert fired is True
    assert state.status == "pause_requested"
    assert state.current_run_task_id == "x"


def test_failed_attempt_is_not_completion(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    assert store.load().completed_run_task_ids == ()


def test_crash_states_can_begin_resume(tmp_path):
    for status in (
        "running",
        "resuming",
        "pause_requested",
        "paused",
        "needs_intervention",
    ):
        store = RunControlStore(tmp_path / f"{status}.json")
        store.create(replace(make_run(), status=status))
        assert store.begin_resume().status == "resuming"


def test_resume_preserves_reason_until_confirm(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    state = replace(
        make_run(),
        status="needs_intervention",
        intervention_reason="authentication",
        exception_type="AuthenticationRequired",
        intervention_message="401",
    )
    store.create(state)

    resumed = store.begin_resume()
    assert resumed.intervention_reason == "authentication"
    assert resumed.intervention_message == "401"

    running = store.confirm_running()
    assert running.intervention_reason is None
    assert running.exception_type is None
    assert running.intervention_message is None


def test_intervention_keeps_current_task_and_evidence(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    store.start_task("x")
    store.intervention(
        "authentication",
        "AuthenticationRequired",
        "401",
    )
    state = store.load()
    assert state.current_run_task_id == "x"
    assert state.exception_type == "AuthenticationRequired"
    assert state.intervention_message == "401"


def test_complete_requires_control_and_storage_completion(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())

    with pytest.raises(RecoveryIncomplete, match="control state"):
        store.complete({"x"})

    store.finish_task("x")
    with pytest.raises(
        RecoveryIncomplete,
        match="storage.status == completed",
    ):
        store.complete(set())

    assert store.complete({"x"}).status == "completed"


def test_schema_uses_required_v3_field_names(tmp_path):
    store = RunControlStore(tmp_path / "active.json")
    state = replace(
        make_run(),
        intervention_reason="infrastructure",
        exception_type="RuntimeError",
        intervention_message="boom",
    )
    store.create(state)

    payload = json.loads(
        (tmp_path / "active.json").read_text(encoding="utf-8")
    )
    planned = payload["selected_tasks"][0]

    assert planned["task_contract_fingerprint"] == "contract"
    assert "contract_fingerprint" not in planned
    assert payload["intervention_message"] == "boom"
    assert "message" not in payload


def test_legacy_v3_field_names_are_read_compatibly(tmp_path):
    state = replace(
        make_run(),
        intervention_reason="recovery",
        exception_type="RecoveryIncomplete",
        intervention_message="legacy",
    )
    payload = asdict(state)
    planned = payload["selected_tasks"][0]
    planned["contract_fingerprint"] = planned.pop(
        "task_contract_fingerprint"
    )
    payload["message"] = payload.pop("intervention_message")

    path = tmp_path / "active.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = RunControlStore(path).load()
    assert loaded is not None
    assert loaded.selected_tasks[0].task_contract_fingerprint == "contract"
    assert loaded.intervention_message == "legacy"


def test_runner_lock_rejects_second_owner(tmp_path):
    path = tmp_path / "runner.lock"
    with RunnerLock(path):
        with pytest.raises(ConcurrentRunnerError):
            with RunnerLock(path):
                pass


def test_first_sigint_persists_pause_request(tmp_path, monkeypatch):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    handlers = {}

    monkeypatch.setattr(signal, "getsignal", lambda *_: object())
    monkeypatch.setattr(
        signal,
        "signal",
        lambda sig, handler: handlers.__setitem__(sig, handler),
    )

    with SigintPause(store.request_pause_from_signal) as guard:
        handlers[signal.SIGINT](signal.SIGINT, None)
        assert guard.pause_requested is True
        assert guard.n == 1
        assert store.load().status == "pause_requested"


def test_second_sigint_is_hard_interrupt(tmp_path, monkeypatch):
    store = RunControlStore(tmp_path / "active.json")
    store.create(make_run())
    handlers = {}

    monkeypatch.setattr(signal, "getsignal", lambda *_: object())
    monkeypatch.setattr(
        signal,
        "signal",
        lambda sig, handler: handlers.__setitem__(sig, handler),
    )

    with SigintPause(store.request_pause_from_signal):
        handlers[signal.SIGINT](signal.SIGINT, None)
        with pytest.raises(KeyboardInterrupt):
            handlers[signal.SIGINT](signal.SIGINT, None)

    assert store.load().status == "pause_requested"


def test_rate_limit_is_paused_not_human_intervention():
    from gpt_trace_runner.exceptions import RateLimited

    assert classify_incident(
        RateLimited("slow down")
    ) == ("rate_limited", False)

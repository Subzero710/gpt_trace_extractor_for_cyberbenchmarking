from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Iterable, Literal

from ..exceptions import RecoveryIncomplete


RunStatus = Literal[
    "running",
    "pause_requested",
    "paused",
    "resuming",
    "needs_intervention",
    "completed",
]


@dataclass(frozen=True, slots=True)
class PlannedTask:
    run_task_id: str
    logical_task_id: str
    adapter_id: str
    adapter_version: str
    task_spec_fingerprint: str
    task_contract_fingerprint: str

    @property
    def contract_fingerprint(self) -> str:
        return self.task_contract_fingerprint


@dataclass(frozen=True, slots=True)
class ActiveRun:
    schema_version: int
    run_id: str
    campaign_id: str
    status: RunStatus
    selected_tasks: tuple[PlannedTask, ...]
    expected_model: str
    configuration_fingerprint: str
    completed_run_task_ids: tuple[str, ...] = ()
    current_run_task_id: str | None = None
    intervention_reason: str | None = None
    exception_type: str | None = None
    intervention_message: str | None = None

    @property
    def message(self) -> str | None:
        return self.intervention_message


class RunControlStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock_path = path.with_suffix(path.suffix + ".lock")
        self._transaction_depth = 0
        self._signal_pause_pending = False

    @contextmanager
    def _lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            self._transaction_depth += 1
            try:
                yield
            finally:
                self._transaction_depth -= 1
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                if self._transaction_depth == 0:
                    self._flush_signal_pause()

    @staticmethod
    def _planned_task_from_json(value: dict) -> PlannedTask:
        value = dict(value)
        if (
            "task_contract_fingerprint" not in value
            and "contract_fingerprint" in value
        ):
            value["task_contract_fingerprint"] = value.pop("contract_fingerprint")
        return PlannedTask(**value)

    def _load(self) -> ActiveRun | None:
        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            payload["selected_tasks"] = tuple(
                self._planned_task_from_json(value)
                for value in payload["selected_tasks"]
            )
            payload["completed_run_task_ids"] = tuple(
                payload.get("completed_run_task_ids", ())
            )
            if (
                "intervention_message" not in payload
                and "message" in payload
            ):
                payload["intervention_message"] = payload.pop("message")
            state = ActiveRun(**payload)
        except Exception as exc:
            raise RecoveryIncomplete(f"active run unreadable: {exc}") from exc
        if state.schema_version != 3:
            raise RecoveryIncomplete("unsupported active-run schema")
        return state

    def _write(self, state: ActiveRun) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            asdict(state),
            sort_keys=True,
            separators=(",", ":"),
        )
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
            text=True,
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
            parent_fd = os.open(self.path.parent, os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def load(self) -> ActiveRun | None:
        with self._lock():
            return self._load()

    def create(self, state: ActiveRun) -> ActiveRun:
        with self._lock():
            old = self._load()
            if old is not None and old.status != "completed":
                raise RecoveryIncomplete(f"active run already {old.status}")
            self._write(state)
            return state

    def _mutate(self, fn) -> ActiveRun:
        with self._lock():
            state = self._load()
            if state is None:
                raise RecoveryIncomplete("no active Superbench run")
            new_state = fn(state)
            self._write(new_state)
            return new_state

    @staticmethod
    def _signal_pause_transition(state: ActiveRun) -> ActiveRun:
        if state.status in {"running", "resuming"}:
            return replace(state, status="pause_requested")
        return state

    def _flush_signal_pause(self) -> None:
        if not self._signal_pause_pending:
            return
        self._signal_pause_pending = False
        self._mutate(self._signal_pause_transition)

    def request_pause_from_signal(self) -> None:
        # If SIGINT arrives while another run-control transaction owns flock,
        # defer the durable pause transition until that transaction releases it.
        self._signal_pause_pending = True
        if self._transaction_depth == 0:
            self._flush_signal_pause()

    def request_pause(self) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            if state.status in {"paused", "pause_requested"}:
                return state
            if state.status not in {"running", "resuming"}:
                raise RecoveryIncomplete(f"cannot pause {state.status}")
            return replace(state, status="pause_requested")

        return self._mutate(transition)

    def pause_if_requested(self) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            if state.status != "pause_requested":
                return state
            return replace(
                state,
                status="paused",
                current_run_task_id=None,
            )

        return self._mutate(transition)

    def begin_resume(self) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            if state.status not in {
                "running",
                "resuming",
                "pause_requested",
                "paused",
                "needs_intervention",
            }:
                raise RecoveryIncomplete(f"cannot resume {state.status}")
            return replace(state, status="resuming")

        return self._mutate(transition)

    def confirm_running(self) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            if state.status == "pause_requested":
                return state
            if state.status not in {"running", "resuming"}:
                raise RecoveryIncomplete(f"cannot run {state.status}")
            return replace(
                state,
                status="running",
                intervention_reason=None,
                exception_type=None,
                intervention_message=None,
            )

        return self._mutate(transition)

    def start_task(self, run_task_id: str) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            if state.status == "pause_requested":
                return state
            selected = {task.run_task_id for task in state.selected_tasks}
            if run_task_id not in selected:
                raise RecoveryIncomplete("task outside frozen selection")
            return replace(state, current_run_task_id=run_task_id)

        return self._mutate(transition)

    def finish_task(self, run_task_id: str) -> ActiveRun:
        def transition(state: ActiveRun) -> ActiveRun:
            selected = {task.run_task_id for task in state.selected_tasks}
            if run_task_id not in selected:
                raise RecoveryIncomplete("task outside frozen selection")
            completed = list(state.completed_run_task_ids)
            if run_task_id not in completed:
                completed.append(run_task_id)
            return replace(
                state,
                completed_run_task_ids=tuple(completed),
                current_run_task_id=(
                    None
                    if state.current_run_task_id == run_task_id
                    else state.current_run_task_id
                ),
            )

        return self._mutate(transition)

    def intervention(
        self,
        reason: str,
        exception_type: str,
        message: str,
    ) -> ActiveRun:
        return self._mutate(
            lambda state: replace(
                state,
                status="needs_intervention",
                intervention_reason=reason,
                exception_type=exception_type,
                intervention_message=message,
            )
        )

    def paused_error(
        self,
        reason: str,
        exception_type: str,
        message: str,
    ) -> ActiveRun:
        return self._mutate(
            lambda state: replace(
                state,
                status="paused",
                intervention_reason=reason,
                exception_type=exception_type,
                intervention_message=message,
            )
        )

    def complete(
        self,
        storage_completed_run_task_ids: Iterable[str],
    ) -> ActiveRun:
        storage_completed = set(storage_completed_run_task_ids)

        def transition(state: ActiveRun) -> ActiveRun:
            selected = {task.run_task_id for task in state.selected_tasks}
            control_completed = set(state.completed_run_task_ids)
            if not selected <= control_completed:
                raise RecoveryIncomplete(
                    "unfinished frozen tasks in active-run control state"
                )
            if not selected <= storage_completed:
                raise RecoveryIncomplete(
                    "active run cannot complete until every frozen task has "
                    "storage.status == completed"
                )
            return replace(
                state,
                status="completed",
                current_run_task_id=None,
                intervention_reason=None,
                exception_type=None,
                intervention_message=None,
            )

        return self._mutate(transition)

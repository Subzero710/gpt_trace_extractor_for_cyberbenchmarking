from __future__ import annotations

from typing import Any, Awaitable, Callable, Protocol
from dataclasses import dataclass, replace
import hashlib
from .workstation_provider import InternalRuntime

from rich.console import Console

from .app_lifecycle import AppLifecycle
from .chatgpt import ChatGPTClient
from .exceptions import (
    FatalUIState,
    RecoveryIncomplete,
    StorageConflict,
    StorageError,
)
from .journal import JournalStore, SubmissionJournal
from .models import (
    BenchmarkTask,
    CapturedConversation,
    StoredRun,
    task_app_provenance,
    task_fingerprint,
    task_with_stored_ui_names,
)
from .provenance import enrich_capture


class StorageLike(Protocol):
    async def get(self, task_id: str) -> StoredRun | None: ...
    async def start(
        self,
        task_id: str,
        runner_id: str,
        expected_attempt: int,
        task_fingerprint: str,
        app_provenance: list[dict],
        logical_task_id: str | None = None,
        dataset_metadata: dict[str, Any] | None = None,
    ) -> StoredRun: ...
    async def set_conversation(self, task_id: str, conversation_id: str, *, attempt: int, runner_id: str) -> StoredRun: ...
    async def complete(self, task_id: str, captured: CapturedConversation, *, attempt: int, runner_id: str, evaluation: dict | None = None) -> StoredRun: ...
    async def fail(self, task_id: str, error: Exception, *, attempt: int, runner_id: str) -> StoredRun: ...



async def abandon_recovery(
    task: BenchmarkTask,
    *,
    storage: StorageLike,
    lifecycle: AppLifecycle,
    journal: JournalStore,
) -> None:
    """Abandon one current running attempt without touching the teacher browser."""
    entry = journal.load()
    if entry is None:
        raise RecoveryIncomplete("no pending recovery journal")
    if entry.task_id != task.task_id:
        raise RecoveryIncomplete(
            f"pending recovery belongs to {entry.task_id!r}, not {task.task_id!r}"
        )

    fingerprint = task_fingerprint(task)
    if entry.task_fingerprint != fingerprint:
        raise RecoveryIncomplete(
            "pending recovery fingerprint does not match the current benchmark"
        )

    expected_environments = lifecycle.environment_ids(
        task,
        attempt=entry.attempt,
        fingerprint=fingerprint,
    )
    if entry.app_environments != expected_environments:
        raise RecoveryIncomplete(
            "pending recovery App environments do not match this attempt"
        )

    existing = await storage.get(task.task_id)
    if existing is None:
        raise RecoveryIncomplete("pending recovery has no matching storage row")
    if existing.task_fingerprint != fingerprint:
        raise RecoveryIncomplete(
            "stored recovery fingerprint does not match the current benchmark"
        )
    if existing.status != "running":
        raise RecoveryIncomplete(
            f"recovery storage row is {existing.status!r}, not 'running'"
        )
    if existing.attempt != entry.attempt or existing.runner_id != entry.runner_id:
        raise RecoveryIncomplete(
            "pending recovery attempt/runner does not match storage"
        )

    # Terminalize first. If App cleanup then fails, keep the journal so the
    # normal reconcile path can retry cleanup of the now-failed attempt.
    await storage.fail(
        task.task_id,
        RecoveryIncomplete("operator abandoned unrecoverable conversation"),
        attempt=entry.attempt,
        runner_id=entry.runner_id,
    )
    reset = lifecycle.abandon if task.workstation_template is not None else lifecycle.reset
    await reset(
        task,
        expected_environments,
        fingerprint,
        attempt=entry.attempt,
    )
    journal.clear()
    journal.clear_capture()


@dataclass(frozen=True)
class RuntimeHooks:
    prepare: Callable
    capture: Callable
    evaluate: Callable


class InterruptedBeforeSubmission(RuntimeError):
    pass


class BenchmarkRunner:
    def __init__(
        self,
        *,
        chatgpt: ChatGPTClient,
        storage: StorageLike,
        lifecycle: AppLifecycle,
        runner_id: str,
        recover_existing: bool,
        console: Console,
        journal: JournalStore,
        storage_context: dict[str, dict[str, Any]] | None = None,
        evaluation_hooks: dict[
            str,
            Callable[[CapturedConversation], Awaitable[dict[str, Any] | None]],
        ] | None = None,
        runtime_hooks: dict[str, RuntimeHooks] | None = None,
    ) -> None:
        self.chatgpt = chatgpt
        self.storage = storage
        self.lifecycle = lifecycle
        self.runner_id = runner_id
        self.recover_existing = recover_existing
        self.console = console
        self.journal = journal
        self._session_prepared = False
        self.storage_context = storage_context or {}
        self.evaluation_hooks = evaluation_hooks or {}
        self.runtime_hooks = runtime_hooks or {}

    def _internal(self, task, environments, fingerprint, attempt):
        key = hashlib.sha256(f"{task.task_id}\0{attempt}\0{fingerprint}".encode()).hexdigest()
        return InternalRuntime(self.lifecycle.runtime, task, environments, fingerprint, attempt,
                               self.journal.path.parent / "evaluation-artifacts" / key)

    async def _evaluate_capture(self, task, captured, attempt, environments, fingerprint):
        hooks = self.runtime_hooks.get(task.task_id)
        if hooks is None:
            evaluation = self.evaluation_hooks.get(task.task_id)
            return await evaluation(captured) if evaluation is not None else None
        entry = self.journal.load()
        if entry is None or entry.task_id != task.task_id or entry.attempt != attempt:
            raise RecoveryIncomplete("missing candidate evaluation journal")
        if entry.phase not in {"conversation_checkpointed", "candidate_checkpointed"}:
            digest = self.journal.write_capture(captured, entry)
            entry = replace(entry, phase="conversation_checkpointed", conversation_id=captured.conversation_id,
                            capture_sha256=digest)
            self.journal.write(entry)
        runtime = self._internal(task, environments, fingerprint, attempt)
        if entry.phase != "candidate_checkpointed":
            candidate = await hooks.capture(captured, runtime)
            entry = replace(entry, phase="candidate_checkpointed", candidate=candidate)
            self.journal.write(entry)
        return await hooks.evaluate(captured, entry.candidate, runtime)

    async def _ensure_session(self) -> None:
        if self._session_prepared:
            return
        await self.chatgpt.prepare_session(fresh_home=False)
        self._session_prepared = True

    @staticmethod
    def _names(task: BenchmarkTask) -> dict[str, str]:
        return {tool.app_id: tool.ui_name for tool in task.tools}

    def _entry(
        self,
        task: BenchmarkTask,
        *,
        runner_id: str,
        attempt: int,
        phase: str,
        fingerprint: str,
        environments: dict[str, str],
        conversation_id: str | None = None,
        user_message_id: str | None = None,
    ) -> SubmissionJournal:
        return SubmissionJournal(
            task_id=task.task_id,
            runner_id=runner_id,
            attempt=attempt,
            phase=phase,
            conversation_id=conversation_id,
            task_fingerprint=fingerprint,
            app_environments=dict(environments),
            resolved_app_names=self._names(task),
            user_message_id=user_message_id,
        )

    @staticmethod
    def _recovery_task(task: BenchmarkTask, existing: StoredRun) -> BenchmarkTask:
        if not task.tools:
            return task
        if existing.app_provenance is None:
            raise RecoveryIncomplete("running task has no stored App provenance")
        try:
            return task_with_stored_ui_names(task, existing.app_provenance)
        except ValueError as exc:
            raise RecoveryIncomplete(str(exc)) from exc

    async def _complete_recovery(
        self,
        task: BenchmarkTask,
        existing: StoredRun,
        conversation_id: str,
        user_message_id: str,
        environments: dict[str, str],
        fingerprint: str,
    ) -> None:
        recovery_task = self._recovery_task(task, existing)
        await self.lifecycle.assert_resume(recovery_task, environments, fingerprint, attempt=existing.attempt)
        identity = existing.runner_id or self.runner_id
        captured = await self.chatgpt.recover(
            conversation_id,
            task=recovery_task,
            user_message_id=user_message_id,
        )
        # Recovery may replace a frontend-local local-chatgpt/WEB route handle
        # with the durable backend conversation ID. Persist and clean up only
        # that resolved identity from this point onward.
        conversation_id = captured.conversation_id
        app_runtime = await self.lifecycle.runtime_metadata(
            recovery_task,
            environments,
            fingerprint,
            attempt=existing.attempt,
        )
        captured = enrich_capture(
            captured,
            task=recovery_task,
            app_environments=environments,
            app_runtime=app_runtime,
        )
        await self.storage.set_conversation(task.task_id, conversation_id, attempt=existing.attempt, runner_id=identity)
        evaluation = await self._evaluate_capture(task, captured, existing.attempt, environments, fingerprint)
        await self.storage.complete(task.task_id, captured, attempt=existing.attempt, runner_id=identity, **({"evaluation": evaluation} if evaluation is not None else {}))
        self.journal.write(
            self._entry(
                recovery_task,
                runner_id=identity,
                attempt=existing.attempt,
                phase="cleanup_pending",
                fingerprint=fingerprint,
                environments=environments,
                conversation_id=conversation_id,
                user_message_id=user_message_id,
            )
        )
        await self.chatgpt.delete_completed_conversation(conversation_id)
        await self.lifecycle.reset(recovery_task, environments, fingerprint, attempt=existing.attempt)
        self.journal.clear()
        self.journal.clear_capture()
        self.console.print(f"[green]{task.task_id}: recovered ({len(captured.messages)} messages)[/]")

    async def reconcile_journal(self, tasks: list[BenchmarkTask]) -> None:
        entry = self.journal.load()
        if entry is None:
            return
        task = {item.task_id: item for item in tasks}.get(entry.task_id)
        if task is None:
            raise RecoveryIncomplete(f"pending submission journal references task {entry.task_id!r} not present in benchmark")
        fingerprint = task_fingerprint(task)
        if entry.task_fingerprint != fingerprint:
            raise RecoveryIncomplete("submission journal task fingerprint does not match the current benchmark")
        expected_environments = self.lifecycle.environment_ids(task, attempt=entry.attempt, fingerprint=fingerprint)
        if entry.app_environments != expected_environments:
            raise RecoveryIncomplete("submission journal App environments do not match this attempt")
        existing = await self.storage.get(entry.task_id)
        if existing is not None and existing.task_fingerprint != fingerprint:
            raise RecoveryIncomplete("storage task fingerprint does not match the crash journal/benchmark")
        recovery_task = self._recovery_task(task, existing) if existing is not None else task
        if entry.resolved_app_names != self._names(recovery_task):
            raise RecoveryIncomplete("submission journal UI App resolution does not match stored provenance")

        if existing is not None and existing.status == "completed":
            conversation_id = entry.conversation_id or existing.conversation_id
            if conversation_id:
                await self.chatgpt.delete_completed_conversation(conversation_id)
            await self.lifecycle.reset(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
            self.journal.clear()
            self.journal.clear_capture()
            return
        if (
            existing is not None
            and existing.status == "failed"
            and existing.attempt == entry.attempt
            and existing.runner_id == entry.runner_id
        ):
            reset = self.lifecycle.abandon if task.workstation_template is not None else self.lifecycle.reset
            await reset(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
            self.journal.clear()
            self.journal.clear_capture()
            return

        if task.task_id in self.runtime_hooks and entry.phase in {
            "starting", "apps_prepared", "benchmark_preparing", "benchmark_ready", "composer_dirty"
        }:
            if existing is None or existing.status != "running" or existing.attempt != entry.attempt or existing.runner_id != entry.runner_id:
                raise RecoveryIncomplete("runtime preparation checkpoint has no matching running attempt")
            await self._run_attempt(recovery_task, fingerprint, expected_environments, entry.attempt,
                                    started=existing, resume_entry=entry)
            return

        if entry.phase in {"conversation_checkpointed", "candidate_checkpointed"}:
            if task.task_id not in self.runtime_hooks:
                raise RecoveryIncomplete("durable evaluation checkpoint has no runtime hooks")
            if existing is None or existing.status != "running" or existing.attempt != entry.attempt or existing.runner_id != entry.runner_id:
                raise RecoveryIncomplete("evaluation checkpoint has no matching running attempt")
            captured = self.journal.load_capture(entry)
            await self.lifecycle.assert_resume(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
            evaluation = await self._evaluate_capture(recovery_task, captured, entry.attempt, expected_environments, fingerprint)
            await self.storage.complete(entry.task_id, captured, attempt=entry.attempt, runner_id=entry.runner_id,
                                        **({"evaluation": evaluation} if evaluation is not None else {}))
            self.journal.write(replace(self.journal.load(), phase="cleanup_pending"))
            await self.chatgpt.delete_completed_conversation(captured.conversation_id)
            await self.lifecycle.reset(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
            self.journal.clear()
            self.journal.clear_capture()
            return

        if entry.phase in {"starting", "apps_prepared", "composer_dirty"}:
            await self.lifecycle.reset(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
            if existing is None:
                self.journal.clear()
                return
            if (
                existing.status == "running"
                and existing.attempt == entry.attempt
                and existing.runner_id == entry.runner_id
                and not existing.conversation_id
            ):
                await self.storage.fail(
                    entry.task_id,
                    InterruptedBeforeSubmission("runner stopped before Send"),
                    attempt=entry.attempt,
                    runner_id=entry.runner_id,
                )
                self.journal.clear()
                return
            raise RecoveryIncomplete("journal/storage state mismatch before submission")

        if existing is None or existing.status != "running":
            raise RecoveryIncomplete("submission journal has no matching running storage row")
        if existing.attempt != entry.attempt or existing.runner_id != entry.runner_id:
            raise RecoveryIncomplete("submission journal attempt/runner does not match storage")
        conversation_id = entry.conversation_id or existing.conversation_id
        if conversation_id:
            if not entry.user_message_id:
                raise RecoveryIncomplete(
                    "submitted conversation has no persisted user_message_id proof"
                )
            await self._complete_recovery(
                task,
                existing,
                conversation_id,
                entry.user_message_id,
                expected_environments,
                fingerprint,
            )
            return
        if entry.phase != "submission_started":
            raise RecoveryIncomplete("conversation_known journal has no conversation_id")
        if not entry.user_message_id:
            raise RecoveryIncomplete(
                "submission journal has no persisted user_message_id proof; "
                "automatic recovery is disabled"
            )
        await self.lifecycle.assert_resume(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
        captured = await self.chatgpt.recover_current_candidate(
            task=recovery_task,
            user_message_id=entry.user_message_id,
        )
        conversation_id = captured.conversation_id
        self.journal.write(
            self._entry(
                recovery_task,
                runner_id=entry.runner_id,
                attempt=entry.attempt,
                phase="conversation_known",
                fingerprint=fingerprint,
                environments=expected_environments,
                conversation_id=conversation_id,
                user_message_id=entry.user_message_id,
            )
        )
        await self.storage.set_conversation(entry.task_id, conversation_id, attempt=entry.attempt, runner_id=entry.runner_id)
        app_runtime = await self.lifecycle.runtime_metadata(
            recovery_task,
            expected_environments,
            fingerprint,
            attempt=entry.attempt,
        )
        captured = enrich_capture(
            captured,
            task=recovery_task,
            app_environments=expected_environments,
            app_runtime=app_runtime,
        )
        evaluation = await self._evaluate_capture(task, captured, entry.attempt, expected_environments, fingerprint)
        await self.storage.complete(entry.task_id, captured, attempt=entry.attempt, runner_id=entry.runner_id, **({"evaluation": evaluation} if evaluation is not None else {}))
        self.journal.write(
            self._entry(
                recovery_task,
                runner_id=entry.runner_id,
                attempt=entry.attempt,
                phase="cleanup_pending",
                fingerprint=fingerprint,
                environments=expected_environments,
                conversation_id=conversation_id,
                user_message_id=entry.user_message_id,
            )
        )
        await self.chatgpt.delete_completed_conversation(conversation_id)
        await self.lifecycle.reset(recovery_task, expected_environments, fingerprint, attempt=entry.attempt)
        self.journal.clear()
        self.journal.clear_capture()
        self.console.print(f"[green]{entry.task_id}: crash recovery completed[/]")

    async def _recover_existing(self, task: BenchmarkTask, existing: StoredRun) -> bool:
        if existing.status == "completed":
            return True
        if existing.status != "running":
            return False
        if not existing.conversation_id:
            raise RecoveryIncomplete(f"{task.task_id} is running without conversation_id or recoverable journal")
        if not self.recover_existing:
            raise RecoveryIncomplete("existing conversation recovery is disabled")
        raise RecoveryIncomplete(
            f"{task.task_id} is running with conversation_id but no submission journal "
            "user_message_id proof; automatic recovery is disabled"
        )

    async def run_task(self, task: BenchmarkTask, resume: bool) -> None:
        fingerprint = task_fingerprint(task)
        provenance = task_app_provenance(task)
        existing = await self.storage.get(task.task_id)
        if existing is not None:
            if existing.task_fingerprint is None:
                raise StorageError(f"{task.task_id} storage row has no task_fingerprint; migrate or delete it before reuse")
            if existing.task_fingerprint != fingerprint:
                raise StorageError(f"{task.task_id} benchmark specification changed since the stored attempt")
        if existing and existing.status == "completed":
            if resume:
                if existing.conversation_id:
                    await self.chatgpt.delete_completed_conversation(existing.conversation_id)
                self.console.print(f"[dim]{task.task_id}: completed, skip[/]")
                return
            raise RuntimeError(f"{task.task_id} already completed; resume the active Superbench run")
        if existing and existing.status == "running":
            if not resume:
                raise RecoveryIncomplete(f"{task.task_id} is already running; resume the active Superbench run")
            if await self._recover_existing(task, existing):
                return
        if existing and existing.status == "failed" and not resume:
            raise RuntimeError(f"{task.task_id} previously failed; resume the active Superbench run for a new attempt")

        expected_attempt = existing.attempt + 1 if existing else 1
        environments = self.lifecycle.environment_ids(task, attempt=expected_attempt, fingerprint=fingerprint)
        self.journal.write(
            self._entry(
                task,
                runner_id=self.runner_id,
                attempt=expected_attempt,
                phase="starting",
                fingerprint=fingerprint,
                environments=environments,
            )
        )
        await self._run_attempt(task, fingerprint, environments, expected_attempt)

    async def _run_attempt(self, task, fingerprint, environments, expected_attempt,
                           *, started=None, resume_entry=None):
        identity = resume_entry.runner_id if resume_entry is not None else self.runner_id
        phase = resume_entry.phase if resume_entry is not None else "starting"
        try:
            if resume_entry is None:
                context = self.storage_context.get(task.task_id, {})
                started = await self.storage.start(
                    task.task_id, identity, expected_attempt, fingerprint, task_app_provenance(task),
                    logical_task_id=context.get("logical_task_id"),
                    dataset_metadata=context.get("dataset_metadata"),
                )
                if started.attempt != expected_attempt or started.runner_id != identity:
                    raise StorageError("storage /start returned unexpected attempt identity")
                await self.lifecycle.prepare(task, environments, fingerprint, attempt=expected_attempt)
            elif resume_entry.phase == "starting":
                await self.lifecycle.prepare(task, environments, fingerprint, attempt=expected_attempt)
            else:
                await self.lifecycle.assert_resume(task, environments, fingerprint, attempt=expected_attempt)
            phase = "apps_prepared"
            self.journal.write(
                self._entry(
                    task,
                    runner_id=identity,
                    attempt=expected_attempt,
                    phase=phase,
                    fingerprint=fingerprint,
                    environments=environments,
                )
            )
            if task.task_id in self.runtime_hooks:
                phase = "benchmark_preparing"
                self.journal.write(self._entry(task, runner_id=identity, attempt=expected_attempt,
                    phase=phase, fingerprint=fingerprint, environments=environments))
                await self.runtime_hooks[task.task_id].prepare(self._internal(task, environments, fingerprint, expected_attempt))
                phase = "benchmark_ready"
                self.journal.write(self._entry(task, runner_id=identity, attempt=expected_attempt,
                    phase=phase, fingerprint=fingerprint, environments=environments))
            await self._ensure_session()
            prepared = await self.chatgpt.prepare_task(task)
            if task_fingerprint(task) != fingerprint:
                raise FatalUIState("benchmark task files or App contracts changed while the task was being prepared")
            phase = "composer_dirty"
            self.journal.write(
                self._entry(
                    task,
                    runner_id=identity,
                    attempt=expected_attempt,
                    phase=phase,
                    fingerprint=fingerprint,
                    environments=environments,
                )
            )

            def mark_submission_started() -> None:
                nonlocal phase
                phase = "submission_started"
                self.journal.write(
                    self._entry(
                        task,
                        runner_id=identity,
                        attempt=expected_attempt,
                        phase=phase,
                        fingerprint=fingerprint,
                        environments=environments,
                    )
                )

            def persist_user_message_id(user_message_id: str) -> None:
                self.journal.write(
                    self._entry(
                        task,
                        runner_id=identity,
                        attempt=expected_attempt,
                        phase="submission_started",
                        fingerprint=fingerprint,
                        environments=environments,
                        user_message_id=user_message_id,
                    )
                )

            submitted = await self.chatgpt.submit_task(
                prepared,
                before_send=mark_submission_started,
                on_user_message_id=persist_user_message_id,
            )
            phase = "conversation_known"
            self.journal.write(
                self._entry(
                    task,
                    runner_id=identity,
                    attempt=expected_attempt,
                    phase=phase,
                    fingerprint=fingerprint,
                    environments=environments,
                    conversation_id=submitted.conversation_id,
                    user_message_id=submitted.user_message_id,
                )
            )
            await self.storage.set_conversation(
                task.task_id,
                submitted.conversation_id,
                attempt=expected_attempt,
                runner_id=identity,
            )
            self.console.print(f"{task.task_id}: conversation {submitted.conversation_id}")
            captured = await self.chatgpt.wait_for_completion(submitted)
            app_runtime = await self.lifecycle.runtime_metadata(
                task,
                environments,
                fingerprint,
                attempt=expected_attempt,
            )
            captured = enrich_capture(
                captured,
                task=task,
                app_environments=environments,
                app_runtime=app_runtime,
            )
            evaluation = await self._evaluate_capture(task, captured, expected_attempt, environments, fingerprint)
            await self.storage.complete(task.task_id, captured, attempt=expected_attempt, runner_id=identity, **({"evaluation": evaluation} if evaluation is not None else {}))
            phase = "cleanup_pending"
            self.journal.write(
                self._entry(
                    task,
                    runner_id=identity,
                    attempt=expected_attempt,
                    phase=phase,
                    fingerprint=fingerprint,
                    environments=environments,
                    conversation_id=submitted.conversation_id,
                    user_message_id=submitted.user_message_id,
                )
            )
            await self.chatgpt.delete_completed_conversation(submitted.conversation_id)
            await self.lifecycle.reset(task, environments, fingerprint, attempt=expected_attempt)
            self.journal.clear()
            self.journal.clear_capture()
            self.console.print(f"[green]{task.task_id}: completed ({len(captured.messages)} messages)[/]")
        except Exception as exc:
            if phase == "starting" and started is None and isinstance(exc, StorageConflict):
                self.journal.clear()
            elif task.task_id not in self.runtime_hooks and phase in {"starting", "apps_prepared", "composer_dirty"} and started is not None and not isinstance(exc, StorageError):
                await self.lifecycle.reset(task, environments, fingerprint, attempt=expected_attempt)
                await self.storage.fail(task.task_id, exc, attempt=expected_attempt, runner_id=identity)
                self.journal.clear()
            raise

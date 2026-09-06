from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from rich.console import Console

from .chatgpt import ChatGPTClient
from .exceptions import BatchCircuitBreaker, FatalUIState, RecoveryIncomplete, RequiredToolNotUsed, StorageConflict, StorageError
from .journal import JournalStore, SubmissionJournal
from .models import BenchmarkTask, CapturedConversation, StoredRun, task_fingerprint


class StorageLike(Protocol):
    async def get(self, task_id: str) -> StoredRun | None: ...
    async def start(self, task_id: str, runner_id: str, expected_attempt: int, task_fingerprint: str) -> StoredRun: ...
    async def set_conversation(self, task_id: str, conversation_id: str, *, attempt: int, runner_id: str) -> StoredRun: ...
    async def complete(self, task_id: str, captured: CapturedConversation, *, attempt: int, runner_id: str) -> StoredRun: ...
    async def fail(self, task_id: str, error: Exception, *, attempt: int, runner_id: str) -> StoredRun: ...


@dataclass(frozen=True, slots=True)
class RunOptions:
    resume: bool = False
    stop_on_error: bool = False
    limit: int | None = None


class InterruptedBeforeSubmission(RuntimeError):
    pass


class BenchmarkRunner:
    def __init__(self, *, chatgpt: ChatGPTClient, storage: StorageLike,
                 runner_id: str, recover_existing: bool, console: Console,
                 journal: JournalStore) -> None:
        self.chatgpt = chatgpt
        self.storage = storage
        self.runner_id = runner_id
        self.recover_existing = recover_existing
        self.console = console
        self.journal = journal
        self._session_prepared = False


    async def _ensure_session(self) -> None:
        if self._session_prepared:
            return
        await self.chatgpt.prepare_session(fresh_home=True)
        self._session_prepared = True

    async def _complete_recovery(self, task: BenchmarkTask, existing: StoredRun,
                                 conversation_id: str) -> None:
        identity = existing.runner_id or self.runner_id
        captured = await self.chatgpt.recover(conversation_id, task=task)
        await self.storage.set_conversation(
            task.task_id, conversation_id, attempt=existing.attempt, runner_id=identity
        )
        await self.storage.complete(
            task.task_id, captured, attempt=existing.attempt, runner_id=identity
        )
        self.journal.clear()
        self.console.print(f"[green]{task.task_id}: recovered ({len(captured.messages)} messages)[/]")

    async def reconcile_journal(self, tasks: list[BenchmarkTask]) -> None:
        entry = self.journal.load()
        if entry is None:
            return
        by_id = {task.task_id: task for task in tasks}
        task = by_id.get(entry.task_id)
        if task is None:
            raise RecoveryIncomplete(
                f"pending submission journal references task {entry.task_id!r} not present in benchmark"
            )
        fingerprint = task_fingerprint(task)
        if entry.task_fingerprint != fingerprint:
            raise RecoveryIncomplete(
                "submission journal task fingerprint does not match the current benchmark"
            )
        existing = await self.storage.get(entry.task_id)
        if existing is not None and existing.task_fingerprint != fingerprint:
            raise RecoveryIncomplete(
                "storage task fingerprint does not match the crash journal/benchmark"
            )
        if (
            existing is not None
            and existing.status == "failed"
            and existing.attempt == entry.attempt
            and existing.runner_id == entry.runner_id
        ):
            # The terminal mutation succeeded but the process may have died before
            # clearing the local journal.  The failed attempt is already immutable.
            self.journal.clear()
            return

        if entry.phase in {"starting", "composer_dirty"}:
            if existing is None:
                self.journal.clear()
                return
            if existing.status == "completed":
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
            if existing is not None and existing.status == "completed":
                self.journal.clear()
                return
            raise RecoveryIncomplete("submission journal has no matching running storage row")
        if existing.attempt != entry.attempt or existing.runner_id != entry.runner_id:
            raise RecoveryIncomplete("submission journal attempt/runner does not match storage")

        conversation_id = entry.conversation_id or existing.conversation_id
        if conversation_id:
            await self._complete_recovery(task, existing, conversation_id)
            return

        if entry.phase != "submission_started":
            raise RecoveryIncomplete("conversation_known journal has no conversation_id")

        captured = await self.chatgpt.recover_current_candidate(task=task)
        conversation_id = captured.conversation_id
        self.journal.write(
            SubmissionJournal(
                entry.task_id, entry.runner_id, entry.attempt, "conversation_known",
                conversation_id, fingerprint,
            )
        )
        await self.storage.set_conversation(
            entry.task_id, conversation_id, attempt=entry.attempt, runner_id=entry.runner_id
        )
        await self.storage.complete(
            entry.task_id, captured, attempt=entry.attempt, runner_id=entry.runner_id
        )
        self.journal.clear()
        self.console.print(f"[green]{entry.task_id}: crash recovery completed[/]")

    async def _recover_existing(self, task: BenchmarkTask, existing: StoredRun) -> bool:
        if existing.status == "completed":
            return True
        if existing.status != "running":
            return False
        if not existing.conversation_id:
            raise RecoveryIncomplete(
                f"{task.task_id} is running without conversation_id or recoverable journal"
            )
        if not self.recover_existing:
            raise RecoveryIncomplete("existing conversation recovery is disabled")
        await self._complete_recovery(task, existing, existing.conversation_id)
        return True

    async def run_task(self, task: BenchmarkTask, resume: bool) -> None:
        fingerprint = task_fingerprint(task)
        existing = await self.storage.get(task.task_id)
        if existing is not None:
            if existing.task_fingerprint is None:
                raise StorageError(
                    f"{task.task_id} is a legacy row without task_fingerprint; reset/migrate it explicitly"
                )
            if existing.task_fingerprint != fingerprint:
                raise StorageError(
                    f"{task.task_id} benchmark specification changed since the stored attempt"
                )
        if existing and existing.status == "completed":
            if resume:
                self.console.print(f"[dim]{task.task_id}: completed, skip[/]")
                return
            raise RuntimeError(f"{task.task_id} already completed; use --resume")

        if existing and existing.status == "running":
            if not resume:
                raise RecoveryIncomplete(f"{task.task_id} is already running; use --resume")
            if await self._recover_existing(task, existing):
                return

        if existing and existing.status == "failed" and not resume:
            raise RuntimeError(f"{task.task_id} previously failed; use --resume for a new attempt")

        expected_attempt = (existing.attempt + 1) if existing else 1
        self.journal.write(
            SubmissionJournal(
                task.task_id, self.runner_id, expected_attempt, "starting",
                task_fingerprint=fingerprint,
            )
        )
        started: StoredRun | None = None
        phase = "starting"
        try:
            started = await self.storage.start(
                task.task_id, self.runner_id, expected_attempt, fingerprint
            )
            if started.attempt != expected_attempt or started.runner_id != self.runner_id:
                raise StorageError("storage /start returned unexpected attempt identity")

            await self._ensure_session()
            prepared = await self.chatgpt.prepare_task(task)
            if task_fingerprint(task) != fingerprint:
                raise FatalUIState(
                    "benchmark task files changed while the task was being prepared"
                )
            phase = "composer_dirty"
            self.journal.write(
                SubmissionJournal(
                    task.task_id, self.runner_id, expected_attempt, phase,
                    task_fingerprint=fingerprint,
                )
            )

            # ChatGPTClient invokes this synchronously after locating a concrete
            # Send control and immediately before clicking it.
            def mark_submission_started() -> None:
                nonlocal phase
                phase = "submission_started"
                self.journal.write(
                    SubmissionJournal(
                        task.task_id, self.runner_id, expected_attempt, phase,
                        task_fingerprint=fingerprint,
                    )
                )

            submitted = await self.chatgpt.submit_task(
                prepared, before_send=mark_submission_started
            )
            phase = "conversation_known"
            self.journal.write(
                SubmissionJournal(
                    task.task_id, self.runner_id, expected_attempt, phase,
                    submitted.conversation_id, fingerprint,
                )
            )
            await self.storage.set_conversation(
                task.task_id, submitted.conversation_id,
                attempt=expected_attempt, runner_id=self.runner_id,
            )
            self.console.print(f"{task.task_id}: conversation {submitted.conversation_id}")

            captured = await self.chatgpt.wait_for_completion(submitted)
            await self.storage.complete(
                task.task_id, captured, attempt=expected_attempt, runner_id=self.runner_id
            )
            self.journal.clear()
            self.console.print(
                f"[green]{task.task_id}: completed ({len(captured.messages)} messages)[/]"
            )
        except Exception as exc:
            if phase == "starting" and started is None and isinstance(exc, StorageConflict):
                # An explicit 409 proves this attempted /start was rejected.
                self.journal.clear()
            elif phase in {"starting", "composer_dirty"} and started is not None and not isinstance(exc, StorageError):
                # Send was definitely not attempted. It is safe to terminalize the
                # attempt; the next explicit --resume may create a fresh attempt.
                await self.storage.fail(
                    task.task_id, exc, attempt=expected_attempt, runner_id=self.runner_id
                )
                self.journal.clear()
            elif isinstance(exc, RequiredToolNotUsed) and started is not None:
                # The turn completed deterministically but failed its benchmark contract.
                await self.storage.fail(
                    task.task_id, exc, attempt=expected_attempt, runner_id=self.runner_id
                )
                self.journal.clear()
            # After submission, all infrastructure/protocol ambiguity preserves
            # running + journal for explicit recovery.
            raise

    async def run(self, tasks: list[BenchmarkTask], options: RunOptions) -> None:
        selected = tasks[: options.limit] if options.limit else tasks
        if not selected:
            raise RuntimeError("benchmark selection is empty")

        await self.reconcile_journal(selected)
        for index, task in enumerate(selected, 1):
            self.console.rule(f"{index}/{len(selected)} {task.task_id}")
            try:
                await self.run_task(task, options.resume)
            except KeyboardInterrupt:
                raise
            except BatchCircuitBreaker as exc:
                self.console.print(
                    f"[bold red]batch paused after {task.task_id}: {type(exc).__name__}: {exc}[/]"
                )
                raise
            except Exception as exc:
                self.console.print(f"[red]{task.task_id}: {type(exc).__name__}: {exc}[/]")
                if options.stop_on_error:
                    raise

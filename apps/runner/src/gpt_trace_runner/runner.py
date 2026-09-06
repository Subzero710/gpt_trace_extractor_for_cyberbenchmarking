from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from rich.console import Console

from .chatgpt import ChatGPTClient
from .exceptions import BatchCircuitBreaker
from .models import BenchmarkTask, CapturedConversation, StoredRun


class StorageLike(Protocol):
    async def get(self, task_id: str) -> StoredRun | None: ...
    async def start(self, task_id: str, runner_id: str): ...
    async def set_conversation(self, task_id: str, conversation_id: str) -> None: ...
    async def complete(self, task_id: str, captured: CapturedConversation) -> None: ...
    async def fail(self, task_id: str, error: Exception) -> None: ...


@dataclass(frozen=True, slots=True)
class RunOptions:
    resume: bool = False
    stop_on_error: bool = False
    limit: int | None = None


class BenchmarkRunner:
    def __init__(
        self,
        *,
        chatgpt: ChatGPTClient,
        storage: StorageLike,
        runner_id: str,
        recover_existing: bool,
        console: Console,
    ) -> None:
        self.chatgpt = chatgpt
        self.storage = storage
        self.runner_id = runner_id
        self.recover_existing = recover_existing
        self.console = console

    async def _recover(self, task: BenchmarkTask) -> bool:
        existing = await self.storage.get(task.task_id)
        if not existing:
            return False
        if existing.status == "completed":
            return True
        if not existing.conversation_id or not self.recover_existing:
            return False

        self.console.print(
            f"[yellow]{task.task_id}[/]: recovering {existing.conversation_id}"
        )
        captured = await self.chatgpt.recover(
            existing.conversation_id,
            task=task,
        )
        await self.storage.complete(task.task_id, captured)
        self.console.print(
            f"[green]{task.task_id}: recovered "
            f"({len(captured.messages)} messages)[/]"
        )
        return True

    async def run_task(self, task: BenchmarkTask, resume: bool) -> None:
        existing = await self.storage.get(task.task_id)
        if existing and existing.status == "completed":
            if resume:
                self.console.print(f"[dim]{task.task_id}: completed, skip[/]")
                return
            raise RuntimeError(f"{task.task_id} already completed; use --resume")

        if resume:
            try:
                if await self._recover(task):
                    return
            except Exception as exc:
                try:
                    await self.storage.fail(task.task_id, exc)
                finally:
                    raise

        await self.storage.start(task.task_id, self.runner_id)

        try:
            submitted = await self.chatgpt.start_task(task)
            await self.storage.set_conversation(
                task.task_id,
                submitted.conversation_id,
            )
            self.console.print(
                f"{task.task_id}: conversation {submitted.conversation_id}"
            )

            captured = await self.chatgpt.wait_for_completion(submitted)
            await self.storage.complete(task.task_id, captured)
            self.console.print(
                f"[green]{task.task_id}: completed "
                f"({len(captured.messages)} messages)[/]"
            )
        except Exception as exc:
            try:
                await self.storage.fail(task.task_id, exc)
            finally:
                raise

    async def run(
        self,
        tasks: list[BenchmarkTask],
        options: RunOptions,
    ) -> None:
        selected = tasks[: options.limit] if options.limit else tasks

        for index, task in enumerate(selected, 1):
            self.console.rule(f"{index}/{len(selected)} {task.task_id}")
            try:
                await self.run_task(task, options.resume)
            except KeyboardInterrupt:
                raise
            except BatchCircuitBreaker as exc:
                self.console.print(
                    f"[bold red]batch paused after {task.task_id}: "
                    f"{type(exc).__name__}: {exc}[/]"
                )
                raise
            except Exception as exc:
                self.console.print(
                    f"[red]{task.task_id}: {type(exc).__name__}: {exc}[/]"
                )
                if options.stop_on_error:
                    raise

            # No fixed inter-task sleep. The next task starts only after the
            # previous turn has completed and been persisted; start_task then
            # waits for ChatGPT's real READY state before any interaction.

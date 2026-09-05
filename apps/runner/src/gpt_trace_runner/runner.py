from __future__ import annotations
import asyncio
from dataclasses import dataclass
from rich.console import Console
from .chatgpt import ChatGPTClient
from .models import BenchmarkTask
from .storage_client import StorageClient

@dataclass(frozen=True, slots=True)
class RunOptions:
    resume: bool = False
    stop_on_error: bool = False
    limit: int | None = None

class BenchmarkRunner:
    def __init__(self, *, chatgpt: ChatGPTClient, storage: StorageClient, runner_id: str,
                 recover_existing: bool, inter_task_delay_seconds: float, console: Console) -> None:
        self.chatgpt = chatgpt
        self.storage = storage
        self.runner_id = runner_id
        self.recover_existing = recover_existing
        self.delay = inter_task_delay_seconds
        self.console = console

    async def _recover(self, task: BenchmarkTask) -> bool:
        existing = await self.storage.get(task.task_id)
        if not existing or not existing.conversation_id or existing.status == "completed":
            return existing is not None and existing.status == "completed"
        if not self.recover_existing:
            return False
        self.console.print(f"[yellow]{task.task_id}[/]: recovering {existing.conversation_id}")
        try:
            captured = await self.chatgpt.recover(existing.conversation_id)
        except Exception as exc:
            self.console.print(f"[yellow]recovery failed: {exc}; creating a new conversation[/]")
            return False
        await self.storage.complete(task.task_id, captured)
        self.console.print(f"[green]{task.task_id}: recovered ({len(captured.messages)} messages)[/]")
        return True

    async def run_task(self, task: BenchmarkTask, resume: bool) -> None:
        existing = await self.storage.get(task.task_id)
        if existing and existing.status == "completed":
            if resume:
                self.console.print(f"[dim]{task.task_id}: completed, skip[/]")
                return
            raise RuntimeError(f"{task.task_id} already completed; use --resume")
        if resume and await self._recover(task):
            return
        await self.storage.start(task.task_id, self.runner_id)
        try:
            cid = await self.chatgpt.start_task(task)
            await self.storage.set_conversation(task.task_id, cid)
            self.console.print(f"{task.task_id}: conversation {cid}")
            captured = await self.chatgpt.wait_for_completion(cid)
            await self.storage.complete(task.task_id, captured)
            self.console.print(f"[green]{task.task_id}: completed ({len(captured.messages)} messages)[/]")
        except Exception as exc:
            try:
                await self.storage.fail(task.task_id, exc)
            finally:
                raise

    async def run(self, tasks: list[BenchmarkTask], options: RunOptions) -> None:
        selected = tasks[:options.limit] if options.limit else tasks
        for index, task in enumerate(selected, 1):
            self.console.rule(f"{index}/{len(selected)} {task.task_id}")
            try:
                await self.run_task(task, options.resume)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.console.print(f"[red]{task.task_id}: {type(exc).__name__}: {exc}[/]")
                if options.stop_on_error:
                    raise
            if index < len(selected) and self.delay:
                await asyncio.sleep(self.delay)

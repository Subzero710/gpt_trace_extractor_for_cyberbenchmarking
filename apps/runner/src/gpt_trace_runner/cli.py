from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .benchmark import load_benchmark
from .browser import BrowserClient
from .chatgpt import ChatGPTClient
from .config import Settings
from .exceptions import RecoveryIncomplete, StorageError
from .journal import JournalStore
from .lock import RunnerLock
from .runner import BenchmarkRunner, RunOptions
from .models import task_fingerprint
from .storage_client import StorageClient

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
console = Console()


def make_chatgpt(settings: Settings, page) -> ChatGPTClient:
    return ChatGPTClient(
        page,
        base_url=settings.chatgpt_base_url,
        conversation_turns=settings.chatgpt_conversation_turns,
        turn_timeout_seconds=settings.chatgpt_turn_timeout_seconds,
        stream_start_timeout_seconds=settings.chatgpt_stream_start_timeout_seconds,
        tool_select_timeout_seconds=settings.chatgpt_tool_select_timeout_seconds,
        upload_timeout_seconds=settings.chatgpt_upload_timeout_seconds,
        site_ready_timeout_seconds=settings.chatgpt_site_ready_timeout_seconds,
        challenge_timeout_seconds=settings.chatgpt_challenge_timeout_seconds,
        natural_snapshot_wait_seconds=settings.chatgpt_natural_snapshot_wait_seconds,
        clipboard_url=settings.validate_clipboard_url(),
        expected_model_slug=settings.chatgpt_expected_model_slug,
    )


def clipboard_health_url(settings: Settings) -> str:
    parsed = urlparse(settings.validate_clipboard_url())
    return urlunparse(parsed._replace(path="/healthz", query=""))



async def ensure_no_running_storage(storage: StorageClient) -> None:
    data = await storage.stats()
    if int(data.get("running", 0)) > 0:
        raise RecoveryIncomplete(
            "storage reports a running benchmark task; do not use auth/doctor --chatgpt until it is recovered"
        )


def ensure_no_pending_journal(settings: Settings) -> None:
    journal = JournalStore(settings.journal_path).load()
    if journal is not None:
        raise RecoveryIncomplete(
            f"pending crash journal for {journal.task_id}; run the benchmark with --resume before auth/doctor --chatgpt"
        )


@app.command()
def doctor(chatgpt: bool = typer.Option(False, "--chatgpt")) -> None:
    async def main() -> None:
        settings = Settings()
        storage = StorageClient(settings.storage_base_url)
        try:
            await storage.health()
            console.print("[green]storage: ok[/]")
            if chatgpt:
                await ensure_no_running_storage(storage)
        finally:
            await storage.close()

        BrowserClient.check_humanize_api(settings.browser_humanize_preset)
        console.print("[green]CloakBrowser humanize API: ok[/]")
        async with httpx.AsyncClient(timeout=10) as client:
            (await client.get(settings.browser_version_url())).raise_for_status()
            console.print("[green]browser CDP: ok[/]")
            (await client.get(clipboard_health_url(settings))).raise_for_status()
            console.print("[green]browser clipboard/X11: ok[/]")
        if not chatgpt:
            return

        ensure_no_pending_journal(settings)
        with RunnerLock(settings.runner_lock_path):
            session = await BrowserClient(
                settings.effective_browser_cdp_url(),
                humanize=settings.browser_humanize,
                humanize_preset=settings.browser_humanize_preset,
            ).connect()
            try:
                client = make_chatgpt(settings, session.page)
                await client.prepare_session()
                console.print("[green]ChatGPT: authenticated and ready[/]")
            finally:
                await session.disconnect()
    asyncio.run(main())


@app.command()
def auth(timeout_minutes: int = typer.Option(30, min=1)) -> None:
    async def main() -> None:
        settings = Settings()
        storage = StorageClient(settings.storage_base_url)
        try:
            await storage.health()
            await ensure_no_running_storage(storage)
        finally:
            await storage.close()
        ensure_no_pending_journal(settings)
        with RunnerLock(settings.runner_lock_path):
            session = await BrowserClient(
                settings.effective_browser_cdp_url(),
                humanize=settings.browser_humanize,
                humanize_preset=settings.browser_humanize_preset,
            ).connect()
            try:
                chatgpt = make_chatgpt(settings, session.page)
                if not session.page.url.startswith(settings.chatgpt_base_url):
                    await chatgpt.goto_home()
                console.print(f"Open noVNC and log in:\n[bold]{settings.browser_novnc_url}[/]")
                await chatgpt.wait_until_authenticated(timeout_minutes * 60)
                console.print("[green]authentication detected[/]")
            finally:
                await session.disconnect()
    asyncio.run(main())


@app.command("run")
def run_command(
    benchmark: Path = typer.Argument(..., exists=True, dir_okay=False),
    resume: bool = typer.Option(False, "--resume"),
    stop_on_error: bool = typer.Option(False, "--stop-on-error"),
    limit: int | None = typer.Option(None, min=1),
) -> None:
    async def main() -> None:
        settings = Settings()
        tasks = load_benchmark(benchmark, tasks_root=settings.tasks_root)
        selected = tasks[:limit] if limit else tasks
        storage = StorageClient(settings.storage_base_url)
        try:
            await storage.health()
            journal = JournalStore(settings.journal_path).load()
            selected_by_id = {task.task_id: task for task in selected}
            if journal is not None:
                journal_task = selected_by_id.get(journal.task_id)
                if journal_task is None:
                    raise RecoveryIncomplete(
                        f"pending journal task {journal.task_id!r} is not in the selected benchmark"
                    )
                if journal.task_fingerprint != task_fingerprint(journal_task):
                    raise RecoveryIncomplete("pending journal fingerprint differs from benchmark")

            states = [await storage.get(task.task_id) for task in selected]
            for task, state in zip(selected, states, strict=True):
                if state is not None and state.task_fingerprint != task_fingerprint(task):
                    raise StorageError(
                        f"{task.task_id} stored task fingerprint differs from benchmark"
                    )
            # Fast path: a completed --resume selection does not touch ChatGPT.
            if resume and journal is None and states and all(
                state and state.status == "completed" for state in states
            ):
                console.print("[green]all selected tasks already completed[/]")
                return

            with RunnerLock(settings.runner_lock_path):
                session = await BrowserClient(
                    settings.effective_browser_cdp_url(),
                    humanize=settings.browser_humanize,
                    humanize_preset=settings.browser_humanize_preset,
                ).connect()
                try:
                    runner = BenchmarkRunner(
                        chatgpt=make_chatgpt(settings, session.page),
                        storage=storage,
                        runner_id=settings.effective_runner_id(),
                        recover_existing=settings.runner_recover_existing,
                        console=console,
                        journal=JournalStore(settings.journal_path),
                    )
                    await runner.run(
                        tasks,
                        RunOptions(resume=resume, stop_on_error=stop_on_error, limit=limit),
                    )
                finally:
                    await session.disconnect()
        finally:
            await storage.close()
    asyncio.run(main())


@app.command()
def status() -> None:
    async def main() -> None:
        settings = Settings()
        storage = StorageClient(settings.storage_base_url)
        try:
            data = await storage.stats()
        finally:
            await storage.close()
        table = Table("status", "count")
        for key in ("pending", "running", "completed", "failed", "total"):
            table.add_row(key, str(data.get(key, 0)))
        console.print(table)
    asyncio.run(main())


@app.command("export")
def export_command(output: Path = typer.Argument(..., dir_okay=False)) -> None:
    async def main() -> None:
        settings = Settings()
        storage = StorageClient(settings.storage_base_url)
        try:
            count = await storage.export(output)
        finally:
            await storage.close()
        console.print(f"[green]exported {count} runs -> {output}[/]")
    asyncio.run(main())

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .benchmark import load_benchmark
from .browser import BrowserClient
from .chatgpt import ChatGPTClient
from .config import Settings
from .runner import BenchmarkRunner, RunOptions
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
        clipboard_url=settings.browser_clipboard_url,
    )


@app.command()
def doctor(
    chatgpt: bool = typer.Option(
        False,
        "--chatgpt",
        help="Also make an explicit ChatGPT UI/auth check.",
    ),
) -> None:
    async def main() -> None:
        settings = Settings()
        storage = StorageClient(settings.storage_base_url)
        try:
            await storage.health()
            console.print("[green]storage: ok[/]")
        finally:
            await storage.close()

        # Local browser multiplexer check only. It uses the same persistent
        # fingerprint seed as the runner, so it cannot spawn a second random
        # browser identity.
        async with httpx.AsyncClient(timeout=10) as client:
            (await client.get(settings.browser_version_url())).raise_for_status()
            console.print("[green]browser CDP: ok[/]")

        if not chatgpt:
            return

        session = await BrowserClient(
            settings.effective_browser_cdp_url(),
            humanize=settings.browser_humanize,
            humanize_preset=settings.browser_humanize_preset,
        ).connect()
        try:
            client = make_chatgpt(settings, session.page)
            try:
                await client.prepare_session()
                console.print("[green]ChatGPT: authenticated[/]")
            except Exception:
                console.print("[yellow]ChatGPT: auth required/unavailable[/]")
        finally:
            await session.disconnect()

    asyncio.run(main())


@app.command()
def auth(timeout_minutes: int = typer.Option(30, min=1)) -> None:
    async def main() -> None:
        settings = Settings()
        session = await BrowserClient(
            settings.effective_browser_cdp_url(),
            humanize=settings.browser_humanize,
            humanize_preset=settings.browser_humanize_preset,
        ).connect()
        try:
            chatgpt = make_chatgpt(settings, session.page)
            if not session.page.url.startswith(settings.chatgpt_base_url):
                await chatgpt.goto_home()
            console.print(
                "Open noVNC and log in:\n"
                f"[bold]{settings.browser_novnc_url}[/]"
            )
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
        storage = StorageClient(settings.storage_base_url)
        session = await BrowserClient(
            settings.effective_browser_cdp_url(),
            humanize=settings.browser_humanize,
            humanize_preset=settings.browser_humanize_preset,
        ).connect()

        try:
            await storage.health()
            chatgpt = make_chatgpt(settings, session.page)
            await chatgpt.prepare_session()

            runner = BenchmarkRunner(
                chatgpt=chatgpt,
                storage=storage,
                runner_id=settings.effective_runner_id(),
                recover_existing=settings.runner_recover_existing,
                console=console,
            )
            await runner.run(
                tasks,
                RunOptions(
                    resume=resume,
                    stop_on_error=stop_on_error,
                    limit=limit,
                ),
            )
        finally:
            await storage.close()
            await session.disconnect()

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

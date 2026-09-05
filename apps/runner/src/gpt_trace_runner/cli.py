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
    return ChatGPTClient(page, base_url=settings.chatgpt_base_url,
        conversation_turns=settings.chatgpt_conversation_turns,
        poll_interval_seconds=settings.chatgpt_poll_interval_seconds,
        completion_timeout_seconds=settings.chatgpt_completion_timeout_seconds,
        stable_polls=settings.chatgpt_stable_polls,
        upload_settle_seconds=settings.chatgpt_upload_settle_seconds)

@app.command()
def doctor() -> None:
    async def main() -> None:
        s = Settings()
        storage = StorageClient(s.storage_base_url)
        try:
            await storage.health(); console.print("[green]storage: ok[/]")
        finally:
            await storage.close()
        async with httpx.AsyncClient(timeout=10) as client:
            base = s.browser_cdp_url.split("?", 1)[0].rstrip("/")
            (await client.get(base + "/json/version")).raise_for_status()
            console.print("[green]browser CDP: ok[/]")
        session = await BrowserClient(s.browser_cdp_url).connect()
        try:
            c = make_chatgpt(s, session.page); await c.goto_home()
            try:
                await c.prompt_box(5000); console.print("[green]ChatGPT: authenticated[/]")
            except Exception:
                console.print("[yellow]ChatGPT: auth required[/]")
        finally:
            await session.disconnect()
    asyncio.run(main())

@app.command()
def auth(timeout_minutes: int = typer.Option(30, min=1)) -> None:
    async def main() -> None:
        s = Settings(); session = await BrowserClient(s.browser_cdp_url).connect()
        try:
            c = make_chatgpt(s, session.page); await c.goto_home()
            console.print(f"Open noVNC and log in:\n[bold]{s.browser_novnc_url}[/]")
            await c.wait_until_authenticated(timeout_minutes * 60)
            console.print("[green]authentication detected[/]")
        finally:
            await session.disconnect()
    asyncio.run(main())

@app.command("run")
def run_command(benchmark: Path = typer.Argument(..., exists=True, dir_okay=False),
                resume: bool = typer.Option(False, "--resume"),
                stop_on_error: bool = typer.Option(False, "--stop-on-error"),
                limit: int | None = typer.Option(None, min=1)) -> None:
    async def main() -> None:
        s = Settings(); tasks = load_benchmark(benchmark)
        storage = StorageClient(s.storage_base_url)
        session = await BrowserClient(s.browser_cdp_url).connect()
        try:
            await storage.health()
            c = make_chatgpt(s, session.page); await c.goto_home(); await c.prompt_box(10000)
            runner = BenchmarkRunner(chatgpt=c, storage=storage, runner_id=s.effective_runner_id(),
                recover_existing=s.runner_recover_existing,
                inter_task_delay_seconds=s.runner_inter_task_delay_seconds, console=console)
            await runner.run(tasks, RunOptions(resume, stop_on_error, limit))
        finally:
            await storage.close(); await session.disconnect()
    asyncio.run(main())

@app.command()
def status() -> None:
    async def main() -> None:
        s = Settings(); storage = StorageClient(s.storage_base_url)
        try: data = await storage.stats()
        finally: await storage.close()
        table = Table("status", "count")
        for key in ("pending", "running", "completed", "failed", "total"):
            table.add_row(key, str(data.get(key, 0)))
        console.print(table)
    asyncio.run(main())

@app.command("export")
def export_command(output: Path = typer.Argument(..., dir_okay=False)) -> None:
    async def main() -> None:
        s = Settings(); storage = StorageClient(s.storage_base_url)
        try: count = await storage.export(output)
        finally: await storage.close()
        console.print(f"[green]exported {count} runs -> {output}[/]")
    asyncio.run(main())

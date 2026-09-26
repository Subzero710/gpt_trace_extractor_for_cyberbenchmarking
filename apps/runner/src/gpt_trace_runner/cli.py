from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .app_lifecycle import AppLifecycle
from .browser import BrowserClient
from .chatgpt import ChatGPTClient
from .config import Settings
from .workstation_provider import LibvirtWorkstationProvider
from .exceptions import RecoveryIncomplete
from .journal import JournalStore
from .lock import RunnerLock
from .models import BenchmarkTask, BenchmarkTool, task_fingerprint
from .registry import AppRegistry
from .runner import abandon_recovery
from .runtime_preflight import preflight_tasks
from .storage_client import StorageClient
from .tools import check_playwright_ui_contracts

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


def make_lifecycle(
    settings: Settings,
    tasks,
    *,
    browser_blocked_hosts: tuple[str, ...] = (),
) -> AppLifecycle:
    runtime = LibvirtWorkstationProvider(
        settings.workstation_broker_socket, settings.app_control_token_file,
    )
    return AppLifecycle(
        settings.app_control_token_file,
        runtime=runtime,
    )


def clipboard_health_url(settings: Settings) -> str:
    parsed = urlparse(settings.validate_clipboard_url())
    return urlunparse(parsed._replace(path="/healthz", query=""))


def internal_local_apps_task(
    registry: AppRegistry,
    *,
    task_id: str,
    prompt: str,
) -> BenchmarkTask:
    tools: list[BenchmarkTool] = []
    for app_id in ("kali-workstation",):
        resolved = registry.resolve_id(app_id)
        if resolved.kind != "local_mcp":
            raise RuntimeError(f"{app_id!r} must resolve to a local_mcp App")
        tools.append(
            BenchmarkTool(
                type="app", app_id=resolved.app_id, ui_name=resolved.ui_name,
                kind=resolved.kind, version=resolved.version,
                manifest_sha256=resolved.manifest_sha256, tool_manifest=resolved.manifest,
                mcp_endpoint=resolved.mcp_endpoint, control_endpoint=resolved.control_endpoint,
                attachment_mode=resolved.attachment_mode,
            )
        )
    return BenchmarkTask(task_id=task_id, prompt=prompt, attachments=(), tools=tuple(tools))


async def ensure_no_running_storage(storage: StorageClient) -> None:
    data = await storage.stats()
    if int(data.get("running", 0)) > 0:
        raise RecoveryIncomplete("storage reports a running benchmark task; recover it before doctor/auth")


def ensure_no_pending_journal(settings: Settings) -> None:
    journal = JournalStore(settings.journal_path).load()
    if journal is not None:
        raise RecoveryIncomplete(f"pending crash journal for {journal.task_id}; resume the active Superbench run first")


@app.command()
def doctor() -> None:
    async def main() -> None:
        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        tasks = (
            internal_local_apps_task(
                registry,
                task_id="__doctor_local_apps__",
                prompt="Internal doctor smoke task for local MCP validation.",
            ),
        )

        storage = StorageClient(settings.storage_base_url)
        try:
            await storage.health()
            await ensure_no_running_storage(storage)
            console.print("[green]storage: ok[/]")
        finally:
            await storage.close()

        ensure_no_pending_journal(settings)

        BrowserClient.check_humanize_api(settings.browser_humanize_preset)
        console.print("[green]CloakBrowser humanize API: ok[/]")
        check_playwright_ui_contracts()
        console.print("[green]Playwright UI API contracts: ok[/]")
        async with httpx.AsyncClient(timeout=10) as client:
            (await client.get(settings.browser_version_url())).raise_for_status()
            console.print("[green]operator browser CDP: ok[/]")
            (await client.get(clipboard_health_url(settings))).raise_for_status()
            console.print("[green]operator browser clipboard/X11: ok[/]")

        lifecycle = make_lifecycle(
            settings,
            tasks,
            browser_blocked_hosts=("chatgpt.com",),
        )
        try:
            with RunnerLock(settings.runner_lock_path):
                await preflight_tasks(
                    lifecycle,
                    tasks,
                    console=console,
                    require_chatgpt_block=True,
                )
        finally:
            await lifecycle.close()

        console.print("[green]doctor: maximal non-ChatGPT preflight passed[/]")


    asyncio.run(main())


@app.command("register-apps")
def register_apps() -> None:
    # Operational lifecycle helper only; it deliberately does not load benchmark data.
    async def main() -> None:
        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        task = internal_local_apps_task(
            registry,
            task_id="__app_registration__",
            prompt="Internal App registration lifecycle task.",
        )

        fingerprint = task_fingerprint(task)
        # Dedicated registration attempt identity; it is not written to storage.
        attempt = 900001
        lifecycle = make_lifecycle(settings, (task,))
        environments = lifecycle.environment_ids(
            task,
            attempt=attempt,
            fingerprint=fingerprint,
        )

        prepared = False
        try:
            with RunnerLock(settings.runner_lock_path):
                await lifecycle.prepare(
                    task,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
                prepared = True
                console.print("[green]registration backends: ready[/]")
                console.print(
                    "[bold]Keep this command running while creating the Kali Workstation App.[/]"
                )
                console.print(
                    "Kali Workstation gateway: http://workstation-gateway:8000/mcp"
                )
                console.print(
                    "Press Enter after the App and its tools are visible."
                )
                await asyncio.to_thread(input)
        finally:
            if prepared:
                try:
                    await lifecycle.reset(
                        task,
                        environments,
                        fingerprint,
                        attempt=attempt,
                    )
                    console.print("[green]registration backends: cleaned up[/]")
                except Exception as exc:
                    console.print(
                        f"[red]registration backend cleanup failed: {exc}[/]"
                    )
            await lifecycle.close()

    asyncio.run(main())



@app.command("superbench-fetch")
def superbench_fetch(adapter: list[str] = typer.Option([], "--adapter")) -> None:
    from .superbench.registry import AdapterRegistry

    if not adapter:
        raise typer.BadParameter("at least one --adapter is required")

    registry = AdapterRegistry.discover()
    for adapter_id in adapter:
        try:
            benchmark_adapter = registry.get(adapter_id)
        except KeyError as exc:
            available = ", ".join(sorted(registry.adapters)) or "<none>"
            raise typer.BadParameter(
                f"unknown adapter {adapter_id!r}; available: {available}"
            ) from exc
        console.print(f"fetching benchmark source: {adapter_id}")
        benchmark_adapter.fetch()
        console.print(f"[green]fetched benchmark source: {adapter_id}[/]")


@app.command("superbench-run")
def superbench_run(adapter: list[str] = typer.Option([], "--adapter"), limit: int | None = typer.Option(None, min=1)) -> None:
    from .superbench.lifecycle import execute_active
    async def main():
        settings=Settings(); registry=AppRegistry.load(settings.app_registry_path); n,cid=await execute_active(settings=settings,registry=registry,make_lifecycle=make_lifecycle,make_chatgpt=make_chatgpt,console=console,adapter_ids=tuple(adapter),limit=limit,resume=False); console.print(f"campaign={cid} attempted={n}")
    asyncio.run(main())


@app.command("export-parquet")
def export_parquet(
    output: Path = typer.Argument(Path("/data/exports/corpus.parquet")),
) -> None:
    from .superbench.exporter import write_corpus_stream

    async def main():
        client = StorageClient(Settings().storage_base_url)
        try:
            count = await write_corpus_stream(client.iter_export_rows(), output)
            console.print(f"wrote {count} corpus rows to {output}")
        finally:
            await client.close()

    asyncio.run(main())


@app.command("export-sft")
def export_sft(
    corpus: Path = typer.Argument(Path("/data/exports/corpus.parquet"), exists=True, dir_okay=False),
    output: Path = typer.Argument(Path("/data/exports/sft.parquet")),
    verdict: list[str] = typer.Option([], "--verdict", help="Optional pass/fail/unevaluated row filter; repeatable. Defaults to pass."),
) -> None:
    from .superbench.exporter import derive_sft

    count = derive_sft(corpus, output, verdicts=verdict)
    console.print(f"derived {count} SFT rows from {corpus} -> {output}")

@app.command("superbench-pause")
def superbench_pause():
 from .superbench.run_control import RunControlStore
 st=RunControlStore(Settings().superbench_active_run_path).request_pause(); console.print(f"run={st.run_id} status={st.status}")
@app.command("superbench-resume-active")
def superbench_resume_active():
 from .superbench.lifecycle import execute_active
 async def main():
  settings=Settings(); registry=AppRegistry.load(settings.app_registry_path); n,cid=await execute_active(settings=settings,registry=registry,make_lifecycle=make_lifecycle,make_chatgpt=make_chatgpt,console=console,resume=True); console.print(f"campaign={cid} attempted={n}")
 asyncio.run(main())
@app.command("superbench-active-status")
def superbench_active_status():
 from .superbench.lifecycle import status_payload
 async def main():
  console.print_json(json.dumps(await status_payload(Settings()),sort_keys=True))
 asyncio.run(main())
@app.command("superbench-auth")
def superbench_auth(timeout_minutes: int = typer.Option(30, min=1)) -> None:
    async def main() -> None:
        settings = Settings()
        from .superbench.run_control import RunControlStore

        with RunnerLock(settings.runner_lock_path):
            active = RunControlStore(settings.superbench_active_run_path).load()
            if active is not None and active.status != "completed":
                raise RecoveryIncomplete(
                    f"auth refused while active Superbench run {active.run_id} is "
                    f"{active.status}; resolve via noVNC then make resume"
                )

            storage = StorageClient(settings.storage_base_url)
            try:
                await storage.health()
                await ensure_no_running_storage(storage)
            finally:
                await storage.close()

            ensure_no_pending_journal(settings)
            registry = AppRegistry.load(settings.app_registry_path)
            task = internal_local_apps_task(
                registry,
                task_id="__superbench_auth__",
                prompt="Internal Superbench auth/App validation.",
            )
            session = await BrowserClient(
                settings.effective_browser_cdp_url(),
                humanize=settings.browser_humanize,
                humanize_preset=settings.browser_humanize_preset,
            ).connect()
            try:
                chatgpt = make_chatgpt(settings, session.page)
                console.print(
                    f"Open noVNC and log in:\n [bold]{settings.browser_novnc_url}[/]"
                )
                await chatgpt.wait_until_authenticated(timeout_minutes * 60)
                await chatgpt.verify_apps_available(task.tools)
            finally:
                await session.disconnect()

    asyncio.run(main())

@app.command("superbench-reset-recovery")
def superbench_reset_recovery(task_id: str = typer.Argument(...), yes: bool = typer.Option(False, "--yes")):
 from .superbench.catalog import SuperbenchCatalog
 from .superbench.registry import AdapterRegistry
 from .superbench.run_control import RunControlStore
 from .superbench.service import campaign, to_benchmark_task
 async def main():
  if not yes: raise typer.BadParameter("superbench-reset-recovery requires --yes")
  settings=Settings(); control=RunControlStore(settings.superbench_active_run_path); active=control.load()
  if active is None or active.status=="completed": raise RecoveryIncomplete("no unfinished active Superbench run")
  frozen=next((x for x in active.selected_tasks if x.run_task_id==task_id),None)
  if frozen is None: raise RecoveryIncomplete("TASK is outside frozen active-run selection")
  registry=AppRegistry.load(settings.app_registry_path); adapters=AdapterRegistry.discover(); from .superbench.lifecycle import validate_frozen; validate_frozen(active,settings,registry,adapters); camp=campaign(settings)
  if camp.campaign_id!=active.campaign_id: raise RecoveryIncomplete("active-run campaign drift")
  entries=SuperbenchCatalog(adapters).discover(tuple(sorted({x.adapter_id for x in active.selected_tasks})))
  entry=next((e for e in entries if e.adapter_id==frozen.adapter_id and e.task.task_id==frozen.logical_task_id),None)
  if entry is None: raise RecoveryIncomplete("frozen task disappeared")
  adapter=adapters.get(entry.adapter_id)
  if adapter.adapter_version!=frozen.adapter_version: raise RecoveryIncomplete("frozen adapter version drift")
  staging=Path("/data/state/superbench/staging"); task=adapter.materialize_task(entry.task,staging); bt=to_benchmark_task(task,registry,camp,adapter)
  if bt.task_id!=task_id: raise RecoveryIncomplete("frozen task identity drift")
  journal=JournalStore(settings.journal_path); pending=journal.load()
  if pending is None or pending.task_id!=task_id: raise RecoveryIncomplete("matching pending recovery journal required")
  storage=StorageClient(settings.storage_base_url); lifecycle=make_lifecycle(settings,[bt])
  try:
   with RunnerLock(settings.runner_lock_path):
    prepared=await adapter.recover(task,attempt=pending.attempt,app_environments=dict(pending.app_environments))
    await storage.health()
    row=await storage.get(task_id)
    if row is None or row.status!='running': raise RecoveryIncomplete('reset-recovery requires matching running storage attempt')
    await abandon_recovery(bt,storage=storage,lifecycle=lifecycle,journal=journal)
    await adapter.cleanup(task,prepared=prepared)
    control.paused_error('recovery','RecoveryReset','operator abandoned recovery; resume retries same frozen task')
  finally:
   await lifecycle.close(); await storage.close()
  console.print(f"[yellow]recovery reset[/] {task_id}; run sudo make resume")
 asyncio.run(main())

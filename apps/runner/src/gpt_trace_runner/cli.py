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
from .benchmark import load_benchmark
from .browser import BrowserClient
from .chatgpt import ChatGPTClient
from .config import Settings
from .docker_runtime import DockerRuntime
from .exceptions import RecoveryIncomplete, StorageError
from .journal import JournalStore
from .lock import RunnerLock
from .models import BenchmarkTask, BenchmarkTool, task_app_provenance, task_fingerprint
from .qwen import flatten_app_provenance
from .registry import AppRegistry
from .runner import BenchmarkRunner, RunOptions, abandon_recovery
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
    needs_browser_app = any(
        tool.app_id == "browser" and tool.kind == "local_mcp"
        for task in tasks
        for tool in task.tools
    )
    runtime = DockerRuntime(
        settings.docker_socket_path,
        workspace_image=settings.app_code_workspace_image,
        browser_image=settings.app_browser_image,
        file_relay_image=settings.app_file_relay_image,
        file_transfer_limits={
            "max_file_bytes": settings.file_transfer_max_file_bytes,
            "max_total_bytes": settings.file_transfer_max_total_bytes,
            "max_objects": settings.file_transfer_max_objects,
            "max_concurrent_uploads": settings.file_transfer_max_concurrent_uploads,
            "max_concurrent_downloads": settings.file_transfer_max_concurrent_downloads,
            "ttl_seconds": settings.file_transfer_ttl_seconds,
        },
        workspace_gateway_container=settings.workspace_gateway_container,
        browser_gateway_container=settings.browser_gateway_container,
        browser_environment=(
            settings.dynamic_browser_environment() if needs_browser_app else {}
        ),
        browser_blocked_hosts=browser_blocked_hosts,
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
    for app_id in ("code-workspace", "browser"):
        resolved = registry.resolve_id(app_id)
        if resolved.kind != "local_mcp":
            raise RuntimeError(f"{app_id!r} must resolve to a local_mcp App")
        tools.append(
            BenchmarkTool(
                type="app", app_id=resolved.app_id, ui_name=resolved.ui_name,
                required=True, kind=resolved.kind, version=resolved.version,
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
        raise RecoveryIncomplete(f"pending crash journal for {journal.task_id}; run the benchmark with --resume first")


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


@app.command()
def auth(
    timeout_minutes: int = typer.Option(30, min=1),
    benchmark: Path = typer.Option(
        Path("/data/benchmarks/benchmark.jsonl"),
        "--benchmark",
        exists=True,
        dir_okay=False,
    ),
) -> None:
    async def main() -> None:
        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        tasks = load_benchmark(
            benchmark,
            tasks_root=settings.tasks_root,
            registry=registry,
        )
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
                # noVNC is the operator surface for headed CloakBrowser. Show
                # it before navigation so login/challenge transitions are
                # observable while the auth waiter runs.
                console.print(f"Open noVNC and log in:\n[bold]{settings.browser_novnc_url}[/]")
                await chatgpt.wait_until_authenticated(timeout_minutes * 60)
                console.print("[green]authentication detected via /backend-api/me[/]")
                await chatgpt.verify_apps_available(
                    tuple(tool for task in tasks for tool in task.tools)
                )
                console.print("[green]ChatGPT benchmark Apps: ok[/]")
            finally:
                await session.disconnect()
    asyncio.run(main())


@app.command("reset-recovery")
def reset_recovery_command(
    benchmark: Path = typer.Argument(..., exists=True, dir_okay=False),
    task_id: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", help="Confirm abandonment of this recovery attempt."),
) -> None:
    """Abandon one unrecoverable running attempt and preserve browser authentication."""

    async def main() -> None:
        if not yes:
            raise typer.BadParameter("reset-recovery requires --yes")

        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        tasks = load_benchmark(
            benchmark,
            tasks_root=settings.tasks_root,
            registry=registry,
        )
        by_id = {task.task_id: task for task in tasks}
        task = by_id.get(task_id)
        if task is None:
            raise typer.BadParameter(f"unknown benchmark task_id: {task_id}")

        storage = StorageClient(settings.storage_base_url)
        lifecycle = make_lifecycle(settings, [task])
        journal_store = JournalStore(settings.journal_path)
        try:
            await storage.health()
            with RunnerLock(settings.runner_lock_path):
                await abandon_recovery(
                    task,
                    storage=storage,
                    lifecycle=lifecycle,
                    journal=journal_store,
                )
                console.print(
                    f"[yellow]abandoned recovery[/] {task.task_id}; "
                    "next --resume run will start a new attempt"
                )
        finally:
            await lifecycle.close()
            await storage.close()

    asyncio.run(main())


@app.command("reset-stale")
def reset_stale_command(
    benchmark: Path = typer.Argument(..., exists=True, dir_okay=False),
    yes: bool = typer.Option(False, "--yes", help="Confirm deletion of stale benchmark state."),
) -> None:
    """Delete only stored runs whose fingerprint no longer matches the benchmark."""

    async def main() -> None:
        if not yes:
            raise typer.BadParameter("reset-stale requires --yes")

        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        tasks = load_benchmark(
            benchmark,
            tasks_root=settings.tasks_root,
            registry=registry,
        )
        by_id = {task.task_id: task for task in tasks}
        storage = StorageClient(settings.storage_base_url)
        journal_store = JournalStore(settings.journal_path)
        try:
            await storage.health()
            with RunnerLock(settings.runner_lock_path):
                journal = journal_store.load()
                if journal is not None:
                    journal_task = by_id.get(journal.task_id)
                    if journal_task is None:
                        raise RecoveryIncomplete(
                            f"pending journal task {journal.task_id!r} is not in benchmark; "
                            "refusing automatic deletion"
                        )
                    current = task_fingerprint(journal_task)
                    if journal.task_fingerprint == current:
                        raise RecoveryIncomplete(
                            "pending journal matches current benchmark; resume it instead of resetting"
                        )

                stale: list[tuple[object, object, str]] = []
                for task in tasks:
                    state = await storage.get(task.task_id)
                    if state is None:
                        continue
                    current = task_fingerprint(task)
                    if state.task_fingerprint == current:
                        continue
                    if state.status == "running":
                        raise RecoveryIncomplete(
                            f"stale run {task.task_id} is marked running; "
                            "refusing reset until that run is explicitly recovered/stopped"
                        )
                    if not state.task_fingerprint:
                        raise StorageError(
                            f"{task.task_id} has no stored fingerprint; refusing blind reset"
                        )
                    stale.append((task, state, current))

                if not stale and journal is None:
                    console.print("[green]no stale benchmark state[/]")
                    return

                for task, state, current in stale:
                    removed = await storage.reset_stale(
                        task.task_id,
                        expected_task_fingerprint=state.task_fingerprint,
                    )
                    if removed:
                        console.print(
                            f"[yellow]reset stale run[/] {task.task_id}: "
                            f"{state.task_fingerprint[:12]} -> {current[:12]}"
                        )

                if journal is not None:
                    journal_store.clear()
                    console.print(
                        f"[yellow]cleared stale submission journal[/] {journal.task_id}"
                    )
        finally:
            await storage.close()

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
        registry = AppRegistry.load(settings.app_registry_path)
        tasks = load_benchmark(benchmark, tasks_root=settings.tasks_root, registry=registry)
        selected = tasks[:limit] if limit else tasks
        storage = StorageClient(settings.storage_base_url)
        lifecycle = make_lifecycle(settings, selected)
        try:
            await storage.health()

            journal = JournalStore(settings.journal_path).load()
            selected_by_id = {task.task_id: task for task in selected}
            if journal is not None:
                journal_task = selected_by_id.get(journal.task_id)
                if journal_task is None:
                    raise RecoveryIncomplete(f"pending journal task {journal.task_id!r} is not in the selected benchmark")
                if journal.task_fingerprint != task_fingerprint(journal_task):
                    raise RecoveryIncomplete("pending journal fingerprint differs from benchmark")
            states = [await storage.get(task.task_id) for task in selected]
            for task, state in zip(selected, states, strict=True):
                if state is not None and state.task_fingerprint != task_fingerprint(task):
                    raise StorageError(f"{task.task_id} stored task fingerprint differs from benchmark")
            if resume and journal is None and states and all(state and state.status == "completed" for state in states):
                console.print("[green]all selected tasks already completed[/]")
                return
            recovery_active = resume and (
                journal is not None
                or any(
                    state is not None and state.status == "running"
                    for state in states
                )
            )

            with RunnerLock(settings.runner_lock_path):
                if not recovery_active:
                    await preflight_tasks(lifecycle, selected, console=console)
                    console.print("[green]pre-auth runtime preflight: ok[/]")
                else:
                    console.print(
                        "[yellow]runtime preflight skipped: recovery is active[/]"
                    )

                browser_client = BrowserClient(
                    settings.effective_browser_cdp_url(),
                    humanize=settings.browser_humanize,
                    humanize_preset=settings.browser_humanize_preset,
                )

                # --resume means the persistent teacher browser is an input to
                # recovery, never a dependency that may be recreated.
                if resume:
                    await browser_client.assert_existing_process()

                session = await browser_client.connect(
                    require_existing_page=recovery_active,
                )
                try:
                    chatgpt = make_chatgpt(settings, session.page)
                    if recovery_active:
                        # Do not pre-classify auth through /backend-api/me here.
                        # Recovery's conversation fetch is authoritative for the
                        # operation we actually need: HTTP 401 means auth expired,
                        # while HTTP 404 means the conversation no longer exists.
                        console.print(
                            "[yellow]ChatGPT auth/App preflight skipped during recovery; "
                            "conversation fetch will classify 401 vs 404[/]"
                        )
                    else:
                        await chatgpt.wait_until_authenticated(
                            settings.chatgpt_site_ready_timeout_seconds
                        )
                        console.print("[green]ChatGPT backend session: ok[/]")
                        await chatgpt.verify_apps_available(
                            tuple(tool for task in selected for tool in task.tools)
                        )
                        console.print("[green]ChatGPT benchmark Apps: ok[/]")
                    runner = BenchmarkRunner(
                        chatgpt=chatgpt,
                        storage=storage,
                        lifecycle=lifecycle,
                        runner_id=settings.effective_runner_id(),
                        recover_existing=settings.runner_recover_existing,
                        console=console,
                        journal=JournalStore(settings.journal_path),
                    )
                    await runner.run(tasks, RunOptions(resume=resume, stop_on_error=stop_on_error, limit=limit))
                finally:
                    await session.disconnect()
        finally:
            await lifecycle.close()
            await storage.close()
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
                    "[bold]Keep this command running while creating the two ChatGPT Plugins.[/]"
                )
                console.print(
                    "Code Workspace gateway: http://workspace-gateway:8000/mcp"
                )
                console.print("Browser gateway: http://browser-gateway:8000/mcp")
                console.print(
                    "Press Enter after both Plugins have been created and their tools are visible."
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


@app.command("inspect-tools")
def inspect_tools(
    benchmark: Path = typer.Argument(..., exists=True, dir_okay=False),
    task_id: str = typer.Option(..., "--task-id"),
) -> None:
    settings = Settings()
    registry = AppRegistry.load(settings.app_registry_path)
    tasks = load_benchmark(benchmark, tasks_root=settings.tasks_root, registry=registry)
    matches = [task for task in tasks if task.task_id == task_id]
    if len(matches) != 1:
        raise typer.BadParameter(f"task_id {task_id!r} is not present exactly once")
    task = matches[0]
    value = {
        "task_id": task.task_id,
        "task_fingerprint": task_fingerprint(task),
        "apps": task_app_provenance(task),
        "qwen": flatten_app_provenance(task_app_provenance(task)),
    }
    console.print_json(json.dumps(value, ensure_ascii=False, sort_keys=True))


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
    from .superbench.execution import run_pending
    async def main():
        settings=Settings(); registry=AppRegistry.load(settings.app_registry_path); n,cid=await run_pending(settings=settings,registry=registry,make_lifecycle=make_lifecycle,make_chatgpt=make_chatgpt,console=console,adapter_ids=tuple(adapter),limit=limit); console.print(f"campaign={cid} attempted={n}")
    asyncio.run(main())

@app.command("superbench-status")
def superbench_status(adapter: list[str] = typer.Option([], "--adapter")) -> None:
    from .superbench.catalog import SuperbenchCatalog
    from .superbench.registry import AdapterRegistry
    from .superbench.service import campaign, to_benchmark_task

    async def main():
        settings = Settings()
        registry = AppRegistry.load(settings.app_registry_path)
        cat = SuperbenchCatalog(AdapterRegistry.discover()).discover(tuple(adapter))
        camp = campaign(settings)
        storage = StorageClient(settings.storage_base_url)
        attempted = completed = evaluated = passed = failed = unevaluated = infra = 0
        try:
            for entry in cat:
                state = await storage.get(
                    to_benchmark_task(entry.task, registry, camp.campaign_id).task_id
                )
                if state is None:
                    continue
                attempted += 1
                if state.status == "failed":
                    infra += 1
                    continue
                if state.status == "completed":
                    completed += 1
                    evaluation = state.evaluation
                    if evaluation is None:
                        unevaluated += 1
                    else:
                        verdict = evaluation.get("verdict")
                        if verdict == "pass":
                            evaluated += 1
                            passed += 1
                        elif verdict == "fail":
                            evaluated += 1
                            failed += 1
                        else:
                            raise RuntimeError(
                                f"{state.task_id}: invalid evaluation verdict {verdict!r}"
                            )
        finally:
            await storage.close()
        console.print(
            f"campaign={camp.campaign_id} catalog={len(cat)} attempted={attempted} "
            f"completed={completed} evaluated={evaluated} pass={passed} fail={failed} "
            f"unevaluated={unevaluated} infra_failed={infra}"
        )

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
    verdict: list[str] = typer.Option([], "--verdict", help="Optional pass/fail/unevaluated row filter; repeatable."),
) -> None:
    from .superbench.exporter import derive_sft

    count = derive_sft(corpus, output, verdicts=verdict)
    console.print(f"derived {count} SFT rows from {corpus} -> {output}")

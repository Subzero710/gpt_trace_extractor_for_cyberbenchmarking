from __future__ import annotations

from pathlib import Path

from ..browser import BrowserClient
from ..exceptions import BatchCircuitBreaker, RecoveryIncomplete
from ..journal import JournalStore
from ..lock import RunnerLock
from ..models import task_app_provenance, task_fingerprint
from ..runner import BenchmarkRunner
from ..runtime_preflight import preflight_tasks
from ..storage_client import StorageClient
from .catalog import SuperbenchCatalog
from .models import run_task_id
from .registry import AdapterRegistry
from .service import campaign, start_metadata, to_benchmark_task


async def _record_pre_runner_failure(*, storage, settings, task, bt, camp, state, error):
    expected = (state.attempt + 1) if state is not None else 1
    started = await storage.start(
        bt.task_id,
        settings.effective_runner_id(),
        expected,
        task_fingerprint(bt),
        task_app_provenance(bt),
        superbench=start_metadata(task, camp),
    )
    await storage.fail(
        bt.task_id,
        error,
        attempt=started.attempt,
        runner_id=settings.effective_runner_id(),
    )


async def _connect_chatgpt(*, settings, make_chatgpt, bt):
    browser = BrowserClient(
        settings.effective_browser_cdp_url(),
        humanize=settings.browser_humanize,
        humanize_preset=settings.browser_humanize_preset,
    )
    session = await browser.connect(require_existing_page=False)
    try:
        chatgpt = make_chatgpt(settings, session.page)
        await chatgpt.wait_until_authenticated(settings.chatgpt_site_ready_timeout_seconds)
        await chatgpt.verify_apps_available(bt.tools)
        return session, chatgpt
    except BaseException:
        await session.disconnect()
        raise


async def _recover_pending_journal(
    *,
    settings,
    registry,
    make_lifecycle,
    make_chatgpt,
    console,
    adapters,
    entries,
    camp,
    storage,
    staging: Path,
) -> None:
    journal = JournalStore(settings.journal_path)
    pending = journal.load()
    if pending is None:
        return

    catalog_entry = next(
        (
            entry
            for entry in entries
            if run_task_id(entry.task.canonical_task_id, camp.campaign_id) == pending.task_id
        ),
        None,
    )
    if catalog_entry is None:
        raise RecoveryIncomplete(
            f"pending Superbench recovery references {pending.task_id!r}, "
            "which is not present in the selected catalog/campaign"
        )

    adapter = adapters.get(catalog_entry.adapter_id)
    task = adapter.materialize_task(catalog_entry.task, staging)
    bt = to_benchmark_task(task, registry, camp.campaign_id)
    prepared = await adapter.recover(
        task,
        attempt=pending.attempt,
        app_environments=dict(pending.app_environments),
    )
    lifecycle = make_lifecycle(settings, [bt])
    session = None
    try:
        session, chatgpt = await _connect_chatgpt(
            settings=settings, make_chatgpt=make_chatgpt, bt=bt
        )

        async def evaluate(captured):
            return (
                await adapter.evaluate(task, prepared=prepared, captured=captured)
            ).as_dict()

        runner = BenchmarkRunner(
            chatgpt=chatgpt,
            storage=storage,
            lifecycle=lifecycle,
            runner_id=settings.effective_runner_id(),
            recover_existing=settings.runner_recover_existing,
            console=console,
            journal=journal,
            superbench_metadata={bt.task_id: start_metadata(task, camp)},
            evaluation_hooks={bt.task_id: evaluate},
        )
        try:
            await runner.reconcile_journal([bt])
        except BaseException as exc:
            # A task-local recovery failure may have terminalized the attempt and
            # cleared the journal (for example RequiredToolNotUsed). In that case
            # recovery is resolved and the Superbench may continue.
            if journal.load() is None and not isinstance(
                exc, (KeyboardInterrupt, BatchCircuitBreaker)
            ):
                if console is not None:
                    console.print(
                        f"[red]{bt.task_id}: recovery terminalized after "
                        f"{type(exc).__name__}: {exc}[/]"
                    )
            else:
                raise
    finally:
        if session is not None:
            await session.disconnect()
        # Never destroy evaluator-side state while recovery is still pending.
        if journal.load() is None:
            await adapter.cleanup(task, prepared=prepared)
        await lifecycle.close()


async def run_pending(
    *,
    settings,
    registry,
    make_lifecycle,
    make_chatgpt,
    console,
    adapter_ids: tuple[str, ...] = (),
    limit: int | None = None,
    adapters=None,
    storage=None,
    executor=None,
):
    adapters = adapters or AdapterRegistry.discover()
    entries = SuperbenchCatalog(adapters).discover(adapter_ids)
    camp = campaign(settings)
    owned_storage = storage is None
    storage = storage or StorageClient(settings.storage_base_url)
    staging = Path("/data/state/superbench/staging")
    staging.mkdir(parents=True, exist_ok=True)
    attempted = 0

    try:
        await storage.health()
        with RunnerLock(settings.runner_lock_path):
            # Production runs reconcile the one durable crash journal before any
            # completed-run skip or new task scheduling. This prevents a stale
            # cleanup_pending journal from poisoning the next task.
            if executor is None:
                await _recover_pending_journal(
                    settings=settings,
                    registry=registry,
                    make_lifecycle=make_lifecycle,
                    make_chatgpt=make_chatgpt,
                    console=console,
                    adapters=adapters,
                    entries=entries,
                    camp=camp,
                    storage=storage,
                    staging=staging,
                )

            for entry in entries:
                if limit is not None and attempted >= limit:
                    break

                adapter = adapters.get(entry.adapter_id)
                task = adapter.materialize_task(entry.task, staging)
                bt = to_benchmark_task(task, registry, camp.campaign_id)
                state = await storage.get(bt.task_id)
                if state is not None:
                    run_status = getattr(state, "run_status", None)
                    if state.status == "completed":
                        if state.success is None:
                            raise RuntimeError(
                                f"{bt.task_id}: invalid Superbench state: "
                                "completed run has success=None"
                            )
                        continue
                    if run_status == "unsupported":
                        continue
                    if state.status == "running":
                        # A running attempt is recoverable only through its durable
                        # journal, which was reconciled before entering this loop.
                        raise RecoveryIncomplete(
                            f"{bt.task_id}: running Superbench attempt has no "
                            "recovery journal; explicit reset/recovery is required"
                        )
                    if state.status != "failed":
                        raise RuntimeError(
                            f"{bt.task_id}: Superbench scheduler cannot handle "
                            f"status={state.status!r}"
                        )

                if executor is not None:
                    try:
                        await executor(adapter, task, bt, camp, storage)
                    except (KeyboardInterrupt, BatchCircuitBreaker):
                        raise
                    except Exception as exc:
                        if console is not None:
                            console.print(
                                f"[red]{bt.task_id}: {type(exc).__name__}: {exc}[/]"
                            )
                    attempted += 1
                    continue

                prepared = None
                lifecycle = None
                session = None
                runner = None
                runner_started = False
                recovery_required = False
                journal = JournalStore(settings.journal_path)

                try:
                    prepared = await adapter.prepare(task)
                    lifecycle = make_lifecycle(settings, [bt])
                    await preflight_tasks(lifecycle, [bt], console=console)
                    session, chatgpt = await _connect_chatgpt(
                        settings=settings, make_chatgpt=make_chatgpt, bt=bt
                    )

                    async def evaluate(captured):
                        return (
                            await adapter.evaluate(
                                task, prepared=prepared, captured=captured
                            )
                        ).as_dict()

                    runner = BenchmarkRunner(
                        chatgpt=chatgpt,
                        storage=storage,
                        lifecycle=lifecycle,
                        runner_id=settings.effective_runner_id(),
                        recover_existing=settings.runner_recover_existing,
                        console=console,
                        journal=journal,
                        superbench_metadata={bt.task_id: start_metadata(task, camp)},
                        evaluation_hooks={bt.task_id: evaluate},
                    )
                    runner_started = True
                    await runner.run_task(bt, True)

                except BaseException as exc:
                    latest = await storage.get(bt.task_id)
                    pending = journal.load()
                    pending_for_task = pending is not None and pending.task_id == bt.task_id

                    # If completion committed but cleanup crashed, reconcile the
                    # *same task* immediately. Never advance with its journal left.
                    if (
                        runner is not None
                        and latest is not None
                        and latest.status == "completed"
                        and pending_for_task
                    ):
                        try:
                            await runner.reconcile_journal([bt])
                        except BaseException:
                            recovery_required = journal.load() is not None
                            raise
                        if journal.load() is not None:
                            recovery_required = True
                            raise RecoveryIncomplete(
                                f"{bt.task_id}: completion committed but cleanup "
                                "journal could not be reconciled"
                            )
                        if console is not None:
                            console.print(
                                f"[yellow]{bt.task_id}: recovered cleanup after "
                                f"{type(exc).__name__}: {exc}[/]"
                            )
                        if isinstance(exc, (KeyboardInterrupt, BatchCircuitBreaker)):
                            raise
                        # The task is durably completed and cleanup is now done.

                    elif (
                        (latest is not None and latest.status == "running")
                        or pending_for_task
                    ):
                        # This includes BatchCircuitBreaker subclasses raised after
                        # submission. Preserve both App/evaluator state and journal.
                        recovery_required = True
                        if console is not None:
                            console.print(
                                f"[red]{bt.task_id}: recovery required after "
                                f"{type(exc).__name__}: {exc}[/]"
                            )
                        raise

                    else:
                        if not runner_started:
                            await _record_pre_runner_failure(
                                storage=storage,
                                settings=settings,
                                task=task,
                                bt=bt,
                                camp=camp,
                                state=latest,
                                error=exc,
                            )
                        if isinstance(exc, (KeyboardInterrupt, BatchCircuitBreaker)):
                            raise
                        if console is not None:
                            console.print(
                                f"[red]{bt.task_id}: {type(exc).__name__}: {exc}[/]"
                            )

                finally:
                    attempted += 1
                    if session is not None:
                        await session.disconnect()
                    if prepared is not None and not recovery_required:
                        try:
                            await adapter.cleanup(task, prepared=prepared)
                        except (KeyboardInterrupt, BatchCircuitBreaker):
                            raise
                        except Exception as exc:
                            if console is not None:
                                console.print(
                                    f"[yellow]{bt.task_id}: cleanup "
                                    f"{type(exc).__name__}: {exc}[/]"
                                )
                    if lifecycle is not None:
                        await lifecycle.close()
    finally:
        if owned_storage:
            await storage.close()

    return attempted, camp.campaign_id

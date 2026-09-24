from __future__ import annotations

from contextlib import nullcontext
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
from .service import campaign, storage_context, to_benchmark_task


def _ordered_entries(entries, limit: int | None):
    """Keep normal order, but front-load required-App coverage for short runs."""
    if limit is None:
        return list(entries)

    remaining = list(entries)
    selected = []
    covered: set[str] = set()

    while remaining:
        gains = [
            len(set(entry.task.required_tools) - covered)
            for entry in remaining
        ]
        best_gain = max(gains) if gains else 0
        if best_gain <= 0:
            break
        index = gains.index(best_gain)
        entry = remaining.pop(index)
        selected.append(entry)
        covered.update(entry.task.required_tools)

    selected.extend(remaining)
    return selected


async def _record_pre_runner_failure(
    *,
    storage,
    settings,
    source_task,
    adapter,
    bt,
    camp,
    registry,
    state,
    error,
):
    expected = (state.attempt + 1) if state is not None else 1
    runner_id = settings.effective_runner_id()
    started = await storage.start(
        bt.task_id,
        runner_id,
        expected,
        task_fingerprint(bt),
        task_app_provenance(bt),
        **storage_context(source_task, camp, adapter, registry),
    )
    await storage.fail(
        bt.task_id,
        error,
        attempt=started.attempt,
        runner_id=runner_id,
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


async def _cleanup_task(
    *,
    adapter,
    task,
    prepared,
    console,
    task_id: str,
    primary_error: BaseException | None,
) -> None:
    try:
        await adapter.cleanup(task, prepared=prepared)
    except (KeyboardInterrupt, BatchCircuitBreaker):
        raise
    except Exception as cleanup_error:
        if console is not None:
            console.print(
                f"[red]{task_id}: cleanup "
                f"{type(cleanup_error).__name__}: {cleanup_error}[/]"
            )
        if primary_error is None:
            raise
        # The batch is already stopping for primary_error. Do not mask it.


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
            if run_task_id(
                entry.task.task_id,
                camp.campaign_id,
                entry.adapter_id,
                adapters.get(entry.adapter_id).adapter_version,
            ) == pending.task_id
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
    bt = to_benchmark_task(task, registry, camp, adapter)
    prepared = await adapter.recover(
        task,
        attempt=pending.attempt,
        app_environments=dict(pending.app_environments),
    )
    lifecycle = make_lifecycle(settings, [bt])
    session = None
    recovery_error: BaseException | None = None
    try:
        session, chatgpt = await _connect_chatgpt(
            settings=settings, make_chatgpt=make_chatgpt, bt=bt
        )

        async def evaluate(captured):
            result = await adapter.evaluate(task, prepared=prepared, captured=captured)
            return result.as_dict() if result is not None else None

        runner = BenchmarkRunner(
            chatgpt=chatgpt,
            storage=storage,
            lifecycle=lifecycle,
            runner_id=settings.effective_runner_id(),
            recover_existing=settings.runner_recover_existing,
            console=console,
            journal=journal,
            storage_context={bt.task_id: storage_context(catalog_entry.task, camp, adapter, registry)},
            evaluation_hooks={bt.task_id: evaluate},
        )
        try:
            await runner.reconcile_journal([bt])
        except BaseException as exc:
            recovery_error = exc
            if console is not None:
                console.print(
                    f"[red]{bt.task_id}: recovery failed after "
                    f"{type(exc).__name__}: {exc}[/]"
                )
            # Recovery failures are technical failures: never continue the batch.
            raise
    finally:
        if session is not None:
            await session.disconnect()
        # Never destroy evaluator-side state while recovery is still pending.
        if journal.load() is None:
            await _cleanup_task(
                adapter=adapter,
                task=task,
                prepared=prepared,
                console=console,
                task_id=bt.task_id,
                primary_error=recovery_error,
            )
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
    selected_run_task_ids: tuple[str, ...] | None = None,
    control_store=None,
    runner_lock_held: bool = False,
    pause_probe=None,
):
    adapters = adapters or AdapterRegistry.discover()
    entries = SuperbenchCatalog(adapters).discover(adapter_ids)
    camp = campaign(settings)
    selected_entries = _ordered_entries(entries, limit)
    if selected_run_task_ids is not None:
        by_id = {}
        for item in entries:
            a = adapters.get(item.adapter_id)
            rid = run_task_id(item.task.task_id, camp.campaign_id, item.adapter_id, a.adapter_version)
            by_id[rid] = item
        missing = set(selected_run_task_ids) - set(by_id)
        if missing:
            raise RecoveryIncomplete(f"frozen selection missing from catalog: {sorted(missing)!r}")
        selected_entries = [by_id[rid] for rid in selected_run_task_ids]
        limit = None
    owned_storage = storage is None
    storage = storage or StorageClient(settings.storage_base_url)
    staging = Path("/data/state/superbench/staging")
    staging.mkdir(parents=True, exist_ok=True)
    attempted = 0

    try:
        await storage.health()
        lock_context = nullcontext() if runner_lock_held else RunnerLock(settings.runner_lock_path)
        with lock_context:
            if control_store is not None and pause_probe is not None and pause_probe():
                control_store.request_pause()
                control_store.pause_if_requested()
                return attempted, camp.campaign_id
            # Production runs reconcile the one durable crash journal before any
            # completed-run skip or new task scheduling. This prevents a stale
            # cleanup_pending journal from poisoning the next task.
            if executor is None:
                if selected_run_task_ids is not None:
                    pending = JournalStore(settings.journal_path).load()
                    if pending is not None and pending.task_id not in set(selected_run_task_ids):
                        raise RecoveryIncomplete(
                            f"pending journal task {pending.task_id!r} is outside frozen active-run selection"
                        )
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
            if control_store is not None:
                active = control_store.confirm_running()
                if active.status == "pause_requested":
                    control_store.pause_if_requested()
                    return attempted, camp.campaign_id

            for entry in selected_entries:
                if control_store is not None and pause_probe is not None and pause_probe():
                    control_store.request_pause()
                if control_store is not None:
                    active = control_store.load()
                    if active.status == "pause_requested":
                        control_store.pause_if_requested()
                        break
                if limit is not None and attempted >= limit:
                    break

                adapter = adapters.get(entry.adapter_id)
                run_id = run_task_id(
                    entry.task.task_id,
                    camp.campaign_id,
                    entry.adapter_id,
                    adapter.adapter_version,
                )
                if control_store is not None:
                    active = control_store.load()
                    if run_id in active.completed_run_task_ids:
                        continue
                    control_store.start_task(run_id)
                    if control_store.load().status == "pause_requested":
                        control_store.pause_if_requested()
                        break
                state = await storage.get(run_id)
                if state is not None:
                    if state.status == "completed":
                        current_context = storage_context(
                            entry.task, camp, adapter, registry
                        )["dataset_metadata"]
                        stored_contract = (state.dataset_metadata or {}).get(
                            "task_contract_fingerprint"
                        )
                        current_contract = current_context["task_contract_fingerprint"]
                        if stored_contract is None:
                            raise RecoveryIncomplete(
                                f"{run_id}: completed Superbench row predates task-contract "
                                "fingerprints; reset/recollect it explicitly"
                            )
                        if stored_contract != current_contract:
                            raise RecoveryIncomplete(
                                f"{run_id}: completed Superbench task contract changed; "
                                "refusing to silently skip stale data"
                            )
                        if control_store is not None:
                            control_store.finish_task(run_id)
                        continue
                    if state.status == "running":
                        # A running attempt is recoverable only through its durable
                        # journal, which was reconciled before entering this loop.
                        raise RecoveryIncomplete(
                            f"{run_id}: running Superbench attempt has no "
                            "recovery journal; explicit reset/recovery is required"
                        )
                    if state.status != "failed":
                        raise RuntimeError(
                            f"{run_id}: Superbench scheduler cannot handle "
                            f"status={state.status!r}"
                        )

                task = adapter.materialize_task(entry.task, staging)
                bt = to_benchmark_task(task, registry, camp, adapter)
                if bt.task_id != run_id:
                    raise RuntimeError("Superbench run identity changed during materialization")

                if executor is not None:
                    executor_error: BaseException | None = None
                    try:
                        await executor(adapter, task, bt, camp, storage)
                    except BaseException as exc:
                        executor_error = exc
                        raise
                    finally:
                        await _cleanup_task(
                            adapter=adapter,
                            task=task,
                            prepared=None,
                            console=console,
                            task_id=bt.task_id,
                            primary_error=executor_error,
                        )
                    attempted += 1
                    if control_store is not None:
                        latest = await storage.get(run_id)
                        if latest is not None and latest.status == "completed":
                            control_store.finish_task(run_id)
                    continue

                prepared = None
                lifecycle = None
                session = None
                runner = None
                runner_started = False
                recovery_required = False
                primary_error: BaseException | None = None
                journal = JournalStore(settings.journal_path)

                try:
                    prepared = await adapter.prepare(task)
                    lifecycle = make_lifecycle(settings, [bt])
                    await preflight_tasks(lifecycle, [bt], console=console)
                    session, chatgpt = await _connect_chatgpt(
                        settings=settings, make_chatgpt=make_chatgpt, bt=bt
                    )

                    async def evaluate(captured):
                        result = await adapter.evaluate(
                            task, prepared=prepared, captured=captured
                        )
                        return result.as_dict() if result is not None else None

                    runner = BenchmarkRunner(
                        chatgpt=chatgpt,
                        storage=storage,
                        lifecycle=lifecycle,
                        runner_id=settings.effective_runner_id(),
                        recover_existing=settings.runner_recover_existing,
                        console=console,
                        journal=journal,
                        storage_context={bt.task_id: storage_context(entry.task, camp, adapter, registry)},
                        evaluation_hooks={bt.task_id: evaluate},
                    )
                    runner_started = True
                    await runner.run_task(bt, True)

                except BaseException as exc:
                    primary_error = exc
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
                        if control_store is not None:
                            control_store.finish_task(run_id)
                        raise exc

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
                                source_task=entry.task,
                                adapter=adapter,
                                bt=bt,
                                camp=camp,
                                registry=registry,
                                state=latest,
                                error=exc,
                            )
                        if isinstance(exc, (KeyboardInterrupt, BatchCircuitBreaker)):
                            raise
                        if console is not None:
                            console.print(
                                f"[red]{bt.task_id}: {type(exc).__name__}: {exc}[/]"
                            )
                        raise

                finally:
                    attempted += 1
                    if session is not None:
                        await session.disconnect()
                    if not recovery_required:
                        await _cleanup_task(
                            adapter=adapter,
                            task=task,
                            prepared=prepared,
                            console=console,
                            task_id=bt.task_id,
                            primary_error=primary_error,
                        )
                    if lifecycle is not None:
                        await lifecycle.close()
                if control_store is not None:
                    if pause_probe is not None and pause_probe():
                        control_store.request_pause()
                    latest = await storage.get(run_id)
                    if latest is not None and latest.status == "completed":
                        control_store.finish_task(run_id)
                    if control_store.load().status == "pause_requested":
                        control_store.pause_if_requested()
                        break
    finally:
        if owned_storage:
            await storage.close()

    return attempted, camp.campaign_id

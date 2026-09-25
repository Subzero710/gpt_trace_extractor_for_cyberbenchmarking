from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal

from ..exceptions import (
    AccessDenied,
    AuthenticationRequired,
    RateLimited,
    RecoveryIncomplete,
    SiteChallengeFailed,
)
from ..lock import RunnerLock
from .catalog import SuperbenchCatalog
from .execution import run_pending
from .models import task_spec_fingerprint
from .registry import AdapterRegistry
from .run_control import ActiveRun, PlannedTask, RunControlStore
from .service import campaign, storage_context, to_benchmark_task


def _hash_json(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


def config_fp(settings) -> str:
    keys = (
        "chatgpt_expected_model_slug",
        "chatgpt_conversation_turns",
        "chatgpt_turn_timeout_seconds",
        "chatgpt_stream_start_timeout_seconds",
        "chatgpt_tool_select_timeout_seconds",
        "chatgpt_upload_timeout_seconds",
        "chatgpt_site_ready_timeout_seconds",
        "chatgpt_challenge_timeout_seconds",
        "chatgpt_natural_snapshot_wait_seconds",
        "browser_humanize",
        "browser_humanize_preset",
        "app_browser_humanize",
        "app_browser_humanize_preset",
        "app_browser_timezone",
        "app_browser_locale",
        "app_browser_geoip",
    )
    return _hash_json({key: getattr(settings, key) for key in keys})


def plan(settings, registry, adapters, adapter_ids=(), limit=None):
    entries = list(SuperbenchCatalog(adapters).discover(adapter_ids))
    if limit is not None:
        entries = entries[:limit]
    if not entries:
        raise RecoveryIncomplete("empty Superbench selection")

    camp = campaign(settings)
    planned: list[PlannedTask] = []
    for entry in entries:
        adapter = adapters.get(entry.adapter_id)
        benchmark_task = to_benchmark_task(
            entry.task,
            registry,
            camp,
            adapter,
        )
        dataset_metadata = storage_context(
            entry.task,
            camp,
            adapter,
            registry,
        )["dataset_metadata"]
        planned.append(
            PlannedTask(
                run_task_id=benchmark_task.task_id,
                logical_task_id=entry.task.task_id,
                adapter_id=entry.adapter_id,
                adapter_version=adapter.adapter_version,
                task_spec_fingerprint=task_spec_fingerprint(entry.task),
                task_contract_fingerprint=dataset_metadata[
                    "task_contract_fingerprint"
                ],
            )
        )
    return camp, tuple(planned)


def validate_frozen(state, settings, registry, adapters):
    adapter_ids = tuple(
        sorted({task.adapter_id for task in state.selected_tasks})
    )
    camp, current = plan(
        settings,
        registry,
        adapters,
        adapter_ids,
        None,
    )
    by_run_task_id = {task.run_task_id: task for task in current}

    if (
        camp.campaign_id != state.campaign_id
        or settings.chatgpt_expected_model_slug != state.expected_model
        or config_fp(settings) != state.configuration_fingerprint
    ):
        raise RecoveryIncomplete(
            "active-run campaign/model/config drift"
        )

    for frozen in state.selected_tasks:
        if by_run_task_id.get(frozen.run_task_id) != frozen:
            raise RecoveryIncomplete(
                "active-run task/adapter/App contract drift: "
                f"{frozen.run_task_id}"
            )

    return tuple(task.run_task_id for task in state.selected_tasks)


class SigintPause:
    def __init__(self, request_pause):
        self._request_pause = request_pause
        self.n = 0
        self.pause_requested = False
        self._task = None

    def __enter__(self):
        self.old = signal.getsignal(signal.SIGINT)
        try:
            self._task = asyncio.current_task()
        except RuntimeError:
            self._task = None

        def handler(*_):
            self.n += 1
            if self.n == 1:
                self.pause_requested = True
                self._request_pause()
                task = self._task
                if task is not None and not task.done():
                    task.cancel("Superbench pause requested")
                return
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, handler)
        return self

    def __exit__(self, *_):
        signal.signal(signal.SIGINT, self.old)
        self._task = None


async def _watch_durable_pause(store, target: asyncio.Task) -> None:
    """Cancel active execution when another process requests a pause."""
    while not target.done():
        await asyncio.sleep(0.1)
        state = store.load()
        if state is None:
            return
        if state.status == "pause_requested":
            target.cancel("Superbench pause requested")
            return
        if state.status in {"paused", "needs_intervention", "completed"}:
            return


def classify_incident(exc):
    if isinstance(exc, AuthenticationRequired):
        return "authentication", True
    if isinstance(exc, SiteChallengeFailed):
        return "challenge", True
    if isinstance(exc, AccessDenied):
        return "access_denied", True
    if isinstance(exc, RateLimited):
        return "rate_limited", False
    if isinstance(exc, RecoveryIncomplete):
        return "recovery", False
    return "infrastructure", False


async def _storage_completed_run_task_ids(settings, state: ActiveRun):
    from ..storage_client import StorageClient

    storage = StorageClient(settings.storage_base_url)
    completed: set[str] = set()
    not_completed: list[str] = []
    try:
        await storage.health()
        for item in state.selected_tasks:
            row = await storage.get(item.run_task_id)
            if row is not None and row.status == "completed":
                completed.add(item.run_task_id)
                continue
            status = "missing" if row is None else row.status
            not_completed.append(f"{item.run_task_id}:{status}")
    finally:
        await storage.close()

    if not_completed:
        raise RecoveryIncomplete(
            "active run cannot complete because storage is not completed for: "
            + ", ".join(not_completed)
        )
    return frozenset(completed)


async def execute_active(
    *,
    settings,
    registry,
    make_lifecycle,
    make_chatgpt,
    console,
    adapter_ids=(),
    limit=None,
    resume=False,
):
    adapters = AdapterRegistry.discover()
    store = RunControlStore(settings.superbench_active_run_path)

    if resume:
        state = store.load()
        if state is None or state.status == "completed":
            raise RecoveryIncomplete(
                "no unfinished active Superbench run"
            )

        validate_frozen(
            state,
            settings,
            registry,
            adapters,
        )

        with RunnerLock(settings.runner_lock_path):
            state = store.load()
            if state is None or state.status == "completed":
                raise RecoveryIncomplete(
                    "active run is no longer resumable"
                )

            selected_ids = validate_frozen(
                state,
                settings,
                registry,
                adapters,
            )
            store.begin_resume()
            return await _execute_locked(
                settings,
                registry,
                adapters,
                store,
                selected_ids,
                make_lifecycle,
                make_chatgpt,
                console,
            )

    with RunnerLock(settings.runner_lock_path):
        existing = store.load()
        if existing is not None and existing.status != "completed":
            raise RecoveryIncomplete(
                "unfinished active Superbench run already exists"
            )

        camp, tasks = plan(
            settings,
            registry,
            adapters,
            adapter_ids,
            limit,
        )
        state = ActiveRun(
            schema_version=3,
            run_id=os.urandom(16).hex(),
            campaign_id=camp.campaign_id,
            status="running",
            selected_tasks=tasks,
            expected_model=settings.chatgpt_expected_model_slug,
            configuration_fingerprint=config_fp(settings),
        )
        store.create(state)
        selected_ids = validate_frozen(
            store.load(),
            settings,
            registry,
            adapters,
        )
        return await _execute_locked(
            settings,
            registry,
            adapters,
            store,
            selected_ids,
            make_lifecycle,
            make_chatgpt,
            console,
        )


async def _execute_locked(
    settings,
    registry,
    adapters,
    store,
    selected_ids,
    make_lifecycle,
    make_chatgpt,
    console,
):
    attempted = 0
    initial_state = store.load()
    if initial_state is None:
        raise RecoveryIncomplete("no active Superbench run")
    campaign_id = initial_state.campaign_id
    target = asyncio.current_task()
    pause_watcher = (
        asyncio.create_task(_watch_durable_pause(store, target))
        if target is not None
        else None
    )
    try:
        with SigintPause(store.request_pause_from_signal) as sigint:
            attempted, campaign_id = await run_pending(
                settings=settings,
                registry=registry,
                make_lifecycle=make_lifecycle,
                make_chatgpt=make_chatgpt,
                console=console,
                adapters=adapters,
                selected_run_task_ids=selected_ids,
                control_store=store,
                runner_lock_held=True,
                pause_probe=lambda: sigint.pause_requested,
            )

            # Keep the first/second Ctrl+C contract active through the final
            # storage proof and active-run transition, not only run_pending().
            state = store.load()
            if state.status == "pause_requested":
                store.pause_if_requested()
            elif state.status in {"running", "resuming"}:
                selected = {
                    task.run_task_id
                    for task in state.selected_tasks
                }
                if not selected <= set(state.completed_run_task_ids):
                    raise RecoveryIncomplete(
                        "runner exited without pause/error but frozen tasks "
                        "remain incomplete"
                    )
                storage_completed = await _storage_completed_run_task_ids(
                    settings,
                    state,
                )

                # SIGINT may have arrived while the final storage proof was in
                # progress. Re-read durable control state before committing the
                # terminal completed transition so a cooperative pause wins.
                state = store.load()
                if state.status == "pause_requested":
                    store.pause_if_requested()
                elif state.status in {"running", "resuming"}:
                    store.complete(storage_completed)
                elif state.status != "completed":
                    raise RecoveryIncomplete(
                        "active-run changed unexpectedly during completion"
                    )

            return attempted, campaign_id

    except asyncio.CancelledError:
        state = store.load()
        if state is not None and state.status == "pause_requested":
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                task.uncancel()
            store.pause_if_requested()
            return attempted, campaign_id
        raise
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        reason, needs_intervention = classify_incident(exc)
        state = store.load()
        if state is not None and state.status != "completed":
            if needs_intervention:
                store.intervention(
                    reason,
                    type(exc).__name__,
                    str(exc),
                )
            else:
                store.paused_error(
                    reason,
                    type(exc).__name__,
                    str(exc),
                )
        raise
    finally:
        if pause_watcher is not None:
            pause_watcher.cancel()
            try:
                await pause_watcher
            except asyncio.CancelledError:
                pass


async def status_payload(settings):
    from ..storage_client import StorageClient

    state = RunControlStore(
        settings.superbench_active_run_path
    ).load()
    if state is None:
        return {"status": "none"}

    storage = StorageClient(settings.storage_base_url)
    completed = 0
    evaluated = 0
    passed = 0
    failed = 0
    infra_failed = 0
    try:
        await storage.health()
        for item in state.selected_tasks:
            row = await storage.get(item.run_task_id)
            if row is None:
                continue
            if row.status == "failed":
                infra_failed += 1
                continue
            if row.status != "completed":
                continue

            completed += 1
            if row.evaluation is None:
                continue
            verdict = row.evaluation.get("verdict")
            if verdict == "pass":
                evaluated += 1
                passed += 1
            elif verdict == "fail":
                evaluated += 1
                failed += 1
    finally:
        await storage.close()

    payload = {
        "run_id": state.run_id,
        "campaign_id": state.campaign_id,
        "status": state.status,
        "current_task": state.current_run_task_id,
        "selected": len(state.selected_tasks),
        "completed": completed,
        "remaining": len(state.selected_tasks) - completed,
        "evaluated": evaluated,
        "pass": passed,
        "fail": failed,
        "infra_failed": infra_failed,
    }
    if state.intervention_reason is not None:
        payload["reason"] = state.intervention_reason
    if state.exception_type is not None:
        payload["exception_type"] = state.exception_type
    if state.intervention_message is not None:
        payload["message"] = state.intervention_message
    if (
        state.status == "needs_intervention"
        and state.intervention_reason
        in {"authentication", "challenge", "access_denied"}
    ):
        payload.update(
            {
                "noVNC": settings.browser_novnc_url,
                "action": "resolve in noVNC then sudo make resume",
            }
        )
    return payload

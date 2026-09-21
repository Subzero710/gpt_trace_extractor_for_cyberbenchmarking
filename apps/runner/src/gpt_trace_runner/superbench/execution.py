from __future__ import annotations
from pathlib import Path
from ..browser import BrowserClient
from ..journal import JournalStore
from ..exceptions import BatchCircuitBreaker
from ..models import task_app_provenance, task_fingerprint
from ..lock import RunnerLock
from ..runner import BenchmarkRunner
from ..runtime_preflight import preflight_tasks
from ..storage_client import StorageClient
from .catalog import SuperbenchCatalog
from .registry import AdapterRegistry
from .service import campaign,start_metadata,to_benchmark_task

async def _record_pre_runner_failure(*,storage,settings,task,bt,camp,state,error):
    expected=(state.attempt+1) if state is not None else 1
    started=await storage.start(bt.task_id,settings.effective_runner_id(),expected,task_fingerprint(bt),task_app_provenance(bt),superbench=start_metadata(task,camp))
    await storage.fail(bt.task_id,error,attempt=started.attempt,runner_id=settings.effective_runner_id())

async def run_pending(*,settings,registry,make_lifecycle,make_chatgpt,console,adapter_ids:tuple[str,...]=(),limit:int|None=None,adapters=None,storage=None,executor=None):
    adapters=adapters or AdapterRegistry.discover();entries=SuperbenchCatalog(adapters).discover(adapter_ids);camp=campaign(settings);owned=storage is None;storage=storage or StorageClient(settings.storage_base_url);staging=Path("/data/state/superbench/staging");staging.mkdir(parents=True,exist_ok=True);attempted=0
    try:
        await storage.health()
        with RunnerLock(settings.runner_lock_path):
            for entry in entries:
                if limit is not None and attempted>=limit:break
                adapter=adapters.get(entry.adapter_id);task=adapter.materialize_task(entry.task,staging);bt=to_benchmark_task(task,registry,camp.campaign_id);state=await storage.get(bt.task_id)
                if state is not None:
                    rs=getattr(state,"run_status",None)
                    if state.status=="completed":
                        if state.success is None:raise RuntimeError(f"{bt.task_id}: invalid Superbench state: completed run has success=None")
                        continue
                    if rs=="unsupported":continue
                    if state.status not in {"failed","running"}:raise RuntimeError(f"{bt.task_id}: Superbench scheduler cannot handle status={state.status!r}")
                if executor is not None:
                    try:await executor(adapter,task,bt,camp,storage)
                    except (KeyboardInterrupt,BatchCircuitBreaker):raise
                    except Exception as exc:
                        if console is not None:console.print(f"[red]{bt.task_id}: {type(exc).__name__}: {exc}[/]")
                    attempted+=1;continue
                prepared=lifecycle=session=None;runner_started=False;recovery_required=False
                try:
                    prepared=await adapter.prepare(task);lifecycle=make_lifecycle(settings,[bt]);await preflight_tasks(lifecycle,[bt],console=console);browser=BrowserClient(settings.effective_browser_cdp_url(),humanize=settings.browser_humanize,humanize_preset=settings.browser_humanize_preset);session=await browser.connect(require_existing_page=False);chatgpt=make_chatgpt(settings,session.page);await chatgpt.wait_until_authenticated(settings.chatgpt_site_ready_timeout_seconds);await chatgpt.verify_apps_available(bt.tools)
                    async def evaluate(captured):return (await adapter.evaluate(task,prepared=prepared,captured=captured)).as_dict()
                    runner=BenchmarkRunner(chatgpt=chatgpt,storage=storage,lifecycle=lifecycle,runner_id=settings.effective_runner_id(),recover_existing=settings.runner_recover_existing,console=console,journal=JournalStore(settings.journal_path),superbench_metadata={bt.task_id:start_metadata(task,camp)},evaluation_hooks={bt.task_id:evaluate})
                    if runner.journal.load() is not None:await runner.reconcile_journal([bt])
                    runner_started=True;await runner.run_task(bt,True)
                except (KeyboardInterrupt,BatchCircuitBreaker):raise
                except Exception as exc:
                    latest=await storage.get(bt.task_id)
                    if runner_started and latest is not None and latest.status=="running":
                        recovery_required=True
                        if console is not None:console.print(f"[red]{bt.task_id}: recovery required after {type(exc).__name__}: {exc}[/]")
                        raise
                    if not runner_started:await _record_pre_runner_failure(storage=storage,settings=settings,task=task,bt=bt,camp=camp,state=latest,error=exc)
                    if console is not None:console.print(f"[red]{bt.task_id}: {type(exc).__name__}: {exc}[/]")
                finally:
                    attempted+=1
                    if session is not None:await session.disconnect()
                    if prepared is not None and not recovery_required:
                        try:await adapter.cleanup(task,prepared=prepared)
                        except (KeyboardInterrupt,BatchCircuitBreaker):raise
                        except Exception as exc:
                            if console is not None:console.print(f"[yellow]{bt.task_id}: cleanup {type(exc).__name__}: {exc}[/]")
                    if lifecycle is not None:await lifecycle.close()
    finally:
        if owned:await storage.close()
    return attempted,camp.campaign_id

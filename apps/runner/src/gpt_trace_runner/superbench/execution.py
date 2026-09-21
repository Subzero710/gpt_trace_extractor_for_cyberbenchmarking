from __future__ import annotations
from pathlib import Path
from ..browser import BrowserClient
from ..journal import JournalStore
from ..lock import RunnerLock
from ..runner import BenchmarkRunner
from ..runtime_preflight import preflight_tasks
from ..storage_client import StorageClient
from .catalog import SuperbenchCatalog
from .registry import AdapterRegistry
from .service import campaign,start_metadata,to_benchmark_task

async def run_pending(*,settings,registry,make_lifecycle,make_chatgpt,console,adapter_ids:tuple[str,...]=(),limit:int|None=None,adapters=None,storage=None,executor=None):
    adapters=adapters or AdapterRegistry.discover(); entries=SuperbenchCatalog(adapters).discover(adapter_ids); camp=campaign(settings)
    owned_storage=storage is None; storage=storage or StorageClient(settings.storage_base_url)
    staging=Path("/data/state/superbench/staging"); staging.mkdir(parents=True,exist_ok=True); attempted=0
    try:
        await storage.health()
        with RunnerLock(settings.runner_lock_path):
            for entry in entries:
                if limit is not None and attempted>=limit: break
                adapter=adapters.get(entry.adapter_id); task=adapter.materialize_task(entry.task,staging); bt=to_benchmark_task(task,registry,camp.campaign_id)
                state=await storage.get(bt.task_id)
                if state is not None and state.status=="completed" and state.success is not None: continue
                if executor is not None:
                    await executor(adapter,task,bt,camp,storage); attempted+=1; continue
                prepared=await adapter.prepare(task); lifecycle=make_lifecycle(settings,[bt])
                try:
                    await preflight_tasks(lifecycle,[bt],console=console)
                    browser=BrowserClient(settings.effective_browser_cdp_url(),humanize=settings.browser_humanize,humanize_preset=settings.browser_humanize_preset); session=await browser.connect(require_existing_page=False)
                    try:
                        chatgpt=make_chatgpt(settings,session.page); await chatgpt.wait_until_authenticated(settings.chatgpt_site_ready_timeout_seconds); await chatgpt.verify_apps_available(bt.tools)
                        async def evaluate(captured): return (await adapter.evaluate(task,prepared=prepared,captured=captured)).as_dict()
                        runner=BenchmarkRunner(chatgpt=chatgpt,storage=storage,lifecycle=lifecycle,runner_id=settings.effective_runner_id(),recover_existing=settings.runner_recover_existing,console=console,journal=JournalStore(settings.journal_path),superbench_metadata={bt.task_id:start_metadata(task,camp)},evaluation_hooks={bt.task_id:evaluate})
                        if runner.journal.load() is not None: await runner.reconcile_journal([bt])
                        await runner.run_task(bt,True); attempted+=1
                    finally: await session.disconnect()
                finally:
                    try: await adapter.cleanup(task,prepared=prepared)
                    finally: await lifecycle.close()
    finally:
        if owned_storage: await storage.close()
    return attempted,camp.campaign_id

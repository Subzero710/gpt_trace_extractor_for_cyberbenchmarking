from __future__ import annotations
import hashlib, json, os, signal
from dataclasses import asdict
from ..exceptions import (
    AccessDenied, AuthenticationRequired, BatchCircuitBreaker, RateLimited,
    RecoveryIncomplete, SiteChallengeFailed,
)
from ..lock import RunnerLock
from .catalog import SuperbenchCatalog
from .execution import _ordered_entries, run_pending
from .models import task_spec_fingerprint
from .registry import AdapterRegistry
from .run_control import ActiveRun, PlannedTask, RunControlStore
from .service import campaign, storage_context, to_benchmark_task

def h(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def config_fp(s):
    keys=('chatgpt_expected_model_slug','chatgpt_conversation_turns','chatgpt_turn_timeout_seconds','chatgpt_stream_start_timeout_seconds','chatgpt_tool_select_timeout_seconds','chatgpt_upload_timeout_seconds','chatgpt_site_ready_timeout_seconds','chatgpt_challenge_timeout_seconds','chatgpt_natural_snapshot_wait_seconds','browser_humanize','browser_humanize_preset','app_browser_humanize','app_browser_humanize_preset','app_browser_timezone','app_browser_locale','app_browser_geoip')
    return h({k:getattr(s,k) for k in keys})
def plan(settings,registry,adapters,adapter_ids=(),limit=None):
    entries=_ordered_entries(SuperbenchCatalog(adapters).discover(adapter_ids),limit)
    if limit is not None: entries=entries[:limit]
    if not entries: raise RecoveryIncomplete('empty Superbench selection')
    camp=campaign(settings); out=[]
    for e in entries:
        a=adapters.get(e.adapter_id); bt=to_benchmark_task(e.task,registry,camp,a); ctx=storage_context(e.task,camp,a,registry)['dataset_metadata']
        out.append(PlannedTask(bt.task_id,e.task.task_id,e.adapter_id,a.adapter_version,task_spec_fingerprint(e.task),ctx['task_contract_fingerprint']))
    return camp,tuple(out)
def validate_frozen(state,settings,registry,adapters):
    camp,current=plan(settings,registry,adapters,tuple(sorted({x.adapter_id for x in state.selected_tasks})),None); by={x.run_task_id:x for x in current}
    if camp.campaign_id!=state.campaign_id or settings.chatgpt_expected_model_slug!=state.expected_model or config_fp(settings)!=state.configuration_fingerprint: raise RecoveryIncomplete('active-run campaign/model/config drift')
    for frozen in state.selected_tasks:
        if by.get(frozen.run_task_id)!=frozen: raise RecoveryIncomplete(f'active-run task/adapter/App contract drift: {frozen.run_task_id}')
    return tuple(x.run_task_id for x in state.selected_tasks)
class SigintPause:
    def __init__(self): self.n=0; self.pause_requested=False
    def __enter__(self):
        self.old=signal.getsignal(signal.SIGINT)
        def handler(*_):
            self.n+=1
            if self.n==1:
                self.pause_requested=True
                return
            raise KeyboardInterrupt
        signal.signal(signal.SIGINT,handler)
        return self
    def __exit__(self,*_): signal.signal(signal.SIGINT,self.old)
def classify_incident(exc):
    if isinstance(exc,AuthenticationRequired): return 'authentication',True
    if isinstance(exc,SiteChallengeFailed): return 'challenge',True
    if isinstance(exc,AccessDenied): return 'access_denied',True
    if isinstance(exc,RateLimited): return 'rate_limited',False
    if isinstance(exc,RecoveryIncomplete): return 'recovery',False
    return 'infrastructure',False

async def execute_active(*,settings,registry,make_lifecycle,make_chatgpt,console,adapter_ids=(),limit=None,resume=False):
    adapters=AdapterRegistry.discover(); store=RunControlStore(settings.superbench_active_run_path)
    if resume:
        state=store.load()
        if state is None or state.status=='completed': raise RecoveryIncomplete('no unfinished active Superbench run')
        ids=validate_frozen(state,settings,registry,adapters)
        with RunnerLock(settings.runner_lock_path):
            state=store.load()
            if state is None or state.status=='completed': raise RecoveryIncomplete('active run is no longer resumable')
            ids=validate_frozen(state,settings,registry,adapters)
            store.begin_resume()
            return await _execute_locked(settings,registry,adapters,store,ids,make_lifecycle,make_chatgpt,console)
    with RunnerLock(settings.runner_lock_path):
        existing=store.load()
        if existing is not None and existing.status!='completed': raise RecoveryIncomplete('unfinished active Superbench run already exists')
        camp,tasks=plan(settings,registry,adapters,adapter_ids,limit)
        state=ActiveRun(3,os.urandom(16).hex(),camp.campaign_id,'running',tasks,settings.chatgpt_expected_model_slug,config_fp(settings))
        store.create(state); ids=tuple(x.run_task_id for x in tasks)
        ids=validate_frozen(store.load(),settings,registry,adapters)
        return await _execute_locked(settings,registry,adapters,store,ids,make_lifecycle,make_chatgpt,console)

async def _execute_locked(settings,registry,adapters,store,ids,make_lifecycle,make_chatgpt,console):
    try:
        with SigintPause() as sigint:
            n,cid=await run_pending(settings=settings,registry=registry,make_lifecycle=make_lifecycle,make_chatgpt=make_chatgpt,console=console,adapters=adapters,selected_run_task_ids=ids,control_store=store,runner_lock_held=True,pause_probe=lambda: sigint.pause_requested)
            if sigint.pause_requested and store.load().status in ('running','resuming'):
                store.request_pause()
    except KeyboardInterrupt:
        raise
    except BaseException as e:
        reason,needs=classify_incident(e)
        if needs: store.intervention(reason,type(e).__name__,str(e))
        else: store.paused_error(reason,type(e).__name__,str(e))
        raise
    state=store.load()
    if state.status=='pause_requested': store.pause_if_requested()
    elif state.status in ('running','resuming') and {x.run_task_id for x in state.selected_tasks}<={*state.completed_run_task_ids}: store.complete()
    return n,cid

async def status_payload(settings):
    from ..storage_client import StorageClient
    s=RunControlStore(settings.superbench_active_run_path).load()
    if s is None: return {'status':'none'}
    storage=StorageClient(settings.storage_base_url); completed=evaluated=passed=failed=infra=0
    try:
        await storage.health()
        for item in s.selected_tasks:
            row=await storage.get(item.run_task_id)
            if row is None: continue
            if row.status=='failed': infra+=1; continue
            if row.status!='completed': continue
            completed+=1
            if row.evaluation is None: continue
            verdict=row.evaluation.get('verdict')
            if verdict=='pass': evaluated+=1; passed+=1
            elif verdict=='fail': evaluated+=1; failed+=1
    finally: await storage.close()
    out={'run_id':s.run_id,'campaign_id':s.campaign_id,'status':s.status,'current_task':s.current_run_task_id,'selected':len(s.selected_tasks),'completed':completed,'remaining':len(s.selected_tasks)-completed,'evaluated':evaluated,'pass':passed,'fail':failed,'infra_failed':infra}
    if s.intervention_reason is not None: out['reason']=s.intervention_reason
    if s.exception_type is not None: out['exception_type']=s.exception_type
    if s.message is not None: out['message']=s.message
    if s.status=='needs_intervention' and s.intervention_reason in {'authentication','challenge','access_denied'}:
        out.update({'noVNC':settings.browser_novnc_url,'action':'resolve in noVNC then sudo make resume'})
    return out

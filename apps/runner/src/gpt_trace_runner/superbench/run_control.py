from __future__ import annotations
import fcntl, json, os
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Literal
from ..exceptions import RecoveryIncomplete

@dataclass(frozen=True, slots=True)
class PlannedTask:
    run_task_id:str; logical_task_id:str; adapter_id:str; adapter_version:str; task_spec_fingerprint:str; contract_fingerprint:str
@dataclass(frozen=True, slots=True)
class ActiveRun:
    schema_version:int; run_id:str; campaign_id:str
    status:Literal['running','pause_requested','paused','resuming','needs_intervention','completed']
    selected_tasks:tuple[PlannedTask,...]; expected_model:str; configuration_fingerprint:str
    completed_run_task_ids:tuple[str,...]=(); current_run_task_id:str|None=None; intervention_reason:str|None=None; exception_type:str|None=None; message:str|None=None
class RunControlStore:
    def __init__(self,path:Path): self.path=path; self.lock_path=path.with_suffix(path.suffix+'.lock')
    @contextmanager
    def _lock(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.lock_path.open('a+b') as f:
            fcntl.flock(f.fileno(),fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(f.fileno(),fcntl.LOCK_UN)
    def _load(self):
        if not self.path.exists(): return None
        try:
            x=json.loads(self.path.read_text()); x['selected_tasks']=tuple(PlannedTask(**v) for v in x['selected_tasks']); x['completed_run_task_ids']=tuple(x.get('completed_run_task_ids',()))
            s=ActiveRun(**x)
        except Exception as e: raise RecoveryIncomplete(f'active run unreadable: {e}') from e
        if s.schema_version!=3: raise RecoveryIncomplete('unsupported active-run schema')
        return s
    def _write(self,s):
        t=self.path.with_suffix(self.path.suffix+'.tmp'); data=json.dumps(asdict(s),sort_keys=True,separators=(',',':'))
        with t.open('w') as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(t,self.path); fd=os.open(self.path.parent,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    def load(self):
        with self._lock(): return self._load()
    def create(self,s):
        with self._lock():
            old=self._load()
            if old and old.status!='completed': raise RecoveryIncomplete(f'active run already {old.status}')
            self._write(s); return s
    def _mut(self,fn):
        with self._lock():
            s=self._load()
            if s is None: raise RecoveryIncomplete('no active Superbench run')
            n=fn(s); self._write(n); return n
    def request_pause(self):
        def f(s):
            if s.status in ('paused','pause_requested'): return s
            if s.status not in ('running','resuming'): raise RecoveryIncomplete(f'cannot pause {s.status}')
            return replace(s,status='pause_requested')
        return self._mut(f)
    def pause_if_requested(self):
        return self._mut(lambda s: replace(s,status='paused',current_run_task_id=None) if s.status=='pause_requested' else s)
    def begin_resume(self):
        def f(s):
            if s.status not in ('running','resuming','pause_requested','paused','needs_intervention'): raise RecoveryIncomplete(f'cannot resume {s.status}')
            return replace(s,status='resuming') # preserve intervention reason until recovery succeeds
        return self._mut(f)
    def confirm_running(self):
        def f(s):
            if s.status=='pause_requested': return s
            if s.status not in ('running','resuming'): raise RecoveryIncomplete(f'cannot run {s.status}')
            return replace(s,status='running',intervention_reason=None,exception_type=None,message=None)
        return self._mut(f)
    def start_task(self,rid):
        def f(s):
            if s.status=='pause_requested': return s
            if rid not in {x.run_task_id for x in s.selected_tasks}: raise RecoveryIncomplete('task outside frozen selection')
            return replace(s,current_run_task_id=rid)
        return self._mut(f)
    def finish_task(self,rid):
        def f(s):
            d=list(s.completed_run_task_ids)
            if rid not in d: d.append(rid)
            return replace(s,completed_run_task_ids=tuple(d),current_run_task_id=None) # status deliberately unchanged
        return self._mut(f)
    def intervention(self,reason,exception_type,message):
        return self._mut(lambda s: replace(s,status='needs_intervention',intervention_reason=reason,exception_type=exception_type,message=message))
    def paused_error(self,reason,exception_type,message):
        return self._mut(lambda s: replace(s,status='paused',intervention_reason=reason,exception_type=exception_type,message=message))
    def complete(self):
        def f(s):
            if not {x.run_task_id for x in s.selected_tasks}<={*s.completed_run_task_ids}: raise RecoveryIncomplete('unfinished frozen tasks')
            return replace(s,status='completed',current_run_task_id=None,intervention_reason=None,exception_type=None,message=None)
        return self._mut(f)

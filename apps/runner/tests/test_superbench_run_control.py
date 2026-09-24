from dataclasses import replace
from gpt_trace_runner.superbench.run_control import *
def mk(): return ActiveRun(3,'r','c','running',(PlannedTask('x','l','a','1','s','c'),),'m','f')
def test_pause_not_overwritten_by_finish(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(mk()); s.request_pause(); s.finish_task('x'); assert s.load().status=='pause_requested'
def test_failed_attempt_is_not_completion(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(mk()); assert s.load().completed_run_task_ids==()

def test_crash_states_can_begin_resume(tmp_path):
 for status in ('running','resuming','pause_requested','paused','needs_intervention'):
  s=RunControlStore(tmp_path/f'{status}.json'); s.create(replace(mk(),status=status)); assert s.begin_resume().status=='resuming'

def test_resume_preserves_reason_until_confirm(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(replace(mk(),status='needs_intervention',intervention_reason='auth')); s.begin_resume(); assert s.load().intervention_reason=='auth'; s.confirm_running(); assert s.load().intervention_reason is None

def test_pause_not_overwritten_by_start(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(mk()); s.request_pause(); s.start_task('x'); assert s.load().status=='pause_requested'

def test_intervention_keeps_current_task_and_evidence(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(mk()); s.start_task('x'); s.intervention('authentication','AuthenticationRequired','401'); x=s.load(); assert x.current_run_task_id=='x'; assert x.exception_type=='AuthenticationRequired'; assert x.message=='401'

def test_completed_requires_all_frozen_tasks(tmp_path):
 s=RunControlStore(tmp_path/'a.json'); s.create(mk())
 import pytest
 with pytest.raises(Exception): s.complete()
 s.finish_task('x'); assert s.complete().status=='completed'

def test_runner_lock_rejects_second_owner(tmp_path):
 import pytest
 from gpt_trace_runner.lock import RunnerLock
 from gpt_trace_runner.exceptions import ConcurrentRunnerError
 p=tmp_path/'runner.lock'
 with RunnerLock(p):
  with pytest.raises(ConcurrentRunnerError):
   with RunnerLock(p): pass

def test_sigint_first_signal_only_sets_memory_flag(monkeypatch):
 import signal
 from gpt_trace_runner.superbench.lifecycle import SigintPause
 handlers={}
 monkeypatch.setattr(signal,'getsignal',lambda *_: object())
 monkeypatch.setattr(signal,'signal',lambda sig,handler: handlers.__setitem__(sig,handler))
 with SigintPause() as guard:
  handlers[signal.SIGINT](signal.SIGINT,None)
  assert guard.pause_requested is True
  assert guard.n==1

def test_rate_limit_is_paused_not_human_intervention():
 from gpt_trace_runner.exceptions import RateLimited
 from gpt_trace_runner.superbench.lifecycle import classify_incident
 assert classify_incident(RateLimited('slow down'))==('rate_limited',False)


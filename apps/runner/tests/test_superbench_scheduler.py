import os
import pytest
from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter,PreparedBenchmarkContext
from gpt_trace_runner.superbench.models import CanonicalTask,EvaluationResult
from gpt_trace_runner.superbench.registry import AdapterRegistry
from gpt_trace_runner.superbench.execution import run_pending
class A(BenchmarkAdapter):
 adapter_id="a"; adapter_version="1"
 def discover_tasks(self): return [CanonicalTask("a:1","original","1","1","repo","commit","p","a","1")]
 async def evaluate(self,task,*,prepared,captured): return EvaluationResult(True,1)
class State:
 def __init__(self,status,success): self.status=status; self.success=success
class Storage:
 def __init__(self,state): self.state=state
 async def health(self): pass
 async def get(self,_): return self.state
class Settings:
 chatgpt_expected_model_slug="m"; chatgpt_conversation_turns=1; chatgpt_turn_timeout_seconds=1; runner_lock_path="/tmp/sb-v2-test.lock"
class R:
 def resolve_id(self,_): raise AssertionError
@pytest.mark.asyncio
@pytest.mark.parametrize("state,expected",[(State("completed",True),0),(State("completed",False),0),(State("failed",None),1),(State("completed",None),1),(None,1)])
async def test_run_pending_terminal_and_retry(monkeypatch,state,expected):
 monkeypatch.setenv("GPT_TRACE_RUNNER_BUILD_ID","test-build"); calls=[]
 async def execute(*args): calls.append(1)
 n,_=await run_pending(settings=Settings(),registry=R(),make_lifecycle=None,make_chatgpt=None,console=None,adapters=AdapterRegistry([A()]),storage=Storage(state),executor=execute); assert n==expected; assert len(calls)==expected

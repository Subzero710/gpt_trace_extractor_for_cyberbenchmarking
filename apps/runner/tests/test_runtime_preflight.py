from __future__ import annotations
import pytest
from rich.console import Console
from gpt_trace_runner.exceptions import AppInfrastructureError
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool
from gpt_trace_runner.runtime_preflight import preflight_tasks, _validate_endpoint

class Lifecycle:
    def __init__(self, fail=False):self.calls=[];self.fail=fail
    def environment_ids(self,task,*,attempt,fingerprint):return {}
    async def health(self,task):self.calls.append('health')
    async def prepare(self,*args,**kw):
        self.calls.append('prepare')
        if self.fail:raise AppInfrastructureError('prepare failed')
    async def reset(self,*args,**kw):self.calls.append('reset')
    async def assert_clean(self,*args,**kw):self.calls.append('assert_clean')

@pytest.mark.asyncio
async def test_preflight_cleanup_even_after_prepare_failure():
    task=BenchmarkTask('t','p',())
    lifecycle=Lifecycle(True)
    with pytest.raises(AppInfrastructureError,match='prepare failed'):
        await preflight_tasks(lifecycle,[task],console=Console())
    assert lifecycle.calls==['health','prepare','reset','assert_clean']

def test_preflight_rejects_external_mcp_endpoint():
    tool=BenchmarkTool('app','kali-workstation','Kali Workstation','local_mcp','3.0.0','a'*64,{},mcp_endpoint='https://attacker.example/mcp')
    with pytest.raises(AppInfrastructureError,match='endpoint'):
        _validate_endpoint(tool)

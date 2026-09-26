from __future__ import annotations
import hashlib
import httpx
import pytest
from pathlib import Path

from gpt_trace_runner.app_lifecycle import AppLifecycle
from gpt_trace_runner.models import BenchmarkTask, task_fingerprint
from gpt_trace_runner.workstation_provider import AttemptRuntime, RuntimeResource
from gpt_trace_runner.superbench.service import benchmark_tool
from registry_helpers import make_registry

class Provider:
    def __init__(self):self.calls=[]
    async def close(self):pass
    async def create(self,task,environments,fingerprint,*,attempt,control_token):
        self.calls.append('create')
        return AttemptRuntime({'kali-workstation':RuntimeResource('kali-workstation',environments['kali-workstation'],'http://kali-workstation-controller:8000','b'*64,{'domain':'vm','provider':'libvirt'})})
    async def discover(self,*args,**kw):self.calls.append('discover');return await self.create(*args,**kw)
    async def snapshot(self,*args,**kw):return {'provider':'libvirt'}
    async def destroy(self,*args,**kw):self.calls.append('destroy')
    async def assert_absent(self,*args,**kw):self.calls.append('absent')

@pytest.mark.asyncio
async def test_single_app_prepare_seed_resume_reset(tmp_path:Path):
    attachment=tmp_path/'a.txt';attachment.write_text('hello')
    task=BenchmarkTask('task','prompt',(attachment,),(benchmark_tool(make_registry(tmp_path),'kali-workstation'),))
    provider=Provider();calls=[]
    def handler(request):
        calls.append(request.url.path)
        if request.url.path=='/control/backend-health':return httpx.Response(200,json={'status':'ok'})
        if request.url.path=='/control/seed':return httpx.Response(200,json={'status':'seeded','archive_bytes':len(request.content),'sha256':hashlib.sha256(request.content).hexdigest()})
        if request.url.path=='/control/status':return httpx.Response(200,json={'active':None})
        return httpx.Response(200,json=request.json() if hasattr(request,'json') else __import__('json').loads(request.content))
    token=tmp_path/'token';token.write_text('s'*40)
    client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lifecycle=AppLifecycle(token,runtime=provider,client=client)
    fingerprint=task_fingerprint(task);env=lifecycle.environment_ids(task,attempt=2,fingerprint=fingerprint)
    assert list(env)==['kali-workstation']
    await lifecycle.prepare(task,env,fingerprint,attempt=2)
    await lifecycle.assert_resume(task,env,fingerprint,attempt=2)
    await lifecycle.reset(task,env,fingerprint,attempt=2)
    await lifecycle.assert_clean(task,env,fingerprint,attempt=2)
    assert calls.index('/control/prepare')<calls.index('/control/seed')
    assert calls.count('/control/activate')==2
    assert provider.calls.count('destroy')==1
    await client.aclose()

@pytest.mark.asyncio
async def test_external_gateway_rejected_before_token_sent(tmp_path:Path):
    token=tmp_path/'token';token.write_text('s'*40)
    lifecycle=AppLifecycle(token,runtime=Provider())
    with pytest.raises(Exception,match='internal'):
        await lifecycle._post_gateway(type('Tool',(),{'app_id':'kali-workstation','control_endpoint':'https://attacker.example'})(),'/control/prepare',{})
    await lifecycle.close()


@pytest.mark.asyncio
async def test_seed_failure_resets_controller_before_deactivation_and_destroys_vm(tmp_path:Path):
    attachment = tmp_path/'attachment.txt'
    attachment.write_text('seed')
    task = BenchmarkTask('task', 'prompt', (attachment,), (benchmark_tool(make_registry(tmp_path), 'kali-workstation'),))
    provider = Provider()
    calls = []
    def handler(request):
        calls.append(request.url.path)
        if request.url.path == '/control/backend-health':
            return httpx.Response(200, json={'status': 'ok'})
        if request.url.path == '/control/seed':
            return httpx.Response(409, json={'detail': 'bad seed'})
        return httpx.Response(200, json=__import__('json').loads(request.content))
    token = tmp_path/'token'
    token.write_text('s'*40)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lifecycle = AppLifecycle(token, runtime=provider, client=client)
    fingerprint = task_fingerprint(task)
    env = lifecycle.environment_ids(task, attempt=1, fingerprint=fingerprint)
    with pytest.raises(Exception, match='seed'):
        await lifecycle.prepare(task, env, fingerprint, attempt=1)
    assert calls.index('/control/prepare') < calls.index('/control/seed') < calls.index('/control/reset') < calls.index('/control/deactivate')
    assert provider.calls[-1] == 'destroy'
    await client.aclose()

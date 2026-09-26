from __future__ import annotations
import httpx
import pytest
from pathlib import Path

from gpt_trace_runner.workstation_provider import LibvirtWorkstationProvider
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool

@pytest.mark.asyncio
async def test_provider_verifies_exact_broker_identity_and_never_requests_host_commands(tmp_path:Path):
    token=tmp_path/'token';token.write_text('s'*40)
    tool=BenchmarkTool('app','kali-workstation','Kali Workstation','local_mcp','3.0.0','a'*64,{'tools':[]})
    task=BenchmarkTask('t','p',(),(tool,))
    env={'kali-workstation':'env-t'}; fingerprint='a'*64; calls=[]
    def handler(request):
        calls.append((request.url.path,request.headers.get('authorization')))
        payload=__import__('json').loads(request.content)
        if request.url.path.endswith('assert_absent'):return httpx.Response(200,json={'absent':True})
        if request.url.path.endswith('destroy_attempt'):return httpx.Response(200,json={'destroyed':True})
        return httpx.Response(200,json={'identity':payload,'provider':'libvirt','domain':'gpt-trace-ws-123'})
    client=httpx.AsyncClient(transport=httpx.MockTransport(handler),base_url='http://broker')
    provider=LibvirtWorkstationProvider(tmp_path/'broker.sock',token,client=client)
    created=await provider.create(task,env,fingerprint,attempt=1,control_token='s'*40)
    assert set(created.resources)=={'kali-workstation'}
    assert created.resources['kali-workstation'].backend_url=='http://kali-workstation-controller:8000'
    await provider.discover(task,env,fingerprint,attempt=1,control_token='s'*40)
    await provider.destroy(task,env,fingerprint,attempt=1)
    await provider.assert_absent(task,env,fingerprint,attempt=1)
    assert [row[0] for row in calls]==['/v1/create_attempt','/v1/inspect_attempt','/v1/destroy_attempt','/v1/assert_absent']
    assert all(row[1]=='Bearer '+'s'*40 for row in calls)
    await client.aclose()

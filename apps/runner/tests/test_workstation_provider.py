from __future__ import annotations
import asyncio
import json
import httpx
import pytest
from pathlib import Path

from gpt_trace_runner.workstation_provider import LibvirtWorkstationProvider
from gpt_trace_runner.exceptions import AppInfrastructureError
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool

@pytest.mark.asyncio
async def test_provider_verifies_exact_broker_identity_and_never_requests_host_commands(tmp_path:Path):
    token=tmp_path/'token';token.write_text('s'*40)
    tool=BenchmarkTool('app','kali-workstation','Kali Workstation','local_mcp','3.0.0','a'*64,{'tools':[]})
    task=BenchmarkTask('t','p',(),(tool,))
    env={'kali-workstation':'env-t'}; fingerprint='a'*64; calls=[]
    def handler(request):
        calls.append((request.url.path,request.headers.get('authorization')))
        payload=json.loads(request.content)
        ident = {key: payload[key] for key in ('task_id', 'attempt', 'environment_id', 'fingerprint')}
        if request.url.path.endswith('reconcile_attempt'):
            return httpx.Response(200, json={'state': 'absent', 'identity': ident})
        if request.url.path.endswith(('begin_async', 'poll_async')):
            status = {'identity': ident, 'operation': payload['operation'], 'operation_id': payload['operation_id']}
            if request.url.path.endswith('begin_async'):
                return httpx.Response(200, json={'state': 'accepted', **status})
            result = {'identity': ident, 'provider': 'libvirt', 'domain': 'gpt-trace-ws-123'}
            return httpx.Response(200, json={'state': 'complete', 'result': result, **status})
        if request.url.path.endswith(('begin_runtime', 'poll_runtime')):
            status = {'identity': ident, 'operation': payload['operation'], 'operation_id': payload['operation_id']}
            if request.url.path.endswith('begin_runtime'):
                return httpx.Response(200, json={'state': 'accepted', **status})
            result = {'destroyed': True} if payload['operation'] == 'destroy_attempt' else {'absent': True}
            return httpx.Response(200, json={'state': 'complete', 'result': result, **status})
        return httpx.Response(200,json={'identity':payload,'provider':'libvirt','domain':'gpt-trace-ws-123'})
    client=httpx.AsyncClient(transport=httpx.MockTransport(handler),base_url='http://broker')
    provider=LibvirtWorkstationProvider(tmp_path/'broker.sock',token,client=client,remote=False,
                                        creation_request_timeout=2,creation_poll_interval=1,guest_command_timeout=180)
    created=await provider.create(task,env,fingerprint,attempt=1,control_token='s'*40)
    assert set(created.resources)=={'kali-workstation'}
    assert created.resources['kali-workstation'].backend_url=='http://kali-workstation-controller:8000'
    await provider.discover(task,env,fingerprint,attempt=1,control_token='s'*40)
    await provider.destroy(task,env,fingerprint,attempt=1)
    await provider.assert_absent(task,env,fingerprint,attempt=1)
    assert [row[0] for row in calls]==['/v1/reconcile_attempt','/v1/begin_async','/v1/poll_async',
                                     '/v1/inspect_attempt','/v1/begin_runtime','/v1/poll_runtime','/v1/begin_runtime','/v1/poll_runtime']
    assert all(row[1]=='Bearer '+'s'*40 for row in calls)
    await client.aclose()


@pytest.mark.asyncio
async def test_expired_vm_acceptance_is_reconciled_by_operation_id_without_repeating_mutation(tmp_path):
    token = tmp_path / 'token'
    token.write_text('s' * 40)
    identity = {'task_id': 'demo', 'attempt': 1, 'environment_id': 'env', 'fingerprint': 'a' * 64}
    observed = []

    async def transport(request):
        payload = json.loads(request.content)
        observed.append((request.url.path, payload['operation_id']))
        if request.url.path == '/v1/begin_async':
            assert request.extensions['timeout']['read'] == 1
            await asyncio.Event().wait()
        assert request.url.path == '/v1/poll_async'
        return httpx.Response(200, json={'state': 'complete', 'operation': payload['operation'],
            'operation_id': payload['operation_id'], 'identity': identity,
            'result': {'identity': identity, 'provider': 'libvirt'}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport), base_url='http://broker') as client:
        provider = LibvirtWorkstationProvider(tmp_path / 'sock', token, creation_request_timeout=1,
                                              creation_poll_interval=1, guest_command_timeout=180, client=client, remote=False)
        result = await provider._await_async_create('create_attempt', identity)
    assert result['identity'] == identity
    assert [path for path, _ in observed] == ['/v1/begin_async', '/v1/poll_async']
    assert observed[0][1] == observed[1][1]


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["complete", "unknown"])
async def test_runtime_status_resolves_a_lost_http_admission_without_resending_command(tmp_path, outcome):
    token = tmp_path / "token"
    token.write_text("s" * 40)
    identity = {"task_id": "demo", "attempt": 1, "environment_id": "env", "fingerprint": "a" * 64}
    calls = []

    async def transport(request):
        payload = json.loads(request.content)
        calls.append((request.url.path, payload["operation_id"]))
        assert request.extensions["timeout"]["read"] == 1
        if request.url.path == "/v1/begin_runtime":
            assert payload["args"] == {"command": "printf '%s' verified", "timeout_seconds": 180}
            await asyncio.Event().wait()
        assert request.url.path == "/v1/poll_runtime" and "args" not in payload
        return httpx.Response(200, json={"state": outcome, "operation": "exec_command",
            "operation_id": payload["operation_id"], "identity": identity, "result": {"exit_code": 0}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport), base_url="http://broker") as client:
        provider = LibvirtWorkstationProvider(tmp_path / "sock", token, creation_request_timeout=1,
                                              creation_poll_interval=1, guest_command_timeout=180, client=client, remote=False)
        args = {"command": "printf '%s' verified"}
        if outcome == "complete":
            assert await provider._guest_call(identity, "exec_command", args) == {"exit_code": 0}
        else:
            with pytest.raises(AppInfrastructureError, match="outcome unconfirmed"):
                await provider._guest_call(identity, "exec_command", args)
    assert [path for path, _ in calls] == ["/v1/begin_runtime", "/v1/poll_runtime"]
    assert calls[0][1] == calls[1][1]

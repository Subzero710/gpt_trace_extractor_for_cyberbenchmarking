from __future__ import annotations
import httpx
import pytest
from mcp_gateway.server import GatewayState, create_app

TOKEN='s'*40
IDENT={'task_id':'task','attempt':1,'environment_id':'env','task_fingerprint':'a'*64}

@pytest.mark.asyncio
async def test_gateway_accepts_only_fixed_trusted_controller():
    state=GatewayState(app_id='kali-workstation',backend_prefix='kali-workstation-controller',control_token=TOKEN)
    app=create_app(state)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://workstation-gateway:8000') as client:
        headers={'authorization':'Bearer '+TOKEN}
        rejected=await client.post('/control/activate',headers=headers,json={**IDENT,'backend_url':'http://172.30.0.17:8000','backend_token':'b'*64})
        assert rejected.status_code==400
        accepted=await client.post('/control/activate',headers=headers,json={**IDENT,'backend_url':'http://kali-workstation-controller:8000','backend_token':'b'*64})
        assert accepted.status_code==200
        changed=await client.post('/control/activate',headers=headers,json={**IDENT,'environment_id':'other','backend_url':'http://kali-workstation-controller:8000','backend_token':'c'*64})
        assert changed.status_code==409
        wrong=await client.post('/control/deactivate',headers=headers,json={**IDENT,'attempt':2})
        assert wrong.status_code==409
        ok=await client.post('/control/deactivate',headers=headers,json=IDENT)
        assert ok.status_code==200
    await state.close()

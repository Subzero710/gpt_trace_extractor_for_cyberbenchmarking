from __future__ import annotations
import hashlib
import hmac
import httpx
import pytest
from kali_workstation.server import WorkstationController, create_app, model_content

IDENT={'task_id':'task','attempt':1,'environment_id':'env','fingerprint':'a'*64}
TOKEN='s'*40
BROKER_TOKEN='b'*40

@pytest.mark.asyncio
async def test_controller_binds_exact_attempt_and_checks_result_schema(tmp_path):
    calls=[]
    def broker(request):
        assert request.headers['authorization'] == 'Bearer '+BROKER_TOKEN
        args=__import__('json').loads(request.content)
        calls.append((request.url.path,args))
        if request.url.path.endswith('inspect_attempt'):
            return httpx.Response(200,json={'identity':args,'provider':'libvirt'})
        return httpx.Response(200,json={'status':'ready',**IDENT})
    controller=WorkstationController(tmp_path/'broker.sock',TOKEN,BROKER_TOKEN)
    await controller.client.aclose()
    controller.client=httpx.AsyncClient(transport=httpx.MockTransport(broker),base_url='http://broker')
    app=create_app(controller)
    header={'authorization':'Bearer '+controller.backend_token('env')}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://kali-workstation-controller:8000') as client:
        payload={**IDENT,'task_fingerprint':IDENT['fingerprint']}
        bad=await client.post('/control/prepare',json={**payload,'environment_id':'other'},headers=header)
        assert bad.status_code==401
        ready=await client.post('/control/prepare',json=payload,headers=header)
        assert ready.status_code==200 and controller.active==IDENT
        conflict=await client.post('/control/prepare',json={**payload,'task_id':'different'},headers=header)
        assert conflict.status_code==409
        reset=await client.post('/control/reset',json=payload,headers=header)
        assert reset.status_code==200 and controller.active is None
    assert [name for name,_ in calls]==['/v1/inspect_attempt','/v1/rpc']
    await controller.client.aclose()


def test_observe_screen_is_model_visible_image_content():
    encoded = 'iVBORw0KGgo='
    result = {'width': 2, 'height': 1, 'mime_type': 'image/png',
              'content_base64': encoded, 'sha256': 'a'*64}
    content = model_content('observe_screen', result)
    assert [block.type for block in content] == ['image', 'text']
    assert content[0].data == encoded
    assert content[0].model_dump(by_alias=True)['mimeType'] == 'image/png'
    assert 'content_base64' not in content[1].text


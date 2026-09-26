from __future__ import annotations

import asyncio
import base64
import hashlib
import json

import pytest
from workstation_broker.computer import character, input_events
from workstation_broker.server import Broker

IDENT = {'task_id': 'task', 'attempt': 1, 'environment_id': 'env', 'fingerprint': 'a'*64}


def test_qmp_events_are_hypervisor_commands_with_validated_coordinates():
    calls = []
    def run(*args):
        calls.append(args)
        return b'{"return":{}}'
    assert input_events(run, 'domain', {'events': [{'type': 'mouse_move', 'x': 10, 'y': 20},
                                                  {'type': 'click', 'button': 'left'},
                                                  {'type': 'text', 'text': 'A!'}]}, 100, 100)['events_processed'] == 3
    assert all(c[3] == 'qemu-monitor-command' for c in calls)
    assert json.loads(calls[0][5])['arguments']['events'][0]['data']['value'] == round(10*32767/99)
    assert character('A')[0]['data']['key']['data'] == 'shift'
    assert character('é')[0]['data']['key']['data'] == 'ctrl'
    assert input_events(run, 'domain', {'events': [{'type': 'key', 'key': 'ENTER'}]}, 100, 100)['events_processed'] == 1


@pytest.mark.asyncio
async def test_export_uses_content_addressed_store_and_import_streams_chunks(tmp_path, monkeypatch):
    broker = Broker.__new__(Broker)
    broker.root = tmp_path
    broker.max_transfer_bytes = 2*1024*1024
    monkeypatch.setattr(broker, '_read', lambda ident: {})
    (tmp_path/'disk').mkdir()
    monkeypatch.setattr(broker, '_paths', lambda ident: ('domain', 'net', tmp_path))
    payload = b'artifact' * 140000
    calls = []
    async def rpc(ident, method, args):
        calls.append((method, args))
        if method == 'artifact_stat': return {'size': len(payload)}
        if method == 'artifact_read_chunk':
            return {'content_base64': base64.b64encode(payload[args['offset']:args['offset']+1048576]).decode()}
        if method == 'artifact_import_end': return {'path': '/home/kali/workspace/out', 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
        return {'ok': True}
    monkeypatch.setattr(broker, 'rpc', rpc)
    exported = await broker.export_artifact(IDENT, {'path': '/home/kali/workspace/out'})
    assert exported['artifact_id'] == hashlib.sha256(payload).hexdigest()
    assert 'content_base64' not in exported
    assert (broker._artifacts(IDENT)/exported['artifact_id']).read_bytes() == payload
    imported = await broker.import_artifact(IDENT, {'path': '/home/kali/workspace/out', 'artifact_id': exported['artifact_id']})
    assert imported['sha256'] == exported['sha256']
    assert b''.join(base64.b64decode(args['content_base64']) for method, args in calls if method == 'artifact_import_chunk') == payload

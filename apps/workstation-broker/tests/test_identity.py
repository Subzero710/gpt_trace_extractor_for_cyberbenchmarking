from __future__ import annotations
import json
import xml.etree.ElementTree as ET
import httpx
import pytest
from pathlib import Path
from workstation_broker.server import identity, domain_xml, suffix, META_NS, create_app, Broker

IDENT={'task_id':'task-1','attempt':3,'environment_id':'env-3','fingerprint':'a'*64}

def test_identity_rejects_malformed_host_inputs():
    assert identity(IDENT)==IDENT
    for altered in ({**IDENT,'task_id':'../../host'}, {**IDENT,'attempt':True}, {**IDENT,'fingerprint':'x'*64}):
        with pytest.raises(ValueError): identity(altered)

def test_domain_contains_exact_metadata_and_no_host_mount():
    xml=ET.fromstring(domain_xml('gpt-trace-ws-'+suffix(IDENT),'gpt-trace-net-'+suffix(IDENT),Path('/safe/overlay.qcow2'),Path('/safe/identity.iso'),7000,8192,4,IDENT,'b'*64))
    metadata=json.loads(xml.find(f'./metadata/{{{META_NS}}}attempt').text)
    assert {k:metadata[k] for k in IDENT}==IDENT
    assert metadata['base_sha256']=='b'*64
    assert xml.find('./devices/vsock/cid').get('address')=='7000'
    assert xml.find('./devices/filesystem') is None


@pytest.mark.asyncio
async def test_broker_controller_token_cannot_manage_vm_lifecycle():
    class FakeBroker:
        admin_token = 'a'*40
        controller_token = 'c'*40
        def destroy_all(self):
            return {'removed': []}
        async def inspect_verified(self, ident):
            return {'identity': ident, 'provider': 'libvirt'}
    app = create_app(FakeBroker())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url='http://broker') as client:
        controller = {'authorization': 'Bearer ' + 'c'*40}
        admin = {'authorization': 'Bearer ' + 'a'*40}
        forbidden = await client.post('/v1/destroy_all', json={}, headers=controller)
        assert forbidden.status_code == 403
        allowed = await client.post('/v1/inspect_attempt', json=IDENT, headers=controller)
        assert allowed.status_code == 200 and allowed.json()['identity'] == IDENT
        cleanup = await client.post('/v1/destroy_all', json={}, headers=admin)
        assert cleanup.status_code == 200


def test_destroy_all_recovers_directory_created_before_state_file(tmp_path, monkeypatch):
    broker = Broker.__new__(Broker)
    broker.root = tmp_path
    key = 'a'*20
    directory = tmp_path/key
    (directory/'disk').mkdir(parents=True)
    calls = []
    def fake_run(*args, **kwargs):
        calls.append(args)
        return b''
    monkeypatch.setattr('workstation_broker.server.run', fake_run)
    monkeypatch.setattr(broker, '_remove_firewall_key', lambda value: calls.append(('firewall', value)))
    result = broker.destroy_all()
    assert result['removed'] == []
    assert result['orphaned'] == [key]
    assert not directory.exists()



def test_firewall_exposes_only_attempt_dns_and_dhcp_on_host(monkeypatch):
    broker = Broker.__new__(Broker)
    broker.egress_allow_cidrs = ()
    scripts = []
    def fake_run(*args, **kwargs):
        if args[:3] == ('nft', '-f', '-'):
            scripts.append(kwargs['input'].decode())
        return b''
    monkeypatch.setattr('workstation_broker.server.run', fake_run)
    broker._firewall(IDENT, 'gtdeadbeef00', '10.200.42.1')
    script = scripts[0]
    assert 'ip daddr 10.200.42.1 udp dport 53 accept' in script
    assert 'ip daddr 10.200.42.1 tcp dport 53 accept' in script
    assert 'ip daddr { 10.200.42.1, 255.255.255.255 } udp dport 67 accept' in script
    assert 'udp dport { 53, 67 } accept' not in script


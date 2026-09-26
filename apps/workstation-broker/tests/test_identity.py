from __future__ import annotations
import json
import xml.etree.ElementTree as ET
import pytest
from pathlib import Path
from workstation_broker.server import identity, domain_xml, suffix, META_NS

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

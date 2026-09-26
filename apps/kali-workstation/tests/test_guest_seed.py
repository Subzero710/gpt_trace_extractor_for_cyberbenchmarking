from __future__ import annotations
import base64
import hashlib
import io
import tarfile
import pytest
from kali_workstation.guest import files

def archive(name,data=b'hello'):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as handle:
        row=tarfile.TarInfo(name);row.size=len(data);handle.addfile(row,io.BytesIO(data))
    return output.getvalue()

def test_chunked_seed_validates_identity_and_blocks_traversal(tmp_path,monkeypatch):
    monkeypatch.setattr(files,'WORKSPACE',tmp_path/'workspace')
    good=archive('a.txt')
    session=files.SeedSession();session.target=tmp_path/'seed.tar'
    session.begin({})
    session.chunk({'content_base64':base64.b64encode(good).decode()})
    assert session.finish({'archive_bytes':len(good),'sha256':hashlib.sha256(good).hexdigest()})['status']=='seeded'
    assert (tmp_path/'workspace/a.txt').read_bytes()==b'hello'
    monkeypatch.setattr(files,'WORKSPACE',tmp_path/'fresh')
    bad=archive('../outside')
    session=files.SeedSession();session.target=tmp_path/'bad.tar'
    session.begin({});session.chunk({'content_base64':base64.b64encode(bad).decode()})
    with pytest.raises(ValueError,match='unsafe'):
        session.finish({'archive_bytes':len(bad),'sha256':hashlib.sha256(bad).hexdigest()})
    assert not (tmp_path/'outside').exists()

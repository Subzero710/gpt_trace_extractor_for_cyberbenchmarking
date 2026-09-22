import hashlib
from pathlib import Path
import pytest
from file_relay.models import Identity,Limits
from file_relay.store import RelayError,Store

@pytest.fixture
def store(tmp_path):
    return Store(tmp_path,Limits(1024*1024,2*1024*1024,4,1,1,60,64))

async def chunks(data):
    yield data

@pytest.mark.asyncio
async def test_acl_integrity_ack_and_no_enumeration(store):
    data=b"\x00abc"*100
    h=hashlib.sha256(data).hexdigest()
    w=Identity("t",1,"code-workspace"); b=Identity("t",1,"browser")
    ref=await store.put(w,"browser","../../x.bin","application/octet-stream",len(data),h,chunks(data))
    row,path=store.get(b,ref["file_id"])
    assert path.name==ref["file_id"]+".blob"
    assert path.read_bytes()==data
    with pytest.raises(RelayError): store.get(w,ref["file_id"])
    assert store.ack(b,ref["file_id"])["state"]=="ACKED"
    assert not path.exists()

@pytest.mark.asyncio
async def test_hash_mismatch_never_becomes_visible(store):
    w=Identity("t",1,"code-workspace")
    with pytest.raises(RelayError):
        await store.put(w,"browser","x","x",3,"0"*64,chunks(b"abc"))
    assert not list((store.root/"objects").glob("*.blob"))

@pytest.mark.asyncio
async def test_attempt_scope(store):
    data=b"x"; h=hashlib.sha256(data).hexdigest()
    ref=await store.put(Identity("a",1,"code-workspace"),"browser","x","x",1,h,chunks(data))
    with pytest.raises(RelayError):
        store.get(Identity("a",2,"browser"),ref["file_id"])

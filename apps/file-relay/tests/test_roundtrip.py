import base64,hashlib,importlib,json
from starlette.testclient import TestClient

def meta(name,media="application/octet-stream"):
    return base64.urlsafe_b64encode(json.dumps({"name":name,"media_type":media},ensure_ascii=False,separators=(",",":")).encode()).decode().rstrip("=")

def test_workspace_browser_workspace_roundtrip(tmp_path,monkeypatch):
    monkeypatch.setenv("FILE_RELAY_DATA_ROOT",str(tmp_path));monkeypatch.setenv("FILE_RELAY_TASK_ID","task");monkeypatch.setenv("FILE_RELAY_ATTEMPT","1")
    monkeypatch.setenv("FILE_RELAY_WORKSPACE_TOKEN","w"*64);monkeypatch.setenv("FILE_RELAY_BROWSER_TOKEN","b"*64)
    import file_relay.auth,file_relay.server
    importlib.reload(file_relay.auth);srv=importlib.reload(file_relay.server)
    with TestClient(srv.app) as c:
        a=b"%PDF-1.7\nhello\n";h=hashlib.sha256(a).hexdigest()
        r=c.post("/v1/files",content=a,headers={"Authorization":"Bearer "+"w"*64,"X-Target-App":"browser","X-File-Metadata":meta("报告.pdf","application/pdf"),"X-Content-SHA256":h,"Content-Length":str(len(a))});assert r.status_code==201;fid=r.json()["file_id"]
        r=c.get("/v1/files/"+fid,headers={"Authorization":"Bearer "+"b"*64});assert r.status_code==200 and r.content==a
        assert c.post("/v1/files/"+fid+"/ack",headers={"Authorization":"Bearer "+"b"*64}).status_code==200
        b=b"browser-download\x00bytes";h=hashlib.sha256(b).hexdigest()
        r=c.post("/v1/files",content=b,headers={"Authorization":"Bearer "+"b"*64,"X-Target-App":"code-workspace","X-File-Metadata":meta("emoji-😀.bin"),"X-Content-SHA256":h,"Content-Length":str(len(b))});assert r.status_code==201;fid=r.json()["file_id"]
        r=c.get("/v1/files/"+fid,headers={"Authorization":"Bearer "+"w"*64});assert r.status_code==200 and r.content==b
        assert c.post("/v1/files/"+fid+"/ack",headers={"Authorization":"Bearer "+"w"*64}).status_code==200


from starlette.testclient import TestClient
from browser_mcp.server import create_app
class Dummy:
 async def start(self):pass
 async def shutdown(self):pass
 async def call(self,name,args):return {}
 def healthy(self):return True
 def state_response(self):return {"status":"ready"}
def test_mcp_backend_auth():
 with TestClient(create_app(Dummy(),control_token="x"*64,allowed_hosts=["localhost:8000"])) as c:
  base={"host":"localhost:8000","origin":"https://chatgpt.com"}
  assert c.post("/mcp/",headers=base).status_code==401
  assert c.post("/mcp/",headers={**base,"authorization":"Bearer "+"y"*64}).status_code==401
  assert c.post("/mcp/",headers={**base,"authorization":"Bearer "+"x"*64}).status_code!=401

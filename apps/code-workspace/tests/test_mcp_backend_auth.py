
from starlette.testclient import TestClient
from code_workspace.server import create_app
class Dummy:
 async def shutdown(self):pass
 async def call_v2(self,*a):return {}
 def template_entries(self):return []
 def state_response(self):return {"status":"ready"}
def test_mcp_backend_auth():
 with TestClient(create_app(Dummy(),"x"*64,["localhost:8000"])) as c:
  h={"host":"localhost:8000"}
  assert c.post("/mcp/",headers=h).status_code==401
  assert c.post("/mcp/",headers={**h,"authorization":"Bearer "+"y"*64}).status_code==401
  assert c.post("/mcp/",headers={**h,"authorization":"Bearer "+"x"*64}).status_code!=401

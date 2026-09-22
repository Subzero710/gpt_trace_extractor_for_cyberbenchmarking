from __future__ import annotations
import contextlib,hashlib,hmac,json,logging,os,tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager,TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount,Route
from .contracts import APP_ID,TOOLS,VERSION,canonical_bytes,manifest,MODELS
from .core import WorkspaceError,WorkspaceManagerV2
MAX=180*1024*1024

def token(path):
 v=os.environ.get('APP_CONTROL_TOKEN','').strip() or path.read_text().strip()
 if len(v)<32:raise RuntimeError('control token is missing or too short')
 return v
def payload(m):
 entries=m.template_entries() if hasattr(m,'template_entries') else []
 return manifest(entries)
def verify(path,m):
 if canonical_bytes(json.loads(path.read_text()))!=canonical_bytes(payload(m)):raise RuntimeError('MCP implementation and tool-manifest.json differ')
async def body(r):
 raw=await r.body()
 if len(raw)>MAX:raise WorkspaceError('control body is too large')
 v=json.loads(raw)
 if not isinstance(v,dict):raise WorkspaceError('control request must be an object')
 return v
def create_app(manager,control_token,allowed_hosts=None):
 server=Server(APP_ID,version=VERSION)
 @server.list_tools()
 async def lt():return [types.Tool(**{k:v for k,v in x.items() if k!='category'}) for x in TOOLS]
 @server.call_tool()
 async def ct(name,arguments):
  if name in MODELS:r=await manager.call_v2(name,arguments)
  elif name=='exec_command':r=await manager.exec_command(arguments)
  elif name=='read_file':r=manager.read_file(arguments)
  elif name=='write_file':r=manager.write_file(arguments)
  elif name=='apply_patch':r=manager.apply_patch(arguments)
  elif name=='list_directory':r=manager.list_directory(arguments)
  elif name=='search_files':r=manager.search_files(arguments)
  else:raise WorkspaceError(f'unknown tool: {name}')
  return ([types.TextContent(type='text',text=json.dumps(r,sort_keys=True,separators=(',',':')))],r)
 sm=StreamableHTTPSessionManager(app=server,event_store=None,json_response=True,stateless=True,security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=True,allowed_hosts=allowed_hosts or []))
 async def mcp(scope,receive,send):
  headers={key.decode('latin1').casefold():value.decode('latin1') for key,value in scope.get('headers',[])}
  if not hmac.compare_digest(headers.get('authorization',''),f'Bearer {control_token}'):
   response=JSONResponse({'error':{'code':'MCP_BACKEND_UNAUTHORIZED','message':'backend authentication required'}},status_code=401)
   await response(scope,receive,send);return
  await sm.handle_request(scope,receive,send)
 def auth(r):return hmac.compare_digest(r.headers.get('authorization',''),f'Bearer {control_token}')
 async def health(r):return JSONResponse({'status':'ok','app_id':APP_ID})
 async def mani(r):return JSONResponse(payload(manager))
 async def state(r):return JSONResponse(manager.state_response()) if auth(r) else JSONResponse({'detail':'unauthorized'},status_code=401)
 async def seed(r):
  if not auth(r):return JSONResponse({'detail':'unauthorized'},status_code=401)
  content_type=r.headers.get('content-type','').split(';',1)[0].strip().casefold()
  if content_type!='application/x-tar':return JSONResponse({'detail':'seed content-type must be application/x-tar'},status_code=415)
  declared=r.headers.get('content-length')
  if declared is not None:
   try:
    if int(declared)>MAX:return JSONResponse({'detail':'seed archive is too large'},status_code=413)
   except ValueError:return JSONResponse({'detail':'invalid content-length'},status_code=400)
  async with manager.lock:
   if manager.load_state() is not None or any(manager.workspace_root.iterdir()):return JSONResponse({'detail':'workspace is not empty before seed'},status_code=409)
   fd,n=tempfile.mkstemp(prefix='.seed-',suffix='.tar',dir=manager.workspace_root);p=Path(n);total=0;digest=hashlib.sha256()
   try:
    with os.fdopen(fd,'wb') as h:
     async for c in r.stream():
      total+=len(c)
      if total>MAX:raise WorkspaceError('seed archive is too large')
      digest.update(c);h.write(c)
     h.flush();os.fsync(h.fileno())
    x=manager.seed_archive(p);return JSONResponse({'status':'seeded','archive_bytes':total,'sha256':digest.hexdigest(),**x})
   except WorkspaceError as e:return JSONResponse({'detail':str(e)},status_code=409)
   finally:p.unlink(missing_ok=True)
 async def control(r):
  if not auth(r):return JSONResponse({'detail':'unauthorized'},status_code=401)
  try:
   a=await body(r);op=r.path_params['operation'];x=await (manager.prepare(a) if op=='prepare' else manager.assert_resume(a) if op=='resume' else manager.reset(a) if op=='reset' else (_ for _ in ()).throw(WorkspaceError('not found')));return JSONResponse(x)
  except WorkspaceError as e:return JSONResponse({'detail':str(e)},status_code=409)
 @contextlib.asynccontextmanager
 async def life(app):
  try:
   async with sm.run():yield
  finally:
   if hasattr(manager,'shutdown'):await manager.shutdown()
 app=Starlette(routes=[Route('/healthz',health),Route('/manifest',mani),Route('/control/state',state),Route('/control/seed',seed,methods=['POST']),Route('/control/{operation}',control,methods=['POST']),Mount('/mcp',app=mcp)],lifespan=life);return CORSMiddleware(app,allow_origins=['https://chatgpt.com'],allow_methods=['GET','POST','DELETE'],expose_headers=['Mcp-Session-Id'])
def main():
 m=WorkspaceManagerV2(Path(os.environ.get('CODE_WORKSPACE_ROOT','/workspace')),Path(os.environ.get('CODE_WORKSPACE_STATE_ROOT','/state')),sandbox_uid=0,sandbox_gid=0,templates_root=Path(os.environ.get('CODE_WORKSPACE_TEMPLATES_ROOT','/app/templates')));verify(Path(os.environ.get('MCP_TOOL_MANIFEST','/app/tool-manifest.json')),m);hosts=[x.strip() for x in os.environ.get('MCP_ALLOWED_HOSTS','').split(',') if x.strip()]
 if not hosts:raise RuntimeError('MCP_ALLOWED_HOSTS must contain at least one exact host[:port]')
 import uvicorn;uvicorn.run(create_app(m,token(Path(os.environ.get('APP_CONTROL_TOKEN_FILE','/run/secrets/app_control_token'))),hosts),host='0.0.0.0',port=8000)
if __name__=='__main__':main()

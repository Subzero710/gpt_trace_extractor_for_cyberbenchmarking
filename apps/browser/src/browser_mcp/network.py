import base64,hashlib,tempfile,time,uuid,os
from pathlib import Path
class NetworkService:
 def __init__(self,r):self.r=r;self.console=[];self.logs=[];self.reqs={};self.resps={};self.ids={};self.tracing=set()
 def rid(self,q):
  k=id(q)
  if k not in self.ids:self.ids[k]=uuid.uuid4().hex
  return self.ids[k]
 def attach(self,c,cid):
  c.on('request',lambda q:self._req(q,cid));c.on('response',lambda x:self._resp(x,cid));c.on('page',lambda p:self.page(p,cid))
  for p in c.pages:self.page(p,cid)
 def page(self,p,cid):p.on('console',lambda m:self.console.append({'timestamp':time.time(),'context_id':cid,'page_id':self.r.pid(p),'type':m.type,'text':m.text}))
 def _req(self,q,cid):i=self.rid(q);self.reqs[i]={'request_id':i,'method':q.method,'url':q.url,'headers':q.headers,'post_data':q.post_data,'resource_type':q.resource_type};self.logs.append({'event':'request','request_id':i,'url':q.url,'method':q.method,'context_id':cid})
 def _resp(self,x,cid):i=self.rid(x.request);self.resps[i]=x;self.logs.append({'event':'response','request_id':i,'url':x.url,'status':x.status,'context_id':cid})
 async def console_logs(self,a):r=self.console[-a.get('limit',200):];self.console.clear() if a.get('clear') else None;return {'entries':r}
 async def network_logs(self,a):r=self.logs[-a.get('limit',200):];self.logs.clear() if a.get('clear') else None;return {'entries':r}
 async def details(self,a):
  if a['request_id'] not in self.reqs:raise self.r.error('unknown request_id')
  return {'request':self.reqs[a['request_id']]}
 async def body(self,a):
  x=self.resps.get(a['request_id'])
  if x is None:raise self.r.error('response is not available for request_id')
  d=await x.body();m=a.get('max_bytes',10485760);tr=len(d)>m;d=d[:m];return {'request_id':a['request_id'],'mime_type':x.headers.get('content-type'),'size':len(d),'sha256':hashlib.sha256(d).hexdigest(),'content_base64':base64.b64encode(d).decode(),'truncated':tr}
 async def trace(self,a):
  cid=self.r.cid(self.r.context)
  if a['action']=='start':await self.r.context.tracing.start(screenshots=a.get('screenshots',True),snapshots=a.get('snapshots',True),sources=a.get('sources',False));self.tracing.add(cid);return {'action':'start','active':True}
  if cid not in self.tracing:raise self.r.error('performance trace is not active')
  fd,n=tempfile.mkstemp(suffix='.zip',dir=self.r.state_root);os.close(fd);Path(n).unlink()
  try:
   await self.r.context.tracing.stop(path=n);p=Path(n);size=p.stat().st_size;limit=a.get('max_bytes',33554432)
   if size>limit:raise self.r.error('performance trace exceeds max_bytes')
   d=p.read_bytes();return {'action':'stop','active':False,'size':size,'sha256':hashlib.sha256(d).hexdigest(),'content_base64':base64.b64encode(d).decode()}
  finally:self.tracing.discard(cid);Path(n).unlink(missing_ok=True)

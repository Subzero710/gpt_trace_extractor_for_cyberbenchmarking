import asyncio,hashlib,socket,time,urllib.request,urllib.error
from urllib.parse import urlparse
class NetworkError(RuntimeError):pass
def url(v):
 p=urlparse(v)
 if p.scheme not in {'http','https'} or not p.hostname or p.username is not None:raise NetworkError('only credential-free HTTP and HTTPS URLs are allowed')
 return v
class NetworkService:
 def __init__(self,sandbox):self.sandbox=sandbox
 async def http(self,a):
  self.sandbox.ready();u=url(a['url']);lim=a.get('max_bytes',1048576)
  def f():
   q=urllib.request.Request(u,data=a.get('body').encode() if a.get('body') is not None else None,headers=a.get('headers',{}),method=a.get('method','GET'))
   try:r=urllib.request.urlopen(q,timeout=a.get('timeout_seconds',30))
   except urllib.error.HTTPError as e:r=e
   with r:d=r.read(lim+1);return r.geturl(),r.status,dict(r.headers.items()),d
  U,s,h,d=await asyncio.to_thread(f);return {'url':U,'status':s,'headers':h,'body':d[:lim].decode(errors='replace'),'size':min(len(d),lim),'truncated':len(d)>lim}
 async def download(self,a):
  self.sandbox.ready();p=self.sandbox.path(a['path']);
  if p.exists() and not a.get('overwrite'):raise NetworkError('download destination already exists')
  def f():
   with urllib.request.urlopen(url(a['url']),timeout=a.get('timeout_seconds',60)) as r:return r.geturl(),r.read(a.get('max_bytes',16777216)+1)
  u,d=await asyncio.to_thread(f);lim=a.get('max_bytes',16777216)
  if len(d)>lim:raise NetworkError('download exceeds max_bytes')
  self.sandbox.atomic_write(p,d);return {'url':u,'path':self.sandbox.rel(p),'size':len(d),'sha256':hashlib.sha256(d).hexdigest()}
 async def dns(self,a):
  fam={'any':socket.AF_UNSPEC,'ipv4':socket.AF_INET,'ipv6':socket.AF_INET6}[a.get('family','any')];r=await asyncio.to_thread(socket.getaddrinfo,a['hostname'],None,fam,socket.SOCK_STREAM);return {'hostname':a['hostname'],'addresses':sorted({x[4][0] for x in r})}
 async def port(self,a):
  t=time.perf_counter()
  try:r,w=await asyncio.wait_for(asyncio.open_connection(a['host'],a['port']),a.get('timeout_seconds',3));w.close();await w.wait_closed();o=True
  except (OSError,TimeoutError):o=False
  return {'host':a['host'],'port':a['port'],'open':o,'latency_ms':round((time.perf_counter()-t)*1000,3) if o else None}

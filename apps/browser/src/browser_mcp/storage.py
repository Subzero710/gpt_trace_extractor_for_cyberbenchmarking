import base64,hashlib,json
class StorageService:
 def __init__(self,r):self.r=r
 async def cookies(self,a):return {'cookies':await self.r.context.cookies(a.get('urls') or None)}
 async def set(self,a):
  c={'name':a['name'],'value':a['value'],'path':a.get('path','/'),'httpOnly':a.get('http_only',False),'secure':a.get('secure',False),'sameSite':a.get('same_site','Lax')};c['url']=a.get('url') or self.r.page.url
  if a.get('domain'):c.pop('url',None);c['domain']=a['domain']
  if a.get('expires') is not None:c['expires']=a['expires']
  await self.r.context.add_cookies([c]);return {'cookies':await self.r.context.cookies()}
 async def clear(self,a):await self.r.context.clear_cookies();return {'cookies':[]}
 async def export(self,a):
  s=await self.r.context.storage_state();raw=json.dumps(s,sort_keys=True,separators=(',',':')).encode();return {'content_base64':base64.b64encode(raw).decode(),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 async def import_(self,a):
  try:raw=base64.b64decode(a['content_base64'],validate=True);s=json.loads(raw)
  except Exception as e:raise self.r.error('invalid storage state') from e
  await self.r.context.add_cookies(s.get('cookies',[]))
  for o in s.get('origins',[]):await self.r.policy.validate_url(o['origin']);await self.r.page.goto(o['origin']);await self.r.page.evaluate("x=>{localStorage.clear();x.forEach(i=>localStorage.setItem(i.name,i.value))}",o.get('localStorage',[]))
  return {'content_base64':a['content_base64'],'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

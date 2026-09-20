import base64,hashlib,os,tempfile
from pathlib import Path
class InteractionService:
 def __init__(self,r):self.r=r
 async def hover(self,a):await self.r.page.locator(a['selector']).first.hover(timeout=a.get('timeout_ms',15000));return {'ok':True,**await self.r.info()}
 async def drag(self,a):await self.r.page.locator(a['source_selector']).first.drag_to(self.r.page.locator(a['target_selector']).first);return {'ok':True,**await self.r.info()}
 async def select(self,a):await self.r.page.locator(a['selector']).first.select_option(a['values']);return {'ok':True,**await self.r.info()}
 async def upload(self,a):
  try:d=base64.b64decode(a['content_base64'],validate=True)
  except Exception as e:raise self.r.error('invalid upload base64') from e
  if len(d)>64*1024*1024:raise self.r.error('upload exceeds 64 MiB')
  fd,n=tempfile.mkstemp(dir=self.r.state_root);os.close(fd);p=Path(n)
  try:p.write_bytes(d);await self.r.page.locator(a['selector']).first.set_input_files(str(p));return {'ok':True,**await self.r.info()}
  finally:p.unlink(missing_ok=True)
 async def download(self,a):
  async with self.r.page.expect_download() as x:await self.r.page.locator(a['selector']).first.click()
  item=await x.value;p=await item.path();d=Path(p).read_bytes();lim=a.get('max_bytes',10485760)
  if len(d)>lim:raise self.r.error('download exceeds max_bytes')
  return {'filename':item.suggested_filename,'size':len(d),'sha256':hashlib.sha256(d).hexdigest(),'content_base64':base64.b64encode(d).decode()}

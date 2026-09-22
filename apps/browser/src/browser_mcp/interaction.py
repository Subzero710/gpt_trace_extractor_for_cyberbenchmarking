import asyncio,base64,hashlib,os,tempfile,stat,shutil
from pathlib import Path
from .transfer import RelayClient,TransferError
class InteractionService:
 def __init__(self,r):
  self.r=r;self.relay=RelayClient();self.upload_root=Path(os.environ.get('APP_BROWSER_STATE_ROOT','/tmp'))/'relay-uploads';self.upload_root.mkdir(parents=True,exist_ok=True);self.upload_quota=int(os.environ.get('FILE_RELAY_BROWSER_UPLOAD_CACHE_BYTES','268435456'));self.upload_lock=asyncio.Lock()
 def _upload_usage(self):return sum(p.stat().st_size for p in self.upload_root.rglob('*') if p.is_file())
 async def cleanup_transfer_files(self):
  async with self.upload_lock:
   await asyncio.to_thread(shutil.rmtree,self.upload_root,True);self.upload_root.mkdir(parents=True,exist_ok=True)
 async def hover(self,a):await self.r.page.locator(a['selector']).first.hover(timeout=a.get('timeout_ms',15000));return {'ok':True,**await self.r.info()}
 async def drag(self,a):await self.r.page.locator(a['source_selector']).first.drag_to(self.r.page.locator(a['target_selector']).first);return {'ok':True,**await self.r.info()}
 async def select(self,a):await self.r.page.locator(a['selector']).first.select_option(a['values']);return {'ok':True,**await self.r.info()}
 async def upload(self,a):
  if a.get('file_id'):
   async with self.upload_lock:return await self._upload_relay(a)
  return await self._upload_inline(a)
 async def _upload_relay(self,a):
  before=self._upload_usage()
  if before>=self.upload_quota:raise self.r.error('browser relay upload cache quota exceeded')
  stage=Path(tempfile.mkdtemp(prefix='relay-',dir=self.upload_root));fd,name=tempfile.mkstemp(prefix='.partial-',dir=stage);committed=False
  try:
   meta=await self.relay.fetch_to_fd(a['file_id'],fd);await asyncio.to_thread(os.fsync,fd);os.close(fd);fd=-1
   if before+meta['size']>self.upload_quota:raise self.r.error('browser relay upload cache quota exceeded')
   final=stage/(Path(meta['name']).name or 'upload');os.replace(name,final);name=str(final)
   await self.r.page.locator(a['selector']).first.set_input_files(name);committed=True
   try:await self.relay.ack(a['file_id'])
   except TransferError:pass
   return {'ok':True,'filename':final.name,'mime_type':meta['media_type'],**await self.r.info()}
  finally:
   if fd>=0:os.close(fd)
   if not committed:await asyncio.to_thread(shutil.rmtree,stage,True)
 async def _upload_inline(self,a):
  try:d=base64.b64decode(a['content_base64'],validate=True)
  except Exception as e:raise self.r.error('invalid upload base64') from e
  if len(d)>64*1024*1024:raise self.r.error('upload exceeds 64 MiB')
  filename=Path(a['filename']).name
  if not filename or filename in {'.','..'}:raise self.r.error('invalid upload filename')
  payload={'name':filename,'mimeType':a.get('mime_type') or 'application/octet-stream','buffer':d}
  await self.r.page.locator(a['selector']).first.set_input_files(payload)
  return {'ok':True,'filename':filename,'mime_type':payload['mimeType'],**await self.r.info()}
 async def download(self,a):
  async with self.r.page.expect_download() as x:await self.r.page.locator(a['selector']).first.click()
  item=await x.value;p=await item.path()
  if not p:raise self.r.error('download has no local content')
  st=os.stat(p,follow_symlinks=False)
  if not stat.S_ISREG(st.st_mode):raise self.r.error('download is not a regular file')
  lim=a.get('max_bytes',134217728)
  if st.st_size>lim:raise self.r.error('download exceeds max_bytes')
  fd=os.open(p,os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0))
  try:
   digest=await __import__('browser_mcp.transfer',fromlist=['sha256_fd']).sha256_fd(fd)
   if a.get('legacy_inline'):
    if st.st_size>64*1024*1024:raise self.r.error('legacy inline download exceeds 64 MiB')
    def read_all():
     os.lseek(fd,0,os.SEEK_SET);parts=[]
     while True:
      chunk=os.read(fd,1024*1024)
      if not chunk:break
      parts.append(chunk)
     return b''.join(parts)
    d=await asyncio.to_thread(read_all)
    return {'filename':item.suggested_filename,'size':st.st_size,'sha256':digest,'content_base64':base64.b64encode(d).decode()}
   ref=await self.relay.publish_fd(fd,size=st.st_size,sha256=digest,name=Path(item.suggested_filename).name or 'download',media_type=a.get('media_type') or 'application/octet-stream',target='code-workspace')
   return {'file_id':ref['file_id'],'name':ref['name'],'size':ref['size'],'sha256':ref['sha256'],'media_type':ref['media_type']}
  finally:os.close(fd)

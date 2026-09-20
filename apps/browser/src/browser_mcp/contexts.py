import uuid
class ContextService:
 def __init__(self,r):self.r=r
 async def create(self,a):
  o={'viewport':{'width':a.get('viewport_width',1280),'height':a.get('viewport_height',720)}}
  for k in ('user_agent','locale','timezone_id'):
   if a.get(k):o[k]=a[k]
  c=await self.r.browser.new_context(**o);cid='ctx-'+uuid.uuid4().hex[:16];await self.r.configure_context(c,cid);p=await c.new_page();self.r.register(p);self.r.context=c;self.r.page=p;return {'context_id':cid,'active':True,'page_id':self.r.pid(p)}
 async def destroy(self,a):
  if a['context_id']=='default':raise self.r.error('default context cannot be destroyed')
  c=self.r.ctx(a['context_id']);await c.close();self.r.contexts.pop(a['context_id']);self.r.context=self.r.contexts['default'];self.r.ensure_page();return {'context_id':a['context_id'],'active':False,'page_id':None}

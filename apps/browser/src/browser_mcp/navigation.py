class NavigationService:
 def __init__(self,r):self.r=r
 async def back(self,a):p=self.r.page_from(a.get('page_id'));await p.go_back(wait_until='domcontentloaded');return await self.r.info(p)
 async def forward(self,a):p=self.r.page_from(a.get('page_id'));await p.go_forward(wait_until='domcontentloaded');return await self.r.info(p)
 async def reload(self,a):p=self.r.page_from(a.get('page_id'));await p.reload(wait_until=a.get('wait_until','domcontentloaded'));return await self.r.info(p)
 async def new(self,a):
  c=self.r.ctx(a.get('context_id')) if a.get('context_id') else self.r.context;p=await c.new_page();self.r.register(p);self.r.page=p;self.r.context=c
  if a.get('url'):await self.r.policy.validate_url(a['url']);await p.goto(a['url'])
  return await self.r.info(p)
 async def switch(self,a):p=self.r.page_by(a['page_id']);self.r.page=p;self.r.context=p.context;await p.bring_to_front();return await self.r.info(p)
 async def close(self,a):
  p=self.r.page_from(a.get('page_id'));await p.close();self.r.unregister(p);self.r.ensure_page();return {'active_page_id':self.r.pid(self.r.page),'pages':[await self.r.info(x) for x in self.r.pages.values() if not x.is_closed()]}

class DomService:
 def __init__(self,r):self.r=r
 async def inspect(self,a):
  q=a.get('selector','html');rows=await self.r.page.locator(q).first.evaluate("""(el,lim)=>Array.from(el.querySelectorAll('*')).slice(0,lim).map((x,i)=>({tag:x.tagName.toLowerCase(),text:(x.childElementCount? '':x.textContent||'').trim().slice(0,1000),attributes:Object.fromEntries(Array.from(x.attributes).map(a=>[a.name,a.value.slice(0,1000)]))}))""",a.get('max_nodes',1000));return {'selector':q,'nodes':rows,'truncated':len(rows)>=a.get('max_nodes',1000)}
 async def query(self,a):
  l=self.r.page.locator(a['selector']);n=await l.count();return {'selector':a['selector'],'count':n,'matches':[{'index':i,'visible':await l.nth(i).is_visible(),'text':(await l.nth(i).inner_text())[:2000]} for i in range(min(n,100))]}
 async def html(self,a):
  h=await (self.r.page.locator(a['selector']).first.evaluate('el=>el.outerHTML') if a.get('selector') else self.r.page.content());m=a.get('max_chars',1000000);return {'html':h[:m],'truncated':len(h)>m}
 async def attr(self,a):return {'selector':a['selector'],'name':a['name'],'value':await self.r.page.locator(a['selector']).first.get_attribute(a['name'])}
 async def eval(self,a):return {'result':await self.r.page.evaluate(a['expression'],a.get('argument'))}

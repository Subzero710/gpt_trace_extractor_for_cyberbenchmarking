class DeviceService:
 def __init__(self,r):self.r=r;self.settings={}
 async def cdp(self):return await self.r.context.new_cdp_session(self.r.page)
 async def ua(self,a):s=await self.cdp();await s.send('Network.setUserAgentOverride',{'userAgent':a['user_agent']});self.settings['user_agent']=a['user_agent'];return {'ok':True,'settings':self.settings}
 async def viewport(self,a):await self.r.page.set_viewport_size({'width':a['width'],'height':a['height']});self.settings['viewport']={'width':a['width'],'height':a['height']};return {'ok':True,'settings':self.settings}
 async def timezone(self,a):s=await self.cdp();await s.send('Emulation.setTimezoneOverride',{'timezoneId':a['timezone_id']});self.settings['timezone_id']=a['timezone_id'];return {'ok':True,'settings':self.settings}
 async def geo(self,a):g={'latitude':a['latitude'],'longitude':a['longitude'],'accuracy':a.get('accuracy',0)};await self.r.context.set_geolocation(g);self.settings['geolocation']=g;return {'ok':True,'settings':self.settings}

import os,platform,re,shutil
from pathlib import Path
class SystemError(RuntimeError):pass
R=re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
class SystemService:
 def __init__(self,root,env,ready):self.root=root;self.env=env;self.ready=ready
 def info(self,a):
  self.ready();m={x.split()[0]:int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith(('MemTotal:','MemAvailable:'))};d=shutil.disk_usage(self.root);return {'os':{'system':platform.system(),'release':platform.release(),'version':platform.version()},'architecture':platform.machine(),'cpu':{'count':os.cpu_count() or 1,'model':platform.processor()},'ram':{'total':m['MemTotal:'],'available':m['MemAvailable:'],'used':m['MemTotal:']-m['MemAvailable:']},'disk':{'total':d.total,'used':d.used,'free':d.free},'cwd':'.'}
 def get_env(self,a):self.ready();return {'environment':dict(sorted(self.env.items()))}
 def set_env(self,a):
  self.ready()
  for k,v in a.get('values',{}).items():
   if not R.fullmatch(k) or '\0' in v:raise SystemError('invalid environment variable')
   self.env[k]=v
  for k in a.get('unset',[]):self.env.pop(k,None)
  return self.get_env({})
 def cwd(self,a):self.ready();return {'cwd':'.','absolute_path':str(self.root)}

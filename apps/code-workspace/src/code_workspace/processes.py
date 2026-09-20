from __future__ import annotations
import os,signal,time
from pathlib import Path
class ProcessError(RuntimeError):pass
class ProcessService:
 def __init__(self,uid,ready):self.uid=uid;self.ready=ready
 def one(self,pid):
  p=Path('/proc')/str(pid)
  try:
   if p.stat().st_uid!=self.uid:raise ProcessError('process is outside sandbox user')
   f=(p/'stat').read_text().split();boot=float(next(x.split()[1] for x in Path('/proc/stat').read_text().splitlines() if x.startswith('btime ')));start=boot+int(f[21])/os.sysconf('SC_CLK_TCK');cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace').strip() or f[1]
   return {'pid':pid,'command':cmd,'status':f[2],'start_time':start,'runtime':max(0,time.time()-start)}
  except FileNotFoundError as e:raise ProcessError('process does not exist') from e
 def list(self,a):self.ready();return {'processes':[x for p in Path('/proc').iterdir() if p.name.isdigit() for x in [self._safe(int(p.name))] if x]}
 def _safe(self,p):
  try:return self.one(p)
  except ProcessError:return None
 def get(self,a):self.ready();return self.one(a['pid'])
 def kill(self,a):self.ready();r=self.one(a['pid']);os.kill(a['pid'],{'TERM':signal.SIGTERM,'KILL':signal.SIGKILL,'INT':signal.SIGINT,'HUP':signal.SIGHUP}[a.get('signal','TERM')]);r['status']='signal-sent';return r

import re,sys
class RuntimeErrorMCP(RuntimeError):pass
class RuntimeService:
 def __init__(self,sandbox,shell):self.sandbox=sandbox;self.shell=shell
 async def venv(self,a):self.sandbox.ready();p=self.sandbox.path(a.get('path','.venv'));return await self.shell.run([sys.executable,'-m','venv',str(p)],self.sandbox.root,300)
 async def pip(self,a):
  self.sandbox.ready();p=self.sandbox.path(a.get('venv_path','.venv'),True)/'bin/python';pk=a['packages'];
  if any(x.startswith('-') or '\0' in x for x in pk):raise RuntimeErrorMCP('invalid Python package specifier')
  return await self.shell.run([str(p),'-m','pip','install',*(['--upgrade'] if a.get('upgrade') else []),*pk],self.sandbox.root,a.get('timeout_seconds',600))
 async def python(self,a):
  self.sandbox.ready();script=self.sandbox.path(a['path'],True);cwd=self.sandbox.path(a.get('cwd','.'),True,True);v=a.get('venv_path','.venv');py=sys.executable if v is None else str(self.sandbox.path(v,True)/'bin/python');return await self.shell.run([py,str(script),*a.get('args',[])],cwd,a.get('timeout_seconds',120))
 async def apt(self,a):
  self.sandbox.ready();pk=a['packages']
  if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*',x) for x in pk):raise RuntimeErrorMCP('invalid Debian package name')
  t=a.get('timeout_seconds',900)
  if a.get('update_index',True):
   r=await self.shell.run(['apt-get','update'],self.sandbox.root,t,True,env={'DEBIAN_FRONTEND':'noninteractive'})
   if r['exit_code']:return r
  return await self.shell.run(['apt-get','install','-y','--no-install-recommends',*pk],self.sandbox.root,t,True,env={'DEBIAN_FRONTEND':'noninteractive'})

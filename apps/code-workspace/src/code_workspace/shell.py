from __future__ import annotations
import asyncio,os,resource,signal,uuid
from dataclasses import dataclass,field
from pathlib import Path
class ShellError(RuntimeError):pass
@dataclass(slots=True)
class Terminal: id:str;proc:asyncio.subprocess.Process;cwd:Path;out:bytearray=field(default_factory=bytearray);err:bytearray=field(default_factory=bytearray);tasks:list=field(default_factory=list)
class ShellService:
 def __init__(self,sandbox,uid,gid):self.sandbox=sandbox;self.uid=uid;self.gid=gid;self.env={'PATH':'/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin','HOME':'/root' if uid==0 else str(sandbox.root),'TMPDIR':'/tmp','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'};self.terminals={}
 def preexec(self):
  os.setsid();resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256));os.umask(0o077)
  if os.geteuid()==0 and (self.uid or self.gid):os.setgroups([]);os.setgid(self.gid);os.setuid(self.uid)
 async def _kill(self,pid,sig):
  try:os.killpg(pid,sig)
  except ProcessLookupError:pass
 async def run(self,argv,cwd,timeout=120,privileged=False,shell=False,env=None):
  kw={'cwd':cwd,'env':{**self.env,**(env or {})},'stdout':asyncio.subprocess.PIPE,'stderr':asyncio.subprocess.PIPE}
  if not privileged:kw['preexec_fn']=self.preexec
  elif os.geteuid()!=0:raise ShellError('privileged command requires root control service')
  p=await (asyncio.create_subprocess_shell(argv,executable='/bin/bash',**kw) if shell else asyncio.create_subprocess_exec(*argv,**kw));timed=False
  try:o,e=await asyncio.wait_for(p.communicate(),timeout)
  except TimeoutError:
   timed=True;(p.kill() if privileged else await self._kill(p.pid,signal.SIGKILL));o,e=await p.communicate()
  finally:
   if not privileged:await self._kill(p.pid,signal.SIGKILL)
  lim=4*1024*1024;return {'command':argv,'cwd':self.sandbox.rel(cwd),'stdout':o[:lim].decode(errors='replace'),'stderr':e[:lim].decode(errors='replace'),'exit_code':p.returncode,'timed_out':timed,'stdout_truncated':len(o)>lim,'stderr_truncated':len(e)>lim}
 async def exec(self,a):
  self.sandbox.ready();cmd=a.get('command');cwd=self.sandbox.path(a.get('cwd','.'),True,True);t=a.get('timeout_seconds',120)
  if not isinstance(cmd,str) or not cmd or '\0' in cmd:raise ShellError('command must be a non-empty string')
  return await self.run(cmd,cwd,t,shell=True)
 async def _pump(self,stream,buf):
  while c:=await stream.read(65536):
   buf.extend(c)
   if len(buf)>4*1024*1024:del buf[:-4*1024*1024]
 async def create(self,a):
  self.sandbox.ready();cwd=self.sandbox.path(a.get('cwd','.'),True,True);p=await asyncio.create_subprocess_exec('/bin/bash','--noprofile','--norc',cwd=cwd,env={**self.env,**a.get('environment',{})},stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,preexec_fn=self.preexec);tid=uuid.uuid4().hex;t=Terminal(tid,p,cwd);self.terminals[tid]=t;t.tasks=[asyncio.create_task(self._pump(p.stdout,t.out)),asyncio.create_task(self._pump(p.stderr,t.err))];return {'terminal_id':tid,'pid':p.pid,'cwd':self.sandbox.rel(cwd),'status':'running'}
 def _t(self,i):
  if i not in self.terminals:raise ShellError('unknown terminal_id')
  return self.terminals[i]
 async def send(self,a):
  t=self._t(a['terminal_id']);data=a['input'];t.proc.stdin.write(data.encode()+b'\n');await t.proc.stdin.drain();return {'terminal_id':t.id,'pid':t.proc.pid,'cwd':self.sandbox.rel(t.cwd),'status':'running'}
 async def read(self,a):
  t=self._t(a['terminal_id']);await asyncio.sleep(a.get('wait_seconds',0));n=a.get('max_bytes',262144);o=bytes(t.out[:n]);e=bytes(t.err[:n]);del t.out[:len(o)];del t.err[:len(e)];return {'terminal_id':t.id,'pid':t.proc.pid,'cwd':self.sandbox.rel(t.cwd),'status':'running' if t.proc.returncode is None else 'exited','stdout':o.decode(errors='replace'),'stderr':e.decode(errors='replace'),'stdout_truncated':False,'stderr_truncated':False,'exit_code':t.proc.returncode}
 async def close(self,a):
  t=self._t(a['terminal_id']);
  if t.proc.returncode is None:await self._kill(t.proc.pid,signal.SIGKILL if a.get('force') else signal.SIGTERM);await t.proc.wait()
  for x in t.tasks:x.cancel()
  await asyncio.gather(*t.tasks,return_exceptions=True);self.terminals.pop(t.id,None);return {'terminal_id':t.id,'pid':t.proc.pid,'cwd':self.sandbox.rel(t.cwd),'status':'closed','exit_code':t.proc.returncode}
 async def close_all(self):
  for i in list(self.terminals):
   try:await self.close({'terminal_id':i,'force':True})
   except Exception:self.terminals.pop(i,None)

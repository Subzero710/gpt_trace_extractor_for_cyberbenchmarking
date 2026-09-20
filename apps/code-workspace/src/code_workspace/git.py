class GitError(RuntimeError):pass
class GitService:
 def __init__(self,sandbox,shell):self.sandbox=sandbox;self.shell=shell
 def cwd(self,a):return self.sandbox.path(a.get('cwd','.'),True,True)
 async def g(self,x,c,t=120):return await self.shell.run(['git',*x],c,t)
 async def clone(self,a):
  d=self.sandbox.path(a['destination']);x=['clone'];x+=['--branch',a['branch']] if a.get('branch') else [];x+=['--depth',str(a['depth'])] if a.get('depth') else [];x+=['--',a['repository'],str(d)];return await self.g(x,self.sandbox.root,600)
 async def status(self,a):return await self.g(['status','--porcelain=v1','--branch'],self.cwd(a))
 async def diff(self,a):return await self.g(['diff',*(['--cached'] if a.get('staged') else []),*(['--',*a['pathspec']] if a.get('pathspec') else [])],self.cwd(a))
 async def log(self,a):return await self.g(['log',f'--max-count={a.get("max_count",20)}','--pretty=format:%H%x09%an%x09%ae%x09%ad%x09%s'],self.cwd(a))
 async def branch(self,a):return await self.g(['branch',*(['-D',a['name']] if a.get('delete') else [a['name']] if a.get('name') else [])],self.cwd(a))
 async def checkout(self,a):return await self.g(['checkout',*(['-b'] if a.get('create') else []),a['ref']],self.cwd(a))
 async def commit(self,a):
  c=self.cwd(a)
  if a.get('all'):
   r=await self.g(['add','-A'],c)
   if r['exit_code']:return r
  return await self.g(['-c',f'user.name={a.get("author_name","MCP Agent")}', '-c',f'user.email={a.get("author_email","mcp-agent@localhost")}', 'commit','-m',a['message']],c)

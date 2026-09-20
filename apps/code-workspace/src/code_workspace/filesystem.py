from __future__ import annotations
import fnmatch, hashlib, os, shutil, stat, tempfile
from pathlib import Path
from typing import Any, Callable
class FilesystemError(RuntimeError): pass
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
class WorkspaceSandbox:
 def __init__(self,root:Path,uid:int,gid:int,ready:Callable[[],None]):self.root=root.resolve();self.uid=uid;self.gid=gid;self.ready=ready;self.root.mkdir(parents=True,exist_ok=True)
 def path(self,value:object,must_exist=False,allow_root=False)->Path:
  if allow_root and value in {'','.'}:return self.root
  if not isinstance(value,str):raise FilesystemError('path must be a string')
  if not value or '\0' in value:raise FilesystemError('path must be a non-empty relative path')
  rel=Path(value)
  if rel.is_absolute() or '..' in rel.parts:raise FilesystemError('path escapes the task workspace')
  cur=self.root
  for part in rel.parts:
   cur/=part
   if cur.is_symlink():raise FilesystemError('symlinks are not accepted for workspace file operations')
   if not cur.exists():break
  try:p=(self.root/rel).resolve(strict=False);p.relative_to(self.root)
  except (OSError,ValueError) as e:raise FilesystemError('path escapes the task workspace') from e
  if must_exist and not p.exists():raise FilesystemError(f'workspace path does not exist: {rel.as_posix()}')
  return p
 def rel(self,p:Path)->str:return p.relative_to(self.root).as_posix() or '.'
 def _chown(self,p:Path):
  if os.geteuid()==0:os.chown(p,self.uid,self.gid,follow_symlinks=False)
 def _parent(self,p:Path):
  p.mkdir(parents=True,exist_ok=True);cur=p
  while True:
   if cur.is_symlink():raise FilesystemError('symlink parent is not accepted')
   os.chmod(cur,0o770);self._chown(cur)
   if cur==self.root:break
   cur=cur.parent
 def atomic_write(self,p:Path,data:bytes):
  if len(data)>16*1024*1024:raise FilesystemError('file exceeds 16777216 bytes')
  self._parent(p.parent);fd,name=tempfile.mkstemp(prefix='.'+p.name+'-',dir=p.parent);tmp=Path(name)
  try:
   with os.fdopen(fd,'wb') as h:h.write(data);h.flush();os.fsync(h.fileno())
   os.chmod(tmp,0o660);self._chown(tmp);os.replace(tmp,p)
  finally:tmp.unlink(missing_ok=True)
 def _tree_safe(self,p:Path):
  for base,dirs,files in os.walk(p,followlinks=False):
   for n in [*dirs,*files]:
    if (Path(base)/n).is_symlink():raise FilesystemError('workspace tree contains a symlink')
 def delete_file(self,a):self.ready();p=self.path(a['path'],True);r=self.rel(p);(p.unlink() if p.is_file() else (_ for _ in ()).throw(FilesystemError('target is not a regular file')));return {'ok':True,'path':r}
 def delete_directory(self,a):
  self.ready();p=self.path(a['path'],True);r=self.rel(p)
  if p==self.root or not p.is_dir():raise FilesystemError('target is not a deletable directory')
  if a.get('recursive'):self._tree_safe(p);shutil.rmtree(p)
  else:p.rmdir()
  return {'ok':True,'path':r}
 def move(self,a):
  self.ready();s=self.path(a['source'],True);d=self.path(a['destination'])
  if s==self.root or d==self.root:raise FilesystemError('workspace root cannot be moved or replaced')
  if s.is_dir():self._tree_safe(s)
  if d.exists():
   if not a.get('overwrite'):raise FilesystemError('destination already exists')
   shutil.rmtree(d) if d.is_dir() else d.unlink()
  self._parent(d.parent);sr=self.rel(s);shutil.move(str(s),str(d));return {'ok':True,'source':sr,'destination':self.rel(d)}
 def copy(self,a):
  self.ready();s=self.path(a['source'],True);d=self.path(a['destination'])
  if s==self.root or d==self.root:raise FilesystemError('workspace root cannot be copied or replaced')
  if s.is_dir():self._tree_safe(s)
  if d.exists():
   if not a.get('overwrite'):raise FilesystemError('destination already exists')
   shutil.rmtree(d) if d.is_dir() else d.unlink()
  self._parent(d.parent);shutil.copytree(s,d) if s.is_dir() else shutil.copy2(s,d);return {'ok':True,'source':self.rel(s),'destination':self.rel(d)}
 def mkdir(self,a):self.ready();p=self.path(a['path']);p.mkdir(parents=a.get('parents',True),exist_ok=a.get('exist_ok',True));os.chmod(p,0o770);self._chown(p);return {'ok':True,'path':self.rel(p)}
 def stat(self,a):
  self.ready();p=self.path(a['path'],True);st=p.lstat();kind='directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other';return {'path':self.rel(p),'type':kind,'size':st.st_size if kind=='file' else None,'mode':oct(stat.S_IMODE(st.st_mode)),'mtime':st.st_mtime,'sha256':sha(p.read_bytes()) if kind=='file' and st.st_size<=16*1024*1024 else None}
 def tree(self,a):
  self.ready();root=self.path(a.get('path','.'),True,True);limit=a.get('max_entries',2000);depth=a.get('max_depth',8);rows=[]
  for base,dirs,files in os.walk(root,followlinks=False):
   b=Path(base);d=len(b.relative_to(root).parts);dirs[:]=sorted(dirs) if d<depth else []
   for n in [*sorted(dirs),*sorted(files)]:
    p=b/n;st=p.lstat();kind='symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if p.is_dir() else 'file' if p.is_file() else 'other';rows.append({'path':self.rel(p),'type':kind,'size':st.st_size if kind=='file' else None,'depth':len(p.relative_to(root).parts)})
    if len(rows)>=limit:return {'path':self.rel(root),'entries':rows,'truncated':True}
  return {'path':self.rel(root),'entries':rows,'truncated':False}
 def find(self,a):
  self.ready();root=self.path(a.get('path','.'),True,True);rows=[];limit=a.get('max_results',1000);wanted=a.get('type','any')
  for base,dirs,files in os.walk(root,followlinks=False):
   for n in [*sorted(dirs),*sorted(files)]:
    if not fnmatch.fnmatch(n,a.get('name','*')):continue
    p=Path(base)/n;kind='symlink' if p.is_symlink() else 'directory' if p.is_dir() else 'file' if p.is_file() else 'other'
    if wanted!='any' and kind!=wanted:continue
    rows.append({'path':self.rel(p),'type':kind,'size':p.stat().st_size if kind=='file' else None})
    if len(rows)>=limit:return {'path':self.rel(root),'entries':rows,'truncated':True}
  return {'path':self.rel(root),'entries':rows,'truncated':False}

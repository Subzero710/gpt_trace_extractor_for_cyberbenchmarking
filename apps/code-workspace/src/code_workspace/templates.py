import hashlib,json,os,shutil,stat
from pathlib import Path
class TemplateError(RuntimeError):pass
def hash_template(root):
 h=hashlib.sha256()
 for base,dirs,files in os.walk(root,followlinks=False):
  dirs.sort();files.sort();b=Path(base)
  for n in [*dirs,*files]:
   p=b/n;r=p.relative_to(root).as_posix();m=p.lstat().st_mode
   if stat.S_ISLNK(m):raise TemplateError('templates must not contain symlinks')
   if p.is_dir():h.update(b'd\0'+r.encode()+b'\0')
   elif p.is_file():d=p.read_bytes();h.update(b'f\0'+r.encode()+b'\0'+str(len(d)).encode()+b'\0'+d+b'\0')
   else:raise TemplateError('unsupported template entry')
 return h.hexdigest()
class TemplateManager:
 def __init__(self,root,workspace,uid,gid):self.root=Path(root).resolve();self.workspace=Path(workspace).resolve();self.uid=uid;self.gid=gid;self.items=self._load()
 def _load(self):
  raw=json.loads((self.root/'manifest.json').read_text());out={}
  if raw.get('schema_version')!=1:raise TemplateError('invalid workspace template manifest')
  for x in raw.get('templates',[]):
   if set(x)!={'id','version','description','hash'} or hash_template(self.root/x['id'])!=x['hash']:raise TemplateError(f'workspace template hash mismatch: {x.get("id")}')
   out[x['id']]=x
  return out
 def entries(self):return [dict(x) for x in self.items.values()]
 def provenance(self,i):
  if i not in self.items:raise TemplateError(f'unknown workspace template: {i}')
  x=self.items[i];return {'template_id':i,'template_version':x['version'],'template_hash':x['hash']}
 def verify(self,r):
  p=self.provenance(r.get('template_id','empty'))
  for k in ('template_version','template_hash'):
   if r.get(k) is not None and r[k]!=p[k]:raise TemplateError(f'workspace template {k} mismatch')
  return p
 def apply(self,r):
  p=self.verify(r);src=self.root/p['template_id']
  for base,dirs,files in os.walk(src,followlinks=False):
   b=Path(base);dst=self.workspace/b.relative_to(src);dst.mkdir(parents=True,exist_ok=True);os.chmod(dst,0o770)
   if os.geteuid()==0:os.chown(dst,self.uid,self.gid)
   for n in files:
    if n=='.gitkeep':continue
    s=b/n;d=dst/n
    if d.exists():raise TemplateError(f'template path collision: {d.relative_to(self.workspace)}')
    shutil.copyfile(s,d);os.chmod(d,0o770 if s.stat().st_mode&0o111 else 0o660)
    if os.geteuid()==0:os.chown(d,self.uid,self.gid)
  return p

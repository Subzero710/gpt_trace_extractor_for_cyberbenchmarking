from __future__ import annotations
import hashlib
import asyncio
import http.client
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from pathlib import Path

class TransferError(RuntimeError): pass


def _write_all(fd: int, data: bytes, writer=None) -> None:
    write = os.write if writer is None else writer
    view = memoryview(data)
    while view:
        written = write(fd, view)
        if not isinstance(written, int) or written <= 0 or written > len(view):
            raise TransferError("FILE_TRANSFER_WRITE_ERROR")
        view = view[written:]


async def sha256_fd(fd:int)->str:
    def work():
        os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256()
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk:break
            h.update(chunk)
        return h.hexdigest()
    return await asyncio.to_thread(work)

class RelayClient:
    def __init__(self):
        self.base=os.environ.get("FILE_RELAY_URL","").rstrip("/")
        self.token=os.environ.get("FILE_RELAY_TOKEN","")
        self.app=os.environ.get("FILE_RELAY_APP_ID","")
        self.max_file=int(os.environ.get("FILE_RELAY_MAX_FILE_BYTES","134217728"))
        if self.base:
            p=urlparse(self.base)
            if p.scheme!="http" or not p.hostname or p.query or p.fragment:
                raise RuntimeError("FILE_RELAY_URL must be an internal http URL")
            self.host=p.hostname; self.port=p.port or 80; self.prefix=p.path.rstrip("/")
        else:self.host="";self.port=0;self.prefix=""

    @property
    def enabled(self): return bool(self.base and self.token and self.app)

    def _conn(self):
        if not self.enabled: raise TransferError("FILE_TRANSFER_UNAVAILABLE: relay is not configured")
        return http.client.HTTPConnection(self.host,self.port,timeout=120)

    async def publish_fd(self, fd: int, *, size: int, sha256: str, name: str, media_type: str, target: str):
        if size > self.max_file: raise TransferError("FILE_TOO_LARGE")
        return await asyncio.to_thread(self._publish_fd_sync,fd,size=size,sha256=sha256,name=name,media_type=media_type,target=target)

    def _publish_fd_sync(self,fd: int,*,size:int,sha256:str,name:str,media_type:str,target:str):
        c=self._conn()
        try:
            import base64,json
            meta=base64.urlsafe_b64encode(json.dumps({"name":name,"media_type":media_type},ensure_ascii=False,separators=(",",":" )).encode()).decode().rstrip("=")
            if len(meta)>4096:raise TransferError("FILE_TRANSFER_METADATA_TOO_LARGE")
            headers={"Authorization":f"Bearer {self.token}","X-Target-App":target,
                     "X-File-Metadata":meta,"X-Content-SHA256":sha256,
                     "Content-Type":"application/octet-stream","Content-Length":str(size)}
            c.putrequest("POST",self.prefix+"/v1/files")
            for k,v in headers.items(): c.putheader(k,v)
            c.endheaders();os.lseek(fd,0,os.SEEK_SET)
            while True:
                chunk=os.read(fd,1024*1024)
                if not chunk:break
                c.send(chunk)
            r=c.getresponse();body=r.read()
            if r.status != 201:raise TransferError(_relay_error(body,r.status))
            return json.loads(body)
        finally:c.close()

    async def fetch_to_fd(self,file_id: str,fd: int):
        return await asyncio.to_thread(self._fetch_to_fd_sync,file_id,fd)

    def _fetch_to_fd_sync(self,file_id: str,fd: int):
        c=self._conn()
        try:
            c.request("GET",self.prefix+"/v1/files/"+file_id,headers={"Authorization":f"Bearer {self.token}"})
            r=c.getresponse()
            if r.status != 200:
                body=r.read();raise TransferError(_relay_error(body,r.status))
            expected=r.getheader("x-content-sha256","");expected_size=int(r.getheader("x-content-size","-1"));h=hashlib.sha256();size=0
            while True:
                chunk=r.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>self.max_file:raise TransferError("FILE_TOO_LARGE")
                h.update(chunk);_write_all(fd,chunk)
            if size!=expected_size or h.hexdigest()!=expected:raise TransferError("FILE_TRANSFER_INTEGRITY_ERROR")
            import base64,json
            raw=r.getheader("x-file-metadata","");pad="="*((4-len(raw)%4)%4);meta=json.loads(base64.urlsafe_b64decode(raw+pad))
            return {"file_id":file_id,"name":meta.get("name","file"),"media_type":meta.get("media_type","application/octet-stream"),"size":size,"sha256":h.hexdigest()}
        finally:c.close()

    async def ack(self,file_id: str):
        return await asyncio.to_thread(self._ack_sync,file_id)

    def _ack_sync(self,file_id: str):
        c=self._conn()
        try:
            c.request("POST",self.prefix+"/v1/files/"+file_id+"/ack",headers={"Authorization":f"Bearer {self.token}","Content-Length":"0"})
            r=c.getresponse();body=r.read()
            if r.status != 200:raise TransferError(_relay_error(body,r.status))
        finally:c.close()

def secure_open_export(root: Path, relative: str) -> tuple[int,str]:
    import ctypes,errno,platform
    rel=Path(relative)
    if rel.is_absolute() or not rel.parts or '..' in rel.parts:raise TransferError('FILE_TRANSFER_PATH_INVALID')
    rootfd=os.open(root,os.O_PATH|os.O_DIRECTORY)
    try:
        class OpenHow(ctypes.Structure):_fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
        libc=ctypes.CDLL(None,use_errno=True);SYS_OPENAT2=437;RESOLVE_NO_SYMLINKS=0x04;RESOLVE_BENEATH=0x08
        how=OpenHow(os.O_RDONLY|getattr(os,'O_CLOEXEC',0),0,RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)
        fd=libc.syscall(SYS_OPENAT2,rootfd,os.fsencode(rel.as_posix()),ctypes.byref(how),ctypes.sizeof(how))
        if fd<0:raise TransferError(f'FILE_TRANSFER_PATH_INVALID:{os.strerror(ctypes.get_errno())}')
        return fd,rel.name
    finally:os.close(rootfd)

def secure_import_target(root: Path, relative: str, sandbox_uid: int, sandbox_gid: int):
    rel=Path(relative)
    if rel.is_absolute() or not rel.parts or '..' in rel.parts:raise TransferError('FILE_TRANSFER_PATH_INVALID')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in rel.parts[:-1]:
            created=False
            try:os.mkdir(part,0o770,dir_fd=fd);created=True
            except FileExistsError:pass
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0),dir_fd=fd)
            if created:
                os.fchmod(nxt,0o770)
                if os.geteuid()==0:os.fchown(nxt,sandbox_uid,sandbox_gid)
            os.close(fd);fd=nxt
        return fd,rel.name
    except BaseException:os.close(fd);raise

def commit_import(dirfd:int,tmp_name:str,dest_name:str,overwrite:bool):
    import ctypes,errno
    if overwrite:
        os.replace(tmp_name,dest_name,src_dir_fd=dirfd,dst_dir_fd=dirfd);return
    libc=ctypes.CDLL(None,use_errno=True)
    fn=getattr(libc,'renameat2',None)
    if fn is None:raise TransferError('FILE_TRANSFER_NOREPLACE_UNAVAILABLE')
    rc=fn(dirfd,os.fsencode(tmp_name),dirfd,os.fsencode(dest_name),1)
    if rc!=0:
        e=ctypes.get_errno()
        if e==errno.EEXIST:raise TransferError('DESTINATION_EXISTS')
        raise TransferError(f'FILE_TRANSFER_COMMIT_ERROR:{os.strerror(e)}')

def _relay_error(body: bytes,status: int):
    try:return __import__("json").loads(body)["error"]["code"]
    except Exception:return f"FILE_TRANSFER_UNAVAILABLE: HTTP {status}"

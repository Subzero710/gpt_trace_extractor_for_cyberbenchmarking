from __future__ import annotations
import asyncio
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from .models import Identity, Limits, ObjectState

class RelayError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message); self.code=code; self.status=status

class Store:
    def __init__(self, root: Path, limits: Limits):
        self.root=root
        self.objects=root/"objects"
        self.db_path=root/"relay.sqlite3"
        self.limits=limits
        self.upload_sem=asyncio.Semaphore(limits.max_concurrent_uploads)
        self.download_sem=asyncio.Semaphore(limits.max_concurrent_downloads)
        self.root.mkdir(parents=True,exist_ok=True)
        self.objects.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS objects("
          "file_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, attempt INTEGER NOT NULL,"
          "source_app TEXT NOT NULL, target_app TEXT NOT NULL, display_name TEXT NOT NULL,"
          "media_type TEXT NOT NULL, size INTEGER, sha256 TEXT, created_at REAL NOT NULL,"
          "expires_at REAL NOT NULL, state TEXT NOT NULL, delivered_at REAL, acked_at REAL)")
        self.db.commit()
        self.reconcile()

    def close(self): self.db.close()

    def reconcile(self):
        now=time.time()
        for p in self.objects.glob("*.partial"): p.unlink(missing_ok=True)
        rows=self.db.execute("SELECT file_id,state,expires_at FROM objects").fetchall()
        for row in rows:
            fid=row["file_id"]; blob=self.objects/f"{fid}.blob"
            if row["expires_at"] <= now:
                blob.unlink(missing_ok=True)
                self.db.execute("UPDATE objects SET state=? WHERE file_id=?",(ObjectState.EXPIRED,fid))
            elif row["state"] in (ObjectState.READY,ObjectState.DELIVERED) and not blob.is_file():
                self.db.execute("DELETE FROM objects WHERE file_id=?",(fid,))
            elif row["state"] == ObjectState.CREATING:
                self.db.execute("DELETE FROM objects WHERE file_id=?",(fid,))
        self.db.commit()

    def _usage(self):
        now=time.time()
        expired=self.db.execute("SELECT file_id FROM objects WHERE expires_at<=? AND state IN (?,?)",(now,ObjectState.READY,ObjectState.DELIVERED)).fetchall()
        for row0 in expired:(self.objects/f"{row0['file_id']}.blob").unlink(missing_ok=True)
        self.db.execute("DELETE FROM objects WHERE (expires_at<=? AND state IN (?,?)) OR state IN (?,?)",(now,ObjectState.READY,ObjectState.DELIVERED,ObjectState.ACKED,ObjectState.EXPIRED));self.db.commit()
        row=self.db.execute(
          "SELECT count(*) n,coalesce(sum(COALESCE(size,0)),0) b FROM objects WHERE state IN (?,?,?)",
          (ObjectState.CREATING,ObjectState.READY,ObjectState.DELIVERED)).fetchone()
        return int(row["n"]),int(row["b"])

    @staticmethod
    def _direction(source: str, target: str):
        if (source,target) not in {("code-workspace","browser"),("browser","code-workspace")}:
            raise RelayError("FILE_TRANSFER_WRONG_TARGET","transfer direction is not allowed",403)

    async def put(self, identity: Identity, target: str, name: str, media_type: str,
                  declared_size: int, declared_hash: str, chunks: AsyncIterator[bytes]) -> dict:
        self._direction(identity.app,target)
        if len(name.encode("utf-8")) > self.limits.max_filename_bytes:
            raise RelayError("FILE_TRANSFER_METADATA_TOO_LARGE","filename is too long")
        if declared_size < 0 or declared_size > self.limits.max_file_bytes:
            raise RelayError("FILE_TOO_LARGE","file exceeds configured limit",413)
        if not re_full_sha(declared_hash):
            raise RelayError("FILE_TRANSFER_INTEGRITY_ERROR","invalid declared sha256")
        count,total=self._usage()
        if count >= self.limits.max_objects:
            raise RelayError("FILE_TRANSFER_QUOTA_EXCEEDED","object quota exceeded",429)
        if total + declared_size > self.limits.max_total_bytes:
            raise RelayError("FILE_TRANSFER_QUOTA_EXCEEDED","byte quota exceeded",429)
        fid="f_"+secrets.token_hex(32)
        created=time.time(); expires=created+self.limits.ttl_seconds
        partial=self.objects/f"{fid}.partial"; blob=self.objects/f"{fid}.blob"
        self.db.execute("INSERT INTO objects(file_id,task_id,attempt,source_app,target_app,"
          "display_name,media_type,size,created_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
          (fid,identity.task_id,identity.attempt,identity.app,target,name,media_type,declared_size,created,expires,ObjectState.CREATING))
        self.db.commit()
        size=0; h=hashlib.sha256()
        try:
            async with self.upload_sem:
                with partial.open("xb") as f:
                    async for chunk in chunks:
                        if not chunk: continue
                        size += len(chunk)
                        if size > declared_size or size > self.limits.max_file_bytes:
                            raise RelayError("FILE_TOO_LARGE","upload exceeded declared/configured size",413)
                        h.update(chunk); await asyncio.to_thread(f.write,chunk)
                    await asyncio.to_thread(f.flush); await asyncio.to_thread(os.fsync,f.fileno())
            digest=h.hexdigest()
            if size != declared_size or digest != declared_hash:
                raise RelayError("FILE_TRANSFER_INTEGRITY_ERROR","declared size/hash mismatch",422)
            os.replace(partial,blob)
            dfd=os.open(self.objects,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
            self.db.execute("UPDATE objects SET size=?,sha256=?,state=? WHERE file_id=?",
                            (size,digest,ObjectState.READY,fid)); self.db.commit()
            return {"file_id":fid,"name":name,"size":size,"sha256":digest,"media_type":media_type,
                    "created_at":created,"expires_at":expires}
        except BaseException:
            partial.unlink(missing_ok=True);blob.unlink(missing_ok=True)
            self.db.execute("DELETE FROM objects WHERE file_id=?",(fid,)); self.db.commit()
            raise

    def get(self, identity: Identity, fid: str):
        row=self.db.execute("SELECT * FROM objects WHERE file_id=?",(fid,)).fetchone()
        if row is None: raise RelayError("FILE_NOT_FOUND","file not found",404)
        if row["task_id"] != identity.task_id or row["attempt"] != identity.attempt:
            raise RelayError("FILE_NOT_FOUND","file not found",404)
        if row["target_app"] != identity.app:
            raise RelayError("FILE_TRANSFER_WRONG_TARGET","file is not targeted to caller",403)
        if row["expires_at"] <= time.time() or row["state"] == ObjectState.EXPIRED:
            (self.objects/f"{fid}.blob").unlink(missing_ok=True)
            self.db.execute("UPDATE objects SET state=? WHERE file_id=?",(ObjectState.EXPIRED,fid)); self.db.commit()
            raise RelayError("FILE_TRANSFER_EXPIRED","file expired",410)
        if row["state"] not in (ObjectState.READY,ObjectState.DELIVERED):
            raise RelayError("FILE_TRANSFER_NOT_READY","file is not ready",409)
        blob=self.objects/f"{fid}.blob"
        if not blob.is_file(): raise RelayError("FILE_NOT_FOUND","file payload is unavailable",404)
        self.db.execute("UPDATE objects SET state=?,delivered_at=? WHERE file_id=?",
                        (ObjectState.DELIVERED,time.time(),fid)); self.db.commit()
        return row,blob

    def ack(self, identity: Identity, fid: str):
        row=self.db.execute("SELECT * FROM objects WHERE file_id=?",(fid,)).fetchone()
        if row is None: raise RelayError("FILE_NOT_FOUND","file not found",404)
        if row["task_id"] != identity.task_id or row["attempt"] != identity.attempt:
            raise RelayError("FILE_NOT_FOUND","file not found",404)
        if row["target_app"] != identity.app:
            raise RelayError("FILE_TRANSFER_WRONG_TARGET","file is not targeted to caller",403)
        if row["state"] not in (ObjectState.READY,ObjectState.DELIVERED):
            raise RelayError("FILE_TRANSFER_NOT_READY","file cannot be acknowledged",409)
        (self.objects/f"{fid}.blob").unlink(missing_ok=True)
        self.db.execute("DELETE FROM objects WHERE file_id=?",(fid,)); self.db.commit()
        return {"file_id":fid,"state":ObjectState.ACKED}

def re_full_sha(value: str) -> bool:
    return len(value)==64 and all(c in "0123456789abcdef" for c in value)

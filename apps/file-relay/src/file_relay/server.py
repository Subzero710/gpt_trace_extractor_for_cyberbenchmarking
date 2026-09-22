from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from starlette.routing import Route

from .auth import AuthError, authenticate
from .models import Limits
from .store import RelayError, Store

def _int(name: str, default: int, minimum: int=1) -> int:
    value=int(os.environ.get(name,str(default)))
    if value < minimum: raise RuntimeError(f"{name} must be >= {minimum}")
    return value

limits=Limits(
    max_file_bytes=_int("FILE_RELAY_MAX_FILE_BYTES",134217728),
    max_total_bytes=_int("FILE_RELAY_MAX_TOTAL_BYTES",268435456),
    max_objects=_int("FILE_RELAY_MAX_OBJECTS",32),
    max_concurrent_uploads=_int("FILE_RELAY_MAX_CONCURRENT_UPLOADS",2),
    max_concurrent_downloads=_int("FILE_RELAY_MAX_CONCURRENT_DOWNLOADS",2),
    ttl_seconds=_int("FILE_RELAY_TTL_SECONDS",1800),
    max_filename_bytes=_int("FILE_RELAY_MAX_FILENAME_BYTES",255),
)
store=Store(Path(os.environ.get("FILE_RELAY_DATA_ROOT","/data")),limits)

def error(code: str,message: str,status: int):
    return JSONResponse({"error":{"code":code,"message":message}},status_code=status)

def identity(request: Request):
    try:return authenticate(request.headers.get("authorization"))
    except AuthError as exc:raise RelayError("FILE_TRANSFER_UNAUTHORIZED",str(exc),401) from exc

async def health(_:Request):
    return JSONResponse({"status":"ok"})

async def put(request:Request):
    who=identity(request)
    target=request.headers.get("x-target-app","")
    import base64
    raw_meta=request.headers.get("x-file-metadata","")
    if len(raw_meta)>4096:raise RelayError("FILE_TRANSFER_METADATA_TOO_LARGE","metadata too large",431)
    try:
        pad="="*((4-len(raw_meta)%4)%4);meta=json.loads(base64.urlsafe_b64decode(raw_meta+pad));name=meta["name"];media=meta.get("media_type") or "application/octet-stream"
    except Exception as exc:raise RelayError("FILE_TRANSFER_METADATA_INVALID","invalid metadata",400) from exc
    if not isinstance(name,str) or not isinstance(media,str) or len(media.encode())>256:raise RelayError("FILE_TRANSFER_METADATA_TOO_LARGE","invalid metadata",400)
    raw_size=request.headers.get("content-length")
    digest=request.headers.get("x-content-sha256","")
    if raw_size is None: raise RelayError("FILE_TRANSFER_LENGTH_REQUIRED","Content-Length is required",411)
    try:size=int(raw_size)
    except ValueError: raise RelayError("FILE_TRANSFER_LENGTH_REQUIRED","invalid Content-Length",411)
    timeout=float(os.environ.get("FILE_RELAY_UPLOAD_TIMEOUT_SECONDS","120"))
    try:result=await asyncio.wait_for(store.put(who,target,name,media,size,digest,request.stream()),timeout=timeout)
    except asyncio.TimeoutError as exc:raise RelayError("FILE_TRANSFER_TIMEOUT","upload deadline exceeded",408) from exc
    return JSONResponse(result,status_code=201)

async def get(request:Request):
    who=identity(request); fid=request.path_params["file_id"]
    row,path=store.get(who,fid)
    import base64
    meta=base64.urlsafe_b64encode(json.dumps({"name":row["display_name"],"media_type":row["media_type"]},ensure_ascii=False,separators=(",",":")).encode()).decode().rstrip("=")
    await store.download_sem.acquire()
    return FileResponse(path,media_type="application/octet-stream",filename=None,headers={
      "x-file-id":fid,"x-file-metadata":meta,"x-content-sha256":row["sha256"],"x-content-size":str(row["size"]),
    },background=BackgroundTask(store.download_sem.release))

async def ack(request:Request):
    return JSONResponse(store.ack(identity(request),request.path_params["file_id"]))

async def guarded(request:Request,handler):
    try:return await handler(request)
    except RelayError as exc:return error(exc.code,str(exc),exc.status)
    except Exception:return error("FILE_TRANSFER_UNAVAILABLE","relay internal error",500)

def wrap(handler):
    async def endpoint(request):return await guarded(request,handler)
    return endpoint

async def gc_loop():
    while True:
        await asyncio.sleep(max(5,min(60,limits.ttl_seconds//4)))
        store._usage()
async def startup():
    app.state.gc_task=asyncio.create_task(gc_loop())
async def shutdown():
    app.state.gc_task.cancel()
    try:await app.state.gc_task
    except asyncio.CancelledError:pass
    store.close()
app=Starlette(on_startup=[startup],on_shutdown=[shutdown],routes=[
  Route("/healthz",health,methods=["GET"]),
  Route("/v1/files",wrap(put),methods=["POST"]),
  Route("/v1/files/{file_id}",wrap(get),methods=["GET"]),
  Route("/v1/files/{file_id}/ack",wrap(ack),methods=["POST"]),
])

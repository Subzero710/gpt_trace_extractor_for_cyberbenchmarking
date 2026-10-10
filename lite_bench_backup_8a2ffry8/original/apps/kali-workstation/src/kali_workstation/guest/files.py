from __future__ import annotations

import base64
import hashlib
import io
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath

MAX_FILE = 64 * 1024 * 1024
MAX_SEED = 268435456
WORKSPACE = Path("/home/kali/workspace")


def path(value: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ValueError("invalid path")
    target = Path(value)
    if not target.is_absolute():
        target = WORKSPACE / target
    # The agent owns the guest filesystem. This validates only a guest path.
    return target


def stat_file(args: dict) -> dict:
    target = path(args["path"])
    if not target.is_file() or target.is_symlink() or target.stat().st_size > MAX_FILE:
        raise ValueError("file missing, symlink, or too large")
    return {"path": str(target), "size": target.stat().st_size}


def read_chunk(args: dict) -> dict:
    target = path(args["path"])
    offset = args["offset"]
    if type(offset) is not int or not 0 <= offset <= MAX_FILE:
        raise ValueError("invalid artifact offset")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_size > MAX_FILE:
            raise ValueError("artifact is not a bounded regular file")
        data = os.pread(fd, min(1048576, MAX_FILE - offset), offset)
    finally:
        os.close(fd)
    return {"content_base64": base64.b64encode(data).decode()}


class ImportSession:
    def __init__(self):
        self.target = None
        self.temp = None
        self.digest = hashlib.sha256()
        self.size = 0
        self.expected = None
        self.overwrite = False

    def begin(self, args):
        if self.temp is not None:
            raise ValueError("artifact import already active")
        target = path(args["path"])
        if target.exists() and not args.get("overwrite", False):
            raise ValueError("artifact destination exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        name = target.parent / (".gpt-trace-import-" + os.urandom(16).hex())
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.target, self.temp = target, name
        self.expected = args["sha256"]
        self.overwrite = args.get("overwrite", False)
        self.size = 0
        self.digest = hashlib.sha256()
        return {"ready": True}

    def chunk(self, args):
        if self.temp is None:
            raise ValueError("artifact import not active")
        data = base64.b64decode(args["content_base64"], validate=True)
        if len(data) > 1048576 or self.size + len(data) > MAX_FILE:
            raise ValueError("artifact chunk exceeds configured limit")
        with self.temp.open("ab") as output:
            output.write(data)
        self.digest.update(data)
        self.size += len(data)
        return {"received": self.size}

    def finish(self, args):
        if self.temp is None:
            raise ValueError("artifact import not active")
        try:
            if self.digest.hexdigest() != self.expected or self.size != args["size"]:
                raise ValueError("artifact import integrity mismatch")
            if self.target.exists() and not self.overwrite:
                raise ValueError("artifact destination exists")
            os.replace(self.temp, self.target)
            return {"path": str(self.target), "size": self.size, "sha256": self.expected}
        finally:
            self.abort()

    def abort(self):
        if self.temp is not None:
            self.temp.unlink(missing_ok=True)
        self.target = self.temp = None


def seed(args: dict) -> dict:
    raw = base64.b64decode(args["archive_base64"], validate=True)
    if len(raw) > MAX_FILE:
        raise ValueError("seed archive too large")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != args.get("sha256"):
        raise ValueError("seed checksum mismatch")
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    if any(WORKSPACE.iterdir()):
        raise ValueError("workspace not empty before seed")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > 4096:
            raise ValueError("too many seed entries")
        names: set[str] = set()
        for member in members:
            candidate = PurePosixPath(member.name)
            if (candidate.is_absolute() or ".." in candidate.parts or not member.name or
                    not (member.isfile() or member.isdir()) or member.name in names or
                    member.size > MAX_FILE or member.mode & (stat.S_ISUID | stat.S_ISGID)):
                raise ValueError("unsafe seed entry")
            names.add(member.name)
        for member in members:
            destination = WORKSPACE / member.name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("xb") as output:
                    while chunk := source.read(65536):
                        output.write(chunk)
                os.chmod(destination, 0o600)
    return {"status": "seeded", "archive_bytes": len(raw), "sha256": digest}


class SeedSession:
    def __init__(self):
        self.target = Path("/tmp/gpt-trace-seed.tar")
        self.size = 0
        self.digest = hashlib.sha256()
        self.open = False

    def begin(self, args):
        if self.open or self.target.exists() or (WORKSPACE.exists() and any(WORKSPACE.iterdir())):
            raise ValueError("seed already started or workspace is not empty")
        with self.target.open("xb"):
            pass
        self.open = True
        return {"ready": True}

    def chunk(self, args):
        if not self.open: raise ValueError("seed is not active")
        data = base64.b64decode(args["content_base64"], validate=True)
        if len(data) > 1048576 or self.size + len(data) > MAX_SEED:
            raise ValueError("seed chunk or total exceeds limit")
        with self.target.open("ab") as output: output.write(data)
        self.digest.update(data)
        self.size += len(data)
        return {"received": self.size}

    def finish(self, args):
        if not self.open: raise ValueError("seed is not active")
        self.open = False
        try:
            if self.digest.hexdigest() != args["sha256"] or self.size != args["archive_bytes"]:
                raise ValueError("seed integrity mismatch")
            WORKSPACE.mkdir(parents=True, exist_ok=True)
            with tarfile.open(self.target, mode="r:") as archive:
                members = archive.getmembers()
                if len(members) > 10000: raise ValueError("too many seed entries")
                names = set()
                for member in members:
                    candidate = PurePosixPath(member.name)
                    if (candidate.is_absolute() or ".." in candidate.parts or not member.name or
                            not (member.isfile() or member.isdir()) or member.name in names or
                            member.size > MAX_SEED or member.mode & (stat.S_ISUID | stat.S_ISGID)):
                        raise ValueError("unsafe seed entry")
                    names.add(member.name)
                for member in members:
                    destination = WORKSPACE / member.name
                    if member.isdir(): destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as source, destination.open("xb") as output:
                            while chunk := source.read(65536): output.write(chunk)
                        os.chmod(destination, 0o600)
            return {"status": "seeded", "archive_bytes": self.size, "sha256": self.digest.hexdigest()}
        finally:
            self.target.unlink(missing_ok=True)

    def abort(self):
        self.open = False
        self.target.unlink(missing_ok=True)

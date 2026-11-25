"""Process-owned deadlines for native APT transfers and package actions."""
from __future__ import annotations

from collections import defaultdict, deque
import contextlib
import hashlib
import os
import re
import select
import subprocess
import time
import urllib.parse


class AptDownloads:
    """Observe the native Acquire messages, one ordered queue per access method."""

    def __init__(self, process, limit, scopes, observe):
        self.pid = process.pid
        self.limit = limit
        self.scopes = scopes
        self.observe = observe
        self.waiting = defaultdict(deque)
        self.active = {}
        self.redirects = {}
        self.idle = time.monotonic() + limit

    def _next(self, method):
        if not self.waiting[method]:
            return
        uri = self.waiting[method].popleft()
        now = time.monotonic()
        started = self.redirects.pop(uri, now)
        scope = self.scopes.enter_context(contextlib.ExitStack())
        scope.enter_context(self.observe('APT ' + method + ' item', process=self.pid, started=started))
        self.active[method] = (uri, started, scope)

    def feed(self, line):
        frame = re.fullmatch(rb'\s*(->|<-)\s+([a-z0-9+._-]+):([1-6][0-9]{2})([^\n]*)', line)
        if frame is None:
            return False
        direction, worker, code, contents = frame.groups()
        if (direction, code) not in {
            (b'->', b'600'), (b'<-', b'103'), (b'<-', b'200'), (b'<-', b'201'), (b'<-', b'400'),
        }:
            return True
        method = worker.decode('ascii')
        fields = dict(field.split(': ', 1) for field in urllib.parse.unquote(
            contents.decode('ascii')).splitlines()[1:] if ': ' in field)
        uri = fields.get('URI')
        if not uri:
            raise RuntimeError('APT transfer has no native URI identity')
        current = self.active.get(method)
        if code == b'600':
            if uri not in self.waiting[method] and (current is None or current[0] != uri):
                self.waiting[method].append(uri)
            if current is None:
                self._next(method)
            return True
        if current is None or current[0] != uri:
            raise RuntimeError('APT result does not match its active transfer')
        if code == b'200':
            return True
        self.remaining()
        _, started, scope = self.active.pop(method)
        scope.close()
        self.idle = time.monotonic() + self.limit
        if code == b'103':
            target = fields.get('New-URI')
            if not target or target in self.redirects:
                raise RuntimeError('APT redirect lacks a unique transfer identity')
            self.redirects[target] = started
        self._next(method)
        return True

    def remaining(self):
        deadline, label = min(((started + self.limit, method)
                               for method, (_, started, _) in self.active.items()),
                              default=(self.idle, 'startup or bookkeeping'))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('APT operation exceeded its deadline: ' + label)
        return remaining


def run_downloads(arguments, *, limit, cadence, observe, terminate, progress=None):
    options = ['-o', 'Debug::pkgAcquire::Worker=true', '-o', 'Acquire::Queue-Mode=access',
               '-o', 'Acquire::http::Pipeline-Depth=0', '-o', 'Acquire::https::Pipeline-Depth=0']
    command = [arguments[0], *options, *arguments[1:]]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    pending = b''
    tail = b''
    try:
        with contextlib.ExitStack() as operations:
            watch = AptDownloads(process, limit, operations, observe)
            next_progress = time.monotonic()
            while True:
                readable, _, _ = select.select([process.stdout], [], [], min(cadence, watch.remaining()))
                if progress is not None and time.monotonic()>=next_progress:
                    progress()
                    next_progress=time.monotonic()+cadence
                if not readable:
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                lines = (pending + chunk).split(b'\n')
                pending = lines.pop()
                for line in lines:
                    if not watch.feed(line):
                        tail = (tail + line + b'\n')[-8192:]
                if len(pending) > 1048576:
                    raise RuntimeError('oversized APT progress record')
            code = process.wait(timeout=watch.remaining())
            if progress is not None:
                progress()
            if code:
                error = subprocess.CalledProcessError(code, arguments, output=tail.decode(errors='replace'))
                error.add_note(error.stdout)
                raise error
            if watch.active or watch.redirects or any(watch.waiting.values()):
                raise RuntimeError('APT exited with unresolved native operations')
    except BaseException:
        terminate(process)
        raise
    finally:
        process.stdout.close()


_DPKG_PHASE = re.compile(
    rb"processing: (upgrade|install|configure|trigproc|disappear|remove|purge): "
    rb"([a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?)")


def _watch_package_install(process, status, *, limit, cadence, observe):
    current = None
    pending = b""
    deadline = time.monotonic() + limit

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            label = b" ".join(current).decode() if current else "startup"
            raise TimeoutError("APT installation deadline exceeded: " + label)
        return seconds

    with contextlib.ExitStack() as operation:
        while True:
            readable, _, _ = select.select([status], [], [], min(cadence, remaining()))
            if not readable:
                continue
            chunk = os.read(status, 65536)
            if not chunk:
                break
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            if len(pending) > 65536:
                raise ValueError("oversized dpkg status record")
            for line in lines:
                remaining()
                if not line.startswith(b"processing:"):
                    continue
                match = _DPKG_PHASE.fullmatch(line)
                if match is None:
                    raise ValueError("invalid dpkg processing record")
                if match.groups() == current:
                    continue
                operation.close()
                current = match.groups()
                stage, package = current
                label = "apt-" + stage.decode() + "-" + hashlib.sha256(package).hexdigest()
                operation.enter_context(observe(label))
                deadline = time.monotonic() + limit
        if pending:
            raise ValueError("truncated dpkg status record")
        result = process.wait(timeout=remaining())
        if result:
            raise subprocess.CalledProcessError(result, process.args)


def run_install(arguments, *, limit, cadence, observe, terminate, launcher=(), **kwargs):
    read_fd, write_fd = os.pipe()
    try:
        try:
            process = subprocess.Popen(
                [*launcher, "apt-get", "-o", "APT::Keep-Fds::=" + str(write_fd),
                 "-o", "DPkg::Options::=--status-fd=" + str(write_fd), *arguments],
                stdin=subprocess.DEVNULL, pass_fds=(write_fd,), start_new_session=True, **kwargs)
        finally:
            os.close(write_fd)
        try:
            _watch_package_install(process, read_fd, limit=limit, cadence=cadence, observe=observe)
        except BaseException:
            terminate(process)
            raise
    finally:
        os.close(read_fd)

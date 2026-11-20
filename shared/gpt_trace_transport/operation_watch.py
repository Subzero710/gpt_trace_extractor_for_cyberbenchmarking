"""Monotonic supervision for trusted, explicitly scoped process operations."""
from __future__ import annotations

import contextlib
import contextvars
import os
import re
import stat
import time

HOST_PHASE_FD = "GPTTRACE_HOST_PHASE_FD"
HOST_PREFIX = b"GPTTRACE_HOST "
_host_phase = contextvars.ContextVar("host_phase_fd", default=None)


def _emit(fd, kind, label):
    payload = HOST_PREFIX + kind.encode("ascii") + b" " + label.encode("ascii") + b"\n"
    if os.write(fd, payload) != len(payload):
        raise OSError("incomplete host operation record")


@contextlib.contextmanager
def host_operation(label):
    fd = _host_phase.get()
    if fd is None:
        yield
        return
    _emit(fd, "begin", label)
    try:
        yield
    finally:
        _emit(fd, "end", label)


def run_host_entry(function):
    raw = os.environ.pop(HOST_PHASE_FD, None)
    if raw is None:
        return function()
    fd = int(raw)
    if fd < 3 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
        raise ValueError("invalid host operation descriptor")
    os.set_inheritable(fd, False)
    token = _host_phase.set(fd)
    try:
        try:
            function()
        except BaseException:
            _emit(fd, "shutdown", "failed")
            raise
        else:
            _emit(fd, "shutdown", "complete")
    finally:
        _host_phase.reset(token)
        os.close(fd)


class OperationWatch:
    def __init__(self, limit, *, prefix, description, requires_proof=True, allow_pause=False):
        self.limit = limit
        self.prefix = prefix
        self.description = description
        self.requires_proof = requires_proof
        self.allow_pause = allow_pause
        self.active = {}
        self.paused = {}
        self.idle_deadline = time.monotonic() + limit
        self.pending = b""
        self.proved = False
        self.outcome = None

    def feed(self, chunk):
        lines = (self.pending + chunk).split(b"\n")
        self.pending = lines.pop()
        if len(self.pending) > 4096:
            raise ValueError("oversized " + self.description + " serial record")
        for line in lines:
            if not line.startswith(self.prefix):
                continue
            kind, _, label = line.removeprefix(self.prefix).strip().partition(b" ")
            if re.fullmatch(rb"[a-zA-Z0-9._+-]{1,128}", label) is None:
                raise ValueError("invalid " + self.description + " operation label")
            now = time.monotonic()
            if kind == b"begin" and label not in self.active and label not in self.paused and self.outcome is None:
                self.active[label] = now + self.limit
            elif kind == b"pause" and self.allow_pause and label in self.active:
                remaining = self.active.pop(label) - now
                if remaining <= 0:
                    raise TimeoutError(self.description + " exceeded deadline: " + label.decode())
                self.paused[label] = remaining
                self.idle_deadline = now + self.limit
            elif kind == b"resume" and self.allow_pause and label in self.paused:
                self.active[label] = now + self.paused.pop(label)
            elif kind == b"end" and label in self.active:
                if now >= self.active.pop(label):
                    raise TimeoutError(self.description + " exceeded deadline: " + label.decode())
                self.proved |= label == b"completion-proof"
                self.idle_deadline = now + self.limit
            elif (kind == b"shutdown" and self.outcome is None
                  and (label == b"failed" or (label == b"complete" and not self.active and not self.paused
                                              and (self.proved or not self.requires_proof)))):
                self.active.clear()
                self.paused.clear()
                self.outcome = label
                self.idle_deadline = now + self.limit
            else:
                raise ValueError("invalid " + self.description + " operation transition: " + line.decode(errors="replace"))

    def check(self):
        idle = b"shutdown" if self.outcome is not None else b"boot or unregistered work"
        deadline, label = min(((deadline, label) for label, deadline in self.active.items()),
                              default=(self.idle_deadline, idle))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(self.description + " exceeded deadline: " + label.decode())
        return remaining


    def require_complete(self):
        if self.outcome is None or self.pending.startswith(self.prefix):
            raise RuntimeError(self.description + " exited without a shutdown transition")
        if self.outcome == b"failed":
            raise RuntimeError(self.description + " reported a failed shutdown")

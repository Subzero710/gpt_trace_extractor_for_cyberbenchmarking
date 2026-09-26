from __future__ import annotations

import asyncio
import base64
import fcntl
import os
import pty
import re
import signal
import struct
import subprocess
import termios
import time
import uuid
import sys

MAX_OUTPUT = 1024 * 1024
MAX_STDIN = 4 * 1024 * 1024
ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def environment(values: dict | None) -> dict[str, str]:
    if values is None:
        return os.environ.copy()
    if not isinstance(values, dict) or len(values) > 128:
        raise ValueError("invalid environment")
    for key, value in values.items():
        if not isinstance(key, str) or not ENV_KEY.fullmatch(key) or not isinstance(value, str) or len(value) > 8192 or "\x00" in value:
            raise ValueError("invalid environment entry")
    return {**os.environ, **values}


async def exec_command(args: dict) -> dict:
    command = args["command"]
    cwd = args.get("cwd", "/home/kali/workspace")
    timeout = args.get("timeout_seconds", 120)
    stdin = args.get("stdin", "")
    if not isinstance(command, str) or not command or len(command) > 131072:
        raise ValueError("command is invalid or too long")
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        raise ValueError("cwd is not a directory")
    if type(timeout) is not int or not 1 <= timeout <= 1800:
        raise ValueError("timeout is out of range")
    if not isinstance(stdin, str) or len(stdin.encode()) > MAX_STDIN:
        raise ValueError("stdin is too large")
    process = await asyncio.create_subprocess_exec(
        "/bin/bash", "-lc", command, cwd=cwd, env=environment(args.get("environment")),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    async def feed():
        try:
            process.stdin.write(stdin.encode())
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()
    async def drain(stream):
        saved = bytearray()
        truncated = False
        while chunk := await stream.read(65536):
            available = MAX_OUTPUT - len(saved)
            saved.extend(chunk[:available])
            truncated |= len(chunk) > available
        return bytes(saved), truncated
    input_task = asyncio.create_task(feed())
    stdout_task = asyncio.create_task(drain(process.stdout))
    stderr_task = asyncio.create_task(drain(process.stderr))
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout)
    except asyncio.TimeoutError:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
    finally:
        if not input_task.done(): input_task.cancel()
    stdout, stdout_truncated = await stdout_task
    stderr, stderr_truncated = await stderr_task
    if input_task.done() and not input_task.cancelled():
        input_task.result()
    return {"exit_code": process.returncode, "timed_out": timed_out,
            "stdout": stdout.decode(errors="replace"), "stderr": stderr.decode(errors="replace"),
            "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated}


class Terminal:
    def __init__(self, cwd: str, env: dict, rows: int, cols: int):
        self.master, slave = pty.openpty()
        self.resize(rows, cols)
        # The child execs a small launcher before acquiring its controlling TTY.
        # No Python code runs in a forked child of the (potentially threaded) agent.
        self.process = subprocess.Popen([sys.executable, "-m", "kali_workstation.guest.pty_child"],
                                        cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave,
                                        close_fds=True, start_new_session=True)
        os.close(slave)
        os.set_blocking(self.master, False)
        self.output = bytearray()
        self.dropped = 0
        self.last_access = time.monotonic()
        self.changed = asyncio.Event()
        asyncio.get_running_loop().add_reader(self.master, self._collect)

    def _collect(self):
        try:
            chunk = os.read(self.master, 65536)
        except (BlockingIOError, OSError):
            chunk = b""
        if not chunk:
            asyncio.get_running_loop().remove_reader(self.master)
            self.changed.set()
            return
        self.output.extend(chunk)
        if len(self.output) > MAX_OUTPUT:
            self.dropped += len(self.output) - MAX_OUTPUT
            del self.output[:len(self.output) - MAX_OUTPUT]
        self.changed.set()

    def resize(self, rows: int, cols: int):
        if type(rows) is not int or type(cols) is not int or not 10 <= rows <= 200 or not 20 <= cols <= 400:
            raise ValueError("terminal size outside configured bounds")
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def read(self, maximum: int) -> dict:
        self.last_access = time.monotonic()
        chunk = bytes(self.output[:maximum])
        del self.output[:maximum]
        return {"output": chunk.decode(errors="replace"), "output_base64": base64.b64encode(chunk).decode(),
                "dropped_bytes": self.dropped, "exit_code": self.process.poll(),
                "running": self.process.poll() is None}

    def close(self):
        asyncio.get_running_loop().remove_reader(self.master)
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGHUP)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        os.close(self.master)


class Terminals:
    def __init__(self, limit: int = 8):
        self.limit = limit
        self.items: dict[str, Terminal] = {}

    def create(self, args: dict) -> dict:
        if len(self.items) >= self.limit:
            raise ValueError("terminal limit reached")
        cwd = args.get("cwd", "/home/kali/workspace")
        if not isinstance(cwd, str) or not os.path.isdir(cwd):
            raise ValueError("cwd is not a directory")
        terminal_id = uuid.uuid4().hex
        term = Terminal(cwd, environment(args.get("environment")), args.get("rows", 24), args.get("cols", 80))
        self.items[terminal_id] = term
        return {"terminal_id": terminal_id, "pid": term.process.pid}

    def get(self, args: dict) -> Terminal:
        terminal_id = args.get("terminal_id")
        if terminal_id not in self.items:
            raise ValueError("unknown terminal")
        return self.items[terminal_id]

    async def send(self, args: dict) -> dict:
        terminal = self.get(args)
        data = args.get("input", "")
        if not isinstance(data, str) or len(data.encode()) > 65536:
            raise ValueError("terminal input too large")
        encoded = data.encode()
        view = memoryview(encoded)
        loop = asyncio.get_running_loop()
        while view:
            try:
                written = os.write(terminal.master, view)
                if written == 0:
                    raise OSError("PTY closed while writing")
                view = view[written:]
            except BlockingIOError:
                ready = loop.create_future()
                loop.add_writer(terminal.master, lambda: not ready.done() and ready.set_result(None))
                try:
                    await asyncio.wait_for(ready, timeout=30)
                finally:
                    loop.remove_writer(terminal.master)
        return {"accepted_bytes": len(encoded)}

    async def read(self, args: dict) -> dict:
        terminal = self.get(args)
        wait = args.get("wait_seconds", 0)
        maximum = args.get("max_bytes", 65536)
        if type(wait) not in (int, float) or not 0 <= wait <= 30 or type(maximum) is not int or not 1 <= maximum <= MAX_OUTPUT:
            raise ValueError("invalid terminal read limits")
        # Wait for output to settle, including data after a prompt/line echo.
        # The deadline bounds the whole read, even with continuous output.
        if wait:
            deadline = asyncio.get_running_loop().time() + wait
            quiet = min(.25, wait)
            while terminal.process.poll() is None:
                terminal.changed.clear()
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    await asyncio.wait_for(terminal.changed.wait(), min(quiet, remaining))
                except asyncio.TimeoutError:
                    if terminal.output:
                        break
        return terminal.read(maximum)

    def resize(self, args: dict) -> dict:
        terminal = self.get(args)
        terminal.resize(args["rows"], args["cols"])
        return {"ok": True}

    def close(self, args: dict) -> dict:
        terminal = self.get(args)
        terminal.close()
        del self.items[args["terminal_id"]]
        return {"closed": True}

    def shutdown(self):
        for terminal in self.items.values():
            terminal.close()
        self.items.clear()

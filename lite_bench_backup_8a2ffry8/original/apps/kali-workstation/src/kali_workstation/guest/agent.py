from __future__ import annotations

import asyncio
import hmac
import json
import os
import socket
import struct
import subprocess
from pathlib import Path

from .browser import Browser
from .files import SeedSession, ImportSession, read_chunk, stat_file
from .shell import Terminals, exec_command
from . import shell, files

PORT = 17171
MAX_FRAME = 32 * 1024 * 1024


class Agent:
    def __init__(self, identity: dict):
        self.identity = {key: identity[key] for key in ("task_id", "attempt", "environment_id", "fingerprint")}
        self.secret = identity["secret"]
        limits = identity["limits"]
        shell.MAX_OUTPUT = limits["max_output_bytes"]
        files.MAX_SEED = limits["max_seed_bytes"]
        files.MAX_FILE = limits["max_transfer_bytes"]
        self.terminals = Terminals(limit=limits["max_terminals"])
        self.browser = Browser(self.identity["fingerprint"])
        self.seed = SeedSession()
        self.import_session = ImportSession()

    async def call(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or payload.get("identity") != self.identity or not hmac.compare_digest(str(payload.get("secret", "")), self.secret):
            raise ValueError("guest attempt authentication failed")
        method = payload.get("method")
        args = payload.get("args", {})
        if not isinstance(args, dict): raise ValueError("RPC arguments must be an object")
        if method == "health": return {"identity": self.identity, "guest_agent_version": "3.0.0"}
        if method == "prepare":
            await self.browser.start()
            return {"status": "ready", **self.identity}
        if method == "resume":
            if self.browser.context is None: await self.browser.start()
            return {"status": "ready", **self.identity}
        if method == "seed_begin": return self.seed.begin(args)
        if method == "seed_chunk": return self.seed.chunk(args)
        if method == "seed_end": return self.seed.finish(args)
        if method == "seed_abort": self.seed.abort(); return {"aborted": True}
        if method == "exec_command": return await exec_command(args)
        if method == "create_terminal": return self.terminals.create(args)
        if method == "send_terminal_input": return await self.terminals.send(args)
        if method == "read_terminal_output": return await self.terminals.read(args)
        if method == "resize_terminal": return self.terminals.resize(args)
        if method == "close_terminal": return self.terminals.close(args)
        if method == "artifact_stat": return stat_file(args)
        if method == "artifact_read_chunk": return read_chunk(args)
        if method == "artifact_import_begin": return self.import_session.begin(args)
        if method == "artifact_import_chunk": return self.import_session.chunk(args)
        if method == "artifact_import_end": return self.import_session.finish(args)
        if method == "artifact_import_abort": self.import_session.abort(); return {"aborted": True}
        if isinstance(method, str) and method.startswith("browser_"):
            return await self.browser.call(method[8:], args)
        raise ValueError("unknown guest RPC method")


async def handle(connection: socket.socket, agent: Agent):
    loop = asyncio.get_running_loop()
    try:
        header = await asyncio.wait_for(read_exact(loop, connection, 4), 30)
        length = struct.unpack("!I", header)[0]
        if length > MAX_FRAME: raise ValueError("request exceeds limit")
        payload = json.loads(await asyncio.wait_for(read_exact(loop, connection, length), 30))
        try: result = {"ok": True, "result": await asyncio.wait_for(agent.call(payload), 1810)}
        except (ValueError, OSError, RuntimeError, KeyError, asyncio.TimeoutError) as exc:
            result = {"ok": False, "error": str(exc)[:1000]}
        data = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
        if len(data) > MAX_FRAME:
            data = json.dumps({"ok": False, "error": "response exceeds limit"}).encode()
        await loop.sock_sendall(connection, struct.pack("!I", len(data)) + data)
    finally:
        connection.close()


async def read_exact(loop, connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = await loop.sock_recv(connection, min(length - len(result), 65536))
        if not chunk: raise OSError("host disconnected")
        result.extend(chunk)
    return bytes(result)


def load_identity() -> dict:
    directory = Path("/run/gpt-trace-identity")
    directory.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(["mount", "-o", "ro,nosuid,nodev,noexec", "/dev/sr0", str(directory)], check=True, timeout=10)
    value = json.loads((directory / "identity.json").read_text())
    if not isinstance(value, dict) or len(value.get("secret", "")) != 64:
        raise RuntimeError("guest attempt identity missing")
    return value


async def main_async():
    agent = Agent(load_identity())
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(32)
    server.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        while True:
            connection, address = await loop.sock_accept(server)
            if address[0] != socket.VMADDR_CID_HOST:
                connection.close()
                continue
            connection.setblocking(False)
            asyncio.create_task(handle(connection, agent))
    finally:
        agent.terminals.shutdown()
        await agent.browser.close()
        server.close()


def main():
    asyncio.run(main_async())


if __name__ == "__main__": main()

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
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
        if identity.get("purpose") == "evaluator":
            self.identity.update(purpose="evaluator", evaluator_retry=identity["evaluator_retry"])
        self.secret = identity["secret"]
        limits = identity["limits"]
        self.frame_timeout = limits["guest_agent_timeout_seconds"]
        if type(self.frame_timeout) is not int or not 1 <= self.frame_timeout <= 180:
            raise ValueError("invalid guest transport deadline")
        shell.MAX_OUTPUT = limits["max_output_bytes"]
        files.MAX_SEED = limits["max_seed_bytes"]
        files.MAX_FILE = limits["max_transfer_bytes"]
        self.terminals = Terminals(limit=limits["max_terminals"])
        self.browser = Browser(self.identity["fingerprint"])
        self.seed = SeedSession()
        self.import_session = ImportSession()
        self.template_import = ImportSession(trusted_template=True)
        self.execution = None

    async def _execute(self, args):
        try:
            return {"state": "complete", "result": await exec_command(args, cleanup_timeout=self.frame_timeout)}
        except Exception as exc:
            return {"state": "failed", "error": str(exc)[:1000]}

    def _execution(self, method, args):
        operation_id = args.get("operation_id")
        if not isinstance(operation_id, str) or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
            raise ValueError("invalid guest execution operation ID")
        if method == "_exec_begin":
            if set(args) != {"operation_id", "args"} or not isinstance(args["args"], dict):
                raise ValueError("invalid guest execution request")
            payload = json.dumps(args["args"], sort_keys=True, separators=(",", ":"), allow_nan=False)
            if self.execution is not None:
                previous, original, task = self.execution
                if previous == operation_id:
                    if original != payload:
                        raise ValueError("guest execution arguments changed")
                    return {"operation_id": operation_id, "state": "accepted"}
                if not task.done():
                    raise ValueError("another guest execution is active")
            self.execution = (operation_id, payload, asyncio.create_task(self._execute(args["args"])))
            return {"operation_id": operation_id, "state": "accepted"}
        if set(args) != {"operation_id"}:
            raise ValueError("invalid guest execution status request")
        if self.execution is None or self.execution[0] != operation_id:
            return {"operation_id": operation_id, "state": "unknown"}
        task = self.execution[2]
        return {"operation_id": operation_id, **(task.result() if task.done() else {"state": "pending"})}

    async def call(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or payload.get("identity") != self.identity or not hmac.compare_digest(str(payload.get("secret", "")), self.secret):
            raise ValueError("guest attempt authentication failed")
        method = payload.get("method")
        args = payload.get("args", {})
        if not isinstance(args, dict): raise ValueError("RPC arguments must be an object")
        if method == "health": return {"identity": self.identity, "guest_agent_version": "3.0.0", "trusted_artifacts_version": 1}
        if self.identity.get("purpose") == "evaluator" and method not in {
            "_exec_begin", "_exec_status", "artifact_stat", "artifact_read_chunk", "artifact_import_begin",
            "artifact_import_chunk", "artifact_import_end", "artifact_import_abort",
            "template_import_begin", "template_import_chunk", "template_import_end", "template_import_abort",
        }:
            raise ValueError("evaluator has no browser, terminal or model control route")
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
        if method in {"_exec_begin", "_exec_status"}: return self._execution(method, args)
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
        if method == "template_import_begin": return self.template_import.begin(args)
        if method == "template_import_chunk": return self.template_import.chunk(args)
        if method == "template_import_end": return self.template_import.finish(args)
        if method == "template_import_abort": self.template_import.abort(); return {"aborted": True}
        if isinstance(method, str) and method.startswith("browser_"):
            return await self.browser.call(method[8:], args)
        raise ValueError("unknown guest RPC method")


async def handle(connection: socket.socket, agent: Agent):
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(agent.frame_timeout):
            header = await read_exact(loop, connection, 4)
            length = struct.unpack("!I", header)[0]
            if length > MAX_FRAME:
                raise ValueError("request exceeds limit")
            payload = json.loads(await read_exact(loop, connection, length))
            try:
                result = {"ok": True, "result": await agent.call(payload)}
            except (ValueError, OSError, RuntimeError, KeyError) as exc:
                result = {"ok": False, "error": str(exc)[:1000]}
            data = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
            if len(data) > MAX_FRAME:
                data = json.dumps({"ok": False, "error": "response exceeds limit"}).encode()
            await loop.sock_sendall(connection, struct.pack("!I", len(data)) + data)
    except (OSError, ValueError):
        pass
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
        if agent.execution is not None:
            execution = agent.execution[2]
            execution.cancel()
            await asyncio.gather(execution, return_exceptions=True)
        agent.terminals.shutdown()
        await agent.browser.close()
        server.close()


def main():
    asyncio.run(main_async())


if __name__ == "__main__": main()

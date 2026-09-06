#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 8 * 1024 * 1024


def set_clipboard(body: bytes) -> bool:
    env = os.environ.copy()
    env.setdefault("DISPLAY", ":99")
    try:
        subprocess.run(
            ["xclip", "-selection", "clipboard", "-in"],
            input=body,
            check=True,
            timeout=10,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "gpt-trace-clipboard/2"

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_error(404)
            return
        env = os.environ.copy()
        env.setdefault("DISPLAY", ":99")
        if shutil.which("xclip") is None:
            self.send_error(503, "xclip unavailable")
            return
        try:
            subprocess.run(
                ["xdpyinfo", "-display", env["DISPLAY"]],
                check=True, timeout=5, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            self.send_error(503, "X11 display unavailable")
            return
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/clipboard":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("content-length", "-1"))
        except ValueError:
            self.send_error(400, "invalid content-length")
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413, "clipboard payload too large")
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400, "incomplete clipboard payload")
            return
        if not set_clipboard(body):
            self.send_error(503, "could not update X11 clipboard")
            return
        self.send_response(204)
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

from __future__ import annotations

import contextlib
import http.server
import os
import shutil
import threading
from pathlib import Path

import pytest

from browser_mcp.core import BrowserPolicy, BrowserRuntime


HTML = b"""<!doctype html><title>fixture</title>
<input aria-label='query'><button onclick=\"document.querySelector('#out').textContent=document.querySelector('input').value\">Apply</button>
<div id='out'></div>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)
    def log_message(self, *args):
        return


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_cloakbrowser_basic_flow_and_state_reset(tmp_path: Path) -> None:
    if shutil.which("cloakserve") is None:
        pytest.fail("CloakBrowser image does not contain cloakserve")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    runtime = BrowserRuntime(
        tmp_path / "state",
        fingerprint_seed=99173,
        search_url_template="https://duckduckgo.com/?q={query}",
        policy=BrowserPolicy({"127.0.0.1"}),
        browser_uid=os.getuid(),
        browser_gid=os.getgid(),
        humanize=False,
    )
    identity = {"task_id": "integration", "environment_id": "env-1", "task_fingerprint": "b" * 64}
    try:
        await runtime.start()
        await runtime.prepare(identity)
        url = f"http://127.0.0.1:{server.server_port}/"
        await runtime.call("navigate", {"url": url})
        page = await runtime.call("read_page", {})
        input_ref = next(item["ref"] for item in page["elements"] if item["name"] == "query")
        button_ref = next(item["ref"] for item in page["elements"] if item["name"] == "Apply")
        await runtime.call("type", {"ref": input_ref, "text": "isolated"})
        await runtime.call("click", {"ref": button_ref})
        assert "isolated" in (await runtime.call("read_page", {}))["text"]
        assert runtime.page is not None
        await runtime.page.evaluate("localStorage.setItem('leak', 'yes')")
        await runtime.reset(identity)
        identity2 = {"task_id": "integration2", "environment_id": "env-2", "task_fingerprint": "c" * 64}
        await runtime.prepare(identity2)
        await runtime.call("navigate", {"url": url})
        assert await runtime.page.evaluate("localStorage.getItem('leak')") is None
    finally:
        with contextlib.suppress(Exception):
            await runtime.shutdown()
        server.shutdown()
        thread.join(timeout=5)

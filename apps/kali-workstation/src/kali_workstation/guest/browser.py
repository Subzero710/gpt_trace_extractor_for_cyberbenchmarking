from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import uuid
from collections import deque
from pathlib import Path
from urllib.parse import urlparse


DOWNLOADS = Path("/home/kali/Downloads")
MAX_BODY = 8 * 1024 * 1024


class Browser:
    def __init__(self, fingerprint: str = "0" * 64):
        self.fingerprint = fingerprint
        self.context = None
        self.pages = {}
        self.current = None
        self.console = deque(maxlen=500)
        self.network = deque(maxlen=500)
        self.requests = {}
        self.responses = {}

    async def start(self):
        if self.context is not None:
            return
        DOWNLOADS.mkdir(parents=True, exist_ok=True)
        binary = Path(os.environ.get("CLOAKBROWSER_BINARY_PATH", ""))
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("the image-pinned CloakBrowser binary is missing")
        from cloakbrowser import launch_persistent_context_async
        # A fixed seed is scoped to the attempt. The wrapper supplies its own
        # patched browser binary, stealth flags and humanized interactions.
        seed = 10000 + int(self.fingerprint[:16], 16) % 90000
        self.context = await launch_persistent_context_async(
            "/home/kali/.config/gpt-trace-cloakbrowser", headless=False,
            humanize=True, human_preset="default", viewport=None,
            accept_downloads=True, downloads_path=str(DOWNLOADS),
            args=[f"--fingerprint={seed}", "--no-sandbox", "--window-size=1280,800"],
        )
        self.context.on("page", self._register)
        for page in self.context.pages:
            self._register(page)
        if not self.pages:
            self._register(await self.context.new_page())

    async def close(self):
        if self.context:
            await self.context.close()
            self.context = None

    def _register(self, page):
        for key, value in self.pages.items():
            if value is page:
                return key
        key = "page-" + uuid.uuid4().hex[:16]
        self.pages[key] = page
        self.current = key
        page.on("close", lambda _: self.pages.pop(key, None))
        page.on("console", lambda message: self.console.append({"page_id": key, "type": message.type, "text": message.text[:4096]}))
        page.on("request", lambda req: self._request(key, req))
        page.on("response", lambda resp: self._response(key, resp))
        return key

    def _request(self, page_id, request):
        key = "req-" + uuid.uuid4().hex[:16]
        self.requests[key] = request
        self.network.append({"request_id": key, "page_id": page_id, "url": request.url[:8192], "method": request.method})
        if len(self.requests) > 500:
            self.requests.pop(next(iter(self.requests)))

    def _response(self, page_id, response):
        key = next((k for k, v in self.requests.items() if v is response.request), None)
        if key:
            self.responses[key] = response
            if len(self.responses) > 500:
                self.responses.pop(next(iter(self.responses)))
        self.network.append({"request_id": key, "page_id": page_id, "url": response.url[:8192], "status": response.status})

    def page(self, args):
        key = args.get("page_id") or self.current
        if key not in self.pages or self.pages[key].is_closed():
            raise ValueError("unknown page")
        return self.pages[key]

    async def info(self, page):
        key = next(k for k, value in self.pages.items() if value is page)
        return {"page_id": key, "url": page.url, "title": await page.title()}

    async def call(self, method: str, args: dict):
        if self.context is None:
            raise ValueError("browser is not ready")
        if method == "new_page":
            page = await self.context.new_page()
            self._register(page)
            if args.get("url"):
                await page.goto(self._url(args["url"]), wait_until="domcontentloaded", timeout=45000)
            return await self.info(page)
        if method == "list_pages":
            return {"pages": [await self.info(p) for p in self.pages.values() if not p.is_closed()], "active_page_id": self.current}
        page = self.page(args)
        if method == "close_page":
            await page.close()
            self.current = next(iter(self.pages), None)
            return {"closed": True, "active_page_id": self.current}
        if method == "switch_page":
            self.current = args["page_id"]
            await page.bring_to_front()
            return await self.info(page)
        if method in {"navigate", "go_back", "go_forward", "reload"}:
            if method == "navigate":
                await page.goto(self._url(args["url"]), wait_until="domcontentloaded", timeout=45000)
            elif method == "go_back": await page.go_back(timeout=45000)
            elif method == "go_forward": await page.go_forward(timeout=45000)
            else: await page.reload(timeout=45000)
            return await self.info(page)
        if method == "click": await page.locator(args["selector"]).click(timeout=15000)
        elif method == "type_text": await page.locator(args["selector"]).fill(args["text"], timeout=15000)
        elif method == "press": await page.locator(args["selector"]).press(args["key"], timeout=15000)
        elif method == "hover": await page.locator(args["selector"]).hover(timeout=15000)
        elif method == "drag": await page.locator(args["source_selector"]).drag_to(page.locator(args["target_selector"]), timeout=15000)
        elif method == "select_option": await page.locator(args["selector"]).select_option(args["values"], timeout=15000)
        elif method == "query_selector":
            loc = page.locator(args["selector"])
            return {"count": min(await loc.count(), 10000), "matches": await loc.evaluate_all("els => els.slice(0,100).map(e => ({tag: e.tagName, text: (e.textContent||'').slice(0,500)}))")}
        elif method == "inspect_dom":
            return {"nodes": await page.locator(args.get("selector", "html")).evaluate_all("els => els.slice(0,100).map(e => ({tag: e.tagName, text: (e.innerText||'').slice(0,1000), html: e.outerHTML.slice(0,4000)}))")}
        elif method == "get_html":
            html = await (page.locator(args["selector"]).first.inner_html() if args.get("selector") else page.content())
            return {"html": html[:MAX_BODY], "truncated": len(html) > MAX_BODY}
        elif method == "get_attribute":
            return {"value": await page.locator(args["selector"]).first.get_attribute(args["name"])}
        elif method == "evaluate_javascript":
            return {"result": await page.evaluate(args["expression"], args.get("argument"))}
        elif method == "get_cookies": return {"cookies": await self.context.cookies(args.get("urls", []))}
        elif method == "set_cookie":
            await self.context.add_cookies([args["cookie"]]); return {"cookies": await self.context.cookies()}
        elif method == "clear_cookies":
            await self.context.clear_cookies(); return {"cookies": []}
        elif method == "get_console_logs": return {"entries": list(self.console)[-args.get("limit", 200):]}
        elif method == "get_network_logs": return {"entries": list(self.network)[-args.get("limit", 200):]}
        elif method == "get_request_details":
            req = self.requests[args["request_id"]]
            return {"request": {"url": req.url, "method": req.method, "headers": await req.all_headers()}}
        elif method == "get_response_body":
            response = self.responses[args["request_id"]]
            body = await response.body()
            limit = min(args.get("max_bytes", MAX_BODY), MAX_BODY)
            return {"size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                    "truncated": len(body) > limit, "content_base64": base64.b64encode(body[:limit]).decode()}
        elif method == "upload_file":
            target = Path(args["path"])
            if not target.is_file() or target.is_symlink(): raise ValueError("upload source missing")
            await page.locator(args["selector"]).set_input_files(str(target))
        elif method == "download_file":
            async with page.expect_download(timeout=45000) as event:
                await page.locator(args["selector"]).click()
            download = await event.value
            target = DOWNLOADS / Path(download.suggested_filename).name
            if target.exists(): target = DOWNLOADS / (uuid.uuid4().hex + "-" + target.name)
            await download.save_as(str(target))
            if target.stat().st_size > MAX_BODY:
                target.unlink()
                raise ValueError("download exceeds limit")
            return {"path": str(target), "size": target.stat().st_size,
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
        else: raise ValueError("unknown browser method")
        return await self.info(page)

    @staticmethod
    def _url(value):
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(value) > 8192:
            raise ValueError("invalid browser URL")
        return value

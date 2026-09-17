from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import httpx
from playwright.async_api import Browser, BrowserContext, Page, Playwright, Route, async_playwright

MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024
STATE_FILE = "active.json"
REF_PATTERN = re.compile(r"^e[1-9][0-9]*$")
ALLOWED_KEYS = {
    "Enter", "Escape", "Tab", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "PageUp", "PageDown", "Home", "End", "Backspace", "Delete",
}


class BrowserAppError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BrowserState:
    task_id: str
    environment_id: str
    task_fingerprint: str
    status: str


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise BrowserAppError(f"{label} must be a string")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
    if not value or len(value) > 255 or any(ch not in allowed for ch in value):
        raise BrowserAppError(f"invalid {label}")
    return value


def _fingerprint(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise BrowserAppError("invalid task_fingerprint")
    return value


class BrowserPolicy:
    def __init__(self, allowed_private_hosts: set[str] | None = None) -> None:
        self.allowed_private_hosts = {host.casefold().rstrip(".") for host in (allowed_private_hosts or set())}

    @staticmethod
    def _blocked_ip(value: str) -> bool:
        address = ipaddress.ip_address(value)
        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    async def validate_url(self, value: object, *, subresource: bool = False) -> str:
        if not isinstance(value, str) or not value or len(value) > 8192:
            raise BrowserAppError("URL must be a non-empty string")
        original = value
        parsed = urlparse(value)
        if subresource and parsed.scheme in {"data", "blob", "about"}:
            return value
        if subresource and parsed.scheme in {"ws", "wss"}:
            value = ("https" if parsed.scheme == "wss" else "http") + value[value.index(":") :]
            parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise BrowserAppError("only HTTP and HTTPS URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise BrowserAppError("URLs containing credentials are not allowed")
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if not hostname:
            raise BrowserAppError("URL has no hostname")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise BrowserAppError("URL contains an invalid port") from exc
        if hostname in self.allowed_private_hosts:
            return original
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise BrowserAppError("local and private network targets are blocked")
        try:
            if self._blocked_ip(hostname):
                raise BrowserAppError("local and private network targets are blocked")
            return original
        except ValueError:
            pass
        try:
            records = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise BrowserAppError(f"DNS resolution failed for {hostname}") from exc
        addresses = sorted({record[4][0] for record in records})
        if not addresses or any(self._blocked_ip(address) for address in addresses):
            raise BrowserAppError("local and private network targets are blocked")
        return original


class BrowserRuntime:
    def __init__(
        self,
        state_root: Path,
        *,
        fingerprint_seed: int,
        search_url_template: str,
        policy: BrowserPolicy | None = None,
        browser_uid: int = 10001,
        browser_gid: int = 10001,
        cdp_port: int = 9222,
        humanize: bool = True,
        humanize_preset: str = "default",
        timezone: str = "",
        locale: str = "",
        geoip: bool = False,
    ) -> None:
        if fingerprint_seed <= 0:
            raise BrowserAppError("APP_BROWSER_FINGERPRINT_SEED must be positive")
        if search_url_template.count("{query}") != 1:
            raise BrowserAppError("APP_BROWSER_SEARCH_URL_TEMPLATE must contain exactly one {query}")
        self.state_root = state_root.resolve()
        self.fingerprint_seed = fingerprint_seed
        self.search_url_template = search_url_template
        self.policy = policy or BrowserPolicy()
        self.browser_uid = browser_uid
        self.browser_gid = browser_gid
        self.state_root.mkdir(parents=True, exist_ok=True)
        if os.geteuid() == 0:
            os.chown(self.state_root, 0, self.browser_gid)
        os.chmod(self.state_root, 0o710)
        self.cdp_port = cdp_port
        self.humanize = humanize
        self.humanize_preset = humanize_preset
        self.timezone = timezone
        self.locale = locale
        self.geoip = geoip
        self.lock = asyncio.Lock()
        self.process: asyncio.subprocess.Process | None = None
        self.playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.page: Page | None = None

    @property
    def state_path(self) -> Path:
        return self.state_root / STATE_FILE

    @property
    def active_root(self) -> Path:
        return self.state_root / "current"

    @property
    def active_profile(self) -> Path:
        return self.active_root / "profile"

    @property
    def idle_profile(self) -> Path:
        return self.state_root / "idle-profile"

    def load_state(self) -> BrowserState | None:
        if not self.state_path.exists():
            return None
        try:
            state = BrowserState(**json.loads(self.state_path.read_text(encoding="utf-8")))
        except Exception as exc:
            raise BrowserAppError("browser task state is unreadable") from exc
        _identity(state.task_id, "task_id")
        _identity(state.environment_id, "environment_id")
        _fingerprint(state.task_fingerprint)
        if state.status not in {"preparing", "ready"}:
            raise BrowserAppError("browser task state status is invalid")
        return state

    def _write_state(self, state: BrowserState) -> None:
        fd, name = tempfile.mkstemp(prefix=".active-", dir=self.state_root)
        tmp = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(state), handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.state_path)
            self._fsync_dir(self.state_root)
        finally:
            if tmp.exists():
                tmp.unlink()

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _browser_preexec(self) -> None:
        os.setsid()
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(self.browser_gid)
            os.setuid(self.browser_uid)
        os.umask(0o077)

    def _chown_tree(self, root: Path) -> None:
        if os.geteuid() != 0:
            return
        os.chown(root, self.browser_uid, self.browser_gid, follow_symlinks=False)
        for directory, names, files in os.walk(root):
            os.chown(directory, self.browser_uid, self.browser_gid, follow_symlinks=False)
            for name in [*names, *files]:
                path = Path(directory) / name
                if not path.is_symlink():
                    os.chown(path, self.browser_uid, self.browser_gid, follow_symlinks=False)

    def _identity_query(self) -> str:
        from urllib.parse import urlencode

        pairs = [("fingerprint", str(self.fingerprint_seed))]
        if self.timezone:
            pairs.append(("timezone", self.timezone))
        if self.locale:
            pairs.append(("locale", self.locale))
        if self.geoip:
            pairs.append(("geoip", "true"))
        return urlencode(pairs)

    async def _launch(self, profile: Path) -> None:
        if self.process is not None:
            raise BrowserAppError("browser process is already running")
        profile.mkdir(parents=True, exist_ok=True)
        self._chown_tree(profile)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(profile),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        license_key = os.environ.get("CLOAKBROWSER_LICENSE_KEY")
        if license_key:
            environment["CLOAKBROWSER_LICENSE_KEY"] = license_key
        self.process = await asyncio.create_subprocess_exec(
            "cloakserve",
            "--headless=true",
            f"--data-dir={profile}",
            env=environment,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            preexec_fn=self._browser_preexec,
        )
        version_url = f"http://127.0.0.1:{self.cdp_port}/json/version?{self._identity_query()}"
        last_error: Exception | None = None
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
            for _ in range(120):
                if self.process.returncode is not None:
                    raise BrowserAppError(f"CloakBrowser exited with status {self.process.returncode}")
                try:
                    response = await client.get(version_url)
                    response.raise_for_status()
                    break
                except Exception as exc:
                    last_error = exc
                    await asyncio.sleep(0.25)
            else:
                await self._stop_process()
                raise BrowserAppError(f"CloakBrowser CDP did not become ready: {last_error}")

        self.playwright = await async_playwright().start()
        try:
            cdp_url = f"http://127.0.0.1:{self.cdp_port}?{self._identity_query()}"
            self.browser = await self.playwright.chromium.connect_over_cdp(cdp_url, timeout=30000)
            if len(self.browser.contexts) != 1:
                raise BrowserAppError("CloakBrowser must expose exactly one isolated context")
            if self.humanize:
                from cloakbrowser.human import patch_browser_async
                from cloakbrowser.human.config import resolve_config

                patch_browser_async(self.browser, resolve_config(self.humanize_preset))
            self.context = self.browser.contexts[0]
            self.context.set_default_timeout(15000)
            self.context.set_default_navigation_timeout(45000)
            await self.context.route("**/*", self._route_guard)
            for extra in list(self.context.pages[1:]):
                await extra.close()
            self.page = self.context.pages[0] if self.context.pages else await self.context.new_page()
        except Exception:
            await self._stop_process()
            raise

    async def _route_guard(self, route: Route) -> None:
        try:
            await self.policy.validate_url(route.request.url, subresource=True)
        except BrowserAppError:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def _stop_process(self) -> None:
        if self.playwright is not None:
            try:
                await self.playwright.stop()
            finally:
                self.playwright = None
                self.browser = None
                self.context = None
                self.page = None
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    async def start(self) -> None:
        async with self.lock:
            state = self.load_state()
            if state is not None:
                if state.status == "preparing":
                    if self.active_root.exists():
                        shutil.rmtree(self.active_root)
                    self.active_profile.mkdir(parents=True)
                    await self._launch(self.active_profile)
                    state = BrowserState(state.task_id, state.environment_id, state.task_fingerprint, "ready")
                    self._write_state(state)
                else:
                    if not self.active_profile.is_dir():
                        raise BrowserAppError("owned browser profile is missing; exact recovery is impossible")
                    await self._launch(self.active_profile)
            else:
                if self.active_root.exists():
                    raise BrowserAppError("browser profile exists without task ownership state")
                if self.idle_profile.exists():
                    shutil.rmtree(self.idle_profile)
                await self._launch(self.idle_profile)

    async def shutdown(self) -> None:
        async with self.lock:
            await self._stop_process()

    @staticmethod
    def _normalized_payload(payload: dict[str, Any]) -> dict[str, str]:
        return {
            "task_id": _identity(payload.get("task_id"), "task_id"),
            "environment_id": _identity(payload.get("environment_id"), "environment_id"),
            "task_fingerprint": _fingerprint(payload.get("task_fingerprint")),
        }

    @staticmethod
    def _same(state: BrowserState, payload: dict[str, str]) -> bool:
        return (
            state.task_id == payload["task_id"]
            and state.environment_id == payload["environment_id"]
            and state.task_fingerprint == payload["task_fingerprint"]
        )

    async def prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._normalized_payload(payload)
        async with self.lock:
            state = self.load_state()
            if state is not None:
                if not self._same(state, normalized):
                    raise BrowserAppError(f"browser is owned by task {state.task_id!r}")
                if state.status == "ready" and self.process is not None and self.process.returncode is None:
                    return asdict(state)
            await self._stop_process()
            if self.idle_profile.exists():
                shutil.rmtree(self.idle_profile)
            if self.active_root.exists():
                shutil.rmtree(self.active_root)
            self.active_profile.mkdir(parents=True)
            preparing = BrowserState(**normalized, status="preparing")
            self._write_state(preparing)
            await self._launch(self.active_profile)
            ready = BrowserState(**normalized, status="ready")
            self._write_state(ready)
            return asdict(ready)

    async def assert_resume(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._normalized_payload(payload)
        async with self.lock:
            state = self.load_state()
            if (
                state is None
                or state.status != "ready"
                or not self._same(state, normalized)
                or self.process is None
                or self.process.returncode is not None
            ):
                raise BrowserAppError("the exact browser environment is not available for recovery")
            return asdict(state)

    async def reset(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._normalized_payload(payload)
        async with self.lock:
            state = self.load_state()
            if state is None:
                if self.active_root.exists():
                    raise BrowserAppError("browser profile exists without state; refusing blind reset")
                return {**normalized, "status": "idle"}
            if not self._same(state, normalized):
                raise BrowserAppError("reset identity does not own the active browser")
            await self._stop_process()
            if self.active_root.exists():
                shutil.rmtree(self.active_root)
            self.state_path.unlink()
            self._fsync_dir(self.state_root)
            if self.idle_profile.exists():
                shutil.rmtree(self.idle_profile)
            await self._launch(self.idle_profile)
            return {**normalized, "status": "idle"}

    def state_response(self) -> dict[str, Any]:
        state = self.load_state()
        if state is None:
            return {"status": "idle"}
        return asdict(state)

    def healthy(self) -> bool:
        return bool(
            self.process is not None
            and self.process.returncode is None
            and self.browser is not None
            and self.context is not None
            and self.page is not None
        )

    def _ready_page(self) -> Page:
        state = self.load_state()
        if state is None or state.status != "ready" or not self.healthy() or self.page is None:
            raise BrowserAppError("no ready task browser is active")
        return self.page

    async def _page_info(self, page: Page | None = None) -> dict[str, Any]:
        target = page or self._ready_page()
        return {"url": target.url, "title": await target.title()}

    async def navigate(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        url = await self.policy.validate_url(args.get("url"))
        wait_until = args.get("wait_until", "domcontentloaded")
        if wait_until not in {"domcontentloaded", "load"}:
            raise BrowserAppError("invalid wait_until")
        response = await page.goto(url, wait_until=wait_until, timeout=45000)
        info = await self._page_info(page)
        info["status"] = response.status if response is not None else None
        return info

    async def _element_rows(self, page: Page, max_elements: int) -> list[dict[str, Any]]:
        return await page.evaluate(
            """(limit) => {
                document.querySelectorAll('[data-qwen-ref]').forEach(el => el.removeAttribute('data-qwen-ref'));
                const all = Array.from(document.querySelectorAll('a,button,input,textarea,select,[role],summary'));
                const visible = all.filter(el => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                }).slice(0, limit);
                return visible.map((el, i) => {
                    const ref = `e${i + 1}`;
                    el.setAttribute('data-qwen-ref', ref);
                    const name = (el.getAttribute('aria-label') || el.innerText || el.value || el.getAttribute('placeholder') || '').trim().slice(0, 500);
                    return {
                        ref,
                        tag: el.tagName.toLowerCase(),
                        role: el.getAttribute('role'),
                        name,
                        href: el.href || null,
                        type: el.getAttribute('type'),
                    };
                });
            }""",
            max_elements,
        )

    async def read_page(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        max_chars = args.get("max_chars", 50000)
        include_elements = args.get("include_elements", True)
        max_elements = args.get("max_elements", 200)
        if isinstance(max_chars, bool) or not isinstance(max_chars, int) or not 1 <= max_chars <= 200000:
            raise BrowserAppError("max_chars is out of range")
        if (
            not isinstance(include_elements, bool)
            or isinstance(max_elements, bool)
            or not isinstance(max_elements, int)
            or not 1 <= max_elements <= 500
        ):
            raise BrowserAppError("invalid read_page options")
        body = await page.evaluate(
            """(limit) => {
                const text = document.body ? document.body.innerText : '';
                return {text: text.slice(0, limit), truncated: text.length > limit};
            }""",
            max_chars,
        )
        if not isinstance(body, dict) or not isinstance(body.get("text"), str) or not isinstance(body.get("truncated"), bool):
            raise BrowserAppError("page text extraction returned an invalid result")
        result = await self._page_info(page)
        result.update(body)
        result["elements"] = await self._element_rows(page, max_elements) if include_elements else []
        return result

    def _ref_locator(self, page: Page, value: object):
        if not isinstance(value, str) or not REF_PATTERN.fullmatch(value):
            raise BrowserAppError("invalid element reference")
        locator = page.locator(f'[data-qwen-ref="{value}"]')
        return locator

    async def click(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        locator = self._ref_locator(page, args.get("ref"))
        if await locator.count() != 1 or not await locator.is_visible():
            raise BrowserAppError("element reference is stale or not visible; call read_page again")
        await locator.click()
        await page.wait_for_timeout(250)
        return await self._page_info(page)

    async def type_text(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        locator = self._ref_locator(page, args.get("ref"))
        text = args.get("text")
        clear = args.get("clear", True)
        submit = args.get("submit", False)
        if not isinstance(text, str) or not isinstance(clear, bool) or not isinstance(submit, bool):
            raise BrowserAppError("invalid type arguments")
        if await locator.count() != 1 or not await locator.is_visible():
            raise BrowserAppError("element reference is stale or not visible; call read_page again")
        if clear:
            await locator.fill(text)
        else:
            await locator.press("End")
            await locator.type(text)
        if submit:
            await locator.press("Enter")
        return await self._page_info(page)

    async def press(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        key = args.get("key")
        if key not in ALLOWED_KEYS:
            raise BrowserAppError("key is not allowed")
        ref = args.get("ref")
        if ref is None:
            await page.keyboard.press(key)
        else:
            locator = self._ref_locator(page, ref)
            if await locator.count() != 1:
                raise BrowserAppError("element reference is stale; call read_page again")
            await locator.press(key)
        return await self._page_info(page)

    async def wait(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        seconds = args.get("seconds", 1)
        text = args.get("text")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 <= float(seconds) <= 30:
            raise BrowserAppError("seconds is out of range")
        if text is not None and not isinstance(text, str):
            raise BrowserAppError("text must be a string or null")
        if text:
            await page.get_by_text(text, exact=True).first.wait_for(state="visible", timeout=max(1, int(float(seconds) * 1000)))
        else:
            await page.wait_for_timeout(int(float(seconds) * 1000))
        return await self._page_info(page)

    async def screenshot(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        full_page = args.get("full_page", False)
        if not isinstance(full_page, bool):
            raise BrowserAppError("full_page must be a boolean")
        content = await page.screenshot(type="png", full_page=full_page)
        if len(content) > MAX_SCREENSHOT_BYTES:
            raise BrowserAppError("screenshot exceeds the 8 MiB result limit")
        return {
            **(await self._page_info(page)),
            "mime_type": "image/png",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    async def download(self, args: dict[str, Any]) -> dict[str, Any]:
        page = self._ready_page()
        locator = self._ref_locator(page, args.get("ref"))
        max_bytes = args.get("max_bytes", 5242880)
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 10485760:
            raise BrowserAppError("max_bytes is out of range")
        if await locator.count() != 1 or not await locator.is_visible():
            raise BrowserAppError("element reference is stale or not visible")
        async with page.expect_download(timeout=45000) as info:
            await locator.click()
        item = await info.value
        failure = await item.failure()
        if failure:
            raise BrowserAppError(f"download failed: {failure}")
        temp_path = await item.path()
        if temp_path is None:
            raise BrowserAppError("download has no local content")
        path = Path(temp_path)
        size = path.stat().st_size
        if size > max_bytes:
            path.unlink(missing_ok=True)
            raise BrowserAppError(f"download exceeds {max_bytes} bytes")
        content = path.read_bytes()
        return {
            "filename": Path(item.suggested_filename).name,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    async def tabs(self, args: dict[str, Any]) -> dict[str, Any]:
        self._ready_page()
        assert self.context is not None and self.page is not None
        action = args.get("action", "list")
        index = args.get("index")
        url = args.get("url")
        if action not in {"list", "new", "select", "close"}:
            raise BrowserAppError("invalid tabs action")
        pages = list(self.context.pages)
        if action == "new":
            target = await self.context.new_page()
            self.page = target
            if url is not None:
                await self.policy.validate_url(url)
                await target.goto(url, wait_until="domcontentloaded")
        elif action in {"select", "close"}:
            if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(pages):
                raise BrowserAppError("tab index is out of range")
            if action == "select":
                self.page = pages[index]
                await self.page.bring_to_front()
            else:
                closing = pages[index]
                await closing.close()
                remaining = list(self.context.pages)
                self.page = remaining[-1] if remaining else await self.context.new_page()
        pages = list(self.context.pages)
        return {
            "active_index": pages.index(self.page),
            "tabs": [
                {"index": position, "url": page.url, "title": await page.title()}
                for position, page in enumerate(pages)
            ],
        }

    async def search(self, args: dict[str, Any]) -> dict[str, Any]:
        query = args.get("query")
        max_results = args.get("max_results", 10)
        if (
            not isinstance(query, str)
            or not query
            or len(query) > 4096
            or isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= 20
        ):
            raise BrowserAppError("invalid search arguments")
        url = self.search_url_template.replace("{query}", quote_plus(query))
        await self.navigate({"url": url, "wait_until": "domcontentloaded"})
        page = self._ready_page()
        rows = await self._element_rows(page, 500)
        search_host = (urlparse(url).hostname or "").casefold()
        results: list[dict[str, str]] = []
        seen: set[str] = set()
        for row in rows:
            href = row.get("href")
            name = row.get("name")
            if not isinstance(href, str) or not isinstance(name, str) or not name:
                continue
            parsed = urlparse(href)
            if (parsed.hostname or "").casefold() == search_host:
                redirected = parse_qs(parsed.query).get("uddg", [])
                if redirected:
                    href = unquote(redirected[0])
                    parsed = urlparse(href)
            if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").casefold() == search_host:
                continue
            try:
                href = await self.policy.validate_url(href)
            except BrowserAppError:
                continue
            if href in seen:
                continue
            seen.add(href)
            results.append({"title": name, "url": href, "ref": row["ref"]})
            if len(results) >= max_results:
                break
        return {"query": query, "search_url": url, "results": results}

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        async with self.lock:
            if name == "search":
                return await self.search(arguments)
            if name == "navigate":
                return await self.navigate(arguments)
            if name == "read_page":
                return await self.read_page(arguments)
            if name == "click":
                return await self.click(arguments)
            if name == "type":
                return await self.type_text(arguments)
            if name == "press":
                return await self.press(arguments)
            if name == "wait":
                return await self.wait(arguments)
            if name == "screenshot":
                return await self.screenshot(arguments)
            if name == "download":
                return await self.download(arguments)
            if name == "tabs":
                return await self.tabs(arguments)
            raise BrowserAppError(f"unknown tool: {name}")

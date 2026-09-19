from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse, urlunparse

import httpx
from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright

from .exceptions import BrowserConnectionError


@dataclass(slots=True)
class BrowserSession:
    playwright: Playwright
    browser: Browser
    context: BrowserContext
    page: Page

    async def disconnect(self) -> None:
        await self.playwright.stop()


class BrowserClient:
    def __init__(
        self,
        cdp_url: str,
        *,
        humanize: bool = True,
        humanize_preset: str = "default",
    ) -> None:
        self._cdp_url = cdp_url
        self._humanize = humanize
        self._humanize_preset = humanize_preset

    @staticmethod
    def check_humanize_api(preset: str) -> None:
        from cloakbrowser.human import patch_browser_async  # noqa: F401
        from cloakbrowser.human.config import resolve_config

        resolve_config(preset)

    async def assert_existing_process(self) -> None:
        """Refuse resume if CloakBrowser would have to spawn a new Chromium."""
        parsed = urlparse(self._cdp_url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        seed = params.get("fingerprint", "")
        if not seed:
            raise BrowserConnectionError(
                "resume requires a fingerprint-bound CloakBrowser CDP URL"
            )

        # cloakserve root is status-only. Do not probe /json/version here: that
        # endpoint may materialize a Chromium process for the requested seed.
        status_url = urlunparse(parsed._replace(path="/", query="", fragment=""))
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(status_url)
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BrowserConnectionError(
                "resume requires the existing CloakBrowser service; "
                "refusing to start or replace it"
            ) from exc

        processes = payload.get("processes") if isinstance(payload, dict) else None
        item = processes.get(seed) if isinstance(processes, dict) else None
        if not isinstance(item, dict) or str(item.get("seed")) != seed:
            raise BrowserConnectionError(
                "resume requires the existing fingerprint-bound Chromium "
                f"process {seed}; refusing to spawn a fresh browser"
            )

    async def connect(
        self,
        *,
        require_existing_page: bool = False,
    ) -> BrowserSession:
        pw = await async_playwright().start()
        try:
            browser = await pw.chromium.connect_over_cdp(self._cdp_url, timeout=30_000)
        except Exception as exc:
            await pw.stop()
            raise BrowserConnectionError(f"cannot connect to {self._cdp_url}: {exc}") from exc

        if len(browser.contexts) != 1:
            await pw.stop()
            raise BrowserConnectionError(
                f"expected exactly one persistent browser context, got {len(browser.contexts)}"
            )

        if self._humanize:
            try:
                from cloakbrowser.human import patch_browser_async
                from cloakbrowser.human.config import resolve_config

                patch_browser_async(browser, resolve_config(self._humanize_preset))
            except Exception as exc:
                await pw.stop()
                raise BrowserConnectionError(
                    "connected to CloakBrowser but could not apply humanize "
                    f"({self._humanize_preset!r}): {exc}"
                ) from exc

        context = browser.contexts[0]
        if len(context.pages) > 1:
            await pw.stop()
            raise BrowserConnectionError(
                f"expected at most one browser page, got {len(context.pages)}; close extra tabs"
            )
        if require_existing_page and len(context.pages) != 1:
            await pw.stop()
            raise BrowserConnectionError(
                "crash recovery requires the existing ChatGPT page; "
                "refusing to create a replacement page"
            )
        page = context.pages[0] if context.pages else await context.new_page()
        return BrowserSession(pw, browser, context, page)

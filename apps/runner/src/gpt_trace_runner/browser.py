from __future__ import annotations

from dataclasses import dataclass

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright

from .exceptions import BrowserConnectionError


@dataclass(slots=True)
class BrowserSession:
    playwright: Playwright
    browser: Browser
    context: BrowserContext
    page: Page

    async def disconnect(self) -> None:
        # Do not close the remote browser process; only drop this CDP client.
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

    async def connect(self) -> BrowserSession:
        pw = await async_playwright().start()
        try:
            browser = await pw.chromium.connect_over_cdp(
                self._cdp_url,
                timeout=30_000,
            )
        except Exception as exc:
            await pw.stop()
            raise BrowserConnectionError(
                f"cannot connect to {self._cdp_url}: {exc}"
            ) from exc

        if not browser.contexts:
            await pw.stop()
            raise BrowserConnectionError("remote browser has no default context")

        if self._humanize:
            try:
                # cloakserve exposes the remote Chromium over CDP, but the
                # Python human-behaviour layer patches the local Playwright
                # Browser/Page/Locator objects. Apply it immediately after CDP
                # connection so every existing and future page is covered.
                from cloakbrowser.human import patch_browser_async
                from cloakbrowser.human.config import resolve_config

                patch_browser_async(
                    browser,
                    resolve_config(self._humanize_preset),
                )
            except Exception as exc:
                await pw.stop()
                raise BrowserConnectionError(
                    "connected to CloakBrowser but could not apply its humanize "
                    f"layer ({self._humanize_preset!r}): {exc}"
                ) from exc

        context = browser.contexts[0]
        page = context.pages[0] if context.pages else await context.new_page()
        return BrowserSession(pw, browser, context, page)

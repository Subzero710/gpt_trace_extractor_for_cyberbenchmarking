from __future__ import annotations

import httpx
from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError


class InteractionGuard:
    """Drive visible UI controls only after the real page is active."""

    def __init__(
        self,
        page: Page,
        *,
        clipboard_url: str,
        timeout_seconds: float,
    ) -> None:
        self._page = page
        self._clipboard_url = clipboard_url
        self._timeout_ms = int(timeout_seconds * 1000)

    async def ensure_page_focus(self) -> None:
        try:
            state = await self._page.evaluate(
                """() => ({
                    visible: document.visibilityState === 'visible',
                    focused: document.hasFocus(),
                })"""
            )
        except Exception as exc:
            raise ChatGPTUIError("could not inspect ChatGPT foreground state") from exc

        if state.get("visible") and state.get("focused"):
            return

        await self._page.bring_to_front()
        try:
            await self._page.wait_for_function(
                "() => document.visibilityState === 'visible' && document.hasFocus()",
                timeout=self._timeout_ms,
            )
        except Exception as exc:
            raise ChatGPTUIError(
                "ChatGPT page did not obtain real foreground focus"
            ) from exc

    async def click(self, locator: Locator, *, timeout_ms: int | None = None) -> None:
        await self.ensure_page_focus()
        timeout = timeout_ms or self._timeout_ms
        try:
            await locator.wait_for(state="visible", timeout=timeout)
            if not await locator.is_enabled():
                raise ChatGPTUIError("target control is visible but disabled")
            # When BrowserClient humanize is enabled, CloakBrowser patches this
            # Locator.click() path with its mouse/actionability implementation.
            await locator.click(timeout=timeout)
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError("browser UI click failed") from exc

    async def _set_system_clipboard(self, text: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self._clipboard_url,
                    content=text.encode("utf-8"),
                    headers={"content-type": "text/plain; charset=utf-8"},
                )
                response.raise_for_status()
        except Exception as exc:
            raise ChatGPTUIError(
                "browser X11 clipboard helper is unavailable"
            ) from exc

    async def paste_text(self, locator: Locator, text: str) -> None:
        """Put prepared text on the browser's X11 clipboard and paste it normally."""
        await self.ensure_page_focus()
        try:
            await locator.wait_for(state="visible", timeout=self._timeout_ms)
            await self.click(locator, timeout_ms=self._timeout_ms)
            await locator.press("Control+A")
            await locator.press("Backspace")
            await self._set_system_clipboard(text)
            await locator.press("Control+V")
            rendered = await locator.inner_text(timeout=self._timeout_ms)
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError(
                "could not paste benchmark prompt through the system clipboard"
            ) from exc

        if rendered.strip() != text.strip():
            raise ChatGPTUIError(
                "composer content does not match the benchmark prompt after paste"
            )

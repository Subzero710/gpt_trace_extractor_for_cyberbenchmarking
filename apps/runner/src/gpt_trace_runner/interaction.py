from __future__ import annotations

from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError


class InteractionGuard:
    """Use ordinary browser/UI interactions only after the page is truly active."""

    def __init__(
        self,
        page: Page,
        *,
        origin: str,
        timeout_seconds: float,
    ) -> None:
        self._page = page
        self._origin = origin.rstrip("/")
        self._timeout_ms = int(timeout_seconds * 1000)

    async def ensure_page_focus(self) -> None:
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
            await locator.click(timeout=timeout)
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError("browser UI click failed") from exc

    async def paste_text(self, locator: Locator, text: str) -> None:
        """Paste prepared benchmark text through Chromium's clipboard path."""
        await self.ensure_page_focus()
        try:
            await locator.wait_for(state="visible", timeout=self._timeout_ms)
            await locator.click(timeout=self._timeout_ms)
            await locator.press("Control+A")
            await locator.press("Backspace")
            await self._page.context.grant_permissions(
                ["clipboard-read", "clipboard-write"],
                origin=self._origin,
            )
            await self._page.evaluate(
                "text => navigator.clipboard.writeText(text)",
                text,
            )
            await locator.press("Control+V")
            rendered = await locator.evaluate(
                "el => (el.innerText || el.textContent || '').trim()"
            )
        except Exception as exc:
            raise ChatGPTUIError(
                "could not paste benchmark prompt through the browser clipboard"
            ) from exc

        if rendered.strip() != text.strip():
            raise ChatGPTUIError(
                "composer content does not match the benchmark prompt after paste"
            )

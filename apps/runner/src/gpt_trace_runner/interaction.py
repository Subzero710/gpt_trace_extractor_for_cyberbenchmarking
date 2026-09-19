from __future__ import annotations

import asyncio
import httpx
from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError, ClipboardUnavailable, FatalUIState


class InteractionGuard:
    """Drive visible controls while keeping focus and clipboard state coherent."""

    def __init__(self, page: Page, *, clipboard_url: str, timeout_seconds: float) -> None:
        self._page = page
        self._clipboard_url = clipboard_url
        self._timeout_ms = int(timeout_seconds * 1000)

    async def ensure_page_focus(self) -> None:
        try:
            state = await self._page.evaluate(
                "() => ({visible: document.visibilityState === 'visible', focused: document.hasFocus()})"
            )
        except Exception as exc:
            raise FatalUIState("could not inspect ChatGPT foreground state") from exc
        if state.get("visible") and state.get("focused"):
            return
        await self._page.bring_to_front()
        try:
            await self._page.wait_for_function(
                "() => document.visibilityState === 'visible' && document.hasFocus()",
                timeout=self._timeout_ms,
            )
        except Exception as exc:
            raise FatalUIState("ChatGPT page did not obtain foreground focus") from exc

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

    async def focus(self, locator: Locator, *, timeout_ms: int | None = None) -> None:
        # Focus a contenteditable without generating a pointer click. This is
        # required when structured App chips are already present in the
        # composer: clicking the editor can activate the chip/link itself.
        await self.ensure_page_focus()
        timeout = timeout_ms or self._timeout_ms
        try:
            await locator.wait_for(state="visible", timeout=timeout)
            await locator.focus(timeout=timeout)
            owns_focus = await locator.evaluate(
                "el => el === document.activeElement || "
                "el.contains(document.activeElement)"
            )
            if not owns_focus:
                raise ChatGPTUIError(
                    "target editor is visible but did not obtain keyboard focus"
                )
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError("browser UI focus failed") from exc

    async def type_text(
        self,
        locator: Locator,
        text: str,
        *,
        clear_existing: bool = True,
    ) -> None:
        """Type benchmark text through real keyboard events.

        CloakBrowser owns keyboard humanization. Newlines use Shift+Enter so a
        multiline prompt cannot submit before composition is complete.

        When clear_existing is False, preserve any structured App mentions
        already present in the composer, append one separating space when
        needed, and validate only the newly appended prompt suffix.
        """
        try:
            # Never click the composer to type. If a structured App mention is
            # present, a pointer click may activate its link/details.
            await self.focus(locator, timeout_ms=self._timeout_ms)

            existing = ""
            if clear_existing:
                await locator.press("Control+A")
                await locator.press("Backspace")
            else:
                existing = (
                    await locator.inner_text(timeout=self._timeout_ms)
                ).replace("\r\n", "\n").replace("\r", "\n")
                await locator.press("Control+End")
                if existing and not existing.endswith((" ", "\n")):
                    await self._page.keyboard.type(" ")

            expected = text.replace("\r\n", "\n").replace("\r", "\n")
            for index, line in enumerate(expected.split("\n")):
                if index:
                    await self._page.keyboard.press("Shift+Enter")
                if line:
                    await self._page.keyboard.type(line)

            deadline = asyncio.get_running_loop().time() + (self._timeout_ms / 1000)
            rendered = ""
            while asyncio.get_running_loop().time() < deadline:
                rendered = (
                    await locator.inner_text(timeout=self._timeout_ms)
                ).replace("\r\n", "\n").replace("\r", "\n")
                if clear_existing:
                    if rendered == expected:
                        return
                elif rendered.endswith(expected):
                    return
                await asyncio.sleep(0.05)
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError("could not type benchmark prompt") from exc

        raise ChatGPTUIError(
            "composer text differs from benchmark prompt after keyboard entry"
        )

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
            raise ClipboardUnavailable("browser X11 clipboard helper is unavailable") from exc

    async def clear_system_clipboard(self) -> None:
        await self._set_system_clipboard("")

    async def paste_text(self, locator: Locator, text: str, *, clear_existing: bool = True) -> None:
        """Paste prepared text through the browser's real X11 clipboard."""
        await self.ensure_page_focus()
        try:
            await locator.wait_for(state="visible", timeout=self._timeout_ms)
            await self.click(locator, timeout_ms=self._timeout_ms)
            if clear_existing:
                await locator.press("Control+A")
                await locator.press("Backspace")
            await self._set_system_clipboard(text)
            await locator.press("Control+V")

            # ChatGPT's Lexical composer applies paste updates asynchronously.
            # inner_text() returns immediately; it does not wait for the editor
            # model to commit the pasted content. Keep the real X11 clipboard
            # populated until the visible editor actually contains text.
            rendered = ""
            if text:
                deadline = asyncio.get_running_loop().time() + (self._timeout_ms / 1000)
                while asyncio.get_running_loop().time() < deadline:
                    rendered = await locator.inner_text(timeout=self._timeout_ms)
                    if rendered:
                        break
                    await asyncio.sleep(0.05)
            else:
                rendered = await locator.inner_text(timeout=self._timeout_ms)
        except (ChatGPTUIError, ClipboardUnavailable):
            raise
        except Exception as exc:
            raise ChatGPTUIError("could not paste benchmark prompt") from exc
        finally:
            # Do not leave benchmark text in the persistent desktop clipboard.
            try:
                await self.clear_system_clipboard()
            except ClipboardUnavailable:
                # Clearing failure is still a global infrastructure failure.
                raise

        if text and not rendered:
            raise ChatGPTUIError("composer is empty after benchmark prompt paste")

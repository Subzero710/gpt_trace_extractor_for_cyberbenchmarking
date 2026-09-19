from __future__ import annotations

import asyncio
import httpx
from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError, ClipboardUnavailable, FatalUIState


_COMPOSER_INPUT_RECEIPT_JS = r"""
(el, op) => {
    const key = "__gptTraceInputReceiptV1";

    const decode = event => {
        if (!event.isTrusted) return null;

        const inputType = event.inputType || "";
        if (
            inputType === "insertLineBreak" ||
            inputType === "insertParagraph"
        ) {
            return "\n";
        }

        if (
            inputType === "insertText" ||
            inputType === "insertCompositionText"
        ) {
            return typeof event.data === "string" ? event.data : null;
        }

        return null;
    };

    const cleanup = slot => {
        try {
            el.removeEventListener("beforeinput", slot.beforeHandler, true);
            el.removeEventListener("input", slot.inputHandler, true);
        } catch (_) {
        }
        try {
            slot.observer.disconnect();
        } catch (_) {
        }
    };

    if (op === "start") {
        const previous = el[key];
        if (previous) {
            cleanup(previous);
            delete el[key];
        }

        const state = {
            before: [],
            input: [],
            mutations: 0,
        };

        const beforeHandler = event => {
            const chunk = decode(event);
            if (chunk !== null) state.before.push(chunk);
        };
        const inputHandler = event => {
            const chunk = decode(event);
            if (chunk !== null) state.input.push(chunk);
        };
        const observer = new MutationObserver(records => {
            state.mutations += records.length;
        });

        el.addEventListener("beforeinput", beforeHandler, true);
        el.addEventListener("input", inputHandler, true);
        observer.observe(el, {
            subtree: true,
            childList: true,
            characterData: true,
        });

        el[key] = {
            state,
            beforeHandler,
            inputHandler,
            observer,
        };
        return true;
    }

    const slot = el[key];
    if (!slot) return null;

    if (op === "stop") {
        try {
            slot.state.mutations += slot.observer.takeRecords().length;
        } catch (_) {
        }

        const result = {
            before: slot.state.before.join(""),
            input: slot.state.input.join(""),
            mutations: slot.state.mutations,
        };

        cleanup(slot);
        delete el[key];
        return result;
    }

    if (op === "cancel") {
        cleanup(slot);
        delete el[key];
        return true;
    }

    throw new Error("unknown input receipt operation");
}
"""


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

        Validation is against the exact trusted browser input events received by
        the composer, not Lexical's rendered innerText. Lexical may legitimately
        turn Markdown-like source into structured DOM after the keystrokes are
        accepted.
        """
        receipt_started = False
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

            await locator.evaluate(_COMPOSER_INPUT_RECEIPT_JS, "start")
            receipt_started = True

            for index, line in enumerate(expected.split("\n")):
                if index:
                    await self._page.keyboard.press("Shift+Enter")
                if line:
                    await self._page.keyboard.type(line)

            receipt = await locator.evaluate(
                _COMPOSER_INPUT_RECEIPT_JS,
                "stop",
            )
            receipt_started = False

            if not isinstance(receipt, dict):
                raise ChatGPTUIError(
                    "composer input receipt was unavailable after keyboard entry"
                )

            before = receipt.get("before")
            after = receipt.get("input")
            mutations = receipt.get("mutations")

            exact_before = before == expected
            exact_after = after == expected
            committed_via_dom = (
                exact_before
                and isinstance(mutations, int)
                and mutations > 0
            )

            # Native input is post-edit. If Lexical prevents native editing and
            # commits its own editor-model update, the exact beforeinput stream
            # plus an observed DOM mutation is the equivalent proof.
            if exact_after or committed_via_dom:
                return

            raise ChatGPTUIError(
                "composer keyboard input receipt differs from benchmark prompt"
            )
        except ChatGPTUIError:
            raise
        except Exception as exc:
            raise ChatGPTUIError("could not type benchmark prompt") from exc
        finally:
            if receipt_started:
                try:
                    await locator.evaluate(
                        _COMPOSER_INPUT_RECEIPT_JS,
                        "cancel",
                    )
                except Exception:
                    pass

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

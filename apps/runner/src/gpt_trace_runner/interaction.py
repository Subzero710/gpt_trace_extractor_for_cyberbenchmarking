from __future__ import annotations

import asyncio
import httpx
from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError, ClipboardUnavailable, FatalUIState


_COMPOSER_INPUT_RECEIPT_JS = r"""
(el, op) => {
    const key = "__gptTraceInputReceiptV2";

    const dropLastGrapheme = value => {
        if (!value) return "";

        try {
            if (typeof Intl !== "undefined" && Intl.Segmenter) {
                const segments = Array.from(
                    new Intl.Segmenter(undefined, {granularity: "grapheme"})
                        .segment(value)
                );
                if (!segments.length) return "";
                return value.slice(0, segments[segments.length - 1].index);
            }
        } catch (_) {
        }

        const codepoints = Array.from(value);
        codepoints.pop();
        return codepoints.join("");
    };

    const appendChunk = (state, field, chunk) => {
        if (typeof chunk !== "string" || chunk === "") return;
        state[field] += chunk;
    };

    const deleteBackward = (state, field) => {
        state[field] = dropLastGrapheme(state[field]);
        state.corrections[field] += 1;
    };

    const applyInputEdit = (state, field, event) => {
        const inputType = event.inputType || "";

        if (inputType === "deleteContentBackward") {
            deleteBackward(state, field);
            return;
        }

        if (
            inputType === "insertLineBreak" ||
            inputType === "insertParagraph"
        ) {
            appendChunk(state, field, "\n");
            return;
        }

        if (typeof event.data === "string" && inputType.startsWith("insert")) {
            appendChunk(state, field, event.data);
        }
    };

    const applyKeyEdit = (state, event) => {
        if (event.ctrlKey || event.metaKey || event.altKey) return;

        if (event.key === "Backspace") {
            deleteBackward(state, "keydown");
            // textInput reports inserted text but has no matching deletion
            // event in Chromium. Mirror the same physical Backspace so this
            // channel also represents effective text rather than raw inserts.
            deleteBackward(state, "textInput");
            return;
        }

        if (event.key === "Enter" && event.shiftKey) {
            appendChunk(state, "keydown", "\n");
            return;
        }

        if (typeof event.key === "string" && event.key.length === 1) {
            appendChunk(state, "keydown", event.key);
        }
    };

    const bump = (state, kind, event) => {
        const trustedKey = event.isTrusted ? "trusted" : "untrusted";
        state.trust[trustedKey] += 1;
        const type = event.inputType || event.type || "unknown";
        state.types[kind][type] = (state.types[kind][type] || 0) + 1;
    };

    const cleanup = slot => {
        try {
            el.removeEventListener("beforeinput", slot.beforeHandler, true);
            el.removeEventListener("input", slot.inputHandler, true);
            el.removeEventListener("textInput", slot.textHandler, true);
            el.removeEventListener("keydown", slot.keyHandler, true);
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
            before: "",
            input: "",
            textInput: "",
            keydown: "",
            mutations: 0,
            linebreaks: 0,
            corrections: {
                before: 0,
                input: 0,
                textInput: 0,
                keydown: 0,
            },
            trust: {trusted: 0, untrusted: 0},
            types: {
                beforeinput: {},
                input: {},
                textInput: {},
                keydown: {},
            },
        };

        const beforeHandler = event => {
            bump(state, "beforeinput", event);
            applyInputEdit(state, "before", event);
        };
        const inputHandler = event => {
            bump(state, "input", event);
            applyInputEdit(state, "input", event);
        };
        const textHandler = event => {
            bump(state, "textInput", event);
            if (typeof event.data === "string") {
                appendChunk(state, "textInput", event.data);
            }
        };
        const keyHandler = event => {
            bump(state, "keydown", event);
            // CloakBrowser/Chromium can materialize Shift+Enter while exposing
            // the Enter keydown without preserving shiftKey on the observed
            // event. Count the physical Enter separately; during benchmark
            // prompt entry every Enter is issued by us as Shift+Enter.
            if (event.key === "Enter") {
                state.linebreaks += 1;
            }
            applyKeyEdit(state, event);
        };
        const observer = new MutationObserver(records => {
            state.mutations += records.length;
        });

        el.addEventListener("beforeinput", beforeHandler, true);
        el.addEventListener("input", inputHandler, true);
        el.addEventListener("textInput", textHandler, true);
        el.addEventListener("keydown", keyHandler, true);
        observer.observe(el, {
            subtree: true,
            childList: true,
            characterData: true,
        });

        el[key] = {
            state,
            beforeHandler,
            inputHandler,
            textHandler,
            keyHandler,
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
            before: slot.state.before,
            input: slot.state.input,
            textInput: slot.state.textInput,
            keydown: slot.state.keydown,
            mutations: slot.state.mutations,
            linebreaks: slot.state.linebreaks,
            corrections: slot.state.corrections,
            trust: slot.state.trust,
            types: slot.state.types,
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
            separator = ""
            if clear_existing:
                await locator.press("Control+A")
                await locator.press("Backspace")
            else:
                existing = (
                    await locator.inner_text(timeout=self._timeout_ms)
                ).replace("\r\n", "\n").replace("\r", "\n")
                await locator.press("Control+End")
                if existing and not existing.endswith((" ", "\n")):
                    separator = " "

            expected_prompt = text.replace("\r\n", "\n").replace("\r", "\n")
            expected_receipt = separator + expected_prompt

            # Keep separator + prompt in one ordered keyboard stream. CloakBrowser
            # humanization may defer actual key delivery, so a standalone space
            # can otherwise arrive late and interleave with prompt characters.
            await locator.evaluate(_COMPOSER_INPUT_RECEIPT_JS, "start")
            receipt_started = True

            for index, line in enumerate(expected_receipt.split("\n")):
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
            text_input = receipt.get("textInput")
            keydown = receipt.get("keydown")
            mutations = receipt.get("mutations")
            linebreaks = receipt.get("linebreaks")

            # input/textInput are post-edit channels. beforeinput/keydown prove
            # the exact source reached the editor boundary, so require an
            # observed DOM mutation when using either as the fallback proof.
            exact_post_edit = (
                after == expected_receipt
                or text_input == expected_receipt
            )
            exact_pre_edit = (
                before == expected_receipt
                or keydown == expected_receipt
            )
            mutated = isinstance(mutations, int) and mutations > 0

            if exact_post_edit or (exact_pre_edit and mutated):
                return

            # Some Chromium/CloakBrowser paths insert Shift+Enter correctly but
            # omit the line break from beforeinput/input/textInput.data and may
            # expose Enter without shiftKey in keydown. In that case require two
            # independent proofs: every non-newline source character must still
            # match exactly in at least one receipt channel, and the observed
            # physical Enter count must equal the requested newline count.
            expected_without_newlines = expected_receipt.replace("\n", "")
            newline_count = expected_receipt.count("\n")
            exact_without_newlines = any(
                channel == expected_without_newlines
                for channel in (before, after, text_input, keydown)
            )
            exact_linebreak_count = (
                isinstance(linebreaks, int)
                and linebreaks == newline_count
            )
            if (
                newline_count > 0
                and exact_without_newlines
                and exact_linebreak_count
                and mutated
            ):
                return

            def first_mismatch(actual: object) -> int | None:
                if not isinstance(actual, str):
                    return None
                limit = min(len(expected_receipt), len(actual))
                for index in range(limit):
                    if expected_receipt[index] != actual[index]:
                        return index
                if len(expected_receipt) != len(actual):
                    return limit
                return None

            details = {
                "prompt_len": len(expected_prompt),
                "separator_len": len(separator),
                "expected_receipt_len": len(expected_receipt),
                "before_len": len(before) if isinstance(before, str) else None,
                "input_len": len(after) if isinstance(after, str) else None,
                "text_input_len": (
                    len(text_input) if isinstance(text_input, str) else None
                ),
                "keydown_len": len(keydown) if isinstance(keydown, str) else None,
                "before_mismatch": first_mismatch(before),
                "input_mismatch": first_mismatch(after),
                "text_input_mismatch": first_mismatch(text_input),
                "keydown_mismatch": first_mismatch(keydown),
                "mutations": mutations,
                "linebreaks": linebreaks,
                "corrections": receipt.get("corrections"),
                "trust": receipt.get("trust"),
                "types": receipt.get("types"),
            }
            raise ChatGPTUIError(
                "composer keyboard input receipt differs from benchmark prompt: "
                f"{details}"
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

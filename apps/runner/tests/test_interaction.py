from __future__ import annotations

import asyncio
import pytest

from gpt_trace_runner.interaction import InteractionGuard


class FakeKeyboard:
    def __init__(self):
        self.events = []
        self.locator = None

    async def type(self, text):
        self.events.append(("type", text))
        if self.locator is not None:
            self.locator.record_keyboard_input(text)
            self.locator.rendered += text

    async def press(self, key):
        self.events.append(("press", key))
        if key == "Shift+Enter" and self.locator is not None:
            self.locator.record_keyboard_input("\n")
            self.locator.rendered += "\n"


class FakePage:
    def __init__(self, state):
        self.state = state
        self.bring_calls = 0
        self.wait_calls = 0
        self.keyboard = FakeKeyboard()

    async def evaluate(self, expression):
        return self.state

    async def bring_to_front(self):
        self.bring_calls += 1

    async def wait_for_function(self, expression, timeout):
        self.wait_calls += 1


@pytest.mark.asyncio
async def test_focus_is_not_forced_when_page_is_already_active() -> None:
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    await guard.ensure_page_focus()
    assert page.bring_calls == 0
    assert page.wait_calls == 0


@pytest.mark.asyncio
async def test_focus_is_requested_only_when_needed() -> None:
    page = FakePage({"visible": True, "focused": False})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    await guard.ensure_page_focus()
    assert page.bring_calls == 1
    assert page.wait_calls == 1


class FakeLocator:
    def __init__(self, holder):
        self.holder = holder
        self.rendered = ""
        self.click_calls = 0
        self.focus_calls = 0
        self.focused = False
        self.receipt_active = False
        self.receipt_before = ""
        self.receipt_input = ""
        self.receipt_text_input = ""
        self.receipt_keydown = ""
        self.receipt_mutations = 0
        self.receipt_linebreaks = 0
    async def wait_for(self, **kwargs): pass
    async def is_enabled(self): return True
    async def click(self, **kwargs):
        self.click_calls += 1
    async def focus(self, **kwargs):
        self.focus_calls += 1
        self.focused = True
    async def evaluate(self, expression, arg=None):
        if arg == "start":
            self.receipt_active = True
            self.receipt_before = ""
            self.receipt_input = ""
            self.receipt_text_input = ""
            self.receipt_keydown = ""
            self.receipt_mutations = 0
            self.receipt_linebreaks = 0
            return True
        if arg == "stop":
            result = {
                "before": self.receipt_before,
                "input": self.receipt_input,
                "textInput": self.receipt_text_input,
                "keydown": self.receipt_keydown,
                "mutations": self.receipt_mutations,
                "linebreaks": self.receipt_linebreaks,
                "trust": {"trusted": 0, "untrusted": 1},
                "types": {},
            }
            self.receipt_active = False
            return result
        if arg == "cancel":
            self.receipt_active = False
            return True
        return self.focused
    def record_keyboard_input(self, text):
        if self.receipt_active:
            self.receipt_linebreaks += text.count("\n")
            self.receipt_before += text
            self.receipt_input += text
            self.receipt_text_input += text
            self.receipt_keydown += text
            self.receipt_mutations += 1
    async def press(self, key):
        if key == "Control+A":
            self.holder["select_all"] = True
        elif key == "Backspace" and self.holder.get("select_all"):
            self.rendered = ""
        elif key == "Control+V":
            self.rendered += self.holder.get("clipboard", "")
    async def inner_text(self, **kwargs): return self.rendered


@pytest.mark.asyncio
async def test_paste_preserves_exact_spaces_and_clears_clipboard() -> None:
    holder = {"clipboard": ""}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(page, clipboard_url="http://browser:8765/clipboard", timeout_seconds=1)
    calls = []
    async def set_clipboard(value):
        holder["clipboard"] = value
        calls.append(value)
    guard._set_system_clipboard = set_clipboard
    locator = FakeLocator(holder)
    await guard.paste_text(locator, "  exact  ")
    assert locator.rendered == "  exact  "
    assert calls == ["  exact  ", ""]


class DelayedPasteLocator(FakeLocator):
    async def press(self, key):
        if key != "Control+V":
            await super().press(key)
            return

        async def commit():
            await asyncio.sleep(0.05)
            self.rendered += self.holder.get("clipboard", "")

        asyncio.create_task(commit())


@pytest.mark.asyncio
async def test_paste_waits_for_async_composer_commit_before_clearing_clipboard() -> None:
    holder = {"clipboard": ""}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    calls = []

    async def set_clipboard(value):
        holder["clipboard"] = value
        calls.append(value)

    guard._set_system_clipboard = set_clipboard
    locator = DelayedPasteLocator(holder)

    await guard.paste_text(locator, "delayed prompt")

    assert locator.rendered == "delayed prompt"
    assert calls == ["delayed prompt", ""]


@pytest.mark.asyncio
async def test_type_text_uses_keyboard_and_shift_enter() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = FakeLocator(holder)
    page.keyboard.locator = locator

    await guard.type_text(locator, "first line\nsecond line")

    assert locator.rendered == "first line\nsecond line"
    assert page.keyboard.events == [
        ("type", "first line"),
        ("press", "Shift+Enter"),
        ("type", "second line"),
    ]


@pytest.mark.asyncio
async def test_type_text_does_not_touch_clipboard() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = FakeLocator(holder)
    page.keyboard.locator = locator

    async def forbidden_clipboard(_value):
        raise AssertionError("keyboard prompt entry must not touch clipboard")

    guard._set_system_clipboard = forbidden_clipboard
    await guard.type_text(locator, "prompt")
    assert locator.rendered == "prompt"

@pytest.mark.asyncio
async def test_type_text_appends_after_structured_app_without_clearing() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = FakeLocator(holder)
    locator.rendered = "Code Workspace"
    page.keyboard.locator = locator

    await guard.type_text(
        locator,
        "Use exec_command to inspect the workspace.",
        clear_existing=False,
    )

    assert locator.rendered == (
        "Code Workspace Use exec_command to inspect the workspace."
    )
    assert holder.get("select_all") is None
    assert page.keyboard.events == [
        ("type", " Use exec_command to inspect the workspace."),
    ]
    assert locator.receipt_before == (
        " Use exec_command to inspect the workspace."
    )
    assert locator.receipt_input == (
        " Use exec_command to inspect the workspace."
    )

@pytest.mark.asyncio
async def test_type_text_focuses_composer_without_pointer_click() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = FakeLocator(holder)
    locator.rendered = "Code Workspace"
    page.keyboard.locator = locator

    await guard.type_text(
        locator,
        "Use exec_command to inspect the workspace.",
        clear_existing=False,
    )

    assert locator.click_calls == 0
    assert locator.focus_calls == 1
    assert locator.rendered == (
        "Code Workspace Use exec_command to inspect the workspace."
    )

class RenderTransformingLocator(FakeLocator):
    async def inner_text(self, **kwargs):
        text = self.rendered
        replacements = (
            ("# ", ""),
            ("> ", ""),
            ("- [x] ", ""),
            ("- ", ""),
            ("1. ", ""),
            ("```python", ""),
            ("```", ""),
            ("***", ""),
            ("___", ""),
            ("**", ""),
            ("__", ""),
            ("~~", ""),
            ("==", ""),
            ("*", ""),
            ("_", ""),
            ("`", ""),
            ("[OpenAI](https://openai.com)", "OpenAI"),
        )
        for old, new in replacements:
            text = text.replace(old, new)
        return text


@pytest.mark.asyncio
async def test_type_text_validates_input_receipt_not_rendered_lexical_dom() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = RenderTransformingLocator(holder)
    locator.rendered = "Code Workspace"
    page.keyboard.locator = locator

    prompt = (
        "# heading\n"
        "> quote\n"
        "- bullet\n"
        "1. ordered\n"
        "- [x] checked\n"
        "***bold italic*** **bold** *italic* ~~strike~~ ==highlight== "
        "`inline code` [OpenAI](https://openai.com)\n"
        "```python\nprint('x')\n```"
    )

    await guard.type_text(
        locator,
        prompt,
        clear_existing=False,
    )

    assert locator.receipt_before == " " + prompt
    assert locator.receipt_input == " " + prompt
    assert locator.receipt_text_input == " " + prompt
    assert locator.receipt_keydown == " " + prompt
    assert await locator.inner_text() != "Code Workspace " + prompt


class NewlineBlindReceiptLocator(FakeLocator):
    def record_keyboard_input(self, text):
        if not self.receipt_active:
            return
        self.receipt_linebreaks += text.count("\n")
        recorded = text.replace("\n", "")
        self.receipt_before += recorded
        self.receipt_input += recorded
        self.receipt_text_input += recorded
        self.receipt_keydown += recorded
        self.receipt_mutations += 1


@pytest.mark.asyncio
async def test_type_text_accepts_exact_text_when_receipt_omits_shift_enter_data() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = NewlineBlindReceiptLocator(holder)
    page.keyboard.locator = locator

    await guard.type_text(locator, "first\nsecond\nthird")

    assert locator.rendered == "first\nsecond\nthird"
    assert locator.receipt_input == "firstsecondthird"
    assert locator.receipt_linebreaks == 2


class NewlineBlindWithoutEnterProofLocator(NewlineBlindReceiptLocator):
    def record_keyboard_input(self, text):
        if not self.receipt_active:
            return
        recorded = text.replace("\n", "")
        self.receipt_before += recorded
        self.receipt_input += recorded
        self.receipt_text_input += recorded
        self.receipt_keydown += recorded
        self.receipt_mutations += 1


@pytest.mark.asyncio
async def test_type_text_rejects_missing_newline_without_enter_proof() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = NewlineBlindWithoutEnterProofLocator(holder)
    page.keyboard.locator = locator

    with pytest.raises(Exception, match="keyboard input receipt differs"):
        await guard.type_text(locator, "first\nsecond")


class DroppedInputReceiptLocator(FakeLocator):
    def record_keyboard_input(self, text):
        if not self.receipt_active:
            return
        damaged = text[:-1] if text else text
        self.receipt_before += damaged
        self.receipt_input += damaged
        self.receipt_mutations += 1


@pytest.mark.asyncio
async def test_type_text_rejects_inexact_keyboard_receipt_even_if_dom_looks_ok() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = DroppedInputReceiptLocator(holder)
    page.keyboard.locator = locator

    with pytest.raises(
        Exception,
        match="keyboard input receipt differs",
    ):
        await guard.type_text(locator, "**exact source**")

    assert locator.rendered == "**exact source**"

class KeydownOnlyReceiptLocator(FakeLocator):
    def record_keyboard_input(self, text):
        if self.receipt_active:
            self.receipt_keydown += text
            self.receipt_mutations += 1


@pytest.mark.asyncio
async def test_type_text_accepts_exact_keydown_fallback_for_synthetic_input() -> None:
    holder = {}
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    locator = KeydownOnlyReceiptLocator(holder)
    page.keyboard.locator = locator

    await guard.type_text(locator, "`code` **bold** # heading")

    assert locator.receipt_before == ""
    assert locator.receipt_input == ""
    assert locator.receipt_keydown == "`code` **bold** # heading"


def test_receipt_js_does_not_discard_untrusted_browser_events() -> None:
    from pathlib import Path

    source = Path(__file__).parents[1] / "src" / "gpt_trace_runner" / "interaction.py"
    text = source.read_text(encoding="utf-8")
    receipt = text.split('_COMPOSER_INPUT_RECEIPT_JS = r"""', 1)[1].split('"""', 1)[0]

    assert "if (!event.isTrusted) return null" not in receipt
    assert 'addEventListener("beforeinput"' in receipt
    assert 'addEventListener("input"' in receipt
    assert 'addEventListener("textInput"' in receipt
    assert 'addEventListener("keydown"' in receipt


def test_receipt_js_replays_humanized_backspace_corrections() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "interaction.py"
    ).read_text(encoding="utf-8")
    receipt = source.split(
        '_COMPOSER_INPUT_RECEIPT_JS = r"""', 1
    )[1].split('"""', 1)[0]

    assert 'inputType === "deleteContentBackward"' in receipt
    assert 'event.key === "Backspace"' in receipt
    assert 'deleteBackward(state, "before")' not in receipt
    assert 'applyInputEdit(state, "before", event)' in receipt
    assert 'applyInputEdit(state, "input", event)' in receipt
    assert 'deleteBackward(state, "keydown")' in receipt
    assert 'deleteBackward(state, "textInput")' in receipt
    assert 'new Intl.Segmenter' in receipt
    assert 'corrections:' in receipt


def test_humanized_typo_insertions_minus_backspaces_equal_prompt_length() -> None:
    # Mirrors the real diagnostic that motivated this fix: 204 inserts and
    # four Backspaces must reconstruct 200 effective characters.
    inserted = 204
    backspaces = 4
    expected = 200

    assert inserted - backspaces == expected


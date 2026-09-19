from __future__ import annotations

from collections.abc import Awaitable, Callable

from playwright.async_api import (
    Locator,
    Page,
    TimeoutError as PlaywrightTimeoutError,
)

from .exceptions import AppUnavailable, FatalUIState
from .interaction import InteractionGuard
from .models import BenchmarkTool

# ChatGPT's @ mention autocomplete is the canonical App resolution path for the
# runner. The "+" / Tools menu is intentionally not used.
#
# App acceptance is validated from the current composer state. The HAR may show
# a context_change request, but that request is not required on every acceptance path.
# No composer Locator is reused across Apps.
#
# No artificial keyboard delay is added here. CloakBrowser owns humanization.

EditorGetter = Callable[[], Awaitable[Locator]]


_COMPOSER_ACCEPTED_JS = r"""
([rawMention, appName]) => {
    const selectors = [
        "#prompt-textarea",
        '[contenteditable="true"][data-lexical-editor="true"]',
    ];
    const seen = new Set();

    for (const selector of selectors) {
        for (const el of document.querySelectorAll(selector)) {
            if (seen.has(el)) continue;
            seen.add(el);

            const rect = el.getBoundingClientRect();
            const style = window.getComputedStyle(el);
            if (
                rect.width <= 0 ||
                rect.height <= 0 ||
                style.visibility === "hidden" ||
                style.display === "none"
            ) {
                continue;
            }

            const tail = (el.innerText || el.textContent || "").trimEnd();
            if (tail.endsWith(appName) && !tail.endsWith(rawMention)) {
                return true;
            }
        }
    }
    return false;
}
"""


async def _wait_app_accepted(
    page: Page,
    *,
    tool: BenchmarkTool,
    timeout_seconds: float,
) -> None:
    raw_mention = f"@{tool.name}"
    try:
        await page.wait_for_function(
            _COMPOSER_ACCEPTED_JS,
            arg=[raw_mention, tool.name],
            timeout=int(timeout_seconds * 1000),
        )
    except PlaywrightTimeoutError as exc:
        raise AppUnavailable(
            f"ChatGPT app {tool.name!r} was typed but Enter did not produce "
            "an accepted App mention in the current composer"
        ) from exc


def check_playwright_ui_contracts() -> None:
    """Fail fast if UI helper call shapes no longer match Playwright."""
    import ast
    import inspect

    signature = inspect.signature(Page.wait_for_function)
    arg_parameter = signature.parameters.get("arg")
    if (
        arg_parameter is None
        or arg_parameter.kind is not inspect.Parameter.KEYWORD_ONLY
    ):
        raise FatalUIState(
            "unexpected Playwright Page.wait_for_function signature"
        )

    source = inspect.getsource(_wait_app_accepted)
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "wait_for_function"
    ]
    if len(calls) != 1:
        raise FatalUIState(
            "expected exactly one wait_for_function call in _wait_app_accepted"
        )

    call = calls[0]
    keyword_names = {keyword.arg for keyword in call.keywords}
    if len(call.args) != 1 or "arg" not in keyword_names:
        raise FatalUIState(
            "Page.wait_for_function payload must be passed as keyword arg=..."
        )


async def _select_app_via_mention(
    page: Page,
    *,
    get_editor: EditorGetter,
    tool: BenchmarkTool,
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    if tool.type != "app":
        raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")

    editor = await get_editor()
    await interaction.click(editor)
    try:
        # Runtime composition can already contain the benchmark prompt. Keep it
        # intact and append the App mention at the end before Enter.
        await editor.press("Control+End")
    except Exception:
        pass

    try:
        before = await editor.inner_text()
    except Exception:
        before = ""

    if before and not before.endswith((" ", "\n")):
        await page.keyboard.type(" ")

    raw_mention = f"@{tool.name}"
    await page.keyboard.type("@")
    await page.keyboard.type(tool.name)

    typed_rendered = await editor.inner_text()
    if not typed_rendered.rstrip().endswith(raw_mention):
        raise AppUnavailable(
            f"ChatGPT app mention query {raw_mention!r} was not reflected in the composer"
        )

    await page.keyboard.press("Enter")

    # Enter may rebuild the Lexical composer. Do not keep reading the pre-Enter
    # element. Wait against the live DOM, then resolve the current composer.
    await _wait_app_accepted(
        page,
        tool=tool,
        timeout_seconds=timeout_seconds,
    )
    editor = await get_editor()
    rendered = await editor.inner_text()
    tail = rendered.rstrip()
    if not tail.endswith(tool.name) or tail.endswith(raw_mention):
        raise AppUnavailable(
            f"ChatGPT app {tool.name!r} acceptance was not reflected "
            "in the current composer"
        )


async def _composer_has_keyboard_focus(editor: Locator) -> bool:
    try:
        return bool(
            await editor.evaluate(
                "el => el === document.activeElement || el.contains(document.activeElement)"
            )
        )
    except Exception:
        return False


async def _clear_auth_editor(
    page: Page,
    *,
    get_editor: EditorGetter,
) -> None:
    """Clear auth scratch text with Backspace only, on the current composer."""
    editor = await get_editor()
    rendered = await editor.inner_text()
    max_backspaces = max(32, len(rendered) * 4 + 32)

    for _ in range(max_backspaces):
        if rendered == "":
            return

        # Never click during cleanup. If context_change did not leave keyboard
        # focus in the current composer, abort instead of acting somewhere else.
        if not await _composer_has_keyboard_focus(editor):
            raise FatalUIState(
                "auth scratch composer does not own keyboard focus"
            )

        await page.keyboard.press("Backspace")

        # Lexical may rebuild the editor after a key event. Resolve the current
        # composer again instead of retaining the old element reference.
        editor = await get_editor()
        rendered = await editor.inner_text()

    raise FatalUIState(
        "auth scratch composer remained non-empty after Backspace cleanup"
    )


async def assert_apps_available(
    page: Page,
    *,
    get_editor: EditorGetter,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    """Verify required Apps by actually resolving each one through '@'."""
    seen: set[str] = set()
    for tool in tools:
        if tool.type != "app":
            raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")
        if tool.name in seen:
            continue
        seen.add(tool.name)

        try:
            await _select_app_via_mention(
                page,
                get_editor=get_editor,
                tool=tool,
                interaction=interaction,
                timeout_seconds=timeout_seconds,
            )
        finally:
            # Escape is only for transient autocomplete UI. Cleanup itself is
            # mandatory and runs against the current composer.
            try:
                await page.keyboard.press("Escape")
            finally:
                await _clear_auth_editor(page, get_editor=get_editor)


async def select_apps(
    page: Page,
    *,
    get_editor: EditorGetter,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    """Append each App, resolving the current composer before every App."""
    for tool in tools:
        await _select_app_via_mention(
            page,
            get_editor=get_editor,
            tool=tool,
            interaction=interaction,
            timeout_seconds=timeout_seconds,
        )

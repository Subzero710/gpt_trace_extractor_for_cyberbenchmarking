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
NetworkQuiet = Callable[[], Awaitable[None]]


# A visually empty contenteditable is not guaranteed to have innerText == "".
# Chromium/ChatGPT can leave line-break whitespace or zero-width formatting
# characters after the last structured mention is removed.
_EMPTY_COMPOSER_FORMAT_CHARS = frozenset("\u200b\u200c\u200d\u2060\ufeff")


def _composer_text_is_empty(text: str) -> bool:
    visible = "".join(ch for ch in text if ch not in _EMPTY_COMPOSER_FORMAT_CHARS)
    return not visible.strip()


_COMPOSER_ACCEPTED_JS = r"""
([rawMention, appName]) => {
    const selectors = [
        "#prompt-textarea",
        '[contenteditable="true"][data-lexical-editor="true"]',
        '[contenteditable="true"][role="textbox"]',
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


_APP_CANDIDATE_VISIBLE_JS = r"""
([appName]) => {
    const editor =
        document.querySelector("#prompt-textarea") ||
        document.querySelector(
            '[contenteditable="true"][data-lexical-editor="true"]'
        ) ||
        document.querySelector(
            '[contenteditable="true"][role="textbox"]'
        );

    const visible = (el) => {
        if (!el) return false;
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        return (
            rect.width > 0 &&
            rect.height > 0 &&
            style.visibility !== "hidden" &&
            style.display !== "none"
        );
    };

    for (const el of document.querySelectorAll("body *")) {
        if (!visible(el)) continue;
        if (editor && editor.contains(el)) continue;

        const text = (el.innerText || el.textContent || "")
            .replace(/\\s+/g, " ")
            .trim();
        if (text === appName) return true;
    }

    return false;
}
"""


_APP_KEYBOARD_ACTIVE_JS = r"""
([appName]) => {
    const normalize = (value) => (value || "").replace(/\\s+/g, " ").trim();
    const editor =
        document.querySelector("#prompt-textarea") ||
        document.querySelector(
            '[contenteditable="true"][data-lexical-editor="true"]'
        ) ||
        document.querySelector(
            '[contenteditable="true"][role="textbox"]'
        );

    const visible = (el) => {
        if (!el) return false;
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        return (
            rect.width > 0 &&
            rect.height > 0 &&
            style.visibility !== "hidden" &&
            style.display !== "none"
        );
    };

    const describe = (el, source) => {
        if (!visible(el)) return null;
        if (editor && editor.contains(el)) return null;

        const ownText = normalize(el.innerText || el.textContent);
        let exact = ownText === appName;
        if (!exact) {
            for (const child of el.querySelectorAll("*")) {
                if (normalize(child.innerText || child.textContent) === appName) {
                    exact = true;
                    break;
                }
            }
        }

        return {
            exact,
            source,
            text: ownText,
            id: el.id || null,
            role: el.getAttribute("role") || null,
            key: [source, el.id || "", el.getAttribute("role") || "", ownText].join("|"),
        };
    };

    const active = document.activeElement;
    const activeDescendant = active && active.getAttribute
        ? active.getAttribute("aria-activedescendant")
        : null;
    if (activeDescendant) {
        const target = document.getElementById(activeDescendant);
        const state = describe(target, "aria-activedescendant");
        if (state) return state;
    }

    const highlighted = document.querySelectorAll([
        '[role="option"][aria-selected="true"]',
        '[role="menuitem"][aria-selected="true"]',
        '[role="option"][data-highlighted]',
        '[role="menuitem"][data-highlighted]',
        '[data-radix-collection-item][data-highlighted]',
    ].join(","));

    let first = null;
    for (const el of highlighted) {
        const state = describe(el, "highlighted");
        if (!state) continue;
        if (state.exact) return state;
        if (!first) first = state;
    }
    if (first) return first;

    const focused = describe(active, "focus");
    return focused;
}
"""


async def _wait_app_candidate_visible(
    page: Page,
    *,
    tool: BenchmarkTool,
    timeout_seconds: float,
) -> None:
    try:
        await page.wait_for_function(
            _APP_CANDIDATE_VISIBLE_JS,
            arg=[tool.name],
            timeout=int(timeout_seconds * 1000),
        )
    except PlaywrightTimeoutError as exc:
        raise AppUnavailable(
            f"ChatGPT app {tool.name!r} autocomplete did not expose a visible "
            "candidate"
        ) from exc


async def _select_app_candidate_with_keyboard(
    page: Page,
    *,
    tool: BenchmarkTool,
    timeout_seconds: float,
) -> None:
    """Select the exact App autocomplete candidate without any pointer action."""
    await _wait_app_candidate_visible(
        page,
        tool=tool,
        timeout_seconds=timeout_seconds,
    )

    seen: set[str] = set()
    for _ in range(64):
        state = await page.evaluate(_APP_KEYBOARD_ACTIVE_JS, [tool.name])
        if isinstance(state, dict) and state.get("exact") is True:
            await page.keyboard.press("Enter")
            return

        key = state.get("key") if isinstance(state, dict) else None
        if isinstance(key, str) and key:
            if key in seen:
                break
            seen.add(key)

        # The composer already owns keyboard focus after typing the @ mention.
        # ArrowDown moves only the autocomplete's keyboard highlight. Enter is
        # never sent until the DOM proves the highlighted item is exactly the
        # requested App, so this cannot submit the composer accidentally.
        await page.keyboard.press("ArrowDown")

    raise AppUnavailable(
        f"ChatGPT app {tool.name!r} autocomplete was visible but the exact App "
        "never became the keyboard-highlighted candidate"
    )


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
    raw_mention = f"@{tool.name}"

    # Keep App selection keyboard-only; never pointer-click a structured chip.
    await interaction.focus(editor)

    # Type the whole mention query through the same validated keyboard receipt
    # used for benchmark prompts. This keeps CloakBrowser humanization ordered
    # and proves the full query reached the composer before autocomplete use.
    await interaction.type_text(
        editor,
        raw_mention,
        clear_existing=False,
    )

    # Select the autocomplete result strictly through keyboard events. The
    # exact App must be visibly present and must become the DOM-highlighted
    # candidate before Enter is allowed, so Enter cannot submit the composer.
    await _select_app_candidate_with_keyboard(
        page,
        tool=tool,
        timeout_seconds=timeout_seconds,
    )

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
        if _composer_text_is_empty(rendered):
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
    network_quiet: NetworkQuiet | None = None,
) -> None:
    """Verify configured Apps by resolving each one through '@'."""
    seen: set[str] = set()
    for tool in tools:
        if tool.type != "app":
            raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")
        if tool.name in seen:
            continue
        seen.add(tool.name)

        try:
            if network_quiet is not None:
                await network_quiet()
            await _select_app_via_mention(
                page,
                get_editor=get_editor,
                tool=tool,
                interaction=interaction,
                timeout_seconds=timeout_seconds,
            )
            if network_quiet is not None:
                await network_quiet()
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
    network_quiet: NetworkQuiet | None = None,
) -> None:
    """Append Apps, retrying once only while still safely pre-submission."""
    for attempt in range(2):
        try:
            for tool in tools:
                if network_quiet is not None:
                    await network_quiet()
                await _select_app_via_mention(
                    page,
                    get_editor=get_editor,
                    tool=tool,
                    interaction=interaction,
                    timeout_seconds=timeout_seconds,
                )
                if network_quiet is not None:
                    await network_quiet()
            return
        except AppUnavailable:
            if attempt:
                raise
            try:
                await page.keyboard.press("Escape")
            finally:
                await _clear_auth_editor(page, get_editor=get_editor)

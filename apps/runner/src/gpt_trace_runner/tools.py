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


_APP_CANDIDATE_VISIBLE_JS = r"""
([appName]) => {
    const editor =
        document.querySelector("#prompt-textarea") ||
        document.querySelector(
            '[contenteditable="true"][data-lexical-editor="true"]'
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
            .replace(/\s+/g, " ")
            .trim();
        if (text === appName) return true;
    }

    return false;
}
"""


async def _find_app_candidate(
    page: Page,
    *,
    editor: Locator,
    tool: BenchmarkTool,
    timeout_seconds: float,
) -> Locator:
    """Resolve the visible autocomplete row itself instead of guessing Enter state."""
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

    matches = page.get_by_text(tool.name, exact=True)
    editor_box = await editor.bounding_box()

    best: Locator | None = None
    best_distance = float("inf")

    for index in range(await matches.count()):
        candidate = matches.nth(index)
        try:
            if not await candidate.is_visible():
                continue
            inside_composer = await candidate.evaluate(
                """el => Boolean(el.closest(
                    '#prompt-textarea, '
                    + '[contenteditable="true"][data-lexical-editor="true"]'
                ))"""
            )
            if inside_composer:
                continue

            box = await candidate.bounding_box()
            if box is None:
                continue

            if editor_box is None:
                return candidate

            candidate_x = box["x"] + box["width"] / 2
            candidate_y = box["y"] + box["height"] / 2
            editor_x = editor_box["x"] + editor_box["width"] / 2
            editor_y = editor_box["y"] + editor_box["height"] / 2
            distance = abs(candidate_x - editor_x) + abs(candidate_y - editor_y)

            if distance < best_distance:
                best = candidate
                best_distance = distance
        except Exception:
            continue

    if best is None:
        raise AppUnavailable(
            f"ChatGPT app {tool.name!r} autocomplete text became visible but "
            "no selectable candidate locator could be resolved"
        )
    return best


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

    # Resolve and click the actual visible autocomplete candidate. Enter is
    # deliberately not used here because it is also ChatGPT's submit key when
    # the picker has no active keyboard selection.
    candidate = await _find_app_candidate(
        page,
        editor=editor,
        tool=tool,
        timeout_seconds=timeout_seconds,
    )
    await interaction.click(candidate)

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
    """Verify configured Apps by resolving each one through '@'."""
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
    """Append Apps, retrying once only while still safely pre-submission."""
    for attempt in range(2):
        try:
            for tool in tools:
                await _select_app_via_mention(
                    page,
                    get_editor=get_editor,
                    tool=tool,
                    interaction=interaction,
                    timeout_seconds=timeout_seconds,
                )
            return
        except AppUnavailable:
            if attempt:
                raise
            try:
                await page.keyboard.press("Escape")
            finally:
                await _clear_auth_editor(page, get_editor=get_editor)

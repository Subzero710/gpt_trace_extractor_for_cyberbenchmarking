from __future__ import annotations

import asyncio

from playwright.async_api import Locator, Page

from .exceptions import AppUnavailable, FatalUIState
from .interaction import InteractionGuard
from .models import BenchmarkTool

# ChatGPT's @ mention autocomplete is the canonical App resolution path for the
# runner. The "+" / Tools menu is intentionally not used.
#
# Selection is keyboard-native: after typing the exact @App query, ChatGPT's
# autocomplete highlights the matching result. Enter accepts that result.
# This deliberately avoids brittle popup DOM selectors.
#
# No per-key delay is added here. CloakBrowser owns humanization for normal
# Playwright keyboard events.


async def _select_app_via_mention(
    page: Page,
    *,
    editor: Locator,
    tool: BenchmarkTool,
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    if tool.type != "app":
        raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")

    await interaction.click(editor)
    try:
        # Contenteditable composers can contain several blocks. Ctrl+End keeps
        # the benchmark prompt intact and appends the mention at the end.
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

    # Real key events are required to drive ChatGPT's mention autocomplete.
    # CloakBrowser applies the configured keyboard humanization; do not add a
    # second artificial per-character delay in the runner.
    await page.keyboard.type("@")
    await asyncio.sleep(0.15)
    await page.keyboard.type(tool.name)

    # Verify that the raw query reached the composer before accepting it.
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    typed_rendered = ""
    while asyncio.get_running_loop().time() < deadline:
        try:
            typed_rendered = await editor.inner_text()
        except Exception:
            typed_rendered = ""
        if typed_rendered.rstrip().endswith(raw_mention):
            break
        await asyncio.sleep(0.05)
    else:
        raise AppUnavailable(
            f"ChatGPT app mention query {raw_mention!r} was not reflected in the composer"
        )

    # The visible autocomplete result is already keyboard-selected. Accept it
    # exactly as a user does instead of trying to rediscover/click popup DOM.
    await page.keyboard.press("Enter")

    # The accepted App is a structured mention node. In visible text, the
    # trailing raw '@Name' query becomes 'Name'. This local transition is enough
    # to prove Enter was handled as mention acceptance rather than leaving raw
    # text behind.
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        try:
            rendered = await editor.inner_text()
        except Exception:
            rendered = ""
        tail = rendered.rstrip()
        if (
            rendered != typed_rendered
            and tail.endswith(tool.name)
            and not tail.endswith(raw_mention)
        ):
            return
        await asyncio.sleep(0.05)

    raise AppUnavailable(
        f"ChatGPT app {tool.name!r} was typed but Enter did not produce "
        "an accepted App mention in the composer"
    )


async def _clear_editor(editor: Locator, interaction: InteractionGuard) -> None:
    """Clear the scratch composer used by the auth/App preflight."""
    await interaction.click(editor)
    await editor.press("Control+A")
    await editor.press("Backspace")


async def assert_apps_available(
    page: Page,
    *,
    editor: Locator,
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
                editor=editor,
                tool=tool,
                interaction=interaction,
                timeout_seconds=timeout_seconds,
            )
        finally:
            # auth is only a preflight; do not leave scratch mentions behind.
            try:
                await page.keyboard.press("Escape")
                await _clear_editor(editor, interaction)
            except Exception:
                pass


async def select_apps(
    page: Page,
    *,
    editor: Locator,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    """Append each benchmark App as a real ChatGPT @ mention."""
    for tool in tools:
        await _select_app_via_mention(
            page,
            editor=editor,
            tool=tool,
            interaction=interaction,
            timeout_seconds=timeout_seconds,
        )

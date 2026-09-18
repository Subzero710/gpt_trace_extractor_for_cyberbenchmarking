from __future__ import annotations

import asyncio

from playwright.async_api import Locator, Page

from .exceptions import AppUnavailable, FatalUIState
from .interaction import InteractionGuard
from .models import BenchmarkTool

# ChatGPT's @ mention autocomplete is the canonical App resolution path for the
# runner. The "+" / Tools menu is intentionally not used: its visible contents
# can be incomplete or reordered independently of whether an App is actually
# resolvable by the composer.
_MENTION_ITEMS = (
    '[role="option"]',
    '[role="menuitem"]',
    '[cmdk-item]',
    '[data-radix-collection-item]',
    'button',
)
_POPUP_ROOTS = (
    '[role="menu"]',
    '[role="listbox"]',
    '[role="dialog"]',
    '[cmdk-root]',
    '[data-radix-menu-content]',
    '[data-radix-popover-content]',
)


async def _visible_popup_snapshot(page: Page) -> tuple[str, ...]:
    """Capture diagnostic text only from currently visible popup surfaces."""
    roots = page.locator(", ".join(_POPUP_ROOTS))
    snapshots: list[str] = []
    try:
        for index in range(await roots.count()):
            root = roots.nth(index)
            if not await root.is_visible():
                continue
            text = " ".join((await root.inner_text()).split())
            if text and text not in snapshots:
                snapshots.append(text[:1200])
    except Exception:
        return tuple(snapshots)
    return tuple(snapshots[:8])


async def _find_mention_result(
    page: Page,
    *,
    name: str,
    timeout_seconds: float,
) -> Locator | None:
    """Resolve an exact App name from the popup opened by typing '@'."""
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        roots = page.locator(", ".join(_POPUP_ROOTS))
        try:
            for root_index in range(await roots.count()):
                root = roots.nth(root_index)
                if not await root.is_visible():
                    continue

                # Prefer an exact visible text node inside the popup. Clicking
                # the text itself is sufficient for ChatGPT's delegated item
                # handlers and avoids matching the typed query in the composer.
                exact = root.get_by_text(name, exact=True)
                for index in range(await exact.count()):
                    candidate = exact.nth(index)
                    if await candidate.is_visible():
                        return candidate

                # Fallback for results whose accessible item contains a small
                # description in addition to the exact App display name.
                for selector in _MENTION_ITEMS:
                    candidates = root.locator(selector).filter(has_text=name)
                    for index in range(await candidates.count()):
                        candidate = candidates.nth(index)
                        if not await candidate.is_visible():
                            continue
                        label = " ".join((await candidate.inner_text()).split())
                        if label == name or name in label:
                            return candidate
        except Exception:
            pass
        await asyncio.sleep(0.1)
    return None


async def _popup_still_visible(page: Page) -> bool:
    roots = page.locator(", ".join(_POPUP_ROOTS))
    try:
        for index in range(await roots.count()):
            if await roots.nth(index).is_visible():
                return True
    except Exception:
        return False
    return False


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

    # Key events are deliberate here. insert_text()/clipboard paste can bypass
    # the key handling ChatGPT uses to open the @ mention autocomplete.
    await page.keyboard.type("@")
    await asyncio.sleep(0.15)
    await page.keyboard.type(tool.name, delay=20)

    result = await _find_mention_result(
        page,
        name=tool.name,
        timeout_seconds=timeout_seconds,
    )
    if result is None:
        snapshots = await _visible_popup_snapshot(page)
        detail = f"; mention-popup snapshots={snapshots!r}" if snapshots else ""
        raise AppUnavailable(
            f"ChatGPT app {tool.name!r} could not be resolved with @ mention search"
            + detail
        )

    await interaction.click(result)

    # Selecting the suggestion should close the autocomplete and leave the
    # visible App mention in the composer. This exercises the same path used by
    # a human typing @App, rather than merely checking a separate Apps menu.
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        try:
            rendered = await editor.inner_text()
        except Exception:
            rendered = ""
        if tool.name in rendered and not await _popup_still_visible(page):
            return
        await asyncio.sleep(0.1)

    snapshots = await _visible_popup_snapshot(page)
    detail = f"; mention-popup snapshots={snapshots!r}" if snapshots else ""
    raise AppUnavailable(
        f"ChatGPT app {tool.name!r} was found by @ search but no accepted app "
        f"mention was observed in the composer{detail}"
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

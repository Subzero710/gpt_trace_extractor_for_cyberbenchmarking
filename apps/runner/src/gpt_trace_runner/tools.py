from __future__ import annotations

from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError
from .interaction import InteractionGuard
from .models import BenchmarkTool


_TOOL_MENU_BUTTONS = (
    'button[data-testid="composer-tools-menu-button"]',
    'button[data-testid="composer-plus-btn"]',
    'button[aria-label*="Tools"]',
    'button[aria-label*="Add"]',
)
_MENU_ITEMS = (
    '[role="menuitem"]',
    '[role="option"]',
    '[cmdk-item]',
    '[data-radix-collection-item]',
)
_SUBMENU_LABELS = ("Apps", "Connectors", "Tools")


async def _first_visible(page: Page, selectors: tuple[str, ...]) -> Locator | None:
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if await locator.count() and await locator.is_visible():
                return locator
        except Exception:
            continue
    return None


async def _find_menu_item(
    page: Page,
    text: str,
    *,
    timeout_seconds: float,
) -> Locator | None:
    combined = ", ".join(_MENU_ITEMS)
    candidate = page.locator(combined).filter(has_text=text).first
    try:
        await candidate.wait_for(
            state="visible",
            timeout=int(timeout_seconds * 1000),
        )
        return candidate
    except Exception:
        fallback = page.get_by_text(text, exact=True).last
        try:
            await fallback.wait_for(
                state="visible",
                timeout=int(timeout_seconds * 1000),
            )
            return fallback
        except Exception:
            return None


async def select_apps(
    page: Page,
    *,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    """Select requested ChatGPT Apps through the visible Tools/Apps UI."""
    for tool in tools:
        if tool.type != "app":
            raise ChatGPTUIError(f"unsupported benchmark tool type: {tool.type}")

        button = await _first_visible(page, _TOOL_MENU_BUTTONS)
        if button is None:
            raise ChatGPTUIError("ChatGPT Tools/Apps menu button was not found")
        await interaction.click(button)

        app = await _find_menu_item(
            page,
            tool.name,
            timeout_seconds=min(2.0, timeout_seconds),
        )
        if app is None:
            for label in _SUBMENU_LABELS:
                submenu = await _find_menu_item(
                    page,
                    label,
                    timeout_seconds=min(2.0, timeout_seconds),
                )
                if submenu is None:
                    continue
                await interaction.click(submenu)
                app = await _find_menu_item(
                    page,
                    tool.name,
                    timeout_seconds=timeout_seconds,
                )
                if app is not None:
                    break

        if app is None:
            raise ChatGPTUIError(
                f"ChatGPT app {tool.name!r} was not found in the visible Apps UI. "
                "Make sure it is installed/connected for this account."
            )

        await interaction.click(app)

        # Confirmation is read-only: the selected app name should remain visible
        # in the composer surface after the menu closes.
        confirmation = page.get_by_text(tool.name, exact=True).last
        try:
            await confirmation.wait_for(
                state="visible",
                timeout=int(timeout_seconds * 1000),
            )
        except Exception as exc:
            raise ChatGPTUIError(
                f"ChatGPT did not confirm app selection: {tool.name!r}"
            ) from exc

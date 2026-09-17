from __future__ import annotations

import asyncio

from playwright.async_api import Locator, Page

from .exceptions import AppUnavailable, FatalUIState
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
        locators = page.locator(selector)
        try:
            for index in range(await locators.count()):
                candidate = locators.nth(index)
                if await candidate.is_visible():
                    return candidate
        except Exception:
            continue
    return None


async def _find_menu_item(page: Page, text: str, *, timeout_seconds: float) -> Locator | None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    combined = ", ".join(_MENU_ITEMS)
    while asyncio.get_running_loop().time() < deadline:
        candidates = page.locator(combined).filter(has_text=text)
        try:
            for index in range(await candidates.count()):
                candidate = candidates.nth(index)
                if await candidate.is_visible():
                    label = (await candidate.inner_text()).strip()
                    if label == text or text in label:
                        return candidate
        except Exception:
            pass

        exact = page.get_by_text(text, exact=True)
        try:
            for index in range(await exact.count()):
                candidate = exact.nth(index)
                if await candidate.is_visible():
                    return candidate
        except Exception:
            pass
        await asyncio.sleep(0.1)
    return None


async def select_apps(
    page: Page,
    *,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    for tool in tools:
        if tool.type != "app":
            raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")
        button = await _first_visible(page, _TOOL_MENU_BUTTONS)
        if button is None:
            raise FatalUIState("ChatGPT Tools/Apps menu button was not found")
        await interaction.click(button)

        app = await _find_menu_item(page, tool.name, timeout_seconds=min(2.0, timeout_seconds))
        if app is None:
            for label in _SUBMENU_LABELS:
                submenu = await _find_menu_item(page, label, timeout_seconds=min(2.0, timeout_seconds))
                if submenu is None:
                    continue
                await interaction.click(submenu)
                app = await _find_menu_item(page, tool.name, timeout_seconds=timeout_seconds)
                if app is not None:
                    break
        if app is None:
            raise AppUnavailable(
                f"ChatGPT app {tool.name!r} is not available in the visible Apps UI"
            )
        await interaction.click(app)

        confirmation = await _find_menu_item(page, tool.name, timeout_seconds=timeout_seconds)
        if confirmation is None:
            raise AppUnavailable(f"ChatGPT did not confirm app selection: {tool.name!r}")

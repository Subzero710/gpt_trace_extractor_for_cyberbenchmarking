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


async def _visible_menu_labels(page: Page) -> tuple[str, ...]:
    combined = ", ".join(_MENU_ITEMS)
    candidates = page.locator(combined)
    labels: list[str] = []
    try:
        for index in range(await candidates.count()):
            candidate = candidates.nth(index)
            if not await candidate.is_visible():
                continue
            label = (await candidate.inner_text()).strip()
            if label and label not in labels:
                labels.append(label)
    except Exception:
        return tuple(labels)
    return tuple(labels[:40])


async def _find_app_from_open_menu(
    page: Page,
    *,
    name: str,
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> Locator | None:
    app = await _find_menu_item(page, name, timeout_seconds=min(2.0, timeout_seconds))
    if app is not None:
        return app

    for label in _SUBMENU_LABELS:
        submenu = await _find_menu_item(
            page,
            label,
            timeout_seconds=min(2.0, timeout_seconds),
        )
        if submenu is None:
            continue
        await interaction.click(submenu)
        app = await _find_menu_item(page, name, timeout_seconds=timeout_seconds)
        if app is not None:
            return app
    return None


async def assert_apps_available(
    page: Page,
    *,
    tools: tuple[BenchmarkTool, ...],
    interaction: InteractionGuard,
    timeout_seconds: float,
) -> None:
    """Verify benchmark Apps are visible without selecting or submitting them."""
    seen: set[str] = set()
    for tool in tools:
        if tool.type != "app":
            raise FatalUIState(f"unsupported benchmark tool type at runtime: {tool.type}")
        if tool.name in seen:
            continue
        seen.add(tool.name)

        button = await _first_visible(page, _TOOL_MENU_BUTTONS)
        if button is None:
            raise FatalUIState("ChatGPT Tools/Apps menu button was not found")

        await interaction.click(button)
        try:
            app = await _find_app_from_open_menu(
                page,
                name=tool.name,
                interaction=interaction,
                timeout_seconds=timeout_seconds,
            )
            if app is None:
                visible = await _visible_menu_labels(page)
                detail = f"; visible menu labels: {visible!r}" if visible else ""
                raise AppUnavailable(
                    f"ChatGPT app {tool.name!r} is not available in the visible Apps UI"
                    + detail
                )
        finally:
            try:
                await page.keyboard.press("Escape")
                await page.keyboard.press("Escape")
            except Exception:
                pass


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

        app = await _find_app_from_open_menu(
            page,
            name=tool.name,
            interaction=interaction,
            timeout_seconds=timeout_seconds,
        )
        if app is None:
            visible = await _visible_menu_labels(page)
            detail = f"; visible menu labels: {visible!r}" if visible else ""
            raise AppUnavailable(
                f"ChatGPT app {tool.name!r} is not available in the visible Apps UI"
                + detail
            )
        await interaction.click(app)

        confirmation = await _find_menu_item(page, tool.name, timeout_seconds=timeout_seconds)
        if confirmation is None:
            raise AppUnavailable(f"ChatGPT did not confirm app selection: {tool.name!r}")

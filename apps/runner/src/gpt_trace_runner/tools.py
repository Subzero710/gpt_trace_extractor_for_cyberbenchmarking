from __future__ import annotations

from playwright.async_api import Locator, Page

from .exceptions import ChatGPTUIError
from .models import BenchmarkTool


_APP_RESULT_SELECTORS = (
    '[role="option"]',
    '[role="menuitem"]',
    '[cmdk-item]',
    '[data-radix-collection-item]',
)


async def _find_app_result(
    page: Page,
    name: str,
    *,
    timeout_seconds: float,
) -> Locator:
    combined = ", ".join(_APP_RESULT_SELECTORS)
    candidate = page.locator(combined).filter(has_text=name).first

    try:
        await candidate.wait_for(
            state="visible",
            timeout=int(timeout_seconds * 1000),
        )
        return candidate
    except Exception:
        fallback = page.get_by_text(name, exact=True).last
        try:
            await fallback.wait_for(
                state="visible",
                timeout=int(timeout_seconds * 1000),
            )
            return fallback
        except Exception as exc:
            raise ChatGPTUIError(
                f"ChatGPT app {name!r} was not found in the @mention menu. "
                "Make sure the app is installed/connected for this account."
            ) from exc


async def compose_with_apps(
    page: Page,
    editor: Locator,
    *,
    prompt: str,
    tools: tuple[BenchmarkTool, ...],
    timeout_seconds: float,
) -> None:
    """Compose one ChatGPT message and select requested Apps via @mentions."""
    await editor.fill("")
    await editor.focus()

    for tool in tools:
        if tool.type != "app":
            raise ChatGPTUIError(f"unsupported benchmark tool type: {tool.type}")

        await editor.press_sequentially(f"@{tool.name}", delay=20)
        result = await _find_app_result(
            page,
            tool.name,
            timeout_seconds=timeout_seconds,
        )
        await result.click()
        await editor.focus()
        await page.keyboard.insert_text(" ")

    await page.keyboard.insert_text(prompt)

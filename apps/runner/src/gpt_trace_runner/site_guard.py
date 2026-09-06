from __future__ import annotations

import asyncio

from playwright.async_api import Locator, Page

from .exceptions import AuthenticationRequired, FatalUIState, RateLimited, SiteChallengeFailed
from .interaction import InteractionGuard
from .traffic import TrafficMonitor

PROMPT_SELECTORS = (
    "#prompt-textarea",
    '[contenteditable="true"][data-lexical-editor="true"]',
)
AUTH_SELECTORS = (
    'button:has-text("Log in")',
    'a:has-text("Log in")',
    'button:has-text("Sign up")',
    'a:has-text("Sign up")',
)


async def first_visible(page: Page, selectors: tuple[str, ...]) -> Locator | None:
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


class SiteGuard:
    def __init__(self, page: Page, *, interaction: InteractionGuard, traffic: TrafficMonitor,
                 ready_timeout_seconds: float, challenge_timeout_seconds: float) -> None:
        self._page = page
        self._interaction = interaction
        self._traffic = traffic
        self._ready_seconds = ready_timeout_seconds
        self._challenge_seconds = challenge_timeout_seconds

    async def _auth_marker_visible(self) -> bool:
        return await first_visible(self._page, AUTH_SELECTORS) is not None

    async def _usable_composer(self) -> Locator | None:
        candidate = await first_visible(self._page, PROMPT_SELECTORS)
        if candidate is None:
            return None
        try:
            if not await candidate.is_editable():
                return None
            box = await candidate.bounding_box()
            if not box or box["width"] <= 0 or box["height"] <= 0:
                return None
        except Exception:
            return None
        return candidate

    async def wait_ready(self) -> Locator:
        if self._traffic.saw_backend_429:
            raise RateLimited("ChatGPT returned HTTP 429")
        if await self._auth_marker_visible():
            raise AuthenticationRequired("ChatGPT authentication is required")

        async def wait_for(seconds: float) -> Locator | None:
            deadline = asyncio.get_running_loop().time() + seconds
            while asyncio.get_running_loop().time() < deadline:
                if self._traffic.saw_backend_429:
                    raise RateLimited("ChatGPT returned HTTP 429")
                if await self._auth_marker_visible():
                    raise AuthenticationRequired("ChatGPT authentication is required")
                composer = await self._usable_composer()
                if composer is not None:
                    return composer
                await asyncio.sleep(0.2)
            return None

        composer = await wait_for(self._ready_seconds)
        if composer is None:
            self._traffic.mark_challenge_seen()
            composer = await wait_for(self._challenge_seconds)
            if composer is None:
                detail = " after backend HTTP 403" if self._traffic.saw_backend_403 else ""
                raise SiteChallengeFailed(
                    "ChatGPT did not return to an actionable composer state" + detail
                )
            self._traffic.mark_challenge_resolved()

        await self._interaction.ensure_page_focus()
        return composer

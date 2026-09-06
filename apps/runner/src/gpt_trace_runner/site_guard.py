from __future__ import annotations

from playwright.async_api import Locator, Page

from .exceptions import (
    AuthenticationRequired,
    RateLimited,
    SiteChallengeFailed,
)
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


class SiteGuard:
    """Wait for ChatGPT's own frontend to return to a usable state."""

    def __init__(
        self,
        page: Page,
        *,
        interaction: InteractionGuard,
        traffic: TrafficMonitor,
        ready_timeout_seconds: float,
        challenge_timeout_seconds: float,
    ) -> None:
        self._page = page
        self._interaction = interaction
        self._traffic = traffic
        self._ready_ms = int(ready_timeout_seconds * 1000)
        self._challenge_ms = int(challenge_timeout_seconds * 1000)

    def prompt_locator(self) -> Locator:
        return self._page.locator(", ".join(PROMPT_SELECTORS)).first

    async def _auth_marker_visible(self) -> bool:
        for selector in AUTH_SELECTORS:
            locator = self._page.locator(selector).first
            try:
                if await locator.count() and await locator.is_visible():
                    return True
            except Exception:
                continue
        return False

    async def wait_ready(self) -> Locator:
        if self._traffic.saw_backend_429:
            raise RateLimited("ChatGPT returned HTTP 429")
        if await self._auth_marker_visible():
            raise AuthenticationRequired("ChatGPT authentication is required")

        composer = self.prompt_locator()
        try:
            await composer.wait_for(state="visible", timeout=self._ready_ms)
        except Exception:
            if await self._auth_marker_visible():
                raise AuthenticationRequired("ChatGPT authentication is required")

            # A missing composer can be a transient interstitial/challenge. Do
            # not click, reload, or resubmit while the site's own flow runs.
            self._traffic.mark_challenge_seen()
            try:
                await composer.wait_for(state="visible", timeout=self._challenge_ms)
            except Exception as exc:
                if self._traffic.saw_backend_429:
                    raise RateLimited("ChatGPT returned HTTP 429") from exc
                if await self._auth_marker_visible():
                    raise AuthenticationRequired(
                        "ChatGPT authentication was lost"
                    ) from exc
                detail = (
                    " after backend HTTP 403"
                    if self._traffic.saw_backend_403
                    else ""
                )
                raise SiteChallengeFailed(
                    "ChatGPT did not return to a ready composer state" + detail
                ) from exc
            self._traffic.mark_challenge_resolved()

        await self._interaction.ensure_page_focus()
        return composer

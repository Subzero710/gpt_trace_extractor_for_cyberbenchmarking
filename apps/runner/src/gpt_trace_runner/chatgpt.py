from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from playwright.async_api import Locator, Page, TimeoutError as PlaywrightTimeoutError

from .conversation import (
    ConversationClient,
    _parse_retry_after,
    assistant_model_slugs,
    conversation_id_from_url,
    extract_dataset_messages,
    invoked_app_names,
    is_transient_conversation_id,
    validate_conversation_identity,
)
from .exceptions import (
    AmbiguousSubmission,
    AppUnavailable,
    AuthenticationRequired,
    ChatGPTUIError,
    ConcurrentTurnError,
    ConversationError,
    ConversationNotFound,
    ConversationStreamAborted,
    ConversationStreamIncomplete,
    DEFAULT_RATE_LIMIT_FALLBACK_SECONDS,
    EnvironmentDrift,
    FatalUIState,
    ModelMismatch,
    RateLimited,
    RecoveryIncomplete,
    SiteChallengeFailed,
)
from .interaction import InteractionGuard
from .models import BenchmarkTask, BenchmarkTool, CapturedConversation
from .site_guard import SiteGuard, first_visible
from .stream import ConversationStream, is_conversation_stream_response
from .tools import assert_apps_available, select_apps
from .traffic import TrafficMonitor
from .uploads import build_file_payloads

SEND_SELECTORS = (
    'button[data-testid="send-button"]',
    "#composer-submit-button",
    'button[aria-label*="Send"]',
)
ATTACH_BUTTON_SELECTORS = (
    'button[data-testid="composer-plus-btn"]',
    'button[aria-label*="Attach"]',
    'button[aria-label*="Upload"]',
    'button[data-testid*="attach"]',
)
UPLOAD_MENU_LABELS = (
    "Upload from computer", "Upload files", "Upload file", "Add photos & files",
)

REQUIRED_THINKING_EFFORT = "extended"
REQUIRED_UI_THINKING_EFFORT = "high"

def _thinking_effort_route_pattern(base_url: str):
    return re.compile(
        rf"^{re.escape(base_url.rstrip('/'))}/backend-api/f/conversation"
        r"(?:/prepare)?(?:\?.*)?$"
    )


def check_chatgpt_protocol_contracts(base_url: str) -> None:
    if REQUIRED_THINKING_EFFORT != "extended":
        raise RuntimeError(
            "ChatGPT benchmark wire thinking_effort must remain 'extended'"
        )
    if REQUIRED_UI_THINKING_EFFORT != "high":
        raise RuntimeError(
            "ChatGPT benchmark UI thinking effort must remain 'high'"
        )
    pattern = _thinking_effort_route_pattern(base_url)
    expected = (
        f"{base_url.rstrip('/')}/backend-api/f/conversation",
        f"{base_url.rstrip('/')}/backend-api/f/conversation/prepare",
    )
    for url in expected:
        if pattern.fullmatch(url) is None:
            raise RuntimeError(
                f"ChatGPT thinking-effort route pattern does not match {url!r}"
            )



@dataclass(slots=True)
class PreparedTurn:
    task: BenchmarkTask


@dataclass(slots=True)
class SubmittedTurn:
    conversation_id: str
    user_message_id: str
    stream: ConversationStream
    task: BenchmarkTask



class ChatGPTClient:
    def __init__(
        self,
        page: Page,
        *,
        base_url: str,
        conversation_turns: int,
        turn_timeout_seconds: float,
        stream_start_timeout_seconds: float,
        tool_select_timeout_seconds: float,
        upload_timeout_seconds: float,
        site_ready_timeout_seconds: float,
        challenge_timeout_seconds: float,
        natural_snapshot_wait_seconds: float,
        clipboard_url: str,
        expected_model_slug: str,
    ) -> None:
        self._page = page
        self._base_url = base_url.rstrip("/")
        self._conversation = ConversationClient(page, turns=conversation_turns)
        self._turn_timeout = turn_timeout_seconds
        self._stream_start_timeout = stream_start_timeout_seconds
        self._tool_select_timeout = tool_select_timeout_seconds
        self._upload_timeout = upload_timeout_seconds
        self._natural_snapshot_wait = natural_snapshot_wait_seconds
        self._expected_model = expected_model_slug.strip()
        self._traffic = TrafficMonitor(page, base_url=self._base_url)
        self._interaction = InteractionGuard(
            page, clipboard_url=clipboard_url, timeout_seconds=site_ready_timeout_seconds
        )
        self._site = SiteGuard(
            page,
            interaction=self._interaction,
            traffic=self._traffic,
            ready_timeout_seconds=site_ready_timeout_seconds,
            challenge_timeout_seconds=challenge_timeout_seconds,
        )
        self._active_turn: SubmittedTurn | None = None
        self._environment_baseline: dict[str, Any] | None = None
        self._environment_hash: str | None = None
        self._thinking_effort_observer_installed = False
        self._thinking_effort_verified_requests = 0
        self._thinking_effort_observer_error: str | None = None
        self._readback_allowed_at = 0.0
        self._readback_rate_limit: RateLimited | None = None

    async def _observe_required_thinking_effort(self, route, request) -> None:
        """Observe generation traffic and fail closed without mutating its payload."""
        request_url = request.url.split("?", 1)[0].rstrip("/")
        conversation_url = f"{self._base_url}/backend-api/f/conversation"
        prepare_url = f"{conversation_url}/prepare"

        if request.method.upper() != "POST" or request_url not in {
            conversation_url,
            prepare_url,
        }:
            await route.continue_()
            return

        # /prepare is not treated as a generation request. Its payload contract
        # is deliberately not assumed to match /conversation.
        if request_url == prepare_url:
            await route.continue_()
            return

        try:
            payload = request.post_data_json
        except Exception as exc:
            self._thinking_effort_observer_error = (
                "could not inspect ChatGPT generation thinking_effort: "
                f"{exc}"
            )
            await route.abort()
            return

        if not isinstance(payload, dict):
            self._thinking_effort_observer_error = (
                "ChatGPT generation request body is not a JSON object"
            )
            await route.abort()
            return

        observed = payload.get("thinking_effort")

        if observed != REQUIRED_THINKING_EFFORT:
            self._thinking_effort_observer_error = (
                "ChatGPT generation request did not use required High thinking: "
                f"thinking_effort={observed!r}, "
                f"expected={REQUIRED_THINKING_EFFORT!r}, url={request_url!r}"
            )
            await route.abort()
            return

        await route.continue_()
        if request_url == conversation_url:
            self._thinking_effort_verified_requests += 1

    async def _ensure_thinking_effort_observer(self) -> None:
        if self._thinking_effort_observer_installed:
            return
        pattern = _thinking_effort_route_pattern(self._base_url)
        await self._page.route(pattern, self._observe_required_thinking_effort)
        self._thinking_effort_observer_installed = True

    def _validate_thinking_effort_observation(self) -> None:
        if self._thinking_effort_observer_error is not None:
            raise FatalUIState(self._thinking_effort_observer_error)
        if self._thinking_effort_verified_requests != 1:
            raise AmbiguousSubmission(
                "expected exactly one ChatGPT conversation POST verified with "
                f"thinking_effort={REQUIRED_THINKING_EFFORT!r}; observed "
                f"{self._thinking_effort_verified_requests}"
            )

    async def ensure_high_thinking_effort(self) -> None:
        """Select UI High via the real reasoning slider and verify the result."""
        trigger = self._page.locator(
            'button[data-composer-navigation-target="reasoning"]'
        )
        picker_open = False
        try:
            await trigger.wait_for(state="visible")
            current = await trigger.get_attribute("data-selected-reasoning-effort")
            if current == REQUIRED_UI_THINKING_EFFORT:
                return

            await self._interaction.ensure_page_focus()
            await self._page.keyboard.press("Control+Shift+M")
            picker_open = True

            active = await self._page.evaluate(
                """() => ({
                    role: document.activeElement?.getAttribute('role') || null,
                    label: document.activeElement?.getAttribute('aria-label') || null,
                })"""
            )
            if active != {"role": "menuitem", "label": "Select model"}:
                raise FatalUIState(
                    "unexpected model-picker focus after Ctrl+Shift+M: "
                    f"{active!r}"
                )

            await self._page.keyboard.press("ArrowDown")
            active = await self._page.evaluate(
                """() => ({
                    role: document.activeElement?.getAttribute('role') || null,
                    label: document.activeElement?.getAttribute('aria-label') || null,
                    reasoningSlider:
                        document.activeElement?.getAttribute('data-reasoning-slider') || null,
                })"""
            )
            if active != {
                "role": "menuitem",
                "label": "Power",
                "reasoningSlider": "true",
            }:
                raise FatalUIState(
                    "ChatGPT reasoning slider did not receive focus: "
                    f"{active!r}"
                )

            slider = self._page.locator(
                '[data-reasoning-slider="true"] [role="slider"]'
            )
            await slider.wait_for(state="attached")

            raw_now = await slider.get_attribute("aria-valuenow")
            raw_max = await slider.get_attribute("aria-valuemax")
            if raw_now is None or raw_max is None:
                raise FatalUIState(
                    "ChatGPT reasoning slider is missing aria-valuenow/aria-valuemax"
                )
            try:
                value_now = int(raw_now)
                value_max = int(raw_max)
            except ValueError as exc:
                raise FatalUIState(
                    "ChatGPT reasoning slider exposed non-integer ARIA values: "
                    f"now={raw_now!r}, max={raw_max!r}"
                ) from exc
            if value_now < 0 or value_max < 0 or value_now > value_max:
                raise FatalUIState(
                    "ChatGPT reasoning slider exposed invalid bounds: "
                    f"now={value_now}, max={value_max}"
                )

            for _ in range(value_max - value_now):
                await self._page.keyboard.press("ArrowRight")

            final_raw = await slider.get_attribute("aria-valuenow")
            final_effort = await trigger.get_attribute(
                "data-selected-reasoning-effort"
            )
            try:
                final_value = int(final_raw) if final_raw is not None else -1
            except ValueError:
                final_value = -1

            if (
                final_value != value_max
                or final_effort != REQUIRED_UI_THINKING_EFFORT
            ):
                raise FatalUIState(
                    "failed to select ChatGPT High thinking effort: "
                    f"effort={final_effort!r}, slider={final_value}/{value_max}"
                )
        except FatalUIState:
            raise
        except Exception as exc:
            raise FatalUIState(
                f"could not select ChatGPT High thinking effort via UI: {exc}"
            ) from exc
        finally:
            if picker_open:
                try:
                    await self._page.keyboard.press("Escape")
                except Exception:
                    pass

    async def _navigate(self, url: str) -> None:
        # BrowserClient applies cloakbrowser.human.patch_browser_async() to the
        # connected Browser before this Page reaches ChatGPTClient. Calling the
        # public Page.goto API here therefore goes through CloakBrowser's
        # frame-aware/humanized wrapper. Never bypass it via private/original
        # Playwright methods.
        #
        # Navigation and page readiness are separate invariants. "commit"
        # proves the navigation response was received; SiteGuard or the auth
        # waiter then handles login pages, interstitials/challenges and the
        # final actionable ChatGPT UI.
        try:
            await self._page.goto(
                url,
                wait_until="commit",
                timeout=60_000,
            )
        except PlaywrightTimeoutError as exc:
            raise FatalUIState(
                "ChatGPT navigation did not commit within 60 seconds"
            ) from exc

    async def goto_home(self) -> None:
        await self._navigate(self._base_url)

    async def delete_completed_conversation(self, conversation_id: str) -> None:
        """Delete only a benchmark conversation already persisted by storage."""
        await self._conversation.delete(conversation_id)

        # A direct backend DELETE does not execute ChatGPT's React mutation
        # callback, so explicitly land on the clean home composer if this page
        # still displays the conversation we just removed. Never navigate away
        # from some other conversation that the operator may have opened.
        if conversation_id_from_url(self._page.url) == conversation_id:
            await self.goto_home()
            await self._site.wait_ready()

    async def _environment(self) -> dict[str, Any]:
        try:
            value = await self._page.evaluate(
                """() => ({
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    language: navigator.language,
                    languages: Array.from(navigator.languages || []),
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    maxTouchPoints: navigator.maxTouchPoints,
                    screenWidth: screen.width,
                    screenHeight: screen.height,
                    colorDepth: screen.colorDepth,
                    devicePixelRatio: window.devicePixelRatio,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    timezoneOffsetMin: new Date().getTimezoneOffset(),
                })"""
            )
        except Exception as exc:
            raise FatalUIState("could not read browser environment") from exc
        if not isinstance(value, dict):
            raise FatalUIState("browser environment probe returned invalid data")
        return value

    async def _check_environment(self) -> None:
        current = await self._environment()
        if self._environment_baseline is None:
            self._environment_baseline = current
            encoded = json.dumps(current, sort_keys=True, separators=(",", ":")).encode()
            self._environment_hash = hashlib.sha256(encoded).hexdigest()
            return
        if current != self._environment_baseline:
            raise EnvironmentDrift("browser environment changed during the batch")

    async def prepare_session(self, *, fresh_home: bool = False) -> None:
        if fresh_home or not self._page.url.startswith(self._base_url):
            await self.goto_home()
        await self._site.wait_ready()
        await self._check_environment()

    async def assert_authenticated_current_page(self) -> None:
        """Verify the current ChatGPT page without navigation or reload."""
        if not self._page.url.startswith(self._base_url):
            raise AuthenticationRequired(
                "resume requires the existing ChatGPT page; "
                f"current URL is {self._page.url!r}"
            )

        try:
            value = await self._page.evaluate(
                """async () => {
                    const response = await fetch('/backend-api/me', {
                        method: 'GET',
                        credentials: 'include',
                        cache: 'no-store',
                    });
                    let payload = null;
                    try {
                        payload = await response.json();
                    } catch (_) {
                    }
                    return {
                        status: response.status,
                        object: payload && payload.object,
                        id: payload && payload.id,
                        retryAfter: response.headers.get('retry-after'),
                        requestId:
                            response.headers.get('x-request-id') ||
                            response.headers.get('openai-request-id') || null,
                    };
                }"""
            )
        except Exception as exc:
            raise AuthenticationRequired(
                "could not verify the existing ChatGPT session during resume"
            ) from exc

        if isinstance(value, dict) and value.get("status") == 429:
            retry_after = _parse_retry_after(value.get("retryAfter"))
            request_id_raw = value.get("requestId")
            request_id = (
                request_id_raw.strip()
                if isinstance(request_id_raw, str) and request_id_raw.strip()
                else None
            )
            detail = "ChatGPT /backend-api/me returned HTTP 429 during resume"
            if retry_after is not None:
                detail += f"; retry_after={retry_after:.3f}s"
            if request_id is not None:
                detail += f"; request_id={request_id}"
            raise RateLimited(
                detail,
                retry_after_seconds=retry_after,
                endpoint="/backend-api/me",
                method="GET",
                request_id=request_id,
            )
        if (
            not isinstance(value, dict)
            or value.get("status") != 200
            or value.get("object") != "user"
            or not isinstance(value.get("id"), str)
            or not value["id"]
        ):
            raise AuthenticationRequired(
                "existing ChatGPT browser session is not authenticated; "
                "resume will not reload or replace it"
            )

    async def wait_until_authenticated(self, timeout_seconds: float) -> None:
        """Use ChatGPT's own backend identity request as the auth oracle.

        The supplied HAR shows authenticated frontend startup issuing:
        GET /backend-api/me -> HTTP 200 with
        {"object": "user", "id": "<non-empty>", ...}.
        """
        self._traffic.reset_auth_probe()

        # TrafficMonitor is already listening before this navigation. Refreshing
        # once makes an existing persistent session emit a fresh /backend-api/me;
        # an unauthenticated session can then complete login normally in noVNC,
        # after which the frontend emits the successful /me response.
        if self._page.url.startswith(self._base_url):
            try:
                await self._page.reload(wait_until="commit", timeout=60_000)
            except PlaywrightTimeoutError as exc:
                raise FatalUIState(
                    "ChatGPT authentication probe reload did not commit within 60 seconds"
                ) from exc
        else:
            await self.goto_home()

        await self._traffic.wait_for_authenticated_user(
            timeout_seconds=timeout_seconds
        )

    async def _new_chat_if_needed(self) -> None:
        # Successful benchmark conversations are deleted explicitly after
        # storage.complete(). If some conversation is still open here, never
        # click the fragile New chat control and never delete an unknown chat:
        # navigate to the clean home composer instead.
        old_id = conversation_id_from_url(self._page.url)
        if old_id is not None:
            await self.goto_home()
            await self._site.wait_ready()
            return

        composer = await self._site.wait_ready()
        try:
            dirty = (await composer.inner_text()) != ""
        except Exception as exc:
            raise FatalUIState("could not inspect home composer state") from exc
        if dirty:
            await self.goto_home()
            await self._site.wait_ready()

    async def _visible_exact_text(self, text: str, timeout_seconds: float) -> Locator | None:
        import asyncio
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            locators = self._page.get_by_text(text, exact=True)
            try:
                for index in range(await locators.count()):
                    candidate = locators.nth(index)
                    if await candidate.is_visible():
                        return candidate
            except Exception as exc:
                raise FatalUIState(f"could not inspect UI text {text!r}") from exc
            await asyncio.sleep(0.1)
        return None

    async def _upload(self, attachments: tuple[Path, ...]) -> None:
        if not attachments:
            return
        payloads = build_file_payloads(attachments)
        attach = await first_visible(self._page, ATTACH_BUTTON_SELECTORS)
        if attach is None:
            raise FatalUIState("visible attachment control was not found")

        chooser = None
        try:
            async with self._page.expect_file_chooser(timeout=3000) as info:
                await self._interaction.click(attach)
            chooser = await info.value
        except PlaywrightTimeoutError:
            pass

        if chooser is None:
            for label in UPLOAD_MENU_LABELS:
                item = await self._visible_exact_text(label, min(2.0, self._upload_timeout))
                if item is None:
                    continue
                try:
                    async with self._page.expect_file_chooser(
                        timeout=int(self._upload_timeout * 1000)
                    ) as info:
                        await self._interaction.click(item)
                    chooser = await info.value
                    break
                except PlaywrightTimeoutError:
                    continue
        if chooser is None:
            raise FatalUIState("attachment UI did not open a browser file chooser")
        await chooser.set_files(payloads)
        for attachment in attachments:
            if await self._visible_exact_text(attachment.name, self._upload_timeout) is None:
                raise FatalUIState(
                    f"attachment did not become ready in ChatGPT: {attachment.name}"
                )

    async def verify_apps_available(
        self,
        tools: tuple[BenchmarkTool, ...],
    ) -> None:
        """Fail before benchmark execution if a configured ChatGPT App is absent."""
        await self._new_chat_if_needed()
        await assert_apps_available(
            self._page,
            get_editor=self._site.wait_ready,
            tools=tools,
            interaction=self._interaction,
            timeout_seconds=self._tool_select_timeout,
        )
        await self._site.wait_ready()

    async def _compose(self, task: BenchmarkTask) -> None:
        # Apps are transport metadata represented by structured @ mentions.
        # task.prompt is the exact benchmark text typed into ChatGPT and later
        # validated against the frontend POST and captured conversation.
        await select_apps(
            self._page,
            get_editor=self._site.wait_ready,
            tools=task.tools,
            interaction=self._interaction,
            timeout_seconds=self._tool_select_timeout,
        )

        # App mentions are structured nodes. Append the exact benchmark prompt
        # after them and never clear/select-all the composer after mentions exist.
        editor = await self._site.wait_ready()
        await self._interaction.type_text(
            editor,
            task.prompt,
            clear_existing=False,
        )
        await self._site.wait_ready()

    async def prepare_task(self, task: BenchmarkTask) -> PreparedTurn:
        if self._active_turn is not None:
            raise ConcurrentTurnError("another ChatGPT turn is already active")
        self._traffic.begin_task()
        self._thinking_effort_verified_requests = 0
        self._thinking_effort_observer_error = None
        await self._ensure_thinking_effort_observer()
        await self._check_environment()
        try:
            await self._new_chat_if_needed()
            await self.ensure_high_thinking_effort()
            await self._upload(task.attachments)
            await self._compose(task)
            await self._interaction.ensure_page_focus()
        except AppUnavailable:
            raise
        except (RateLimited, AuthenticationRequired, SiteChallengeFailed, FatalUIState):
            raise
        except Exception as exc:
            raise FatalUIState(f"ChatGPT preparation failed: {exc}") from exc
        return PreparedTurn(task=task)

    async def _click_send(self, before_send: Callable[[], None]) -> None:
        button = await first_visible(self._page, SEND_SELECTORS)
        if button is None:
            raise FatalUIState("visible enabled Send button was not found")
        try:
            if not await button.is_enabled():
                raise FatalUIState("Send button is visible but disabled")
        except FatalUIState:
            raise
        except Exception as exc:
            raise FatalUIState("could not inspect Send button state") from exc
        # Durable submission marker is committed only after a concrete Send
        # control is found, immediately before the potentially-successful click.
        before_send()
        await self._interaction.click(button)

    @staticmethod
    def _conversation_has_exact_user_message(
        conversation: dict[str, Any],
        user_message_id: str,
    ) -> bool:
        messages = extract_dataset_messages(conversation)
        user_ids = [
            message.get("id")
            for message in messages
            if isinstance(message.get("author"), dict)
            and message["author"].get("role") == "user"
        ]
        if not user_ids:
            return False
        if len(user_ids) != 1 or user_ids[0] != user_message_id:
            raise AmbiguousSubmission(
                "durable conversation candidate does not contain exactly the "
                "submitted frontend user_message_id"
            )
        return True

    async def _wait_for_conversation_id(self, user_message_id: str) -> str:
        """Resolve a durable ID without hammering conversation readback endpoints."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._stream_start_timeout
        route_grace = max(
            0.0,
            float(getattr(self, "_conversation_id_route_grace_seconds", 1.0)),
        )
        route_check = max(
            0.05,
            float(getattr(self, "_conversation_id_route_check_seconds", 0.1)),
        )
        poll_delay = max(
            0.1,
            float(getattr(self, "_conversation_id_poll_initial_seconds", 1.0)),
        )
        poll_max = max(
            poll_delay,
            float(getattr(self, "_conversation_id_poll_max_seconds", 8.0)),
        )
        rate_limit_default = max(
            poll_delay,
            float(getattr(self, "_conversation_id_rate_limit_backoff_seconds", DEFAULT_RATE_LIMIT_FALLBACK_SECONDS)),
        )
        rate_limit_recovery = max(
            0.0,
            float(getattr(self, "_durable_error_recovery_seconds", 120.0)),
        )
        candidate_budget = max(
            1,
            int(getattr(self, "_conversation_id_candidate_fetches_per_poll", 1)),
        )

        last_route: str | None = None
        last_error: str | None = None
        last_rate_limit: RateLimited | None = None
        rate_limit_deadline_extended = False
        rejected_ids: set[str] = set()
        candidate_attempts: dict[str, int] = {}
        route_next_fetch_at: dict[str, float] = {}

        def extend_deadline_for_rate_limit(now: float) -> None:
            nonlocal deadline, rate_limit_deadline_extended
            if rate_limit_deadline_extended or rate_limit_recovery <= 0:
                return
            deadline = max(deadline, now + rate_limit_recovery)
            rate_limit_deadline_extended = True

        async def try_route_candidate(
            now: float,
        ) -> tuple[str | None, float | None, bool]:
            nonlocal last_route, last_error, last_rate_limit
            candidate = conversation_id_from_url(self._page.url)
            if not candidate:
                return None, None, False
            last_route = candidate
            if is_transient_conversation_id(candidate):
                return None, None, False

            next_fetch_at = route_next_fetch_at.get(candidate, 0.0)
            if now < next_fetch_at:
                return None, next_fetch_at - now, True

            candidate_attempts[candidate] = candidate_attempts.get(candidate, 0) + 1
            try:
                conversation = await self._conversation.fetch(candidate)
                if self._conversation_has_exact_user_message(
                    conversation,
                    user_message_id,
                ):
                    last_rate_limit = None
                    return candidate, None, True
            except RateLimited as exc:
                last_rate_limit = exc
                last_error = f"{type(exc).__name__}: {exc}"
                extend_deadline_for_rate_limit(now)
                delay = max(
                    poll_delay,
                    exc.retry_delay(
                        rate_limit_default,
                        maximum_seconds=max(30.0, poll_max),
                    ),
                )
                if delay > deadline - loop.time():
                    raise exc
                route_next_fetch_at[candidate] = loop.time() + delay
                return None, delay, True
            except (ConversationError, AmbiguousSubmission) as exc:
                last_rate_limit = None
                last_error = f"{type(exc).__name__}: {exc}"
                route_next_fetch_at[candidate] = loop.time() + poll_delay
            else:
                last_rate_limit = None
                route_next_fetch_at[candidate] = loop.time() + poll_delay

            return (
                None,
                max(0.0, route_next_fetch_at[candidate] - loop.time()),
                True,
            )

        # First give ChatGPT's own navigation a chance to expose the durable ID.
        # Reading page.url is local and creates no backend traffic.
        grace_deadline = min(deadline, loop.time() + route_grace)
        while loop.time() < grace_deadline:
            resolved, route_delay, route_owned = await try_route_candidate(loop.time())
            if resolved is not None:
                return resolved
            remaining = grace_deadline - loop.time()
            if remaining <= 0:
                break
            sleep_for = (
                route_delay
                if route_owned and route_delay is not None
                else route_check
            )
            await asyncio.sleep(min(sleep_for, remaining))

        while True:
            now = loop.time()
            if now >= deadline:
                if last_rate_limit is not None:
                    raise last_rate_limit
                detail = f"; last route={last_route!r}"
                if last_error is not None:
                    detail += f"; last error={last_error}"
                raise AmbiguousSubmission(
                    "conversation SSE started but no verified durable conversation ID "
                    "was resolved" + detail
                )
            resolved, route_delay, route_owned = await try_route_candidate(now)
            if resolved is not None:
                return resolved

            if route_owned:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    if last_rate_limit is not None:
                        raise last_rate_limit
                    continue
                sleep_for = route_delay if route_delay is not None else poll_delay
                if last_rate_limit is not None and sleep_for > remaining:
                    raise last_rate_limit
                await asyncio.sleep(min(sleep_for, remaining))
                continue

            if loop.time() >= deadline:
                continue

            try:
                resolved = await self._conversation.find_recent_conversation_id_by_user_message_id(
                    user_message_id,
                    limit=5,
                    exclude_ids=rejected_ids,
                    max_candidate_fetches=candidate_budget,
                    candidate_attempts=candidate_attempts,
                    candidate_fetch_delay_seconds=max(1.0, poll_delay),
                )
            except RateLimited as exc:
                last_rate_limit = exc
                last_error = f"{type(exc).__name__}: {exc}"
                extend_deadline_for_rate_limit(loop.time())
                retry_wait = exc.retry_delay(
                    rate_limit_default,
                    maximum_seconds=max(30.0, poll_max),
                )
                sleep_for = max(poll_delay, retry_wait)
                poll_delay = min(max(poll_delay * 2.0, sleep_for), poll_max)
            except ConversationError as exc:
                last_rate_limit = None
                last_error = f"{type(exc).__name__}: {exc}"
                sleep_for = poll_delay
                poll_delay = min(poll_delay * 2.0, poll_max)
            else:
                last_rate_limit = None
                if resolved is not None:
                    return resolved
                sleep_for = poll_delay
                poll_delay = min(poll_delay * 2.0, poll_max)

            remaining = deadline - loop.time()
            if remaining <= 0:
                if last_rate_limit is not None:
                    raise last_rate_limit
                detail = f"; last route={last_route!r}"
                if last_error is not None:
                    detail += f"; last error={last_error}"
                raise AmbiguousSubmission(
                    "conversation SSE started but no verified durable conversation ID "
                    "was resolved" + detail
                )
            if last_rate_limit is not None and sleep_for > remaining:
                # Retry-After is authoritative. Do not shorten it to fit the local
                # resolver window and then hit the same endpoint too early.
                raise last_rate_limit
            await asyncio.sleep(min(sleep_for, remaining))

    async def _resolve_durable_conversation_id(
        self,
        conversation_id: str,
        user_message_id: str,
    ) -> str:
        if not is_transient_conversation_id(conversation_id):
            return conversation_id
        try:
            return await self._wait_for_conversation_id(user_message_id)
        except AmbiguousSubmission as exc:
            raise RecoveryIncomplete(
                "transient ChatGPT route could not be mapped to the durable "
                "conversation using the persisted user_message_id"
            ) from exc

    def _validate_requested_app_transport(self, task: BenchmarkTask) -> None:
        if not task.tools:
            return
        if len(task.tools) != 1:
            raise FatalUIState(
                "runtime supports exactly one model-facing App per benchmark task"
            )
        if not self._traffic.app_system_hints:
            raise AmbiguousSubmission(
                "ChatGPT conversation POST did not contain an App system hint "
                f"for requested App {task.tools[0].name!r}"
            )

    def _validate_submitted_model(self) -> None:
        model = self._traffic.submitted_model
        if self._expected_model and model != self._expected_model:
            raise ModelMismatch(
                f"frontend submitted model {model!r}; expected {self._expected_model!r}"
            )
        timezone = self._traffic.submitted_timezone
        baseline_timezone = (
            self._environment_baseline.get("timezone") if self._environment_baseline else None
        )
        if timezone and baseline_timezone and timezone != baseline_timezone:
            raise EnvironmentDrift(
                f"frontend timezone {timezone!r} != browser timezone {baseline_timezone!r}"
            )
        submitted_offset = self._traffic.submitted_timezone_offset_min
        baseline_offset = (
            self._environment_baseline.get("timezoneOffsetMin")
            if self._environment_baseline else None
        )
        if (
            submitted_offset is not None
            and baseline_offset is not None
            and submitted_offset != baseline_offset
        ):
            raise EnvironmentDrift(
                f"frontend timezone offset {submitted_offset!r} != "
                f"browser offset {baseline_offset!r}"
            )

    async def submit_task(
        self,
        prepared: PreparedTurn,
        *,
        before_send: Callable[[], None],
        on_user_message_id: Callable[[str], None],
    ) -> SubmittedTurn:
        if self._thinking_effort_observer_error is not None:
            raise FatalUIState(self._thinking_effort_observer_error)
        try:
            async with self._page.expect_response(
                is_conversation_stream_response,
                timeout=int(self._stream_start_timeout * 1000),
            ) as response_info:
                await self._click_send(before_send)
            response = await response_info.value
        except Exception as exc:
            if self._thinking_effort_observer_error is not None:
                raise FatalUIState(self._thinking_effort_observer_error) from exc
            if self._traffic.saw_backend_429:
                raise RateLimited("ChatGPT returned HTTP 429 during submit") from exc
            if self._traffic.saw_backend_403:
                raise SiteChallengeFailed(
                    "ChatGPT returned backend HTTP 403 and no conversation SSE was observed"
                ) from exc
            raise AmbiguousSubmission(
                "no conversation SSE observed after Send; automatic resubmission is disabled"
            ) from exc

        self._traffic.validate_single_stream_request()
        self._validate_thinking_effort_observation()
        self._validate_requested_app_transport(prepared.task)
        self._validate_submitted_model()
        user_message_id = self._traffic.submitted_user_message_id()
        on_user_message_id(user_message_id)

        # The POST response itself is authoritative. A direct 429/403 must stop
        # here, before conversation-ID resolution can generate any auxiliary
        # /conversations or /api/auth/session traffic. Persisting the frontend
        # user_message_id first keeps the already-submitted attempt recoverable.
        stream = ConversationStream(response, timeout_seconds=self._turn_timeout)
        await stream.raise_for_initial_status()

        conversation_id = await self._wait_for_conversation_id(user_message_id)
        submitted = SubmittedTurn(
            conversation_id=conversation_id,
            user_message_id=user_message_id,
            stream=stream,
            task=prepared.task,
        )
        self._active_turn = submitted
        return submitted

    def _validate_message_models(self, messages: list[dict]) -> set[str]:
        slugs = assistant_model_slugs(messages)
        if self._expected_model:
            unexpected = sorted(slug for slug in slugs if slug != self._expected_model)
            if unexpected:
                raise ModelMismatch(
                    f"assistant messages contain unexpected model slug(s): {unexpected}; "
                    f"expected only {self._expected_model!r}"
                )
        return slugs

    def _validated_messages(
        self,
        conversation: dict[str, Any],
        user_message_id: str,
    ) -> list[dict]:
        messages = extract_dataset_messages(conversation)
        validate_conversation_identity(messages, user_message_id)
        self._validate_message_models(messages)
        return messages

    async def _wait_stream_or_durable_completion(
        self,
        submitted: SubmittedTurn,
    ):
        """Race SSE completion against low-rate durable completion checks.

        Current ChatGPT can finish a turn while the frontend SSE remains open or
        ends as net::ERR_ABORTED. Durable polling is intentionally sparse so the
        runner cannot create its own /conversations readback rate limit.
        """
        stream_task = asyncio.create_task(submitted.stream.wait())
        loop = asyncio.get_running_loop()
        turn_timeout = float(getattr(self, "_turn_timeout", 1800.0))
        deadline = loop.time() + turn_timeout
        poll_delay = float(
            getattr(self, "_durable_poll_initial_seconds", 10.0)
        )
        poll_max = float(
            getattr(self, "_durable_poll_max_seconds", 30.0)
        )
        rate_limit_backoff = float(
            getattr(self, "_durable_poll_rate_limit_backoff_seconds", DEFAULT_RATE_LIMIT_FALLBACK_SECONDS)
        )
        stream_error: (
            ConversationStreamIncomplete | ConversationStreamAborted | None
        ) = None
        stream_error_deadline: float | None = None

        async def durable_snapshot():
            # First consume a snapshot the frontend already fetched. This creates
            # no additional ChatGPT request.
            natural = None
            natural_snapshot = getattr(self._traffic, "natural_snapshot", None)
            if callable(natural_snapshot):
                natural = await natural_snapshot(
                    submitted.conversation_id,
                    wait_seconds=0,
                )
            if natural is not None:
                try:
                    messages = self._validated_messages(
                        natural,
                        submitted.user_message_id,
                    )
                except ConversationError:
                    pass
                else:
                    self._traffic.mark_natural_snapshot_used()
                    self._readback_allowed_at = 0.0
                    self._readback_rate_limit = None
                    return natural, messages, None

            if loop.time() < getattr(self, "_readback_allowed_at", 0.0):
                return None, None, self._readback_rate_limit

            # Only then perform one explicit readback.
            self._traffic.mark_fallback_snapshot()
            try:
                conversation = await self._conversation.fetch(
                    submitted.conversation_id
                )
            except ConversationNotFound:
                self._readback_allowed_at = 0.0
                self._readback_rate_limit = None
                return None, None, None
            except RateLimited as exc:
                # A readback 429 is not evidence that the teacher generation was
                # rate-limited. Back off and keep the already-submitted turn.
                delay = max(
                    1.0,
                    exc.retry_delay(rate_limit_backoff, maximum_seconds=rate_limit_backoff),
                )
                self._readback_allowed_at = loop.time() + delay
                self._readback_rate_limit = exc
                return None, None, exc

            self._readback_allowed_at = 0.0
            self._readback_rate_limit = None

            try:
                messages = self._validated_messages(
                    conversation,
                    submitted.user_message_id,
                )
            except ConversationError:
                return conversation, None, None
            return conversation, messages, None

        try:
            while True:
                now = loop.time()
                if now >= deadline:
                    if self._readback_rate_limit is not None:
                        raise self._readback_rate_limit
                    if stream_error is not None:
                        raise stream_error
                    raise RecoveryIncomplete(
                        "ChatGPT turn did not become durably complete before timeout"
                    )

                if stream_task.done() and stream_error is None:
                    try:
                        return stream_task.result(), None, None, None
                    except (
                        ConversationStreamIncomplete,
                        ConversationStreamAborted,
                    ) as exc:
                        stream_error = exc
                        stream_error_deadline = min(
                            deadline,
                            loop.time()
                            + float(
                                getattr(
                                    self,
                                    "_durable_error_recovery_seconds",
                                    120.0,
                                )
                            ),
                        )

                if stream_error is not None:
                    assert stream_error_deadline is not None
                    if loop.time() >= stream_error_deadline:
                        if self._readback_rate_limit is not None:
                            raise self._readback_rate_limit
                        raise stream_error
                    conversation, messages, readback_limit = (
                        await durable_snapshot()
                    )
                    if messages is not None:
                        return None, stream_error, conversation, messages
                    if readback_limit is None:
                        raise stream_error

                    remaining = stream_error_deadline - loop.time()
                    if remaining <= 0:
                        raise readback_limit
                    cooldown = max(0.0, self._readback_allowed_at - loop.time())
                    if cooldown > remaining:
                        raise readback_limit
                    await asyncio.sleep(cooldown)
                    continue

                remaining = deadline - loop.time()
                done, _pending = await asyncio.wait(
                    {stream_task},
                    timeout=min(poll_delay, remaining),
                )
                if done:
                    continue

                conversation, messages, readback_limit = (
                    await durable_snapshot()
                )
                if messages is not None:
                    stream_task.cancel()
                    await asyncio.gather(
                        stream_task,
                        return_exceptions=True,
                    )
                    return None, None, conversation, messages

                if readback_limit is not None:
                    poll_delay = max(
                        min(poll_delay * 2.0, max(rate_limit_backoff, poll_max)),
                        self._readback_allowed_at - loop.time(),
                    )
                else:
                    poll_delay = min(poll_delay * 2.0, poll_max)
        finally:
            if not stream_task.done():
                stream_task.cancel()
                await asyncio.gather(
                    stream_task,
                    return_exceptions=True,
                )

    async def wait_for_completion(self, submitted: SubmittedTurn) -> CapturedConversation:
        if self._active_turn is not submitted:
            raise ConcurrentTurnError("submitted turn is not active")
        try:
            (
                stream_result,
                stream_error,
                conversation,
                messages,
            ) = await self._wait_stream_or_durable_completion(submitted)

            if (
                stream_result is not None
                and stream_result.conversation_id != submitted.conversation_id
            ):
                raise AmbiguousSubmission(
                    "conversation ID mismatch between browser URL and completed SSE: "
                    f"url={submitted.conversation_id!r}, "
                    f"sse={stream_result.conversation_id!r}"
                )

            self._traffic.validate_single_stream_request()
            self._validate_submitted_model()
            await self._check_environment()
            if self._traffic.saw_backend_429:
                raise RateLimited("ChatGPT returned HTTP 429 during the turn")

            if messages is None:
                conversation = await self._traffic.natural_snapshot(
                    submitted.conversation_id,
                    wait_seconds=self._natural_snapshot_wait,
                )
                if conversation is not None:
                    try:
                        messages = self._validated_messages(
                            conversation,
                            submitted.user_message_id,
                        )
                        self._traffic.mark_natural_snapshot_used()
                    except Exception:
                        messages = None

            if messages is None:
                self._traffic.mark_fallback_snapshot()
                try:
                    conversation = await self._fetch_recovery_snapshot(
                        submitted.conversation_id
                    )
                    messages = self._validated_messages(
                        conversation,
                        submitted.user_message_id,
                    )
                except ConversationError as exc:
                    if stream_error is not None:
                        raise stream_error from exc
                    raise

            used_apps = invoked_app_names(messages)
            if stream_result is not None:
                metadata = stream_result.runtime_metadata()
            else:
                metadata = {
                    "stream_protocol": "sse",
                    "conversation_id": submitted.conversation_id,
                    "final_end_turn": True,
                    "message_stream_complete": False,
                    "done": False,
                    "last_token": False,
                    "stream_completed_via_durable_snapshot": True,
                    "stream_transport_finished": False,
                }
                if isinstance(stream_error, ConversationStreamIncomplete):
                    metadata["stream_recovered_from_incomplete"] = True
                if stream_error is not None:
                    metadata.update(
                        {
                            "stream_recovered_from_error": True,
                            "stream_error_type": type(stream_error).__name__,
                            "stream_error_message": str(stream_error),
                        }
                    )
                else:
                    metadata["stream_transport_cancelled_after_durable_completion"] = True

            metadata.update(self._traffic.runtime_metadata())
            metadata.update({
                "recovered": False,
                "environment_sha256": self._environment_hash,
                "expected_model": self._expected_model,
                "required_thinking_effort": REQUIRED_THINKING_EFFORT,
                "required_ui_thinking_effort": REQUIRED_UI_THINKING_EFFORT,
                "thinking_effort_verified_requests": getattr(
                    self,
                    "_thinking_effort_verified_requests",
                    0,
                ),
                "requested_tools": [
                    {"type": t.type, "name": t.name}
                    for t in submitted.task.tools
                ],
                "used_apps": sorted(used_apps),
                "submitted_user_message_id": submitted.user_message_id,
            })
            return CapturedConversation(
                submitted.conversation_id,
                messages,
                metadata,
            )
        finally:
            self._active_turn = None

    async def _fetch_recovery_snapshot(self, conversation_id: str):
        """Retry only durable readback 429s during crash recovery."""
        loop = asyncio.get_running_loop()
        timeout_seconds = float(
            getattr(self, "_durable_error_recovery_seconds", 120.0)
        )
        deadline = loop.time() + timeout_seconds
        delay = float(
            getattr(self, "_durable_poll_rate_limit_backoff_seconds", DEFAULT_RATE_LIMIT_FALLBACK_SECONDS)
        )
        attempted = False

        while True:
            if attempted and loop.time() >= deadline:
                raise self._readback_rate_limit
            cooldown = max(0.0, getattr(self, "_readback_allowed_at", 0.0) - loop.time())
            if cooldown:
                if cooldown > deadline - loop.time():
                    raise self._readback_rate_limit
                await asyncio.sleep(cooldown)
                if loop.time() >= deadline:
                    raise self._readback_rate_limit
            try:
                attempted = True
                snapshot = await self._conversation.fetch(conversation_id)
                self._readback_allowed_at = 0.0
                self._readback_rate_limit = None
                return snapshot
            except RateLimited as exc:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise
                wait = max(1.0, exc.retry_delay(delay, maximum_seconds=DEFAULT_RATE_LIMIT_FALLBACK_SECONDS))
                self._readback_allowed_at = loop.time() + wait
                self._readback_rate_limit = exc
                if wait > remaining:
                    raise
                await asyncio.sleep(wait)
                delay = min(max(delay * 2.0, 1.0), DEFAULT_RATE_LIMIT_FALLBACK_SECONDS)

    async def recover(
        self,
        conversation_id: str,
        *,
        task: BenchmarkTask,
        user_message_id: str,
    ) -> CapturedConversation:
        if self._active_turn is not None:
            raise ConcurrentTurnError("cannot recover while another turn is active")
        conversation_id = await self._resolve_durable_conversation_id(
            conversation_id,
            user_message_id,
        )
        await self._navigate(f"{self._base_url}/c/{conversation_id}")
        await self._site.wait_ready()
        await self._check_environment()
        try:
            conversation = await self._fetch_recovery_snapshot(conversation_id)
        except ConversationNotFound as exc:
            raise RecoveryIncomplete(
                f"conversation {conversation_id!r} no longer exists; "
                "it may have been deleted. Abandon this recovery explicitly "
                "before starting a new attempt."
            ) from exc
        try:
            messages = self._validated_messages(conversation, user_message_id)
        except Exception as exc:
            raise RecoveryIncomplete(
                f"existing conversation cannot be safely recovered: {exc}"
            ) from exc
        used_apps = invoked_app_names(messages)
        return CapturedConversation(
            conversation_id,
            messages,
            {
                "recovered": True,
                "stream_observed": False,
                "environment_sha256": self._environment_hash,
                "expected_model": self._expected_model,
                "required_thinking_effort": REQUIRED_THINKING_EFFORT,
                "required_ui_thinking_effort": REQUIRED_UI_THINKING_EFFORT,
                "requested_tools": [
                    {"type": t.type, "name": t.name}
                    for t in task.tools
                ],
                "used_apps": sorted(used_apps),
                "submitted_user_message_id": user_message_id,
            },
        )

    async def recover_current_candidate(
        self,
        *,
        task: BenchmarkTask,
        user_message_id: str,
    ) -> CapturedConversation:
        conversation_id = await self._wait_for_conversation_id(user_message_id)
        return await self.recover(
            conversation_id,
            task=task,
            user_message_id=user_message_id,
        )

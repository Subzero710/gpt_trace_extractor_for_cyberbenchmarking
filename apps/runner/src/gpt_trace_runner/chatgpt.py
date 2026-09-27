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

def _thinking_effort_route_pattern(base_url: str):
    return re.compile(
        rf"^{re.escape(base_url.rstrip('/'))}/backend-api/f/conversation"
        r"(?:/prepare)?(?:\?.*)?$"
    )


def check_chatgpt_protocol_contracts(base_url: str) -> None:
    if REQUIRED_THINKING_EFFORT != "extended":
        raise RuntimeError(
            "ChatGPT benchmark thinking effort must remain forced to 'extended'"
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
        self._thinking_effort_route_installed = False
        self._thinking_effort_stream_requests = 0
        self._thinking_effort_force_error: str | None = None

    @staticmethod
    def _extended_thinking_post_data(payload: Any) -> str:
        if not isinstance(payload, dict):
            raise ValueError("ChatGPT conversation request body is not a JSON object")
        rewritten = dict(payload)
        rewritten["thinking_effort"] = REQUIRED_THINKING_EFFORT
        return json.dumps(
            rewritten,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    async def _force_extended_thinking_effort(self, route, request) -> None:
        request_url = request.url.split("?", 1)[0].rstrip("/")
        conversation_url = f"{self._base_url}/backend-api/f/conversation"
        prepare_url = f"{conversation_url}/prepare"

        if request.method.upper() != "POST" or request_url not in {
            conversation_url,
            prepare_url,
        }:
            await route.continue_()
            return

        try:
            post_data = self._extended_thinking_post_data(request.post_data_json)
        except Exception as exc:
            self._thinking_effort_force_error = (
                "could not force ChatGPT thinking_effort="
                f"{REQUIRED_THINKING_EFFORT!r}: {exc}"
            )
            await route.abort()
            return

        try:
            await route.continue_(post_data=post_data)
        except Exception as exc:
            self._thinking_effort_force_error = (
                "failed to continue ChatGPT request after forcing "
                f"thinking_effort={REQUIRED_THINKING_EFFORT}: {exc}"
            )
            raise
        else:
            if request_url == conversation_url:
                self._thinking_effort_stream_requests += 1

    async def _ensure_thinking_effort_enforcer(self) -> None:
        if self._thinking_effort_route_installed:
            return
        pattern = _thinking_effort_route_pattern(self._base_url)
        await self._page.route(pattern, self._force_extended_thinking_effort)
        self._thinking_effort_route_installed = True

    def _validate_thinking_effort_enforcement(self) -> None:
        if self._thinking_effort_force_error is not None:
            raise FatalUIState(self._thinking_effort_force_error)
        if self._thinking_effort_stream_requests != 1:
            raise AmbiguousSubmission(
                "expected exactly one ChatGPT conversation POST rewritten with "
                f"thinking_effort={REQUIRED_THINKING_EFFORT!r}; observed "
                f"{self._thinking_effort_stream_requests}"
            )

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
                    };
                }"""
            )
        except Exception as exc:
            raise AuthenticationRequired(
                "could not verify the existing ChatGPT session during resume"
            ) from exc

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
        self._thinking_effort_stream_requests = 0
        self._thinking_effort_force_error = None
        await self._ensure_thinking_effort_enforcer()
        await self._check_environment()
        try:
            await self._new_chat_if_needed()
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
        """Resolve only a durable conversation identity for the submitted message."""
        deadline = asyncio.get_running_loop().time() + self._stream_start_timeout
        last_route: str | None = None
        last_error: str | None = None

        while True:
            candidate = conversation_id_from_url(self._page.url)
            if candidate:
                last_route = candidate
                if not is_transient_conversation_id(candidate):
                    try:
                        conversation = await self._conversation.fetch(candidate)
                        if self._conversation_has_exact_user_message(
                            conversation,
                            user_message_id,
                        ):
                            return candidate
                    except (ConversationError, AmbiguousSubmission) as exc:
                        last_error = f"{type(exc).__name__}: {exc}"

            try:
                resolved = await self._conversation.find_recent_conversation_id_by_user_message_id(
                    user_message_id,
                    limit=5,
                )
            except ConversationError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if resolved is not None:
                    return resolved

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                detail = f"; last route={last_route!r}"
                if last_error is not None:
                    detail += f"; last error={last_error}"
                raise AmbiguousSubmission(
                    "conversation SSE started but no verified durable conversation ID "
                    "was resolved" + detail
                )
            await asyncio.sleep(min(0.25, remaining))

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
        try:
            async with self._page.expect_response(
                is_conversation_stream_response,
                timeout=int(self._stream_start_timeout * 1000),
            ) as response_info:
                await self._click_send(before_send)
            response = await response_info.value
        except Exception as exc:
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
        self._validate_thinking_effort_enforcement()
        self._validate_submitted_model()
        user_message_id = self._traffic.submitted_user_message_id()
        on_user_message_id(user_message_id)
        conversation_id = await self._wait_for_conversation_id(user_message_id)
        submitted = SubmittedTurn(
            conversation_id=conversation_id,
            user_message_id=user_message_id,
            stream=ConversationStream(response, timeout_seconds=self._turn_timeout),
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
        """Race the SSE transport against durable conversation completion."""
        stream_task = asyncio.create_task(submitted.stream.wait())
        await asyncio.sleep(0)

        async def durable_snapshot():
            self._traffic.mark_fallback_snapshot()
            try:
                conversation = await self._conversation.fetch(
                    submitted.conversation_id
                )
            except ConversationNotFound:
                return None, None
            try:
                messages = self._validated_messages(
                    conversation,
                    submitted.user_message_id,
                )
            except ConversationError:
                return conversation, None
            return conversation, messages

        try:
            while True:
                if stream_task.done():
                    try:
                        return stream_task.result(), None, None, None
                    except (
                        ConversationStreamIncomplete,
                        ConversationStreamAborted,
                    ) as exc:
                        conversation, messages = await durable_snapshot()
                        if messages is not None:
                            return None, exc, conversation, messages
                        raise exc

                conversation, messages = await durable_snapshot()
                if messages is not None:
                    stream_task.cancel()
                    await asyncio.gather(stream_task, return_exceptions=True)
                    return None, None, conversation, messages

                await asyncio.wait({stream_task}, timeout=0.5)
        finally:
            if not stream_task.done():
                stream_task.cancel()
                await asyncio.gather(stream_task, return_exceptions=True)

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
                    conversation = await self._conversation.fetch(
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
                "thinking_effort_forced_requests": getattr(
                    self,
                    "_thinking_effort_stream_requests",
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
            conversation = await self._conversation.fetch(conversation_id)
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

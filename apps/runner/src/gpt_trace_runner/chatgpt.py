from __future__ import annotations

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
    validate_task_conversation,
)
from .exceptions import (
    AmbiguousSubmission,
    AppUnavailable,
    AuthenticationRequired,
    ChatGPTUIError,
    ConcurrentTurnError,
    EnvironmentDrift,
    FatalUIState,
    ModelMismatch,
    RateLimited,
    RecoveryIncomplete,
    RequiredToolNotUsed,
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
NEW_CHAT_SELECTORS = (
    'a[data-testid="create-new-chat-button"]',
    'button[data-testid="create-new-chat-button"]',
    'a[aria-label*="New chat"]',
    'button[aria-label*="New chat"]',
)


@dataclass(slots=True)
class PreparedTurn:
    task: BenchmarkTask


@dataclass(slots=True)
class SubmittedTurn:
    conversation_id: str
    stream: ConversationStream
    task: BenchmarkTask



def _prompt_for_chatgpt(task: BenchmarkTask) -> str:
    # task.prompt is immutable provenance and participates in task_fingerprint.
    # Remove only redundant App-activation prose from the UI projection because
    # Apps are already represented by structured @ mentions in the composer.
    prompt = task.prompt
    names = tuple(tool.name for tool in task.tools)
    if not names:
        return prompt

    if len(names) == 1:
        name = names[0]
        prefix = f"Use the {name} app. "
        if prompt.startswith(prefix):
            prompt = prompt[len(prefix):]

        suffixes = (
            f" You must use {name} and must not answer from reasoning alone.",
            f" You must use {name} and must not answer from prior knowledge.",
            f" You must use {name}.",
        )
        for suffix in suffixes:
            if prompt.endswith(suffix):
                prompt = prompt[:-len(suffix)]
                break

    elif len(names) == 2:
        joined = f"{names[0]} and {names[1]}"
        prefix = f"Use both {joined}. "
        if prompt.startswith(prefix):
            prompt = prompt[len(prefix):]

        suffix = f" You must use both {joined}."
        if prompt.endswith(suffix):
            prompt = prompt[:-len(suffix)]

    projected = prompt.strip()
    if not projected:
        raise FatalUIState(
            "benchmark prompt contains only App activation prose"
        )
    return projected


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
        old_id = conversation_id_from_url(self._page.url)
        if old_id is None:
            composer = await self._site.wait_ready()
            try:
                dirty = (await composer.inner_text()) != ""
            except Exception as exc:
                raise FatalUIState("could not inspect home composer state") from exc
            if dirty:
                await self.goto_home()
                await self._site.wait_ready()
            return

        button = await first_visible(self._page, NEW_CHAT_SELECTORS)
        if button is None:
            raise FatalUIState("visible New chat control was not found")
        await self._interaction.click(button)
        try:
            await self._page.wait_for_function(
                "old => !location.pathname.startsWith('/c/' + old)",
                arg=old_id,
                timeout=int(self._stream_start_timeout * 1000),
            )
        except Exception as exc:
            raise FatalUIState("New chat did not leave the previous conversation") from exc
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
        """Fail before benchmark execution if a required ChatGPT App is absent."""
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
        # Resolve Apps first through ChatGPT's real @ mention autocomplete.
        # task.prompt stays canonical for provenance/fingerprints. Only the
        # composer projection removes redundant App-activation prose.
        await select_apps(
            self._page,
            get_editor=self._site.wait_ready,
            tools=task.tools,
            interaction=self._interaction,
            timeout_seconds=self._tool_select_timeout,
        )

        prompt = _prompt_for_chatgpt(task)

        # App mentions are structured nodes. Append the projected prompt after
        # them and never clear/select-all the composer after mentions exist.
        editor = await self._site.wait_ready()
        await self._interaction.type_text(
            editor,
            prompt,
            clear_existing=False,
        )
        await self._site.wait_ready()

    async def prepare_task(self, task: BenchmarkTask) -> PreparedTurn:
        if self._active_turn is not None:
            raise ConcurrentTurnError("another ChatGPT turn is already active")
        self._traffic.begin_task()
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

    async def _wait_for_conversation_id(self) -> str:
        try:
            await self._page.wait_for_url(
                re.compile(r"/c/[^/?#]+"),
                timeout=int(self._stream_start_timeout * 1000),
            )
        except Exception as exc:
            raise AmbiguousSubmission(
                "conversation SSE started but no conversation URL was assigned"
            ) from exc
        value = conversation_id_from_url(self._page.url)
        if not value:
            raise AmbiguousSubmission("conversation URL has no usable ID")
        return value

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

    async def submit_task(self, prepared: PreparedTurn, *, before_send: Callable[[], None]) -> SubmittedTurn:
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
        self._validate_submitted_model()
        if not self._traffic.submitted_prompt_matches(prepared.task.prompt):
            raise AmbiguousSubmission(
                "frontend conversation POST prompt differs from benchmark prompt"
            )
        conversation_id = await self._wait_for_conversation_id()
        submitted = SubmittedTurn(
            conversation_id=conversation_id,
            stream=ConversationStream(response, timeout_seconds=self._turn_timeout),
            task=prepared.task,
        )
        self._active_turn = submitted
        return submitted

    def _validate_required_tools(self, task: BenchmarkTask, messages: list[dict]) -> set[str]:
        used = invoked_app_names(messages)
        folded = {name.casefold() for name in used}
        missing = [
            tool.name for tool in task.tools
            if tool.required and tool.name.casefold() not in folded
        ]
        if missing:
            raise RequiredToolNotUsed(
                "required ChatGPT app(s) were not invoked: " + ", ".join(missing)
            )
        return used

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

    def _validated_messages(self, conversation: dict[str, Any], task: BenchmarkTask) -> list[dict]:
        messages = extract_dataset_messages(conversation)
        validate_task_conversation(messages, task.prompt)
        self._validate_message_models(messages)
        return messages

    async def wait_for_completion(self, submitted: SubmittedTurn) -> CapturedConversation:
        if self._active_turn is not submitted:
            raise ConcurrentTurnError("submitted turn is not active")
        try:
            stream_result = await submitted.stream.wait()
            if stream_result.conversation_id != submitted.conversation_id:
                raise AmbiguousSubmission(
                    "conversation ID mismatch between browser URL and completed SSE"
                )
            self._traffic.validate_single_stream_request()
            self._validate_submitted_model()
            await self._check_environment()
            if self._traffic.saw_backend_429:
                raise RateLimited("ChatGPT returned HTTP 429 during the turn")

            conversation = await self._traffic.natural_snapshot(
                submitted.conversation_id,
                wait_seconds=self._natural_snapshot_wait,
            )
            messages = None
            if conversation is not None:
                try:
                    messages = self._validated_messages(conversation, submitted.task)
                    self._traffic.mark_natural_snapshot_used()
                except Exception:
                    messages = None
            if messages is None:
                self._traffic.mark_fallback_snapshot()
                conversation = await self._conversation.fetch(submitted.conversation_id)
                messages = self._validated_messages(conversation, submitted.task)

            used_apps = self._validate_required_tools(submitted.task, messages)
            metadata = stream_result.runtime_metadata()
            metadata.update(self._traffic.runtime_metadata())
            metadata.update({
                "recovered": False,
                "environment_sha256": self._environment_hash,
                "expected_model": self._expected_model,
                "requested_tools": [
                    {"type": t.type, "name": t.name, "required": t.required}
                    for t in submitted.task.tools
                ],
                "used_apps": sorted(used_apps),
            })
            return CapturedConversation(submitted.conversation_id, messages, metadata)
        finally:
            self._active_turn = None

    async def recover(self, conversation_id: str, *, task: BenchmarkTask) -> CapturedConversation:
        if self._active_turn is not None:
            raise ConcurrentTurnError("cannot recover while another turn is active")
        await self._navigate(f"{self._base_url}/c/{conversation_id}")
        await self._site.wait_ready()
        await self._check_environment()
        conversation = await self._conversation.fetch(conversation_id)
        try:
            messages = self._validated_messages(conversation, task)
        except Exception as exc:
            raise RecoveryIncomplete(
                f"existing conversation cannot be safely recovered: {exc}"
            ) from exc
        used_apps = self._validate_required_tools(task, messages)
        return CapturedConversation(
            conversation_id,
            messages,
            {
                "recovered": True,
                "stream_observed": False,
                "environment_sha256": self._environment_hash,
                "expected_model": self._expected_model,
                "requested_tools": [
                    {"type": t.type, "name": t.name, "required": t.required}
                    for t in task.tools
                ],
                "used_apps": sorted(used_apps),
            },
        )

    async def recover_current_candidate(self, *, task: BenchmarkTask) -> CapturedConversation:
        conversation_id = conversation_id_from_url(self._page.url)
        if not conversation_id:
            raise RecoveryIncomplete(
                "submission may have happened but current browser URL has no conversation ID"
            )
        return await self.recover(conversation_id, task=task)

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import Locator, Page

from .conversation import (
    ConversationClient,
    conversation_id_from_url,
    extract_dataset_messages,
    invoked_app_names,
    is_complete,
)
from .exceptions import (
    AmbiguousSubmission,
    ChatGPTUIError,
    ConcurrentTurnError,
    ConversationError,
    RateLimited,
    RecoveryIncomplete,
    RequiredToolNotUsed,
    SiteChallengeFailed,
)
from .interaction import InteractionGuard
from .models import BenchmarkTask, CapturedConversation
from .site_guard import PROMPT_SELECTORS, SiteGuard
from .stream import ConversationStream, is_conversation_stream_response
from .tools import select_apps
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
    "Upload from computer",
    "Upload files",
    "Upload file",
    "Add photos & files",
)
NEW_CHAT_SELECTORS = (
    'a[data-testid="create-new-chat-button"]',
    'button[data-testid="create-new-chat-button"]',
    'a[aria-label*="New chat"]',
    'button[aria-label*="New chat"]',
    'a[href="/"]',
)


@dataclass(slots=True)
class SubmittedTurn:
    conversation_id: str
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
    ) -> None:
        self._page = page
        self._base_url = base_url.rstrip("/")
        self._conversation = ConversationClient(page, turns=conversation_turns)
        self._turn_timeout = turn_timeout_seconds
        self._stream_start_timeout = stream_start_timeout_seconds
        self._tool_select_timeout = tool_select_timeout_seconds
        self._upload_timeout = upload_timeout_seconds
        self._natural_snapshot_wait = natural_snapshot_wait_seconds
        self._traffic = TrafficMonitor(page, base_url=self._base_url)
        self._interaction = InteractionGuard(
            page,
            origin=self._base_url,
            timeout_seconds=site_ready_timeout_seconds,
        )
        self._site = SiteGuard(
            page,
            interaction=self._interaction,
            traffic=self._traffic,
            ready_timeout_seconds=site_ready_timeout_seconds,
            challenge_timeout_seconds=challenge_timeout_seconds,
        )
        self._active_turn: SubmittedTurn | None = None

    async def goto_home(self) -> None:
        await self._page.goto(
            self._base_url,
            wait_until="domcontentloaded",
            timeout=60_000,
        )

    async def prepare_session(self) -> None:
        if not self._page.url.startswith(self._base_url):
            await self.goto_home()
        await self._site.wait_ready()

    async def prompt_box(self, timeout_ms: int = 10_000) -> Locator:
        # Keep this compatibility surface for auth/diagnostics while using the
        # same visible composer selectors as SiteGuard.
        each = max(1000, timeout_ms // len(PROMPT_SELECTORS))
        for selector in PROMPT_SELECTORS:
            locator = self._page.locator(selector).first
            try:
                await locator.wait_for(state="visible", timeout=each)
                return locator
            except Exception:
                pass
        raise ChatGPTUIError("ChatGPT composer unavailable")

    async def wait_until_authenticated(self, timeout_seconds: float) -> None:
        try:
            await self._site.prompt_locator().wait_for(
                state="visible",
                timeout=int(timeout_seconds * 1000),
            )
        except Exception as exc:
            raise ChatGPTUIError("authentication timeout") from exc

    async def _new_chat_if_needed(self) -> None:
        if conversation_id_from_url(self._page.url) is None:
            await self._site.wait_ready()
            return

        for selector in NEW_CHAT_SELECTORS:
            button = self._page.locator(selector).first
            try:
                if not await button.count() or not await button.is_visible():
                    continue
                await self._interaction.click(button)
                await self._site.wait_ready()
                if conversation_id_from_url(self._page.url) is not None:
                    raise ChatGPTUIError(
                        "New chat UI action did not leave the previous conversation"
                    )
                return
            except ChatGPTUIError:
                raise
            except Exception:
                continue

        raise ChatGPTUIError("visible New chat control was not found")

    async def _find_visible(self, selectors: tuple[str, ...]) -> Locator | None:
        for selector in selectors:
            locator = self._page.locator(selector).first
            try:
                if await locator.count() and await locator.is_visible():
                    return locator
            except Exception:
                continue
        return None

    async def _upload(self, attachments: tuple[Path, ...]) -> None:
        if not attachments:
            return

        payloads = build_file_payloads(attachments)
        attach = await self._find_visible(ATTACH_BUTTON_SELECTORS)
        if attach is None:
            raise ChatGPTUIError("visible ChatGPT attachment control was not found")

        chooser = None
        try:
            async with self._page.expect_file_chooser(timeout=3000) as info:
                await self._interaction.click(attach)
            chooser = await info.value
        except Exception:
            # Some ChatGPT layouts open a visible menu first. Follow that UI;
            # never set a hidden input[type=file] directly.
            for label in UPLOAD_MENU_LABELS:
                item = self._page.get_by_text(label, exact=True).last
                try:
                    if not await item.count() or not await item.is_visible():
                        continue
                    async with self._page.expect_file_chooser(
                        timeout=int(self._upload_timeout * 1000)
                    ) as info:
                        await self._interaction.click(item)
                    chooser = await info.value
                    break
                except Exception:
                    continue

        if chooser is None:
            raise ChatGPTUIError(
                "ChatGPT attachment UI did not open a browser file chooser"
            )

        await chooser.set_files(payloads)

        for attachment in attachments:
            try:
                await self._page.get_by_text(
                    attachment.name,
                    exact=True,
                ).last.wait_for(
                    state="visible",
                    timeout=int(self._upload_timeout * 1000),
                )
            except Exception as exc:
                raise ChatGPTUIError(
                    "attachment did not become ready in ChatGPT: "
                    f"{attachment.name}"
                ) from exc

    async def _compose(self, task: BenchmarkTask) -> Locator:
        editor = await self._site.wait_ready()
        await select_apps(
            self._page,
            tools=task.tools,
            interaction=self._interaction,
            timeout_seconds=self._tool_select_timeout,
        )
        editor = await self._site.wait_ready()
        await self._interaction.paste_text(editor, task.prompt)
        return editor

    async def _click_send(self) -> None:
        for selector in SEND_SELECTORS:
            button = self._page.locator(selector).first
            try:
                if not await button.count() or not await button.is_visible():
                    continue
                await self._interaction.click(button)
                return
            except ChatGPTUIError:
                raise
            except Exception:
                continue
        raise ChatGPTUIError("visible enabled ChatGPT Send button was not found")

    async def _wait_for_conversation_id(self) -> str:
        pattern = re.compile(r"/c/[^/?#]+")
        try:
            await self._page.wait_for_url(
                pattern,
                timeout=int(self._stream_start_timeout * 1000),
            )
        except Exception as exc:
            raise AmbiguousSubmission(
                "ChatGPT stream started but no conversation URL was assigned; "
                "the runner will not resubmit automatically"
            ) from exc

        conversation_id = conversation_id_from_url(self._page.url)
        if not conversation_id:
            raise AmbiguousSubmission(
                f"conversation URL has no usable ID: {self._page.url}"
            )
        return conversation_id

    async def start_task(self, task: BenchmarkTask) -> SubmittedTurn:
        if self._active_turn is not None:
            raise ConcurrentTurnError(
                "refusing to start a second ChatGPT turn while one is active"
            )

        self._traffic.begin_task()
        await self._new_chat_if_needed()
        await self._site.wait_ready()
        await self._upload(task.attachments)
        await self._compose(task)
        await self._interaction.ensure_page_focus()

        try:
            async with self._page.expect_response(
                is_conversation_stream_response,
                timeout=int(self._stream_start_timeout * 1000),
            ) as response_info:
                await self._click_send()
            response = await response_info.value
        except Exception as exc:
            if self._traffic.saw_backend_429:
                raise RateLimited("ChatGPT returned HTTP 429 during submit") from exc
            if self._traffic.saw_backend_403:
                # Do not resubmit after an ambiguous security/interstitial flow.
                raise SiteChallengeFailed(
                    "ChatGPT returned backend HTTP 403 and no conversation SSE "
                    "was observed; batch paused without resubmitting"
                ) from exc
            raise AmbiguousSubmission(
                "ChatGPT did not start the conversation SSE after Send; "
                "batch paused because automatic resubmission could duplicate a turn"
            ) from exc

        conversation_id = await self._wait_for_conversation_id()
        submitted = SubmittedTurn(
            conversation_id=conversation_id,
            stream=ConversationStream(
                response,
                timeout_seconds=self._turn_timeout,
            ),
            task=task,
        )
        self._active_turn = submitted
        return submitted

    def _validate_required_tools(
        self,
        task: BenchmarkTask,
        messages: list[dict],
    ) -> set[str]:
        used = invoked_app_names(messages)
        used_folded = {name.casefold() for name in used}
        missing = [
            tool.name
            for tool in task.tools
            if tool.required and tool.name.casefold() not in used_folded
        ]
        if missing:
            raise RequiredToolNotUsed(
                "required ChatGPT app(s) were not invoked: " + ", ".join(missing)
            )
        return used

    async def wait_for_completion(
        self,
        submitted: SubmittedTurn,
    ) -> CapturedConversation:
        if self._active_turn is not submitted:
            raise ConcurrentTurnError("submitted turn is not the active ChatGPT turn")

        try:
            stream_result = await submitted.stream.wait()

            if stream_result.conversation_id != submitted.conversation_id:
                raise ConversationError(
                    "conversation ID mismatch between browser URL and SSE: "
                    f"{submitted.conversation_id!r} != "
                    f"{stream_result.conversation_id!r}"
                )

            conversation = await self._traffic.natural_snapshot(
                submitted.conversation_id,
                wait_seconds=self._natural_snapshot_wait,
            )
            if conversation is None:
                self._traffic.mark_fallback_snapshot()
                conversation = await self._conversation.fetch(
                    submitted.conversation_id
                )

            messages = extract_dataset_messages(conversation)
            if not is_complete(messages):
                raise ConversationError(
                    "SSE reported a complete turn but the persisted conversation "
                    f"{submitted.conversation_id} has no assistant end_turn=true"
                )

            used_apps = self._validate_required_tools(submitted.task, messages)
            runtime_metadata = stream_result.runtime_metadata()
            runtime_metadata.update(self._traffic.runtime_metadata())
            runtime_metadata.update(
                {
                    "recovered": False,
                    "requested_tools": [
                        {
                            "type": tool.type,
                            "name": tool.name,
                            "required": tool.required,
                        }
                        for tool in submitted.task.tools
                    ],
                    "used_apps": sorted(used_apps),
                }
            )

            return CapturedConversation(
                conversation_id=submitted.conversation_id,
                messages=messages,
                runtime_metadata=runtime_metadata,
            )
        finally:
            self._active_turn = None

    async def recover(
        self,
        conversation_id: str,
        *,
        task: BenchmarkTask,
    ) -> CapturedConversation:
        if self._active_turn is not None:
            raise ConcurrentTurnError("cannot recover while another turn is active")

        # Recovery is intentionally allowed to navigate directly to a known
        # conversation. It never creates or resubmits a new turn.
        await self._page.goto(
            f"{self._base_url}/c/{conversation_id}",
            wait_until="domcontentloaded",
            timeout=60_000,
        )
        await self._site.wait_ready()

        conversation = await self._conversation.fetch(conversation_id)
        messages = extract_dataset_messages(conversation)
        if not is_complete(messages):
            raise RecoveryIncomplete(
                "existing conversation is not complete. The historical SSE "
                "cannot be re-attached after runner restart; batch paused "
                "instead of creating a duplicate conversation."
            )

        used_apps = self._validate_required_tools(task, messages)
        return CapturedConversation(
            conversation_id=conversation_id,
            messages=messages,
            runtime_metadata={
                "recovered": True,
                "stream_observed": False,
                "requested_tools": [
                    {
                        "type": tool.type,
                        "name": tool.name,
                        "required": tool.required,
                    }
                    for tool in task.tools
                ],
                "used_apps": sorted(used_apps),
            },
        )

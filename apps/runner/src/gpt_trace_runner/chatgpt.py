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
    AuthenticationRequired,
    ChatGPTUIError,
    ConversationError,
    RecoveryIncomplete,
    RequiredToolNotUsed,
)
from .models import BenchmarkTask, CapturedConversation
from .stream import (
    ConversationStream,
    is_conversation_stream_response,
)
from .tools import compose_with_apps
from .uploads import build_file_payloads


PROMPT_SELECTORS = (
    "#prompt-textarea",
    '[contenteditable="true"][data-lexical-editor="true"]',
)
SEND_SELECTORS = (
    'button[data-testid="send-button"]',
    "#composer-submit-button",
    'button[aria-label*="Send"]',
)
ATTACH_BUTTON_SELECTORS = (
    'button[aria-label*="Attach"]',
    'button[aria-label*="Upload"]',
    'button[data-testid*="attach"]',
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
    ) -> None:
        self._page = page
        self._base_url = base_url.rstrip("/")
        self._conversation = ConversationClient(
            page,
            turns=conversation_turns,
        )
        self._turn_timeout = turn_timeout_seconds
        self._stream_start_timeout = stream_start_timeout_seconds
        self._tool_select_timeout = tool_select_timeout_seconds
        self._upload_timeout = upload_timeout_seconds

    async def goto_home(self) -> None:
        await self._page.goto(
            self._base_url,
            wait_until="domcontentloaded",
            timeout=60_000,
        )

    async def prompt_box(self, timeout_ms: int = 10_000) -> Locator:
        each = max(1000, timeout_ms // len(PROMPT_SELECTORS))
        for selector in PROMPT_SELECTORS:
            locator = self._page.locator(selector).first
            try:
                await locator.wait_for(
                    state="visible",
                    timeout=each,
                )
                return locator
            except Exception:
                pass
        raise AuthenticationRequired("ChatGPT composer unavailable")

    async def wait_until_authenticated(self, timeout_seconds: float) -> None:
        combined = ", ".join(PROMPT_SELECTORS)
        try:
            await self._page.locator(combined).first.wait_for(
                state="visible",
                timeout=int(timeout_seconds * 1000),
            )
        except Exception as exc:
            raise AuthenticationRequired("authentication timeout") from exc

    async def _upload(self, attachments: tuple[Path, ...]) -> None:
        if not attachments:
            return

        file_input = self._page.locator('input[type="file"]')
        if await file_input.count() == 0:
            for selector in ATTACH_BUTTON_SELECTORS:
                button = self._page.locator(selector).first
                if await button.count() == 0:
                    continue
                try:
                    await button.click(timeout=2000)
                    break
                except Exception:
                    pass

            try:
                await file_input.first.wait_for(
                    state="attached",
                    timeout=5000,
                )
            except Exception:
                pass
            file_input = self._page.locator('input[type="file"]')

        if await file_input.count() == 0:
            raise ChatGPTUIError("file upload input not found")

        payloads = build_file_payloads(attachments)
        await file_input.last.set_input_files(payloads)

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
        editor = await self.prompt_box()
        await compose_with_apps(
            self._page,
            editor,
            prompt=task.prompt,
            tools=task.tools,
            timeout_seconds=self._tool_select_timeout,
        )
        return editor

    async def _click_send(self, editor: Locator) -> None:
        for selector in SEND_SELECTORS:
            button = self._page.locator(selector).first
            if await button.count() == 0:
                continue
            try:
                await button.click(timeout=3000)
                return
            except Exception:
                pass
        await editor.press("Enter")

    async def _wait_for_conversation_id(self) -> str:
        pattern = re.compile(r"/c/[^/?#]+")
        try:
            await self._page.wait_for_url(
                pattern,
                timeout=int(self._stream_start_timeout * 1000),
            )
        except Exception as exc:
            raise ChatGPTUIError(
                "ChatGPT did not assign a conversation ID"
            ) from exc

        conversation_id = conversation_id_from_url(self._page.url)
        if not conversation_id:
            raise ChatGPTUIError(
                f"conversation URL has no usable ID: {self._page.url}"
            )
        return conversation_id

    async def start_task(self, task: BenchmarkTask) -> SubmittedTurn:
        await self.goto_home()
        await self.prompt_box()
        await self._upload(task.attachments)
        editor = await self._compose(task)

        try:
            async with self._page.expect_response(
                is_conversation_stream_response,
                timeout=int(self._stream_start_timeout * 1000),
            ) as response_info:
                await self._click_send(editor)
            response = await response_info.value
        except Exception as exc:
            raise ChatGPTUIError(
                "ChatGPT did not start the /backend-api/f/conversation SSE"
            ) from exc

        conversation_id = await self._wait_for_conversation_id()
        return SubmittedTurn(
            conversation_id=conversation_id,
            stream=ConversationStream(
                response,
                timeout_seconds=self._turn_timeout,
            ),
            task=task,
        )

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
                "required ChatGPT app(s) were not invoked: "
                + ", ".join(missing)
            )
        return used

    async def wait_for_completion(
        self,
        submitted: SubmittedTurn,
    ) -> CapturedConversation:
        stream_result = await submitted.stream.wait()

        if stream_result.conversation_id != submitted.conversation_id:
            raise ConversationError(
                "conversation ID mismatch between browser URL and SSE: "
                f"{submitted.conversation_id!r} != "
                f"{stream_result.conversation_id!r}"
            )

        conversation = await self._conversation.fetch(
            submitted.conversation_id
        )
        messages = extract_dataset_messages(conversation)
        if not is_complete(messages):
            raise ConversationError(
                "SSE reported a complete turn but the persisted conversation "
                f"{submitted.conversation_id} has no assistant end_turn=true"
            )

        used_apps = self._validate_required_tools(
            submitted.task,
            messages,
        )
        runtime_metadata = stream_result.runtime_metadata()
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

    async def recover(
        self,
        conversation_id: str,
        *,
        task: BenchmarkTask,
    ) -> CapturedConversation:
        await self._page.goto(
            f"{self._base_url}/c/{conversation_id}",
            wait_until="domcontentloaded",
            timeout=60_000,
        )

        conversation = await self._conversation.fetch(conversation_id)
        messages = extract_dataset_messages(conversation)
        if not is_complete(messages):
            raise RecoveryIncomplete(
                "existing conversation is not complete. The historical SSE "
                "cannot be re-attached after runner restart; retry recovery "
                "later instead of creating a duplicate conversation."
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

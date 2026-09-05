from __future__ import annotations
import asyncio
import time
from pathlib import Path
from playwright.async_api import Locator, Page
from .conversation import ConversationClient, conversation_id_from_url, extract_dataset_messages, is_complete
from .exceptions import AuthenticationRequired, ChatGPTUIError, CompletionTimeout
from .models import BenchmarkTask, CapturedConversation
from .uploads import build_file_payloads

PROMPT_SELECTORS = (
    "#prompt-textarea",
    '[contenteditable="true"][data-lexical-editor="true"]',
)
SEND_SELECTORS = (
    'button[data-testid="send-button"]',
    'button[aria-label*="Send"]',
)
ATTACH_BUTTON_SELECTORS = (
    'button[aria-label*="Attach"]',
    'button[aria-label*="Upload"]',
    'button[data-testid*="attach"]',
)

class ChatGPTClient:
    def __init__(self, page: Page, *, base_url: str, conversation_turns: int,
                 poll_interval_seconds: float, completion_timeout_seconds: float,
                 stable_polls: int, upload_settle_seconds: float) -> None:
        self._page = page
        self._base_url = base_url.rstrip("/")
        self._conversation = ConversationClient(page, turns=conversation_turns)
        self._poll = poll_interval_seconds
        self._timeout = completion_timeout_seconds
        self._stable_polls = stable_polls
        self._upload_settle = upload_settle_seconds

    async def goto_home(self) -> None:
        await self._page.goto(self._base_url, wait_until="domcontentloaded", timeout=60_000)

    async def prompt_box(self, timeout_ms: int = 10_000) -> Locator:
        each = max(1000, timeout_ms // len(PROMPT_SELECTORS))
        for selector in PROMPT_SELECTORS:
            locator = self._page.locator(selector).first
            try:
                await locator.wait_for(state="visible", timeout=each)
                return locator
            except Exception:
                pass
        raise AuthenticationRequired("ChatGPT composer unavailable")

    async def wait_until_authenticated(self, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                await self.prompt_box(3000)
                return
            except AuthenticationRequired:
                await asyncio.sleep(1)
        raise AuthenticationRequired("authentication timeout")

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
            await asyncio.sleep(0.5)
            file_input = self._page.locator('input[type="file"]')
        if await file_input.count() == 0:
            raise ChatGPTUIError("file upload input not found")
        payloads = build_file_payloads(attachments)
        await file_input.last.set_input_files(payloads)
        if self._upload_settle:
            await asyncio.sleep(self._upload_settle)

    async def _submit(self, prompt: str) -> None:
        editor = await self.prompt_box()
        await editor.fill(prompt)
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

    async def _wait_for_conversation_id(self, timeout_seconds: float = 60) -> str:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            cid = conversation_id_from_url(self._page.url)
            if cid:
                return cid
            await asyncio.sleep(0.25)
        raise ChatGPTUIError("ChatGPT did not assign a conversation ID")

    async def start_task(self, task: BenchmarkTask) -> str:
        await self.goto_home()
        await self.prompt_box()
        await self._upload(task.attachments)
        await self._submit(task.prompt)
        return await self._wait_for_conversation_id()

    async def wait_for_completion(self, conversation_id: str, timeout_seconds: float | None = None) -> CapturedConversation:
        timeout = timeout_seconds or self._timeout
        deadline = time.monotonic() + timeout
        stable = 0
        last_count: int | None = None
        while time.monotonic() < deadline:
            conversation = await self._conversation.fetch(conversation_id)
            messages = extract_dataset_messages(conversation)
            if is_complete(messages):
                count = len(messages)
                stable = stable + 1 if count == last_count else 1
                last_count = count
                if stable >= self._stable_polls:
                    return CapturedConversation(conversation_id, messages)
            else:
                stable = 0
                last_count = len(messages)
            await asyncio.sleep(self._poll)
        raise CompletionTimeout(f"conversation {conversation_id} timed out after {timeout:.0f}s")

    async def recover(self, conversation_id: str) -> CapturedConversation:
        await self._page.goto(f"{self._base_url}/c/{conversation_id}", wait_until="domcontentloaded", timeout=60_000)
        return await self.wait_for_completion(conversation_id)

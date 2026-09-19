from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from gpt_trace_runner.chatgpt import ChatGPTClient
from gpt_trace_runner.exceptions import (
    AmbiguousSubmission,
    AuthenticationRequired,
    FatalUIState,
)


@pytest.mark.asyncio
async def test_navigation_uses_wrapped_page_goto_and_commit() -> None:
    page = type("PageDouble", (), {})()
    page.goto = AsyncMock(return_value=None)

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"

    await client.goto_home()

    page.goto.assert_awaited_once_with(
        "https://chatgpt.com",
        wait_until="commit",
        timeout=60_000,
    )


@pytest.mark.asyncio
async def test_navigation_timeout_is_fatal() -> None:
    page = type("PageDouble", (), {})()
    page.goto = AsyncMock(
        side_effect=PlaywrightTimeoutError("navigation did not commit")
    )

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"

    with pytest.raises(
        FatalUIState,
        match="ChatGPT navigation did not commit within 60 seconds",
    ):
        await client.goto_home()


def test_navigation_never_bypasses_cloakbrowser_page_wrapper() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")

    assert source.count("self._page.goto(") == 1
    assert "._original.goto" not in source
    assert 'wait_until="commit"' in source


def test_auth_and_run_validate_benchmark_apps_before_task_execution() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "cli.py"
    ).read_text(encoding="utf-8")

    assert source.count("await chatgpt.verify_apps_available(") == 2
    assert "ChatGPT benchmark Apps: ok" in source


class AuthTrafficDouble:
    def __init__(self) -> None:
        self.reset_calls = 0
        self.wait_calls = []

    def reset_auth_probe(self) -> None:
        self.reset_calls += 1

    async def wait_for_authenticated_user(self, *, timeout_seconds: float) -> None:
        self.wait_calls.append(timeout_seconds)


@pytest.mark.asyncio
async def test_auth_wait_reloads_chatgpt_and_uses_backend_me_oracle() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/"
    page.reload = AsyncMock(return_value=None)

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"
    client._traffic = AuthTrafficDouble()

    await client.wait_until_authenticated(17.0)

    assert client._traffic.reset_calls == 1
    assert client._traffic.wait_calls == [17.0]
    page.reload.assert_awaited_once_with(wait_until="commit", timeout=60_000)


def test_auth_waiter_does_not_use_frontend_auth_selectors() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")

    waiter = source.split("async def wait_until_authenticated", 1)[1].split(
        "async def _new_chat_if_needed", 1
    )[0]
    assert "/backend-api/me" in waiter
    assert "AUTH_SELECTORS" not in waiter
    assert "PROMPT_SELECTORS" not in waiter

@pytest.mark.asyncio
async def test_resume_auth_check_is_non_mutating() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/c/existing"
    page.evaluate = AsyncMock(return_value={"status": 200, "object": "user", "id": "user-1"})
    page.reload = AsyncMock()
    page.goto = AsyncMock()

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"

    await client.assert_authenticated_current_page()

    page.reload.assert_not_awaited()
    page.goto.assert_not_awaited()
    page.evaluate.assert_awaited_once()


@pytest.mark.asyncio
async def test_resume_auth_check_rejects_missing_session_without_reload() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/c/existing"
    page.evaluate = AsyncMock(return_value={"status": 401, "object": None, "id": None})
    page.reload = AsyncMock()

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"

    with pytest.raises(AuthenticationRequired, match="will not reload or replace it"):
        await client.assert_authenticated_current_page()

    page.reload.assert_not_awaited()


def test_make_run_never_starts_dependencies_during_resume() -> None:
    from pathlib import Path

    makefile = (Path(__file__).parents[3] / "Makefile").read_text(encoding="utf-8")
    run_block = makefile.split("run:", 1)[1].split("down:", 1)[0]
    assert "docker compose run --rm --no-deps runner run" in run_block
    assert "--resume" in run_block


def test_run_recovery_skips_mutating_chatgpt_preflight() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1] / "src" / "gpt_trace_runner" / "cli.py"
    ).read_text(encoding="utf-8")
    run = source.split("def run_command(", 1)[1].split(
        '@app.command("register-apps")', 1
    )[0]
    assert "recovery_active = resume and" in run
    assert "await browser_client.assert_existing_process()" in run
    assert "require_existing_page=recovery_active" in run
    recovery = run.split("if recovery_active:", 1)[1].split("else:", 1)[0]
    assert "assert_authenticated_current_page" not in recovery
    assert "wait_until_authenticated" not in recovery
    assert "verify_apps_available" not in recovery
    assert "conversation fetch will classify 401 vs 404" in recovery

@pytest.mark.asyncio
async def test_wait_for_conversation_id_ignores_transient_web_route() -> None:
    stable = "6aaf0c08-96f0-83eb-8994-4584094a99b3"
    page = type("PageDouble", (), {})()
    page.url = f"https://chatgpt.com/c/{stable}"
    page.wait_for_url = AsyncMock(return_value=None)

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._stream_start_timeout = 17.0

    result = await client._wait_for_conversation_id()

    assert result == stable
    pattern = page.wait_for_url.await_args.args[0]
    assert pattern.search("https://chatgpt.com/c/WEB:565d236a-8024-4ec4-ac02-06dfc91cc8da") is None
    assert pattern.search(f"https://chatgpt.com/c/{stable}") is not None
    assert page.wait_for_url.await_args.kwargs["timeout"] == 17_000


@pytest.mark.asyncio
async def test_wait_for_conversation_id_refuses_web_route_defensively() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/c/WEB:565d236a-8024-4ec4-ac02-06dfc91cc8da"
    page.wait_for_url = AsyncMock(return_value=None)

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._stream_start_timeout = 17.0

    with pytest.raises(AmbiguousSubmission, match="still transient"):
        await client._wait_for_conversation_id()


def test_completion_still_requires_stable_url_id_to_equal_sse_id() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")
    wait = source.split("async def wait_for_completion", 1)[1].split(
        "async def recover", 1
    )[0]

    assert "stream_result.conversation_id != submitted.conversation_id" in wait
    assert "conversation ID mismatch between browser URL and completed SSE" in wait


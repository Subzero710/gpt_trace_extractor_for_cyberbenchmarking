from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from gpt_trace_runner.chatgpt import ChatGPTClient
from gpt_trace_runner.exceptions import (
    AmbiguousSubmission,
    AuthenticationRequired,
    FatalUIState,
)


def _repository_makefile_text() -> str:
    candidates = [Path("/repo/Makefile")]
    candidates.extend(parent / "Makefile" for parent in Path(__file__).resolve().parents)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError(
        "repository Makefile is unavailable; compose must mount it at /repo/Makefile"
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


def test_auth_command_preflights_apps_but_runtime_uses_real_task_selection() -> None:
    from pathlib import Path

    package = Path(__file__).parents[1] / "src" / "gpt_trace_runner"
    cli_source = (package / "cli.py").read_text(encoding="utf-8")
    execution_source = (
        package / "superbench" / "execution.py"
    ).read_text(encoding="utf-8")

    assert "await chatgpt.verify_apps_available(task.tools)" in cli_source
    assert "await chatgpt.verify_apps_available(bt.tools)" not in execution_source


class AuthTrafficDouble:
    def __init__(self) -> None:
        self.reset_calls = 0
        self.wait_calls = []

    def reset_auth_probe(self) -> None:
        self.reset_calls += 1

    async def wait_for_authenticated_user(self, *, timeout_seconds: float) -> None:
        self.wait_calls.append(timeout_seconds)


@pytest.mark.asyncio
async def test_auth_wait_polls_backend_me_without_forced_reload() -> None:
    page = type("PageDouble", (), {})()
    page.url = "https://chatgpt.com/"
    page.reload = AsyncMock()
    page.evaluate = AsyncMock(
        side_effect=[
            {"status": 401, "object": None, "id": None},
            {"status": 200, "object": "user", "id": "user-1"},
        ]
    )

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._base_url = "https://chatgpt.com"
    client._backend_quiet_seconds = 0.0

    await client.wait_until_authenticated(17.0)

    assert page.evaluate.await_count == 2
    page.reload.assert_not_awaited()


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
    assert "assert_authenticated_current_page()" in waiter
    assert ".reload(" not in waiter
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


def test_make_run_and_resume_use_no_deps_superbench_commands() -> None:
    from pathlib import Path

    makefile = _repository_makefile_text()
    run_block = makefile.split("run:", 1)[1].split("pause:", 1)[0]
    resume_block = makefile.split("resume:", 1)[1].split("status:", 1)[0]

    assert "docker compose run --rm --no-deps" in run_block
    assert "runner superbench-run" in run_block
    assert "docker compose run --rm --no-deps" in resume_block
    assert "runner superbench-resume-active" in resume_block


def test_superbench_run_does_not_invoke_doctor_preflight_per_task() -> None:
    from pathlib import Path

    package = Path(__file__).parents[1] / "src" / "gpt_trace_runner"
    execution = (
        package / "superbench" / "execution.py"
    ).read_text(encoding="utf-8")
    cli = (package / "cli.py").read_text(encoding="utf-8")
    doctor = cli.split("def doctor()", 1)[1].split(
        '@app.command("register-apps")', 1
    )[0]

    assert "preflight_tasks(" not in execution
    assert "await preflight_tasks(" in doctor


def test_superbench_recovery_is_centralized_in_execution_path() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "superbench"
        / "execution.py"
    ).read_text(encoding="utf-8")

    recovery = source.split("async def _recover_pending_journal", 1)[1].split(
        "async def run_pending", 1
    )[0]
    scheduler = source.split("async def run_pending", 1)[1]

    assert "chatgpt = await get_chatgpt()" in recovery
    assert "await runner.reconcile_journal([bt])" in recovery
    assert "await _recover_pending_journal(" in scheduler
    assert "pending.task_id not in set(selected_run_task_ids)" in scheduler

@pytest.mark.asyncio
async def test_wait_for_conversation_id_accepts_stable_route_without_lookup() -> None:
    stable = "6aaf0c08-96f0-83eb-8994-4584094a99b3"
    page = type("PageDouble", (), {})()
    page.url = f"https://chatgpt.com/c/{stable}"
    conversation = type("ConversationDouble", (), {})()
    conversation.fetch = AsyncMock(
        return_value={
            "messages": [
                {"id": "user-1", "author": {"role": "user"}},
            ]
        }
    )
    conversation.find_recent_conversation_id_by_user_message_id = AsyncMock()

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._conversation = conversation
    client._stream_start_timeout = 17.0

    result = await client._wait_for_conversation_id("user-1")

    assert result == stable
    conversation.fetch.assert_awaited_once_with(stable)
    conversation.find_recent_conversation_id_by_user_message_id.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route",
    [
        "WEB:565d236a-8024-4ec4-ac02-06dfc91cc8da",
        "local-chatgpt%3A8104476a-ffc2-4170-bc04-ec817470d8a2",
    ],
)
async def test_wait_for_conversation_id_resolves_transient_route_by_message_identity(route) -> None:
    stable = "6aaf0c08-96f0-83eb-8994-4584094a99b3"
    page = type("PageDouble", (), {})()
    page.url = f"https://chatgpt.com/c/{route}"
    conversation = type("ConversationDouble", (), {})()
    conversation.find_recent_conversation_id_by_user_message_id = AsyncMock(return_value=stable)

    client = ChatGPTClient.__new__(ChatGPTClient)
    client._page = page
    client._conversation = conversation
    client._stream_start_timeout = 17.0
    client._conversation_id_route_grace_seconds = 0.0

    result = await client._wait_for_conversation_id("user-1")

    assert result == stable
    conversation.find_recent_conversation_id_by_user_message_id.assert_awaited_once_with(
        "user-1",
        limit=5,
        exclude_ids=set(),
        max_candidate_fetches=1,
        candidate_attempts={},
        candidate_fetch_delay_seconds=0.0,
    )


def test_recovery_does_not_navigate_to_conversation_before_readback() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "chatgpt.py"
    ).read_text(encoding="utf-8")
    recover = source.split("async def recover(", 1)[1].split(
        "async def recover_current_candidate", 1
    )[0]

    assert "self._navigate(" not in recover
    assert "self._fetch_recovery_snapshot(conversation_id)" in recover


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

def test_superbench_auth_reports_success_after_app_verification() -> None:
    package = Path(__file__).parents[1] / "src" / "gpt_trace_runner"
    cli_source = (package / "cli.py").read_text(encoding="utf-8")
    auth = cli_source.split("def superbench_auth(", 1)[1].split(
        '@app.command("superbench-reset-recovery")', 1
    )[0]

    verify = "await chatgpt.verify_apps_available(task.tools)"
    success = 'console.print("[green]auth detected; Kali Workstation available[/]")'
    assert verify in auth
    assert success in auth
    assert auth.index(verify) < auth.index(success)

def test_superbench_keeps_one_browser_attachment_for_the_batch() -> None:
    package = Path(__file__).parents[1] / "src" / "gpt_trace_runner"
    execution = (
        package / "superbench" / "execution.py"
    ).read_text(encoding="utf-8")
    scheduler = execution.split("async def run_pending", 1)[1]

    assert scheduler.count("await _connect_chatgpt(") == 1
    assert "chatgpt = await get_chatgpt()" in scheduler
    assert "await browser_session.disconnect()" in scheduler
    per_task_finally = scheduler.split("finally:", 1)[1]
    assert "await session.disconnect()" not in per_task_finally


def test_superbench_runtime_bootstrap_avoids_private_thinking_patch_and_app_scratch_preflight() -> None:
    package = Path(__file__).parents[1] / "src" / "gpt_trace_runner"
    execution = (
        package / "superbench" / "execution.py"
    ).read_text(encoding="utf-8")
    connect = execution.split("async def _connect_chatgpt(", 1)[1].split(
        "async def _cleanup_task", 1
    )[0]

    assert "assert_authenticated_current_page()" in connect
    assert "wait_until_authenticated(" in connect
    assert "ensure_extended_thinking_effort_setting()" not in connect
    assert "ensure_high_thinking_effort()" not in connect
    assert "await chatgpt.goto_home()" not in connect
    assert "verify_apps_available(bt.tools)" not in connect

    chatgpt = (package / "chatgpt.py").read_text(encoding="utf-8")
    prepare_task = chatgpt.split("async def prepare_task(", 1)[1].split(
        "async def _click_send", 1
    )[0]
    assert "await self.ensure_high_thinking_effort()" in prepare_task


def test_runner_session_bootstrap_does_not_force_second_home_navigation() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "runner.py"
    ).read_text(encoding="utf-8")
    ensure = source.split("async def _ensure_session", 1)[1].split(
        "@staticmethod", 1
    )[0]
    assert "prepare_session(fresh_home=False)" in ensure
    assert "prepare_session(fresh_home=True)" not in ensure

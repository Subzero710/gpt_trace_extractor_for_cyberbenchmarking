from __future__ import annotations

import pytest

from gpt_trace_runner.interaction import InteractionGuard


class FakePage:
    def __init__(self, state):
        self.state = state
        self.bring_calls = 0
        self.wait_calls = 0

    async def evaluate(self, expression):
        return self.state

    async def bring_to_front(self):
        self.bring_calls += 1

    async def wait_for_function(self, expression, timeout):
        self.wait_calls += 1


@pytest.mark.asyncio
async def test_focus_is_not_forced_when_page_is_already_active() -> None:
    page = FakePage({"visible": True, "focused": True})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    await guard.ensure_page_focus()
    assert page.bring_calls == 0
    assert page.wait_calls == 0


@pytest.mark.asyncio
async def test_focus_is_requested_only_when_needed() -> None:
    page = FakePage({"visible": True, "focused": False})
    guard = InteractionGuard(
        page,
        clipboard_url="http://browser:8765/clipboard",
        timeout_seconds=1,
    )
    await guard.ensure_page_focus()
    assert page.bring_calls == 1
    assert page.wait_calls == 1

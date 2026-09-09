from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_mcp.core import BrowserAppError, BrowserPolicy, BrowserRuntime


class FakeRuntime(BrowserRuntime):
    async def _launch(self, profile: Path) -> None:
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "marker").write_text("profile")
        self.process = SimpleNamespace(returncode=None)
        self.playwright = SimpleNamespace()
        self.browser = SimpleNamespace()
        self.context = SimpleNamespace()
        self.page = SimpleNamespace()

    async def _stop_process(self) -> None:
        self.process = None
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None


def identity(task: str = "one", environment: str = "env-one") -> dict:
    return {"task_id": task, "environment_id": environment, "task_fingerprint": "a" * 64}


@pytest.mark.asyncio
async def test_task_profiles_are_owned_recoverable_and_reset(tmp_path: Path) -> None:
    runtime = FakeRuntime(
        tmp_path / "browser-state",
        fingerprint_seed=7,
        search_url_template="https://search.example/?q={query}",
        policy=BrowserPolicy(),
        browser_uid=0,
        browser_gid=0,
    )
    await runtime.start()
    state = await runtime.prepare(identity())
    assert state["status"] == "ready"
    assert (runtime.active_profile / "marker").is_file()
    assert (await runtime.assert_resume(identity()))["environment_id"] == "env-one"
    with pytest.raises(BrowserAppError, match="exact browser"):
        await runtime.assert_resume(identity(environment="wrong"))
    with pytest.raises(BrowserAppError, match="does not own"):
        await runtime.reset(identity(environment="wrong"))
    await runtime.reset(identity())
    assert runtime.state_response() == {"status": "idle"}
    assert not runtime.active_root.exists()
    assert runtime.idle_profile.exists()

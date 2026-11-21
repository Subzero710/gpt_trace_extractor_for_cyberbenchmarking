from __future__ import annotations

import pytest
from kali_workstation.guest import browser as module


@pytest.mark.asyncio
async def test_agent_launches_pinned_cloakbrowser_with_attempt_seed(tmp_path, monkeypatch):
    binary = tmp_path/'chrome'
    binary.write_text('#!/bin/sh\n')
    binary.chmod(0o755)
    monkeypatch.setenv('CLOAKBROWSER_BINARY_PATH', str(binary))
    monkeypatch.setattr(module.os, 'access', lambda path, mode: path == binary and mode == module.os.X_OK)
    monkeypatch.setattr(module, 'DOWNLOADS', tmp_path/'downloads')
    calls = []
    class Page:
        def on(self, *args): pass
    class Context:
        pages = []
        def on(self, *args): pass
        async def new_page(self): return Page()
        async def close(self): pass
    async def launch(*args, **kwargs):
        calls.append((args, kwargs))
        return Context()
    import cloakbrowser
    monkeypatch.setattr(cloakbrowser, 'launch_persistent_context_async', launch)
    agent_browser = module.Browser('a'*64)
    await agent_browser.start()
    assert calls and calls[0][1]['headless'] is False
    assert calls[0][1]['humanize'] is True
    assert calls[0][1]['args'][0] == f'--fingerprint={10000 + int("a"*16, 16)%90000}'
    assert 'executable_path' not in calls[0][1]
    await agent_browser.close()


@pytest.mark.asyncio
async def test_browser_start_serializes_competing_prepare_calls(tmp_path, monkeypatch):
    import asyncio
    import cloakbrowser

    binary = tmp_path / "chrome"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setenv("CLOAKBROWSER_BINARY_PATH", str(binary))
    monkeypatch.setattr(module, "DOWNLOADS", tmp_path / "downloads")
    entered, finish = asyncio.Event(), asyncio.Event()
    attempts = []

    class Context:
        pages = [object()]
        def on(self, *args): pass
        async def close(self): pass

    async def launch(*args, **kwargs):
        attempts.append((args, kwargs))
        entered.set()
        await finish.wait()
        return Context()

    monkeypatch.setattr(cloakbrowser, "launch_persistent_context_async", launch)
    browser = module.Browser("a" * 64)
    monkeypatch.setattr(browser, "_register", lambda page: browser.pages.setdefault("test", page))
    tasks = [asyncio.create_task(browser.start()) for _ in range(2)]
    await asyncio.wait_for(entered.wait(), 1)
    finish.set()
    await asyncio.wait_for(asyncio.gather(*tasks), 1)
    assert len(attempts) == 1
    await browser.close()
    assert browser.context is None and not browser.pages


@pytest.mark.asyncio
async def test_browser_start_cleans_partially_initialized_context(tmp_path, monkeypatch):
    import cloakbrowser

    binary = tmp_path / "chrome"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setenv("CLOAKBROWSER_BINARY_PATH", str(binary))
    monkeypatch.setattr(module, "DOWNLOADS", tmp_path / "downloads")
    closed = []

    class Context:
        pages = []
        def on(self, *args): pass
        async def new_page(self):
            raise RuntimeError("new page failed")
        async def close(self):
            closed.append(True)

    async def launch(*args, **kwargs):
        return Context()

    monkeypatch.setattr(cloakbrowser, "launch_persistent_context_async", launch)
    browser = module.Browser("a" * 64)
    with pytest.raises(RuntimeError, match="new page failed"):
        await browser.start()
    assert closed == [True]
    assert browser.context is None
    assert browser.current is None and not browser.pages

from __future__ import annotations

import pytest
from kali_workstation.guest import browser as module


@pytest.mark.asyncio
async def test_agent_launches_pinned_cloakbrowser_with_attempt_seed(tmp_path, monkeypatch):
    binary = tmp_path/'chrome'
    binary.write_text('#!/bin/sh\n')
    binary.chmod(0o755)
    monkeypatch.setenv('CLOAKBROWSER_BINARY_PATH', str(binary))
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

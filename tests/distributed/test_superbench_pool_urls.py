from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "distributed_superbench_pool",
    ROOT / "scripts/superbench_pool.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("superbench dependency-pool module is unavailable")
POOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POOL)

GITLINK = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    "url",
    (
        "https://github.com/example-org/example-repo",
        "https://github.com/example-org/example-repo/",
        "https://github.com/example-org/example-repo.git",
        "https://github.com/example-org/example-repo.git/",
    ),
)
def test_read_submodules_accepts_canonical_github_url_forms(monkeypatch, url):
    config = (
        '[submodule "fixture"]\n'
        "path = vendor/example\n"
        f"url = {url}\n"
    )
    monkeypatch.setattr(POOL, "git_file", lambda *args, **kwargs: config)
    monkeypatch.setattr(
        POOL,
        "invoke",
        lambda *args, **kwargs: f"160000 commit {GITLINK}\tvendor/example\n",
    )

    assert POOL.read_submodules(Path("/unused/mirror.git"), "f" * 40) == [
        ("vendor/example", "example-org/example-repo", GITLINK)
    ]


@pytest.mark.parametrize(
    "url",
    (
        "http://github.com/example-org/example-repo",
        "https://github.com/example-org/example-repo/?ref=mutable",
        "https://github.com/example-org/example-repo/#fragment",
        "https://user@github.com/example-org/example-repo",
        "https://github.com/example-org/example-repo/extra",
    ),
)
def test_read_submodules_rejects_untrusted_or_ambiguous_github_urls(monkeypatch, url):
    config = (
        '[submodule "fixture"]\n'
        "path = vendor/example\n"
        f"url = {url}\n"
    )
    monkeypatch.setattr(POOL, "git_file", lambda *args, **kwargs: config)

    with pytest.raises(RuntimeError, match="unsupported Git submodule URL"):
        POOL.read_submodules(Path("/unused/mirror.git"), "f" * 40)

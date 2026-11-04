from __future__ import annotations

import os
import hashlib
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from workstation_broker import preparation as jobs


def _source_tree(root: Path) -> None:
    for relative in jobs.FETCH_SOURCE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative + "\n")


def test_known_pre_download_failures_retry_only_before_any_pool_bytes(tmp_path, monkeypatch):
    base = tmp_path / "golden.qcow2"
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    original_stat = Path.stat
    def root_owned_pool(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if Path(path) == pool:
            fields = list(result)
            fields[4] = 0
            return os.stat_result(fields)
        return result
    monkeypatch.setattr(Path, "stat", root_owned_pool)
    state = {
        "phase": "interrupted",
        "result": None,
        "error": "PermissionError: [Errno 13] Permission denied: "
                 "'/private/repo/.venv-workstation-broker/bin/python'",
    }
    assert jobs.pre_download_fetch_retryable(state, base)
    state["error"] = (
        "RuntimeError: trusted system Python cannot import pip required by dependency fetch"
    )
    assert jobs.pre_download_fetch_retryable(state, base)
    state["error"] = "RuntimeError: arbitrary worker failure"
    assert not jobs.pre_download_fetch_retryable(state, base)
    state["error"] = (
        "RuntimeError: trusted system Python cannot import pip required by dependency fetch"
    )
    (pool / "incoming").mkdir()
    assert not jobs.pre_download_fetch_retryable(state, base)


def test_fetch_sources_are_staged_outside_private_repo_and_sealed(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root ownership is required for fetch source sealing")
    private = tmp_path / "private-repo"
    private.mkdir(mode=0o700)
    _source_tree(private)
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    dependency = {"schema": 1, "target_environment": {"schema": 2}, "npm_version": "10.9.9"}
    packages = tmp_path / "kali-packages.txt"
    packages.write_bytes(b"fixture-package\t1\tall\n")
    packages.chmod(0o444)
    dependency["apt_package_manifest_sha256"] = hashlib.sha256(packages.read_bytes()).hexdigest()
    manager = SimpleNamespace(source_root=private, base=tmp_path / "golden.qcow2")
    original_identity = jobs.golden_dependency_identity
    jobs.golden_dependency_identity = lambda *args, **kwargs: dependency
    try:
        expected_sources = {name: hashlib.sha256((private/name).read_bytes()).hexdigest()
                            for name in jobs.FETCH_SOURCE_FILES}
        source_root, program = jobs.stage_fetch_sources(manager, pool, golden_dependency=dependency,
                                                       expected_sources=expected_sources)
    finally:
        jobs.golden_dependency_identity = original_identity
    assert source_root == pool / "source"
    assert program == source_root / "scripts/superbench_pool.py"
    assert "config/preparation.toml" in jobs.FETCH_SOURCE_FILES
    for relative in jobs.FETCH_SOURCE_FILES:
        original = private / relative
        staged = source_root / relative
        assert staged.read_bytes() == original.read_bytes()
        assert staged.stat().st_uid == 0
        assert stat.S_IMODE(staged.stat().st_mode) == 0o444
    staged_dependency = source_root / "golden-dependency.json"
    assert staged_dependency.read_bytes() == jobs.canonical(dependency) + b"\n"
    assert staged_dependency.stat().st_uid == 0
    assert (source_root / "golden-packages.txt").read_bytes() == packages.read_bytes()
    assert stat.S_IMODE(staged_dependency.stat().st_mode) == 0o444
    assert stat.S_IMODE(source_root.stat().st_mode) == 0o555


def test_fetch_worker_uses_system_python_not_broker_venv():
    source = Path(jobs.__file__).read_text()
    physical = source.split("def _prepare(manager, state):", 1)[1].split(
        "def worker(operation_id, slot_fd):", 1
    )[0]
    assert "trusted_fetch_python()" in physical
    assert "state['compatibility']['golden_dependency']" in physical
    assert 'subprocess.Popen([str(interpreter), "-I", "-B"' in physical
    assert "sys.executable" not in physical
    trusted = source.split("def trusted_fetch_python():", 1)[1].split(
        "def stage_fetch_sources", 1
    )[0]
    assert '"-m", "pip", "--version"' in trusted


def test_resume_compatibility_is_structural_not_fetch_source_identity():
    first = {
        "fetch_kind": "download-only-pool-v4",
        "pool_schema": 4,
        "platform": "linux-x86_64",
        "pins": {"revision": "old"},
        "conda_lock_sha256": "1" * 64,
        "fetcher_sha256": "2" * 64,
        "fetch_sources": {"worker": "2" * 64, "contract": "3" * 64},
        "golden_dependency": {"identity": "old"},
    }
    changed = {
        **first,
        "pins": {"revision": "new"},
        "conda_lock_sha256": "4" * 64,
        "fetcher_sha256": "5" * 64,
        "fetch_sources": {"worker": "5" * 64, "contract": "6" * 64},
        "golden_dependency": {"identity": "new"},
    }
    assert jobs._salvage_identity(first) == jobs._salvage_identity(changed)
    incompatible = {**changed, "pool_schema": 5}
    assert jobs._salvage_identity(first) != jobs._salvage_identity(incompatible)


def test_retained_stage_score_prefers_existing_cas_over_newer_empty_stage(tmp_path):
    rich = tmp_path / "rich"
    empty = tmp_path / "empty"
    rich.mkdir()
    empty.mkdir()
    sha = "a" * 64
    obj = rich / "objects" / "sha256" / sha[:2] / sha
    obj.parent.mkdir(parents=True)
    obj.write_bytes(b"reusable")
    newer = rich.stat().st_mtime_ns + 10_000_000
    os.utime(empty, ns=(newer, newer))
    assert jobs._retained_stage_score(rich) > jobs._retained_stage_score(empty)

from __future__ import annotations

import os
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


def test_legacy_venv_exec_failure_is_retryable_only_before_any_pool_bytes(tmp_path):
    base = tmp_path / "golden.qcow2"
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    state = {
        "phase": "interrupted",
        "result": None,
        "error": "PermissionError: [Errno 13] Permission denied: "
                 "'/private/repo/.venv-workstation-broker/bin/python'",
    }
    assert jobs.legacy_fetch_exec_retryable(state, base)
    (pool / "incoming").mkdir()
    assert not jobs.legacy_fetch_exec_retryable(state, base)


def test_fetch_sources_are_staged_outside_private_repo_and_sealed(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root ownership is required for fetch source sealing")
    private = tmp_path / "private-repo"
    private.mkdir(mode=0o700)
    _source_tree(private)
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    source_root, program = jobs.stage_fetch_sources(SimpleNamespace(source_root=private), pool)
    assert source_root == pool / "source"
    assert program == source_root / "scripts/superbench_pool.py"
    for relative in jobs.FETCH_SOURCE_FILES:
        original = private / relative
        staged = source_root / relative
        assert staged.read_bytes() == original.read_bytes()
        assert staged.stat().st_uid == 0
        assert stat.S_IMODE(staged.stat().st_mode) == 0o444
    assert stat.S_IMODE(source_root.stat().st_mode) == 0o555


def test_fetch_worker_uses_system_python_not_broker_venv():
    source = Path(jobs.__file__).read_text()
    physical = source.split("def _prepare(manager, state):", 1)[1].split(
        "def worker(operation_id, slot_fd):", 1
    )[0]
    assert "trusted_fetch_python()" in physical
    assert "stage_fetch_sources(manager, root)" in physical
    assert "subprocess.Popen([str(interpreter)" in physical
    assert "sys.executable" not in physical

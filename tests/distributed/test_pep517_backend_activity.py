"""Tests for PEP 517 backend visibility and real activity detection."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys

import pytest

import superbench_pool as pool


def _fake_pip(root, body):
    project = root / 'pip'
    project.mkdir()
    (project / '__init__.py').write_text('')
    (project / '__main__.py').write_text(body)
    return {'root': root, 'env': {
        'PATH': os.environ['PATH'], 'PYTHONPATH': str(root),
        'PYTHONDONTWRITEBYTECODE': '1'}}


def test_native_pip_cpu_active_child_has_a_per_process_limit(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path,
        'import subprocess, sys\n'
        'subprocess.run([sys.executable, "-c", "while True: pass"], check=True)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (7, 2))
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 2)
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            with pytest.raises(TimeoutError, match='elementary subprocess exceeded'):
                pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'], runtime, timeout=7)
        finally:
            runtime['_pip_byte_progress'].close()


def test_native_pip_does_not_enforce_a_cumulative_build_deadline(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'import time\n'
                                  'finish = time.monotonic() + 3\n'
                                  'while time.monotonic() < finish:\n'
                                  '    pass\n'
                                  'print("finished",flush=True)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (1, 10))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                      runtime, timeout=1)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'finished' in result


def test_pip_observation_uses_only_the_spawned_root(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'print("backend completed", flush=True)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (7, 2))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    original = pool._native_process_tree_snapshot
    def scoped(pid):
        assert pid > 0 and pid != os.getpid()
        return original(pid)
    monkeypatch.setattr(pool, '_native_process_tree_snapshot', scoped)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                      runtime, timeout=7)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'backend completed' in result


def test_reaped_child_cpu_survives_process_tree_sampling():
    before = [{'pid': 1, 'start_ticks': 1, 'cpu_ticks': 0, 'reaped_cpu_ticks': 0}]
    after = [{'pid': 1, 'start_ticks': 1, 'cpu_ticks': 0, 'reaped_cpu_ticks': 100}]
    activity = pool._native_process_activity(before, after, 1.0)
    assert activity[0]['reaped_cpu_seconds'] > 0


def test_native_pip_active_hook_output_keeps_stall_budget(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path,
        'import time\n'
        'for index in range(7):\n'
        '    print(f"build step {index}", flush=True)\n'
        '    time.sleep(0.3)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (6, 1))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                      runtime, timeout=6)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'build step 0' in result and b'build step 6' in result


def test_parallel_silent_pip_workers_release_slots(tmp_path, monkeypatch):
    import concurrent.futures
    import time
    runtime = _fake_pip(tmp_path,
        'import subprocess, sys\n'
        'subprocess.run([sys.executable, "-c", "while True: pass"], check=True)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (8, 2))
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 2)
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    start = time.monotonic()
    def run():
        with pytest.raises(TimeoutError, match='elementary subprocess exceeded'):
            pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                             runtime, timeout=8)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                tuple(executor.map(lambda _index: run(), range(3)))
        finally:
            runtime['_pip_byte_progress'].close()
    assert time.monotonic() - start < 10



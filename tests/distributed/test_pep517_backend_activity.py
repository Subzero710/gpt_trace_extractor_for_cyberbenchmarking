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
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 2)
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
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 10)
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                      runtime, timeout=1)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'finished' in result


def test_backend_parent_pauses_while_independent_build_children_own_work(tmp_path, monkeypatch):
    backend = (
        "import subprocess, sys, time\n"
        "time.sleep(0.12)\n"
        "for phase in range(3):\n"
        "    subprocess.run([sys.executable, '-c', 'import time; time.sleep(0.55)'], check=True)\n"
        "time.sleep(0.35)\n"
    )
    runtime = _fake_pip(tmp_path, "import subprocess, sys\n"
                        f"subprocess.run([sys.executable, '-c', {backend!r}], check=True)\n"
                        "print('metadata generated', flush=True)\n")
    runtime['_pip_byte_progress'] = pool._NativePipByteProgress(1)
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 0.02)
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 1)
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'], runtime)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'metadata generated' in result


def test_pip_observation_uses_only_the_spawned_root(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'print("backend completed", flush=True)\n')
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 2)
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
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 1)
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
    monkeypatch.setattr(pool, '_native_pip_stall_timeout', lambda: 2)
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


def test_pip_rejects_and_stops_descendant_that_outlives_its_parent(tmp_path, monkeypatch):
    pid_path = tmp_path / 'child-pid'
    child = (
        'import os, signal, time\n'
        'from pathlib import Path\n'
        'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
        f'Path({str(pid_path)!r}).write_text(str(os.getpid()))\n'
        'time.sleep(30)\n'
    )
    runtime = _fake_pip(tmp_path, 'import subprocess, sys, time\n'
        'from pathlib import Path\n'
        f'subprocess.Popen([sys.executable, "-c", {child!r}])\n'
        f'while not Path({str(pid_path)!r}).exists(): time.sleep(0.01)\n')
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            with pytest.raises(RuntimeError, match='Pip exited while'):
                pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'], runtime)
        finally:
            runtime['_pip_byte_progress'].close()
    pid = pid_path.read_text()
    stat = Path('/proc') / pid / 'stat'
    if stat.exists():
        assert stat.read_text().rsplit(') ', 1)[1].split()[0] == 'Z'

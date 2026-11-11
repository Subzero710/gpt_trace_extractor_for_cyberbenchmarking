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


def test_native_pip_silent_active_child_is_not_killed(tmp_path, monkeypatch):
    child = ('import time\n'
             'finish = time.monotonic() + 2.8\n'
             'while time.monotonic() < finish:\n'
             '    pass\n')
    runtime = _fake_pip(tmp_path, 'import subprocess, sys\n'
                                'subprocess.run([sys.executable, "-c", ' + repr(child) + '], check=True)\n'
                                'print("backend completed", flush=True)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (7, 1))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            output = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                      runtime, timeout=7)
        finally:
            runtime['_pip_byte_progress'].close()
    assert b'backend completed' in output


def test_native_pip_still_enforces_total_deadline_during_active_build(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'import time\n'
                                  'finish = time.monotonic() + 4\n'
                                  'while time.monotonic() < finish:\n'
                                  '    pass\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (1, 10))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                 runtime, timeout=5)
        finally:
            runtime['_pip_byte_progress'].close()


def test_native_process_progress_requires_cpu_or_io_delta():
    idle = [{'pid': 1, 'cpu_seconds': 0.0, 'reaped_cpu_seconds': 0.0,
             'rchar_delta': 0, 'wchar_delta': 0, 'read_bytes_delta': 0,
             'write_bytes_delta': 0}]
    assert not pool._native_process_made_progress(idle)
    assert not pool._native_process_made_progress([])
    for key in ('cpu_seconds', 'reaped_cpu_seconds', 'rchar_delta',
                'wchar_delta', 'read_bytes_delta', 'write_bytes_delta'):
        active = [dict(idle[0], **{key: 1})]
        assert pool._native_process_made_progress(active)


def test_reaped_child_cpu_survives_process_tree_sampling():
    before = [{'pid': 1, 'start_ticks': 1, 'cpu_ticks': 0, 'reaped_cpu_ticks': 0}]
    after = [{'pid': 1, 'start_ticks': 1, 'cpu_ticks': 0, 'reaped_cpu_ticks': 100}]
    activity = pool._native_process_activity(before, after, 1.0)
    assert activity[0]['reaped_cpu_seconds'] > 0
    assert pool._native_process_made_progress(activity)

"""Metadata build CPU silence differs from stalled pip network activity."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys

import pytest
import superbench_pool as pool


def _fixture(tmp_path, code):
    package = tmp_path / 'pip'
    package.mkdir()
    (package / '__init__.py').write_text('')
    (package / '__main__.py').write_text(code)
    return {'root': tmp_path, 'env': {
        'PATH': os.environ['PATH'], 'PYTHONPATH': str(tmp_path),
        'PYTHONDONTWRITEBYTECODE': '1'}}


def _execute(runtime, *, metadata_build):
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                    runtime, timeout=8, metadata_build=metadata_build)
        finally:
            runtime['_pip_byte_progress'].close()


def test_silent_cpu_backend_completes_after_idle_limit(tmp_path, monkeypatch):
    code = ('import subprocess,sys\n'
            'subprocess.run([sys.executable, "-c", '
            '"import time; end=time.monotonic()+4.4; exec(\'while time.monotonic()<end: pass\')"],'
            ' check=True)\n'
            'print("metadata complete", flush=True)\n')
    runtime = _fixture(tmp_path, code)
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (8, 2))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    assert b'metadata complete' in _execute(runtime, metadata_build=True)


def test_silent_sleeping_metadata_build_still_stalls(tmp_path, monkeypatch):
    runtime = _fixture(tmp_path, 'import time\nprint("start",flush=True)\ntime.sleep(20)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (8, 2))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with pytest.raises(RuntimeError, match='no new output/download bytes'):
        _execute(runtime, metadata_build=True)


def test_cpu_loop_in_metadata_cannot_extend_total_deadline(tmp_path, monkeypatch, capsys):
    runtime = _fixture(tmp_path, 'print("start",flush=True)\nwhile True: pass\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (4, 2))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with pytest.raises(subprocess.TimeoutExpired):
        _execute(runtime, metadata_build=True)
    prefix = '[pool] native pip timeout diagnostic: '
    line = next(row for row in capsys.readouterr().err.splitlines() if row.startswith(prefix))
    observation = json.loads(line.removeprefix(prefix))
    assert observation['timeout'] == 'total'
    assert observation['silent_seconds'] >= 2


def test_silent_cpu_normal_pip_retains_stall_watchdog(tmp_path, monkeypatch):
    runtime = _fixture(tmp_path, 'print("start",flush=True)\nwhile True: pass\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (8, 2))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with pytest.raises(RuntimeError, match='no new output/download bytes'):
        _execute(runtime, metadata_build=False)


def test_metadata_command_scopes_compute_grace_to_isolated_hook(tmp_path, monkeypatch):
    runtime = {'root': tmp_path, 'env': {'HOME': str(tmp_path), 'PATH': os.environ['PATH']}}
    seen = []
    monkeypatch.setattr(pool, '_native_interpreter_has_stdlib_distutils',
                        lambda runtime, interpreter: False)
    monkeypatch.setattr(pool, '_native_build_requirements', lambda path: [])

    def run(command, local_runtime, **options):
        seen.append((command, options))
        return b''

    monkeypatch.setattr(pool, '_native_run', run)
    assert pool._native_metadata_command([sys.executable, '-m', 'pip', 'install', '.'],
                                         runtime, tmp_path) == []
    assert len(seen) == 1
    command, options = seen[0]
    assert options['metadata_build'] is True
    assert options['interpreter'] == sys.executable
    assert command[-2:] == ['--verbose', '--no-clean']

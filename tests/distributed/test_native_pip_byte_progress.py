"""Regression tests: reported pip percentages are exclusively real file bytes."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'native_pip_progress_under_test', ROOT / 'scripts/superbench_pool.py')
pool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pool)


def test_real_file_byte_percentage_and_restart_accounting():
    meter = pool._NativePipByteProgress(3600)
    with contextlib.redirect_stdout(io.StringIO()):
        meter.begin('job')
        assert meter.observe('job', b'Progress 1048576 of 4194304\n')
        assert meter.snapshot()['file'] == ('job', 1048576, 4194304)
        assert '[#####---------------] 25.0%' in meter._render()
        assert meter.observe('job', b'Progress 3145728 of 4194304\n')
        assert meter.snapshot()['bytes'] == 3145728
        assert meter.observe('job', b'Progress 0 of 1048576\n')
        assert meter.snapshot()['bytes'] == 3145728
        assert meter.observe('job', b'Progress 524288 of 1048576\n')
        assert meter.snapshot()['bytes'] == 3670016
        meter.end('job')
        meter.close()


def test_unknown_size_never_displays_fictitious_percentage():
    meter = pool._NativePipByteProgress(3600)
    with contextlib.redirect_stdout(io.StringIO()):
        meter.begin('job')
        assert meter.observe('job', b'Progress 1048576 of 0\n')
        assert meter.snapshot()['file'] is None
        assert 'no global percent' in meter._render()
        assert '%' not in meter._render()
        meter.end('job')
        meter.close()


def test_native_pip_subprocess_streams_raw_protocol_without_normal_log_dump():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        package = root / 'pip'
        package.mkdir()
        (package / '__init__.py').write_text('')
        (package / '__main__.py').write_text(
            'import sys\n'
            'print("Progress 0 of 2097152", flush=True)\n'
            'print("Progress 1048576 of 2097152", flush=True)\n'
            'print("Progress 2097152 of 2097152", flush=True)\n'
            'print("diagnostic marker", flush=True)\n')
        runtime = {'root': root, 'env': {
            'PATH': os.environ['PATH'], 'PYTHONPATH': str(root),
            'PYTHONDONTWRITEBYTECODE': '1'}}
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = pool._native_run(
                [sys.executable, '-m', 'pip', 'install', 'fake-package'],
                runtime, timeout=15)
            meter = runtime['_pip_byte_progress']
            meter.close()
        assert b'diagnostic marker' in result
        assert b'Progress ' not in result
        assert 'diagnostic marker' not in output.getvalue()
        assert meter.snapshot()['bytes'] == 2097152


def test_timeout_retains_partial_pip_output():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        package = root / 'pip'
        package.mkdir()
        (package / '__init__.py').write_text('')
        (package / '__main__.py').write_text(
            'import time\n'
            'print("Progress 0 of 2097152", flush=True)\n'
            'print("Progress 1048576 of 2097152", flush=True)\n'
            'print("error context marker", flush=True)\n'
            'time.sleep(20)\n')
        runtime = {'root': root, 'env': {
            'PATH': os.environ['PATH'], 'PYTHONPATH': str(root),
            'PYTHONDONTWRITEBYTECODE': '1'}}
        with contextlib.redirect_stdout(io.StringIO()):
            with pytest.raises(subprocess.TimeoutExpired) as error:
                pool._native_run([sys.executable, '-m', 'pip', 'install', 'fake-package'],
                                 runtime, timeout=1)
            runtime['_pip_byte_progress'].close()
        assert b'error context marker' in error.value.output
        assert runtime['_pip_byte_progress'].snapshot()['bytes'] == 1048576

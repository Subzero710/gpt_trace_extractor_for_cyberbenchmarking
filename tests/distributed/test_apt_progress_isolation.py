from __future__ import annotations

import contextlib
import importlib.util
import inspect
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pool(monkeypatch):
    module = load("apt_progress_pool_test", ROOT / "scripts/superbench_pool.py")
    monkeypatch.setattr(module, "_operation_timeout", lambda: 5)
    monkeypatch.setattr(module, "_conda_progress_interval", lambda: 0.01)
    monkeypatch.setattr(module, "_registered_operation", lambda *a, **kw: contextlib.nullcontext())
    return module


def test_golden_has_no_preparation_progress_parameter(pool):
    helper = pool._apt_download_module()
    assert "progress" not in inspect.signature(helper.run_downloads).parameters
    assert "progress" in inspect.signature(pool._run_apt_downloads).parameters


def fake_apt(tmp_path, *, status=0, incomplete=False):
    path = tmp_path / "apt-fixture"
    lines = ["-> http:600%0AURI: https://example.invalid/test", "<- http:200%0AURI: https://example.invalid/test"]
    if not incomplete:
        lines.append("<- http:201%0AURI: https://example.invalid/test")
    path.write_text("#!" + sys.executable + "\nimport time\n" +
                    "\n".join(f"print({line!r}, flush=True); time.sleep(0.04)" for line in lines) +
                    f"\nraise SystemExit({status})\n")
    path.chmod(0o755)
    return path


def test_host_progress_preserved(pool, tmp_path):
    seen = []
    pool._run_apt_downloads([str(fake_apt(tmp_path))], progress=lambda: seen.append(True))
    assert len(seen) >= 2


def test_host_without_progress(pool, tmp_path):
    pool._run_apt_downloads([str(fake_apt(tmp_path))])


def test_host_failure_propagates(pool, tmp_path):
    seen = []
    with pytest.raises(subprocess.CalledProcessError) as error:
        pool._run_apt_downloads([str(fake_apt(tmp_path, status=7))], progress=lambda: seen.append(True))
    assert error.value.returncode == 7
    assert seen


def test_host_rejects_unfinished_transfer(pool, tmp_path):
    with pytest.raises(RuntimeError, match="unresolved native operations"):
        pool._run_apt_downloads([str(fake_apt(tmp_path, incomplete=True))])


def test_reuses_only_one_native_supervisor(pool, monkeypatch):
    calls = []
    helper = pool._apt_download_module()
    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
    monkeypatch.setattr(helper, 'run_downloads', run)
    pool._run_apt_downloads(['apt-get'], progress=lambda: None)
    assert len(calls) == 1
    assert calls[0][1]['limit'] == 5
    assert 'progress' not in calls[0][1]


def test_observer_failure_is_not_silenced(pool, tmp_path):
    import threading
    main = threading.current_thread()
    def progress():
        if threading.current_thread() is not main:
            raise ValueError('bad progress')
    with pytest.raises(ValueError, match='bad progress'):
        pool._run_apt_downloads([str(fake_apt(tmp_path))], progress=progress)


def test_progress_does_not_extend_transfer_deadline(pool, tmp_path, monkeypatch):
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 0.08)
    path = tmp_path/'apt-stall'
    path.write_text('#!' + sys.executable + '\nimport time\nprint("-> http:600%0AURI: https://example.invalid/test", flush=True)\ntime.sleep(2)\n')
    path.chmod(0o755)
    seen = []
    with pytest.raises(TimeoutError, match='deadline'):
        pool._run_apt_downloads([str(path)], progress=lambda: seen.append(True))
    assert len(seen) >= 2

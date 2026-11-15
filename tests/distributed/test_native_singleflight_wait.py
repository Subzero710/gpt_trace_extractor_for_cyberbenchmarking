"""The original producer may run multiple individually bounded commands."""
from __future__ import annotations

import concurrent.futures
import hashlib
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import superbench_pool as pool


def test_waiter_survives_an_owner_longer_than_one_operation(tmp_path):
    root = tmp_path / 'native'
    root.mkdir()
    version = '3.11.11'
    content = b'verified interpreter archive'
    sha = hashlib.sha256(content).hexdigest()
    object_path = tmp_path / 'objects' / sha[:2] / sha
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(content)
    lock = {
        'artifacts': {
            sha: {'name': 'python', 'version': version,
                  'url': 'https://example.invalid/locked-python.conda'}},
        'environments': {'target': {'transactions': [
            {'key': 'target', 'packages': [sha]}]}},
    }
    calls = []
    entered = threading.Event()
    release = threading.Event()
    candidate = SimpleNamespace(conda_lock=lock)
    candidate.download = lambda _url, _category, _key, sha: calls.append(sha)
    candidate.link_verified_object = lambda _sha, dest: os.link(object_path, dest)
    runtime = {
        'root': root, 'env': {}, 'prefixes': {},
        'conda_install_lock': threading.RLock(),
        'bootstrapped': True,
    }
    conda = root / 'conda' / 'bin' / 'conda'
    conda.parent.mkdir(parents=True)
    conda.write_text('instrumented conda')
    target = SimpleNamespace(python_artifact_sha256=sha,
                             python_full_version=version)

    def native_run(argv, _runtime, **_kwargs):
        if list(argv[1:4]) == ['-m', 'conda', 'create']:
            entered.set()
            assert release.wait(timeout=3)
            return b''
        if '-c' in argv:
            return version.encode()
        return b''

    with patch.object(pool, '_native_pool_runtime', return_value=runtime), \
         patch.object(pool, '_coerce_target', side_effect=lambda value: value), \
         patch.object(pool, '_native_bootstrap', return_value=conda), \
         patch.object(pool, '_native_run', side_effect=native_run), \
         patch.object(pool, '_operation_timeout', return_value=0.04), \
         patch.object(pool, '_conda_progress_interval', return_value=0.01):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            owner = executor.submit(pool._native_locked_python, candidate, target)
            assert entered.wait(timeout=2)
            waiter = executor.submit(pool._native_locked_python, candidate, target)
            try:
                time.sleep(0.12)
                assert not waiter.done()
            finally:
                release.set()
            expected = root / 'envs' / sha / 'bin' / 'python'
            assert owner.result(timeout=3) == expected
            assert waiter.result(timeout=3) == expected
    assert calls == [sha]
    assert not runtime['locked_python_inflight']


def test_shared_wait_propagates_real_owner_error_without_timeout_masking():
    pending = concurrent.futures.Future()
    with patch.object(pool, '_conda_progress_interval', return_value=0.01), \
         patch.object(pool, '_operation_timeout', return_value=0.01):
        def owner():
            time.sleep(0.06)
            pending.set_exception(ValueError('actual producer failure'))
        thread = threading.Thread(target=owner)
        thread.start()
        try:
            with pytest.raises(ValueError, match='actual producer failure'):
                pool._shared_future_result(pending)
        finally:
            thread.join(timeout=2)
        assert not thread.is_alive()


def test_shared_wait_obeys_inherited_pip_closure_deadline():
    pending = concurrent.futures.Future()
    token = pool._NATIVE_CLOSURE_DEADLINE.set(time.monotonic() + 0.05)
    try:
        with patch.object(pool, '_conda_progress_interval', return_value=0.01):
            with pytest.raises(TimeoutError, match='native Pip closure exceeded'):
                pool._shared_future_result(pending)
    finally:
        pool._NATIVE_CLOSURE_DEADLINE.reset(token)

"""Real timeout evidence and nested lifetime coherence in the verified Pip resolver."""
from __future__ import annotations

import json
import threading
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

import superbench_pool as pool


def test_nested_metadata_build_budget_is_covered_by_closure_deadline():
    root = Path(pool.__file__).resolve().parents[1]
    with (root / 'config/preparation.toml').open('rb') as stream:
        acquisition = tomllib.load(stream)['acquisition']
    assert acquisition['pip_total_timeout_seconds'] >= max(
        row['timeout_seconds'] for row in
        acquisition['pip_metadata_elementary_timeout_overrides'])
    assert pool._native_pip_timeouts()[0] == acquisition['pip_total_timeout_seconds']
    assert pool._operation_timeout() < acquisition['pip_total_timeout_seconds']
    assert pool._native_pip_timeouts()[1] < pool._native_pip_timeouts()[0]


def test_metadata_pool_snapshot_counts_real_work():
    executor = pool._PriorityMetadataExecutor(1)
    started, released = threading.Event(), threading.Event()

    def blocking():
        started.set()
        if not released.wait(timeout=5):
            raise TimeoutError('test worker release timeout')

    try:
        running = executor.submit(blocking)
        assert started.wait(timeout=2)
        queued = executor.submit_speculative(lambda: 1)
        snapshot = executor.snapshot()
        assert snapshot['workers'] == 1
        assert snapshot['running'] == snapshot['running_required'] == 1
        assert snapshot['queued'] == snapshot['queued_speculative'] == 1
        executor.promote(queued)
        assert executor.snapshot()['queued_required'] == 1
        released.set()
        running.result(timeout=5)
        assert queued.result(timeout=5) == 1
        assert executor.snapshot()['running'] == executor.snapshot()['queued'] == 0
    finally:
        released.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_expired_required_closure_names_its_own_exact_inputs(monkeypatch, tmp_path, capsys):
    target = SimpleNamespace(python_full_version='3.8.19')
    group = {
        'target': {}, 'requirements': ['heavy>=1', 'torch'],
        'constraints': ['torch<3'], 'no_deps': False,
        'preferred_versions': {}, 'required': True,
        'tasks': ['sample-task'],
    }
    monkeypatch.setattr(pool, '_coerce_target', lambda value: target)
    monkeypatch.setattr(pool, '_target_fingerprint', lambda value: 'verified-target')
    monkeypatch.setattr(pool, 'reuse_pip_plan', lambda *args, **kwargs: False)
    monkeypatch.setattr(pool, '_native_resolve_registry',
                        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError('metadata wait')))
    token = pool._NATIVE_CLOSURE_DEADLINE.set(time.monotonic() - 1)
    try:
        with pytest.raises(RuntimeError, match='closure exceeded configured total deadline'):
            pool._native_pip_group_locked(SimpleNamespace(stage=tmp_path), 'actual-closure', group)
    finally:
        pool._NATIVE_CLOSURE_DEADLINE.reset(token)
    marker = '[pool] timed-out pip closure input evidence: '
    evidence = next(json.loads(line.split(marker, 1)[1])
                    for line in capsys.readouterr().err.splitlines() if marker in line)
    assert evidence['closure'] == 'actual-closure'
    assert evidence['tasks'] == ['sample-task']
    assert evidence['requirements'] == ['heavy>=1', 'torch']
    assert evidence['target_python'] == '3.8.19'
    assert evidence['target_fingerprint'] == 'verified-target'

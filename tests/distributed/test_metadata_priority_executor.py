"""Deterministic work-conserving metadata scheduling regression tests."""
from __future__ import annotations

import importlib.util
import threading
from pathlib import Path

import pytest


def _load(name):
    source = Path(__file__).resolve().parents[2] / 'scripts' / name
    spec = importlib.util.spec_from_file_location('priority_test_' + source.stem, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_all_metadata_workers_accept_speculation_without_static_reservation():
    bridge = _load('verified_resolver_bridge.py')
    pool = _load('superbench_pool.py')
    running = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    capacity = 4

    def work(ref):
        nonlocal active
        with lock:
            active += 1
            if active == capacity:
                running.set()
        assert release.wait(10)
        return ref

    with pool._PriorityMetadataExecutor(capacity) as executor:
        prefetch = bridge._BoundedPrefetch(
            executor, work, speculative_submit=executor.submit_speculative)
        try:
            prefetch.schedule(tuple(range(capacity)), capacity, {})
            assert running.wait(5), 'some metadata capacity was unnecessarily reserved'
        finally:
            release.set()
        assert [prefetch.take(i).result(timeout=5) for i in range(capacity)] == list(range(capacity))
        prefetch.close()


def test_queued_mandatory_metadata_overtakes_speculative_ancestor_work():
    pool = _load('superbench_pool.py')
    started = threading.Event()
    release = threading.Event()
    order = []

    def work(name):
        if name == 'running':
            started.set()
            assert release.wait(10)
        order.append(name)
        return name

    with pool._PriorityMetadataExecutor(1) as executor:
        blocking = executor.submit_speculative(work, 'running')
        try:
            assert started.wait(5)
            ancestor = executor.submit_speculative(work, 'ancestor')
            required = executor.submit(work, 'required')
            sibling = executor.submit_speculative(work, 'sibling')
        finally:
            release.set()
        assert [future.result(timeout=5) for future in (blocking, ancestor, required, sibling)] == [
            'running', 'ancestor', 'required', 'sibling']
    assert order == ['running', 'required', 'ancestor', 'sibling']


def test_priority_changes_queue_order_not_running_pep517_work():
    pool = _load('superbench_pool.py')
    release = threading.Event()
    running = threading.Event()
    completion = []

    def slow():
        running.set()
        assert release.wait(10)
        completion.append('slow')

    def fast():
        completion.append('fast')

    with pool._PriorityMetadataExecutor(1) as executor:
        pending = executor.submit_speculative(slow)
        try:
            assert running.wait(5)
            urgent = executor.submit(fast)
            assert not urgent.done(), 'a running PEP 517 worker was preempted'
        finally:
            release.set()
        pending.result(timeout=5)
        urgent.result(timeout=5)
    assert completion == ['slow', 'fast']


def test_prefetch_cancellation_and_failed_metadata_remain_exact():
    bridge = _load('verified_resolver_bridge.py')
    pool = _load('superbench_pool.py')
    started = threading.Event()
    release = threading.Event()
    visited = []

    def work(ref):
        if ref == 0:
            started.set()
            assert release.wait(10)
        visited.append(ref)
        if ref == 3:
            raise RuntimeError('metadata infrastructure failure')
        return ref

    with pool._PriorityMetadataExecutor(1) as executor:
        prefetch = bridge._BoundedPrefetch(
            executor, work, speculative_submit=executor.submit_speculative)
        prefetch.schedule((0, 1, 2), 3, {})
        try:
            assert started.wait(5)
            # Cancellation must not cancel the task already executing.
            prefetch.schedule((0, 3), 3, {})
            assert not prefetch.futures[0].cancelled()
            assert 1 not in prefetch.futures and 2 not in prefetch.futures
            urgent = executor.submit(work, 4)
        finally:
            release.set()
        assert urgent.result(timeout=5) == 4
        assert prefetch.take(0).result(timeout=5) == 0
        with pytest.raises(RuntimeError, match='metadata infrastructure failure'):
            prefetch.take(3).result(timeout=5)
        prefetch.close()
    assert visited == [0, 4, 3]


def test_shutdown_cancels_queued_work_without_discarding_running_results():
    pool = _load('superbench_pool.py')
    started = threading.Event()
    release = threading.Event()

    def slow():
        started.set()
        assert release.wait(10)
        return 'verified'

    executor = pool._PriorityMetadataExecutor(1)
    pending = executor.submit(slow)
    try:
        assert started.wait(5)
        queued = executor.submit_speculative(lambda: 'never')
        executor.shutdown(wait=False, cancel_futures=True)
    finally:
        release.set()
        executor.shutdown(wait=True)
    assert pending.result(timeout=5) == 'verified'
    assert queued.cancelled()
    with pytest.raises(RuntimeError, match='shutdown'):
        executor.submit(lambda: 'unexpected')


def test_exceptions_propagate_without_killing_metadata_workers():
    pool = _load('superbench_pool.py')

    def fail():
        raise ValueError('verified metadata failure')

    with pool._PriorityMetadataExecutor(2) as executor:
        first = executor.submit(fail)
        second = executor.submit(lambda: 'still alive')
        with pytest.raises(ValueError, match='verified metadata failure'):
            first.result(timeout=5)
        assert second.result(timeout=5) == 'still alive'


def test_existing_queued_prefetch_is_promoted_when_rust_requires_it():
    bridge = _load('verified_resolver_bridge.py')
    pool = _load('superbench_pool.py')
    started = threading.Event()
    release = threading.Event()
    seen = []

    def work(ref):
        if ref == 'running':
            started.set()
            assert release.wait(10)
        seen.append(ref)
        return ref

    with pool._PriorityMetadataExecutor(1) as executor:
        blocker = executor.submit_speculative(work, 'running')
        try:
            assert started.wait(5)
            prefetch = bridge._BoundedPrefetch(
                executor, work, speculative_submit=executor.submit_speculative,
                promote=executor.promote)
            prefetch.schedule(('ancestor', 'required'), 3, {})
            required = prefetch.take('required')
            assert required is not None
            # Promotion preserves Future identity and skips stale heap entries.
        finally:
            release.set()
        assert required.result(timeout=5) == 'required'
        assert prefetch.take('ancestor').result(timeout=5) == 'ancestor'
        assert blocker.result(timeout=5) == 'running'
        prefetch.close()
    assert seen == ['running', 'required', 'ancestor']


def test_shared_closure_pool_installs_and_removes_priority_hooks(monkeypatch):
    from types import SimpleNamespace

    module = _load('superbench_pool.py')
    cache = {}
    checked = []

    def closure(_pool, key, _group):
        executor = cache['metadata_executor']
        assert cache['metadata_speculative_submit'] == executor.submit_speculative
        assert cache['metadata_promote'] == executor.promote
        assert executor.submit(lambda value: value, key).result(timeout=5) == key
        checked.append(key)

    monkeypatch.setattr(module, '_native_solver_cache', lambda _pool: cache)
    monkeypatch.setattr(module, '_pip_worker_controls', lambda: (2, 3))
    monkeypatch.setattr(module, 'acquire_pip_group', closure)
    module.acquire_pip_groups(SimpleNamespace(_state_lock=threading.RLock()),
                              {'first': {}, 'second': {}})
    assert set(checked) == {'first', 'second'}
    assert 'metadata_executor' not in cache
    assert 'metadata_speculative_submit' not in cache
    assert 'metadata_promote' not in cache

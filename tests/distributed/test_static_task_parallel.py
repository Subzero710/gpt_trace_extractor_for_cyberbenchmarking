"""Static task analysis: concurrent Git blob coalescing and deterministic aggregation."""
from __future__ import annotations

import concurrent.futures
import threading
from unittest.mock import patch

import pytest

import superbench_pool as pool


def test_git_metadata_single_flight_and_cross_commit_blob_reuse():
    oid = 'e' * 40
    first = 'a' * 40
    second = 'b' * 40
    calls = []
    lock = threading.Lock()
    entered = threading.Event()
    release = threading.Event()

    def tree(argv, *, capture):
        assert capture and argv[3] == 'ls-tree'
        with lock:
            calls.append(('tree', argv[4], argv[-1]))
        return '100644 blob ' + oid + '\tpyproject.toml\n'

    def blob(argv, *, timeout):
        assert argv[-2:] == ['blob', oid] and timeout == 60
        with lock:
            calls.append(('blob', oid))
        entered.set()
        assert release.wait(5)
        return b'[project]\nname = "fixture"\n'

    cache = pool._StaticGitReadCache(workers=2)
    with patch.object(pool, 'invoke', side_effect=tree), patch.object(
            pool.subprocess, 'check_output', side_effect=blob):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as workers:
            first_result = workers.submit(cache.read, '/mirror', first, 'pyproject.toml')
            assert entered.wait(5)
            second_result = workers.submit(cache.read, '/mirror', first, 'pyproject.toml')
            third_result = workers.submit(cache.read, '/mirror', second, 'pyproject.toml')
            release.set()
            values = [result.result(timeout=5) for result in
                      (first_result, second_result, third_result)]
            assert len(set(values)) == 1
            assert cache.read('/mirror', second, 'pyproject.toml') == values[0]
    assert calls.count(('blob', oid)) == 1
    assert calls.count(('tree', first, 'pyproject.toml')) == 1
    assert calls.count(('tree', second, 'pyproject.toml')) == 1


def test_missing_optional_and_required_paths_are_distinct():
    with patch.object(pool, 'invoke', return_value='') as tree:
        cache = pool._StaticGitReadCache(workers=1)
        assert cache.read('/mirror', 'c' * 40, 'requirements.txt') is None
        with pytest.raises(RuntimeError, match='missing source input requirements.txt'):
            cache.read('/mirror', 'c' * 40, 'requirements.txt', required=True)
        assert tree.call_count == 1
        with pytest.raises(ValueError, match='unsafe Git dependency file'):
            cache.read('/mirror', 'c' * 40, '../escape')


def test_group_merge_keeps_original_sorted_task_step_order():
    plans, groups, apt, upgrades, vcs, issues = {}, {}, set(), set(), set(), []

    def row(task, *, required, steps, note):
        group = {'target': {'python': 'fixture'}, 'requirements': ['a'],
                 'constraints': [], 'preferred_versions': {}, 'no_deps': False,
                 'required': required, 'tasks': [task], 'steps': steps}
        return (task, {'task': task}, {'shared': group}, {note}, {task}, {note},
                [task + ': ' + note])

    for item in (row('alpha', required=False, steps=['first', 'second'], note='x'),
                 row('beta', required=True, steps=['third'], note='y')):
        pool._merge_static_task_result(item, plans, groups, apt, upgrades, vcs, issues)
    assert list(plans) == ['alpha', 'beta']
    assert groups['shared']['required'] is True
    assert groups['shared']['tasks'] == ['alpha', 'beta']
    assert groups['shared']['steps'] == ['first', 'second', 'third']
    assert apt == {'x', 'y'} and upgrades == {'alpha', 'beta'}
    assert vcs == {'x', 'y'} and issues == ['alpha: x', 'beta: y']
    with pytest.raises(RuntimeError, match='duplicate static analysis task'):
        pool._merge_static_task_result(row('alpha', required=True, steps=[], note='x'),
                                       plans, groups, apt, upgrades, vcs, issues)


def test_native_local_metadata_is_serialized_without_holding_native_runtime_lock():
    import time
    active = 0
    peak = 0
    guard = threading.Lock()

    def isolated(*args):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.01)
        with guard:
            active -= 1
        return set(), set()

    with patch.object(pool, '_native_local_metadata', side_effect=isolated):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(pool._static_native_local_metadata, range(6)))
    assert results == [(set(), set())] * 6
    assert peak == 1

"""Check phase boundaries without using the network, Conda or a VM."""
from __future__ import annotations

import importlib.util
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'pool_phase_boundaries_under_test', ROOT / 'scripts/superbench_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def test_completed_recipe_counts_are_not_transfer_counts():
    stages = []
    tasks = [(str(i), i) for i in range(7)]
    with patch.object(pool, '_pool_progress', side_effect=lambda *args: stages.append(args)):
        with pool._static_task_completions(tasks, 3, lambda item: item) as results:
            assert list(results) == tasks
    updates = [args for args in stages if args[0] == 'Static task analysis']
    assert sorted(args[1] for args in updates) == list(range(1, len(tasks) + 1))
    assert all(args[2:] == (len(tasks), 'recipes') for args in updates)


def test_reassembly_does_not_claim_static_task_progress():
    observed = []
    with patch.object(pool, '_pool_progress', side_effect=lambda *args: observed.append(args)):
        with pool._static_task_completions(
                list(range(5)), 2, lambda item: item,
                stage='Dependency plan assembly') as results:
            assert list(results) == list(range(5))
    assert len(observed) == 5
    assert all(row[0] == 'Dependency plan assembly' for row in observed)


def test_native_build_requirements_are_queued_for_one_global_plan():
    target = SimpleNamespace(as_dict=lambda: {'python': 'locked'})
    worker = SimpleNamespace(_state_lock=threading.RLock())
    artifact = {'kind': 'sdist', 'build_requirements': [
        ['wheel>=0.1', 'setuptools>=60'], ['setuptools>=60', 'wheel>=0.1']]}
    with (patch.object(pool, 'pip_group_key', return_value='verified-build-identity'),
          patch.object(pool, 'acquire_pip_group', side_effect=AssertionError('premature closure'))):
        assert pool._native_acquire_build_dependencies(worker, target, [artifact], defer=True) == {}
        assert pool._native_acquire_build_dependencies(worker, target, [artifact], defer=True) == {}
    pending = worker._deferred_build_groups
    assert len(pending) == 1
    assert pending['verified-build-identity'] == {
        'target': target.as_dict(), 'requirements': ['setuptools>=60', 'wheel>=0.1'],
        'constraints': [], 'preferred_versions': {}, 'no_deps': False,
        'required': True, 'tasks': [],
        'steps': ['observed PEP517 build environment'],
    }


def test_invalid_native_build_requirements_do_not_get_registered():
    worker = SimpleNamespace(_state_lock=threading.RLock())
    target = SimpleNamespace(as_dict=lambda: {'python': 'locked'})
    with pytest.raises(RuntimeError, match='invalid observed build dependency group'):
        pool._native_acquire_build_dependencies(worker, target, [{
            'kind': 'sdist', 'build_requirements': [['wheel', 42]],
        }], defer=True)
    assert not hasattr(worker, '_deferred_build_groups')


def test_deferred_pep517_groups_merge_into_existing_global_roots():
    build={'target': {'python':'locked'}, 'requirements':['setuptools>=60'],
           'constraints':[], 'preferred_versions':{},'no_deps':False,
           'required':True,'tasks':[], 'steps':['observed PEP517 build environment']}
    worker=SimpleNamespace(_deferred_build_groups={'same-id': build})
    existing={**build,'required':False,'tasks':['recipe-1'], 'steps':['static project']}
    groups={'same-id':existing}
    pool._merge_deferred_build_groups(worker,groups)
    assert groups['same-id']['tasks']==['recipe-1']
    assert groups['same-id']['required'] is True
    assert groups['same-id']['steps']==['static project','observed PEP517 build environment']


def test_deferred_pep517_group_conflict_fails_closed():
    build={'target': {'python':'locked'}, 'requirements':['setuptools>=60'],
           'constraints':[], 'preferred_versions':{},'no_deps':False,
           'required':True,'tasks':[], 'steps':['observed PEP517 build environment']}
    worker=SimpleNamespace(_deferred_build_groups={'same-id': build})
    inconsistent={**build,'requirements':['different-package']}
    with pytest.raises(RuntimeError,match='inconsistent deferred PEP 517 closure identity'):
        pool._merge_deferred_build_groups(worker,{'same-id':inconsistent})


def test_static_recipe_deadline_is_not_extended_by_partial_activity(monkeypatch):
    import time
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 0.02)
    with pytest.raises(TimeoutError, match='static recipe exceeded versioned total deadline'):
        with pool._static_task_completions([('recipe', None)], 1,
                                           lambda item: time.sleep(0.03)) as results:
            list(results)
    assert pool._STATIC_RECIPE_DEADLINE.get() is None


def test_static_subprocess_timeout_consumes_shared_recipe_budget(monkeypatch):
    import time
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 0.1)
    with pool._static_task_completions([('recipe', None)], 1,
                                       lambda item: (time.sleep(0.04), pool._static_recipe_timeout(0.1))) as results:
        (_ignored, remaining), = list(results)
    assert 0 < remaining < 0.1

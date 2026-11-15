"""The metadata compiler exception applies only to two identified pandas tasks."""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib
from unittest.mock import patch

import pytest

import superbench_pool as pool


@pytest.fixture(scope='module')
def policy_exceptions():
    source = Path(pool.__file__).resolve().parents[1] / 'config/preparation.toml'
    with source.open('rb') as stream:
        policy = tomllib.load(stream)['acquisition']
    return policy['pip_metadata_elementary_timeout_overrides']


def context(row):
    return {'_native_source_context': {
        'kind': 'pinned-git-checkout',
        'mirror': str(Path('/tmp/native-timeout-policy/git') /
                      (row['repository'].replace('/', '_') + '.git')),
        'commit': row['commit'],
        'initiating_task': row['task_id'],
        'declared_backend': row['build_backend'],
    }}


def test_policy_lists_only_the_two_reported_pandas_builds(policy_exceptions):
    assert {(row['repository'], row['task_id'], row['commit'], row['timeout_seconds'])
            for row in policy_exceptions} == {
        ('pandas-dev/pandas', 'pandas-dev__pandas-53958',
         '1186ee0080a43a08c3431a5bfa86898f6ec3b54d', 900),
        ('pandas-dev/pandas', 'pandas-dev__pandas-56849',
         '612823e824805b97a2dbe258ba808dc572083d49', 900),
    }
    assert all(row['build_backend'] == 'mesonpy' for row in policy_exceptions)


@pytest.mark.parametrize('index', (0, 1))
def test_only_matching_metadata_build_receives_900_seconds(policy_exceptions, index):
    row = policy_exceptions[index]
    assert pool._native_pip_elementary_timeout(context(row), metadata_build=True) == 900


@pytest.mark.parametrize('index', (0, 1))
def test_normal_pip_execution_retains_standard_limit(policy_exceptions, index):
    assert (pool._native_pip_elementary_timeout(context(policy_exceptions[index]),
                                                metadata_build=False)
            == pool._operation_timeout())


@pytest.mark.parametrize('alteration', (
    {'kind': 'pypi-sdist'},
    {'commit': '0' * 40},
    {'initiating_task': 'different-task'},
    {'declared_backend': 'other-backend'},
    {'mirror': '/tmp/native-timeout-policy/git/other_repository.git'},
    {'mirror': '/tmp/native-timeout-policy/git-extra/pandas-dev_pandas.git'},
))
def test_near_matches_do_not_receive_exception(policy_exceptions, alteration):
    scoped = copy.deepcopy(context(policy_exceptions[0]))
    scoped['_native_source_context'].update(alteration)
    assert (pool._native_pip_elementary_timeout(scoped, metadata_build=True)
            == pool._operation_timeout())


def test_missing_identity_retains_standard_limit():
    assert pool._native_pip_elementary_timeout({}, metadata_build=True) == pool._operation_timeout()


def test_declared_exceptions_are_unique_and_well_formed(policy_exceptions):
    parsed = pool._native_pip_metadata_timeout_overrides()
    assert len(parsed) == len(policy_exceptions)
    assert all(value > pool._operation_timeout() for value in parsed.values())


@pytest.mark.parametrize('bad_rows,error', (
    ([{'repository': 'pandas-dev/pandas'}], 'schema'),
    ([], None),
))
def test_policy_validation_is_explicit(policy_exceptions, bad_rows, error):
    original = {'acquisition': {'pip_metadata_elementary_timeout_overrides': bad_rows}}
    pool._native_pip_metadata_timeout_overrides.cache_clear()
    try:
        with patch.object(pool.tomllib, 'load', return_value=original):
            if error is None:
                assert pool._native_pip_metadata_timeout_overrides() == {}
            else:
                with pytest.raises(RuntimeError, match=error):
                    pool._native_pip_metadata_timeout_overrides()
    finally:
        pool._native_pip_metadata_timeout_overrides.cache_clear()


def test_duplicate_exception_is_rejected(policy_exceptions):
    row = dict(policy_exceptions[0])
    pool._native_pip_metadata_timeout_overrides.cache_clear()
    try:
        with patch.object(pool.tomllib, 'load', return_value={
            'acquisition': {'pip_metadata_elementary_timeout_overrides': [row, row]}
        }):
            with pytest.raises(RuntimeError, match='duplicate'):
                pool._native_pip_metadata_timeout_overrides()
    finally:
        pool._native_pip_metadata_timeout_overrides.cache_clear()

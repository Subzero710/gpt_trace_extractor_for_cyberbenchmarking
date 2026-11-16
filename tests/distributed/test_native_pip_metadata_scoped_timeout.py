"""All verified pandas metadata builds get 900 s; other Pip work keeps 180 s."""
from __future__ import annotations

from pathlib import Path
import tomllib
from unittest.mock import patch

import pytest

import superbench_pool as pool


@pytest.fixture(autouse=True)
def clean_policy_cache():
    pool._native_pip_metadata_timeout_overrides.cache_clear()
    yield
    pool._native_pip_metadata_timeout_overrides.cache_clear()


def git_context(*, repository='pandas-dev/pandas', commit='a' * 40,
                task='pandas-dev__pandas-53958', backend='mesonpy',
                mirror_folder='git'):
    return {'_native_source_context': {
        'kind': 'pinned-git-checkout',
        'mirror': str(Path('/tmp/verified-pip-identity') / mirror_folder /
                      (repository.replace('/', '_') + '.git')),
        'commit': commit,
        'initiating_task': task,
        'declared_backend': backend,
    }}


def sdist_context(*, name='pandas', sha='a' * 64):
    return {'_native_source_context': {
        'kind': 'pypi-sdist', 'name': name, 'version': '1.5.3',
        'sha256': sha, 'target_python': '3.8.20',
    }}


def test_versioned_policy_is_project_scoped():
    path = Path(pool.__file__).resolve().parents[1] / 'config/preparation.toml'
    with path.open('rb') as stream:
        acquisition = tomllib.load(stream)['acquisition']
    assert acquisition['timeout_seconds'] == 180
    assert acquisition['pip_total_timeout_seconds'] >= max(
        rule['timeout_seconds'] for rule in
        acquisition['pip_metadata_elementary_timeout_overrides'])
    assert acquisition['pip_stall_timeout_seconds'] == 120
    assert acquisition['progress_stall_timeout_seconds'] == 900
    assert acquisition['pip_metadata_elementary_timeout_overrides'] == [
        {'kind': 'pinned-git-checkout', 'identity': 'pandas-dev/pandas',
         'timeout_seconds': 900},
        {'kind': 'pypi-sdist', 'identity': 'pandas',
         'timeout_seconds': 900},
    ]


@pytest.mark.parametrize('commit,task,backend', (
    ('a' * 40, 'pandas-dev__pandas-53958', 'mesonpy'),
    ('b' * 40, 'pandas-dev__pandas-56849', 'mesonpy'),
    ('c' * 40, 'pandas-dev__pandas-12345', 'setuptools.build_meta'),
    ('d' * 40, 'another-task', None),
))
def test_any_pandas_git_revision_and_backend_receives_900(commit, task, backend):
    assert pool._native_pip_elementary_timeout(
        git_context(commit=commit, task=task, backend=backend),
        metadata_build=True) == 900


@pytest.mark.parametrize('name', ('pandas', 'Pandas', 'PANDAS'))
def test_verified_pandas_sdist_receives_900(name):
    assert pool._native_pip_elementary_timeout(
        sdist_context(name=name), metadata_build=True) == 900


@pytest.mark.parametrize('runtime', (
    git_context(repository='numpy/numpy'),
    git_context(repository='pandas-dev/pandas-extra'),
    git_context(mirror_folder='git-extra'),
    git_context(commit='invalid'),
    sdist_context(name='numpy'),
    sdist_context(name='pandas-datareader'),
    sdist_context(sha='invalid'),
    {'_native_source_context': {'kind': 'unknown', 'name': 'pandas'}},
    {'_native_source_context': {'kind': 'pinned-git-checkout'}},
    {},
))
def test_nonmatching_or_unverified_sources_keep_normal_limit(runtime):
    assert pool._native_pip_elementary_timeout(
        runtime, metadata_build=True) == pool._operation_timeout()


@pytest.mark.parametrize('runtime', (git_context(), sdist_context()))
def test_normal_pip_execution_never_receives_metadata_exception(runtime):
    assert pool._native_pip_elementary_timeout(
        runtime, metadata_build=False) == pool._operation_timeout()


def test_metadata_runner_consumes_the_selected_elementary_limit():
    source = Path(pool.__file__).read_text()
    start = source.index('def _native_run_pip_elementary(')
    end = source.index('def _native_run_pip_with_byte_progress(', start)
    implementation = source[start:end]
    assert 'limit = _native_pip_elementary_timeout(runtime, metadata_build=metadata_build)' in implementation
    assert "expired('elementary', limit" in implementation
    assert "'PIP_DEFAULT_TIMEOUT': str(limit)" in implementation
    assert "source['initiating_task']" not in implementation


@pytest.mark.parametrize('rows,expected', (
    ([{'kind': 'pypi-sdist', 'identity': 'pandas', 'timeout_seconds': 180}], 'rule'),
    ([{'kind': 'pypi-sdist', 'identity': 'pandas', 'timeout_seconds': 900}] * 2, 'duplicate'),
    ([{'kind': 'arbitrary', 'identity': 'pandas', 'timeout_seconds': 900}], 'rule'),
    ([{'kind': 'pinned-git-checkout', 'identity': 'invalid', 'timeout_seconds': 900}], 'rule'),
    ([{'repository': 'pandas-dev/pandas', 'timeout_seconds': 900}], 'schema'),
    ([], 'missing'),
))
def test_invalid_policy_fails_closed(rows, expected):
    with patch.object(pool.tomllib, 'load', return_value={
            'acquisition': {'pip_metadata_elementary_timeout_overrides': rows}}):
        with pytest.raises(RuntimeError, match=expected):
            pool._native_pip_metadata_timeout_overrides()

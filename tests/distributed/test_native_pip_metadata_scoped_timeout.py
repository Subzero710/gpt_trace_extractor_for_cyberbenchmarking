"""Every native Pip backend uses the versioned elementary operation limit."""
from __future__ import annotations

from pathlib import Path
import tomllib
from unittest.mock import patch

import pytest

import superbench_pool as pool


@pytest.fixture(autouse=True)
def clean_policy_cache():
    pool._operation_timeout.cache_clear()
    yield
    pool._operation_timeout.cache_clear()


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
    assert 'pip_total_timeout_seconds' not in acquisition
    assert acquisition['pip_stall_timeout_seconds'] == 120
    assert acquisition['unregistered_work_timeout_seconds'] == 180
    assert 'pip_metadata_elementary_timeout_overrides' not in acquisition


class _RecordedEnvironment(Exception):
    pass


def verify_effective_timeout(runtime, root, metadata_build, monkeypatch):
    def start(_command, *, env, **_options):
        assert env['PIP_DEFAULT_TIMEOUT'] == str(pool._operation_timeout())
        raise _RecordedEnvironment

    runtime = {**runtime, 'root': root, '_pip_byte_progress': pool._NativePipByteProgress(1)}
    monkeypatch.setattr(pool.subprocess, 'Popen', start)
    try:
        with pytest.raises(_RecordedEnvironment):
            pool._native_run_pip_elementary(['pip', 'install'], runtime, {}, metadata_build=metadata_build)
    finally:
        runtime['_pip_byte_progress'].close()


@pytest.mark.parametrize('commit,task,backend', (
    ('a' * 40, 'pandas-dev__pandas-53958', 'mesonpy'),
    ('b' * 40, 'pandas-dev__pandas-56849', 'mesonpy'),
    ('c' * 40, 'pandas-dev__pandas-12345', 'setuptools.build_meta'),
    ('d' * 40, 'another-task', None),
))
def test_any_pandas_git_revision_and_backend_obeys_the_operation_limit(commit, task, backend, tmp_path, monkeypatch):
    verify_effective_timeout(git_context(commit=commit, task=task, backend=backend), tmp_path, True, monkeypatch)


@pytest.mark.parametrize('name', ('pandas', 'Pandas', 'PANDAS'))
def test_verified_pandas_sdist_obeys_the_operation_limit(name, tmp_path, monkeypatch):
    verify_effective_timeout(sdist_context(name=name), tmp_path, True, monkeypatch)


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
def test_nonmatching_or_unverified_sources_keep_normal_limit(runtime, tmp_path, monkeypatch):
    verify_effective_timeout(runtime, tmp_path, True, monkeypatch)


@pytest.mark.parametrize('runtime', (git_context(), sdist_context()))
def test_normal_pip_execution_never_receives_metadata_exception(runtime, tmp_path, monkeypatch):
    verify_effective_timeout(runtime, tmp_path, False, monkeypatch)


def test_metadata_runner_consumes_the_selected_elementary_limit():
    source = Path(pool.__file__).read_text()
    start = source.index('def _native_run_pip_elementary(')
    end = source.index('def _native_run(', start)
    implementation = source[start:end]
    assert 'limit = _operation_timeout()' in implementation
    assert "expired('elementary', limit" in implementation
    assert "'PIP_DEFAULT_TIMEOUT': str(limit)" in implementation
    assert "source['initiating_task']" not in implementation


@pytest.mark.parametrize('rows', (
    [{'kind': 'pypi-sdist', 'identity': 'pandas', 'timeout_seconds': 180}],
    [{'kind': 'pypi-sdist', 'identity': 'pandas', 'timeout_seconds': 900}] * 2,
    [{'kind': 'arbitrary', 'identity': 'pandas', 'timeout_seconds': 900}],
    [{'kind': 'pinned-git-checkout', 'identity': 'invalid', 'timeout_seconds': 900}],
    [{'repository': 'pandas-dev/pandas', 'timeout_seconds': 900}],
    [],
))
def test_invalid_policy_fails_closed(rows):
    with patch.object(pool.tomllib, 'load', return_value={
            'acquisition': {'timeout_seconds': 180, 'pip_metadata_elementary_timeout_overrides': rows}}):
        with pytest.raises(RuntimeError, match='cannot override'):
            pool._operation_timeout()

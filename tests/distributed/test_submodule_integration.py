import subprocess
from types import SimpleNamespace

import pytest

from scripts import build_local_templates as builder
from scripts import superbench_pool as pool
from workstation_broker import preparation


def git(*args):
    return subprocess.check_output(['git', *map(str, args)], timeout=30).decode().strip()


@pytest.mark.parametrize('suffix', ['', '/', '.git', '.git/'])
def test_local_submodule_uses_acquisition_url_policy(tmp_path, suffix):
    dependencies = tmp_path / 'pool'
    origin = dependencies / 'git-extra' / 'example_project.git'
    origin.parent.mkdir(parents=True)
    git('init', '--bare', origin)
    tree = subprocess.check_output(['git', '--git-dir', str(origin), 'mktree'], input=b'', timeout=30).decode().strip()
    commit = subprocess.check_output(['git', '--git-dir', str(origin), '-c', 'user.name=fixture',
                                      '-c', 'user.email=fixture@example.invalid', 'commit-tree', tree],
                                     input=b'fixture\n', timeout=30).decode().strip()
    cache = tmp_path / 'cache'
    cache.mkdir()
    url = 'https://github.com/example/project' + suffix
    result = builder.local_submodule_mirror(url, commit, dependencies, cache,
                                           repository_from_url=pool.github_repository, command=lambda *args: git(*args[1:]))
    assert git('--git-dir', result, 'rev-parse', commit + '^{commit}') == commit
    assert builder.local_submodule_mirror(url, commit, dependencies, cache,
                                          repository_from_url=pool.github_repository, command=lambda *args: git(*args[1:])) == result


@pytest.mark.parametrize('url', ['http://github.com/example/project',
                                'https://github.com/example/project?x=1',
                                'https://github.com:443/example/project',
                                'https://github.com/example/project/extra',
                                'https://other.example/example/project'])
def test_local_submodule_rejects_unadmitted_url(tmp_path, url):
    with pytest.raises(RuntimeError, match='invalid pinned Git submodule URL'):
        builder.local_submodule_mirror(url, 'a'*40, tmp_path, tmp_path,
                                       repository_from_url=pool.github_repository,
                                       command=lambda *args: pytest.fail('unexpected Git operation'))


@pytest.mark.parametrize('phase,error', [('interrupted', 'RecoverableBuildError: task source failed'),
                                        ('canceled', 'canceled by make down'), ('running', None)])
def test_reconciliation_preserves_worker_error_and_closes_scope(tmp_path, monkeypatch, phase, error):
    ready = tmp_path / 'dependency-pool' / 'ready'
    ready.mkdir(parents=True)
    proof = {'kind': 'download-only-pool', 'complete': True, 'pool_directory': str(ready),
             'tasks': 1, 'repos': 1, 'conda_recipes': 1, 'runtime_integrated': 'pending'}
    state = {'operation_id': 'a'*64, 'phase': phase, 'error': error, 'publication_verified': proof}
    writes = []
    manager = object.__new__(preparation.PreparationManager)
    manager.base = tmp_path / 'golden.qcow2'
    manager._reap = lambda: None
    manager._containers = lambda state: []
    manager._write = writes.append
    monkeypatch.setattr(preparation, 'JobScope', SimpleNamespace(members=lambda state: [],
                        close=lambda state: {**state, 'scope': {'closed': True}}))
    monkeypatch.setattr(preparation, 'verify_published_inventory',
                        lambda folder, state, proof: {**proof, 'operation_id': state['operation_id']})
    result = manager._reconcile(state)
    assert result['error'] == (error or 'runtime integration remains incomplete; sealed pool retained')
    assert result['phase'] == ('interrupted' if phase == 'running' else phase)
    assert result['scope']['closed'] is True
    assert writes[-1] == result

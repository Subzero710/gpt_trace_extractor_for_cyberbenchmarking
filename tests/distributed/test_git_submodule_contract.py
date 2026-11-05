"""Pinned Git submodule contracts with real Git, offline and disposable worktrees.

Fixtures are created during the test; no repository-specific or historical
submodule name, SHA, remote, or dependency version is embedded in the checks.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import superbench_pool as pool


def git(*args, check=True, env=None):
    result = subprocess.run(['git', *map(str, args)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, timeout=60)
    if check and result.returncode:
        raise AssertionError('generated Git fixture failed: ' + result.stderr)
    return result.stdout.strip(), result.returncode


def make_repository(tmp_path, label):
    source = tmp_path / ('source-' + label)
    source.mkdir()
    git('init', '-q', source)
    git('-C', source, 'config', 'user.name', 'Generated')
    git('-C', source, 'config', 'user.email', 'fixture@example.invalid')
    (source / 'content.txt').write_text('generated content ' + label + '\n')
    git('-C', source, 'add', '.')
    git('-C', source, 'commit', '-qm', 'initial fixture')
    return source


def add_submodule(parent, source, path, repository):
    git('-c', 'protocol.file.allow=always', '-C', parent,
        'submodule', 'add', '-q', source, path)
    # Keep the public source identity independent of the test's local origin.
    git('-C', parent, 'config', '-f', '.gitmodules',
        'submodule.' + path + '.url', 'https://github.com/' + repository + '.git')
    git('-C', parent, 'add', '.')
    git('-C', parent, 'commit', '-qm', 'pinned submodule')


def commit(source):
    return git('-C', source, 'rev-parse', 'HEAD')[0]


def mirror(source, stage, repository, label='git-extra'):
    destination = stage / label / (repository.replace('/', '_') + '.git')
    destination.parent.mkdir(parents=True, exist_ok=True)
    git('clone', '--bare', '-q', source, destination)
    return destination


@pytest.fixture
def generated_graph(tmp_path):
    stage = tmp_path / 'stage'
    stage.mkdir()
    leaf = make_repository(tmp_path, 'leaf')
    middle = make_repository(tmp_path, 'middle')
    root = make_repository(tmp_path, 'root')
    add_submodule(middle, leaf, 'inside/leaf', 'fixture/leaf')
    add_submodule(root, middle, 'vendor/middle', 'fixture/middle')
    roots = {
        'fixture/leaf': leaf,
        'fixture/middle': middle,
        'fixture/root': root,
    }
    hashes = {repo: commit(source) for repo, source in roots.items()}
    first_mirror = mirror(root, stage, 'fixture/root', label='git')
    second_mirror = mirror(middle, stage, 'fixture/middle')
    return SimpleNamespace(stage=stage, roots=roots, hashes=hashes,
                           root_mirror=first_mirror, middle_mirror=second_mirror)


def local_fetch_from_generated_sources(graph, calls):
    def fetch(folder, repository, refs, *, refetch=False, explicit_tags=False, timeout=3600):
        calls.append((repository, tuple(refs), refetch))
        assert not explicit_tags
        cmd = ['--git-dir', str(folder), 'fetch', '-q', '--depth=1']
        if refetch:
            cmd.append('--refetch')
        git(*cmd, graph.roots[repository].as_uri(), *refs)
    return fetch


def test_pinned_transitive_submodule_discovery_and_offline_materialization(
        generated_graph, tmp_path, monkeypatch):
    graph = generated_graph
    # Only the direct child was acquired by the preceding top-level pass.
    # Discovery itself must acquire the nested gitlink and record its identity.
    plan = {'fixture/root': {
        'commits': [graph.hashes['fixture/root']],
        'submodules': {'vendor/middle': {
            'repo': 'fixture/middle', 'commits': [graph.hashes['fixture/middle']]}}
    }}
    calls = []
    monkeypatch.setattr(pool, '_git_fetch', local_fetch_from_generated_sources(graph, calls))
    pool._acquire_nested_submodules(graph.stage, plan)
    assert plan['fixture/root']['submodules']['vendor/middle/inside/leaf'] == {
        'repo': 'fixture/leaf', 'commits': [graph.hashes['fixture/leaf']]}
    assert all(repository == 'fixture/leaf' for repository, _refs, _refetch in calls)
    assert (graph.stage / 'git-extra' / 'fixture_leaf.git').is_dir()

    def forbidden_fetch(*args, **kwargs):
        raise AssertionError('complete local submodules may not use network transport')
    monkeypatch.setattr(pool, '_git_fetch', forbidden_fetch)
    checkout = tmp_path / 'checkout'
    git('clone', '--quiet', '--shared', '--no-checkout', graph.root_mirror, checkout)
    git('-C', checkout, 'checkout', '--quiet', '--detach', graph.hashes['fixture/root'])
    scratch = tmp_path / 'runtime'
    scratch.mkdir()
    runtime = {'root': scratch, 'env': {'HOME': str(scratch), 'PATH': os.environ['PATH']}}
    pool._native_populate_submodules(
        SimpleNamespace(stage=graph.stage), runtime,
        graph.root_mirror, graph.hashes['fixture/root'], checkout)
    nested = checkout / 'vendor/middle/inside/leaf/content.txt'
    assert nested.read_bytes() == (graph.roots['fixture/leaf'] / 'content.txt').read_bytes()
    for repository, path in [('fixture/middle', 'vendor/middle'),
                             ('fixture/leaf', 'vendor/middle/inside/leaf')]:
        assert git('-C', checkout / path, 'rev-parse', 'HEAD')[0] == graph.hashes[repository]
    initialized = git('-C', checkout, 'submodule', 'status', '--recursive')[0].splitlines()
    assert len(initialized) == 2
    assert all(line and line[0] != '-' for line in initialized)
    # Repeated materialization must be idempotent and preserve exact Git objects.
    pool._native_populate_submodules(
        SimpleNamespace(stage=graph.stage), runtime,
        graph.root_mirror, graph.hashes['fixture/root'], checkout)
    assert nested.is_file()


def test_untrusted_submodule_url_is_rejected_without_remote_access(generated_graph, monkeypatch):
    graph = generated_graph
    middle = graph.roots['fixture/middle']
    git('-C', middle, 'config', '-f', '.gitmodules',
        'submodule.inside/leaf.url', 'file:///tmp/untrusted')
    git('-C', middle, 'add', '.gitmodules')
    git('-C', middle, 'commit', '-qm', 'changed source metadata')
    changed = commit(middle)
    dest = mirror(middle, graph.stage, 'fixture/rejected')
    def forbidden_fetch(*args, **kwargs):
        raise AssertionError('Git must not fetch untrusted submodule origins')
    monkeypatch.setattr(pool, '_git_fetch', forbidden_fetch)
    with pytest.raises(RuntimeError, match='untrusted pinned Git submodule'):
        pool._git_submodule_entries(dest, changed)


@pytest.mark.parametrize('unsafe', ['../outside', '/absolute', 'relative/../traversal'])
def test_submodule_path_never_escapes_checkout(tmp_path, unsafe):
    leaf = make_repository(tmp_path, 'leaf')
    root = make_repository(tmp_path, 'root')
    add_submodule(root, leaf, 'inside/leaf', 'fixture/leaf')
    git('-C', root, 'config', '-f', '.gitmodules', 'submodule.inside/leaf.path', unsafe)
    git('-C', root, 'add', '.gitmodules')
    git('-C', root, 'commit', '-qm', 'invalid pinned configuration')
    stage = tmp_path / 'stage'; stage.mkdir()
    source = mirror(root, stage, 'fixture/root', label='git')
    with pytest.raises(RuntimeError, match='unsafe or ambiguous'):
        pool._git_submodule_entries(source, commit(root))


def test_submodule_gitlink_must_match_pinned_configuration(generated_graph):
    graph = generated_graph
    source = graph.roots['fixture/root']
    git('-C', source, 'config', '-f', '.gitmodules',
        'submodule.vendor/middle.path', 'vendor/not-present')
    git('-C', source, 'add', '.gitmodules')
    git('-C', source, 'commit', '-qm', 'misidentified gitlink')
    mirror_path = mirror(source, graph.stage, 'fixture/wrong', label='git')
    with pytest.raises(RuntimeError, match='not a matching gitlink'):
        pool._git_submodule_entries(mirror_path, commit(source))


def test_real_pep517_metadata_observes_the_complete_pinned_source_tree(
        generated_graph, tmp_path, monkeypatch):
    """Run an actual pip/PEP 517 backend, not a mocked metadata command."""
    import sys

    graph = generated_graph
    source = graph.roots['fixture/root']
    (source / 'pyproject.toml').write_text(
        '[build-system]\nrequires=[]\n'
        'build-backend="fixture_backend"\nbackend-path=["."]\n')
    (source / 'fixture_backend.py').write_text('''from pathlib import Path

def get_requires_for_build_wheel(config_settings=None):
    artifact = Path(__file__).parent / 'vendor/middle/inside/leaf/content.txt'
    if not artifact.is_file():
        raise RuntimeError('pinned source content is absent from PEP 517 build input')
    return []

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    get_requires_for_build_wheel()
    info = Path(metadata_directory) / 'generated_local-1.0.dist-info'
    info.mkdir()
    (info / 'METADATA').write_text('Metadata-Version: 2.1\\nName: generated-local\\nVersion: 1.0\\n')
    return info.name

def build_wheel(*args, **kwargs):
    raise RuntimeError('dependency acquisition must not build or install a wheel')
''')
    git('-C', source, 'add', '.')
    git('-C', source, 'commit', '-qm', 'generated PEP 517 source')
    pinned = commit(source)
    root_mirror = mirror(source, graph.stage, 'fixture/metadata', label='git')
    mirror(graph.roots['fixture/leaf'], graph.stage, 'fixture/leaf')
    def forbidden_fetch(*args, **kwargs):
        raise AssertionError('pinned metadata evaluation cannot fetch missing remote sources')
    monkeypatch.setattr(pool, '_git_fetch', forbidden_fetch)
    # Real package metadata and Git execute.  Only the expensive Conda
    # interpreter-provisioning boundary is represented by the current Python.
    candidate = pool.Pool(graph.stage)
    candidate.conda_lock = {}
    try:
        runtime = pool._native_pool_runtime(candidate)
        runtime['env']['PIP_NO_INDEX'] = '1'
        runtime['env']['GIT_ALLOW_PROTOCOL'] = 'file'
        monkeypatch.setattr(pool, '_native_locked_python', lambda _pool, _target: Path(sys.executable))
        target = pool._target_environment_module().capture_current()
        dependencies, remotes = pool._native_local_metadata(
            candidate, target, root_mirror, pinned, [], ())
        assert dependencies == set()
        assert remotes == set()
    finally:
        pool._native_close(candidate)
        candidate._pip_cache_context.cleanup()

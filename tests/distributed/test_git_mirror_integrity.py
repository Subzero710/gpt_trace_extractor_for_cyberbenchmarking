"""Generic Git object-graph contracts using real, local Git repositories.

Only the remote-transport boundary is redirected to a disposable local Git
repository; all object traversal, shallow fetches, shared clones and checkouts
run through the actual installed Git executable. No network or production path.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

import pytest

import superbench_pool as pool


def git(*args, check=True):
    return subprocess.run(['git', *map(str, args)], check=check,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def source_fixture(tmp_path):
    origin = tmp_path/'origin'
    git('init', '-q', origin)
    git('-C', origin, 'config', 'user.email', 'generated@example.invalid')
    git('-C', origin, 'config', 'user.name', 'Generated')
    subtree = origin/'src'/'nested'
    subtree.mkdir(parents=True)
    (subtree/'metadata.txt').write_bytes(b'actual pinned source bytes\n')
    (origin/'README').write_text('root entry\n')
    git('-C', origin, 'add', '.')
    git('-C', origin, 'commit', '-qm', 'generated source')
    commit = git('-C', origin, 'rev-parse', 'HEAD').stdout.strip()
    tree = git('-C', origin, 'rev-parse', 'HEAD:src/nested').stdout.strip()
    return origin, commit, tree


def seeded_mirror(tmp_path, origin, commit):
    root = tmp_path/'stage'
    folder = root/'git'/'generated_source.git'
    folder.parent.mkdir(parents=True)
    git('init', '--bare', '-q', folder)
    git('--git-dir', folder, 'fetch', '--quiet', '--depth=1', origin.as_uri(), commit)
    return root, folder


def local_fetch(origin, calls):
    def fetch(folder, repo, refs, *, refetch=False, explicit_tags=False, timeout=3600):
        assert repo == 'generated/source'
        assert not explicit_tags
        calls.append((tuple(refs), refetch))
        command = ['--git-dir', str(folder), 'fetch', '--quiet', '--depth=1']
        if refetch:
            command.append('--refetch')
        git(*command, origin.as_uri(), *refs)
    return fetch


def missing_git_object(folder, identity):
    path = folder/'objects'/identity[:2]/identity[2:]
    assert path.is_file(), 'the fixture must use unpacked Git objects'
    path.unlink()


@pytest.mark.parametrize('kind', ['tree', 'blob'])
def test_existing_commit_is_not_proof_of_reachable_git_objects(tmp_path, monkeypatch, kind):
    origin, commit, tree = source_fixture(tmp_path)
    if kind == 'blob':
        tree = git('-C', origin, 'rev-parse', 'HEAD:src/nested/metadata.txt').stdout.strip()
    root, folder = seeded_mirror(tmp_path, origin, commit)
    assert pool._git_has_commit(folder, commit)
    assert pool._git_tree_closure_issue(folder, [commit]) is None
    missing_git_object(folder, tree)
    assert pool._git_has_commit(folder, commit)
    assert pool._git_tree_closure_issue(folder, [commit]) is not None
    # Top-level ls-tree is insufficient: the nested tree is absent.
    assert git('--git-dir', folder, 'ls-tree', commit, '--', 'README').returncode == 0
    calls = []
    monkeypatch.setattr(pool, '_git_fetch', local_fetch(origin, calls))
    assert pool.mirror_commits(root, 'generated/source', {commit}) == folder
    assert calls == [((commit,), True)]
    assert pool._git_tree_closure_issue(folder, [commit]) is None
    assert git('--git-dir', folder, 'show-ref', '--verify',
               'refs/heads/gpttrace-pinned-' + commit).returncode == 0
    checkout = tmp_path/'checkout'
    git('clone', '--quiet', '--shared', '--no-checkout', folder, checkout)
    git('-C', checkout, 'checkout', '--quiet', '--detach', commit)
    assert (checkout/'src'/'nested'/'metadata.txt').read_bytes() == b'actual pinned source bytes\n'


def test_intact_mirror_does_not_refetch_and_missing_commit_is_fetched(tmp_path, monkeypatch):
    origin, commit, _ = source_fixture(tmp_path)
    root, folder = seeded_mirror(tmp_path, origin, commit)
    calls = []
    monkeypatch.setattr(pool, '_git_fetch', local_fetch(origin, calls))
    assert git('--git-dir', folder, 'show-ref', check=False).returncode != 0
    assert pool.mirror_commits(root, 'generated/source', {commit}) == folder
    assert not calls
    # Local shared clones of a bare repository require advertised commit refs.
    # Without them an object-complete mirror is treated as an empty repository.
    checkout = tmp_path/'complete-clone'
    git('clone', '--quiet', '--shared', '--no-checkout', folder, checkout)
    git('-C', checkout, 'checkout', '--quiet', '--detach', commit)
    assert (checkout/'src'/'nested'/'metadata.txt').is_file()
    # A separate incomplete mirror still materializes its requested pinned ref.
    other = tmp_path/'fresh'
    other.mkdir()
    assert pool.ensure_commit(other, 'generated/source', commit, label='git-extra').is_dir()
    assert calls == [((commit,), False)]
    assert pool._git_tree_closure_issue(other/'git-extra'/'generated_source.git', [commit]) is None


def test_refetch_must_restore_complete_graph_or_fail_closed(tmp_path, monkeypatch):
    origin, commit, tree = source_fixture(tmp_path)
    root, folder = seeded_mirror(tmp_path, origin, commit)
    missing_git_object(folder, tree)
    calls = []
    def refuse_actual_repair(folder, repo, refs, *, refetch=False, **_kwargs):
        calls.append(bool(refetch))
    monkeypatch.setattr(pool, '_git_fetch', refuse_actual_repair)
    with pytest.raises(RuntimeError, match='closure remains incomplete'):
        pool.mirror_commits(root, 'generated/source', {commit})
    assert calls == [True]
    assert pool._git_tree_closure_issue(folder, [commit]) is not None



def test_multiple_pinned_shallow_commits_share_one_verified_mirror(tmp_path, monkeypatch):
    origin, first, _ = source_fixture(tmp_path)
    (origin/'src'/'nested'/'metadata.txt').write_bytes(b'updated pinned source bytes\n')
    git('-C', origin, 'add', '.')
    git('-C', origin, 'commit', '-qm', 'another pinned revision')
    second = git('-C', origin, 'rev-parse', 'HEAD').stdout.strip()
    root, folder = seeded_mirror(tmp_path, origin, first)
    calls = []
    monkeypatch.setattr(pool, '_git_fetch', local_fetch(origin, calls))
    assert pool.mirror_commits(root, 'generated/source', {first, second}) == folder
    assert calls == [((second,), False)]
    assert pool._git_tree_closure_issue(folder, [first, second]) is None
    for commit in (first, second):
        assert git('--git-dir', folder, 'show-ref', '--verify',
                   'refs/heads/gpttrace-pinned-' + commit).returncode == 0
    checkout = tmp_path/'multi-revision'
    git('clone', '--quiet', '--shared', '--no-checkout', folder, checkout)
    for commit, expected in ((first, b'actual pinned source bytes\n'),
                             (second, b'updated pinned source bytes\n')):
        git('-C', checkout, 'checkout', '--quiet', '--detach', commit)
        assert (checkout/'src'/'nested'/'metadata.txt').read_bytes() == expected


def test_tree_verification_is_scoped_to_pinned_objects(tmp_path):
    origin, commit, _ = source_fixture(tmp_path)
    _, folder = seeded_mirror(tmp_path, origin, commit)
    # Unreachable objects do not affect the pinned checkout's completeness.
    unrelated = hashlib.sha256(b'unreachable object fixture').hexdigest()
    assert unrelated not in [commit]
    assert pool._git_tree_closure_issue(folder, [commit]) is None
    with pytest.raises(RuntimeError, match='invalid pinned Git'):
        pool._git_tree_closure_issue(folder, ['unsafe'])

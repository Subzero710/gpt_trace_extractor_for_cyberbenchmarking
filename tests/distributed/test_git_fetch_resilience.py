"""Offline regression tests for resilient, verified GitHub pack acquisition."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import superbench_pool as pool


def test_git_progress_counts_received_bytes_from_git_only(monkeypatch, tmp_path):
    path = tmp_path / 'fetch-progress.json'
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=0,
                              progress_path=path, operation_id='a'*64)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', view)
    meter = pool._GitVerifiedTransfer('fixture/source')
    meter.feed(b'remote: Receiving objects:  90% (9/10), 900.00 GiB | 1 GiB/s\r')
    assert view.network_bytes == 0
    meter.feed(b'Receiving objects:  70% (7/10), 1.25 Mi')
    meter.feed(b'B | 512 KiB/s\r')
    assert view.network_bytes == 5 * 1048576 // 4
    meter.feed(b'Receiving objects:  70% (7/10), 1.25 MiB | 512 KiB/s\r')
    assert view.network_bytes == 5 * 1048576 // 4
    meter.feed(b'Receiving objects: 100% (10/10), 2.50 MiB | 1 MiB/s, done.\r')
    meter.close()
    assert view.network_bytes == 5 * 1048576 // 2
    assert view.transfers == {}
    observed = json.loads(path.read_bytes())
    assert observed['network_bytes'] == view.network_bytes
    assert observed['stage'] == 'Preparation'


def test_git_progress_does_not_publish_fake_heartbeat(monkeypatch, tmp_path):
    path = tmp_path / 'fetch-progress.json'
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=0,
                              progress_path=path, operation_id='a'*64)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', view)
    view.update('Git mirrors: git', 0, 11, 'repositories')
    before = path.read_bytes()
    meter = pool._GitVerifiedTransfer('fixture/source')
    meter.feed(b'remote: Counting objects: 100% (500/500), done.\r')
    meter.close()
    assert path.read_bytes() == before


def test_git_run_fetch_streams_actual_child_progress(monkeypatch, tmp_path):
    path = tmp_path / 'fetch-progress.json'
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=0,
                              progress_path=path, operation_id='a'*64)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', view)
    command = [sys.executable, '-c',
        'import os,time; os.write(2,b"Receiving objects:  60% (3/5), 3.00 MiB | 1 MiB/s\\r"); '
        'time.sleep(.05); os.write(2,b"fatal: simulated HTTP2 CANCEL\\n"); raise SystemExit(128)']
    result = pool._git_run_fetch(command, timeout=3, repo='fixture/source')
    assert result.returncode == 128
    assert 'simulated HTTP2 CANCEL' in result.stderr
    assert view.network_bytes == 3 * 1048576
    assert json.loads(path.read_text())['network_bytes'] == 3 * 1048576
    assert view.transfers == {}


def test_git_fetch_timeout_kills_private_process_group(monkeypatch):
    script = ('import os,subprocess,sys,time; '
              'subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]); '
              'sys.stderr.write("Receiving objects:  50% (2/4), 1.00 MiB | 1 MiB/s\\r"); '
              'sys.stderr.flush(); time.sleep(30)')
    with pytest.raises(subprocess.TimeoutExpired):
        pool._git_run_fetch([sys.executable, '-c', script],
                            timeout=0.15, repo='fixture/source')


def test_git_fetch_chunking_preserves_every_exact_commit(monkeypatch, tmp_path):
    controls = pool._git_acquisition_controls()
    commits = {'%040x' % value for value in range(1, controls['git_fetch_batch_size'] * 2 + 2)}
    fetches = []
    present = set()
    monkeypatch.setattr(pool, '_git_has_commit', lambda _folder, ref: ref in present)
    monkeypatch.setattr(pool, '_git_tree_closure_issue', lambda *_args: None)
    def transfer(_folder, _repo, refs, **kw):
        fetches.append((tuple(refs), kw))
        present.update(refs)
    monkeypatch.setattr(pool, '_git_fetch', transfer)
    pool._git_ensure_complete(tmp_path, 'fixture/repo', commits)
    fetched = [commit for batch, _ in fetches for commit in batch]
    assert fetched == sorted(commits)
    assert all(0 < len(batch) <= controls['git_fetch_batch_size'] for batch, _ in fetches)
    assert all(not options for _batch, options in fetches)


def test_git_fetch_refetch_batches_still_verify_all_trees(monkeypatch, tmp_path):
    controls = pool._git_acquisition_controls()
    commits = {'%040x' % value for value in range(1, controls['git_fetch_batch_size'] + 3)}
    audits = iter(['incomplete pinned objects', None])
    fetches = []
    monkeypatch.setattr(pool, '_git_has_commit', lambda *_args: True)
    monkeypatch.setattr(pool, '_git_tree_closure_issue', lambda *_args: next(audits))
    monkeypatch.setattr(pool, '_git_fetch', lambda _folder, _repo, refs, **kw:
                        fetches.append((tuple(refs), kw)))
    pool._git_ensure_complete(tmp_path, 'fixture/repo', commits)
    assert [ref for batch, _ in fetches for ref in batch] == sorted(commits)
    assert all(kw == {'refetch': True} for _batch, kw in fetches)


def test_git_worker_limit_comes_from_versioned_controls(monkeypatch, tmp_path):
    # Worker count cannot exceed the dedicated configured Git I/O budget.
    controls = pool._git_acquisition_controls()
    workers = []
    original = pool.concurrent.futures.ThreadPoolExecutor

    class RecordingExecutor(original):
        def __init__(self, max_workers, **kwargs):
            workers.append(max_workers)
            super().__init__(max_workers=max_workers, **kwargs)

    monkeypatch.setattr(pool.concurrent.futures, 'ThreadPoolExecutor', RecordingExecutor)
    monkeypatch.setattr(pool.os, 'sched_getaffinity', lambda _: set(range(controls['git_fetch_workers'] + 3)))
    monkeypatch.setattr(pool, 'mirror_commits', lambda path, repo, commits, **kw: tmp_path / repo.replace('/', '_'))
    repos = {'owner' + str(i) + '/repo': {'a'*40} for i in range(controls['git_fetch_workers'] + 3)}
    mirrors, _ = pool._acquire_git_mirrors(tmp_path, repos)
    assert len(mirrors) == len(repos)
    assert workers == [controls['git_fetch_workers']]


def test_git_fetch_does_not_change_remote_or_pinned_refs(monkeypatch, tmp_path):
    sha = 'a' * 40
    captured = []

    def interrupted(command, **kwargs):
        captured.append(command)
        if len(captured) == 1:
            return subprocess.CompletedProcess(command, 128, stderr='HTTP/2 CANCEL')
        return subprocess.CompletedProcess(command, 0, stderr='')

    monkeypatch.setattr(pool, '_git_run_fetch', interrupted)
    monkeypatch.setattr(pool.time, 'sleep', lambda _: None)
    pool._git_fetch(tmp_path, 'owner/repo', [sha])
    assert len(captured) == 2
    assert captured[0] == captured[1]
    assert captured[0][-2:] == ['https://github.com/owner/repo.git', sha]


@pytest.mark.parametrize('field,invalid', [
    ('git_fetch_workers', lambda c: 0),
    ('git_fetch_workers', lambda c: c['workers'] + 1),
    ('git_fetch_batch_size', lambda c: 0),
    ('git_fetch_attempts', lambda c: 0),
    ('git_fetch_attempt_timeout_seconds', lambda c: 0),
    ('git_fetch_attempt_timeout_seconds', lambda c: c['timeout_seconds'] + 1),
    ('git_fetch_retry_backoff_seconds', lambda c: c['git_fetch_retry_backoff_seconds'][:-1]),
    ('git_fetch_retry_backoff_seconds', lambda c:
        [True, *c['git_fetch_retry_backoff_seconds'][1:]]),
])
def test_git_fetch_timeout_controls_validate_strictly(monkeypatch, tmp_path, field, invalid):
    import tomllib
    source = Path(pool.__file__).resolve().parents[1] / 'config/preparation.toml'
    contents = source.read_text()
    acquisition = tomllib.loads(contents)['acquisition']
    rows = contents.splitlines(keepends=True)
    index = next(i for i, row in enumerate(rows) if row.startswith(field + ' = '))
    rows[index] = field + ' = ' + json.dumps(invalid(acquisition)) + '\n'
    fake_root = tmp_path / 'root'
    (fake_root / 'scripts').mkdir(parents=True)
    (fake_root / 'config').mkdir()
    (fake_root / 'config/preparation.toml').write_text(''.join(rows))
    monkeypatch.setattr(pool, '__file__', str(fake_root / 'scripts/superbench_pool.py'))
    pool._git_acquisition_controls.cache_clear()
    try:
        with pytest.raises(RuntimeError, match='Git|git'):
            pool._git_acquisition_controls()
    finally:
        pool._git_acquisition_controls.cache_clear()


def test_git_run_fetch_actual_git_receives_complete_pack(monkeypatch, tmp_path):
    origin = tmp_path / 'origin'
    destination = tmp_path / 'mirror.git'
    subprocess.run(['git', 'init', '--quiet', str(origin)], check=True)
    subprocess.run(['git', 'init', '--quiet', '--bare', str(destination)], check=True)
    (origin / 'artifact.bin').write_bytes(os.urandom(2 * 1048576))
    for argv in (('add', 'artifact.bin'),
                 ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                  'commit', '--quiet', '-m', 'verified source')):
        subprocess.run(['git', '-C', str(origin), *argv], check=True)
    commit = subprocess.check_output(['git', '-C', str(origin), 'rev-parse', 'HEAD'],
                                     text=True).strip()
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=0)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', view)
    command = ['git', '-c', 'protocol.file.allow=always', '--git-dir', str(destination),
               'fetch', '--progress', '--depth=1', '--no-tags', origin.as_uri(), commit]
    result = pool._git_run_fetch(command, timeout=30, repo='fixture/source')
    assert result.returncode == 0, result.stderr[-1000:]
    # Small local packs can finish before Git emits a progress counter.
    assert pool._git_tree_closure_issue(destination, [commit]) is None
    assert view.transfers == {}


def test_git_fetch_refspecs_are_immutable_commit_ids(monkeypatch, tmp_path):
    monkeypatch.setattr(pool, '_git_run_fetch', lambda *args, **kw: (_ for _ in ()).throw(
        AssertionError('untrusted Git arguments must not execute')))
    for invalid in ('--upload-pack=/bin/sh', '../../escape', 'refs/heads/main', 'a' * 39):
        with pytest.raises(RuntimeError, match='invalid Git fetch refspec'):
            pool._git_fetch(tmp_path, 'owner/repo', [invalid])
    with pytest.raises(RuntimeError, match='invalid Git fetch refspec'):
        pool._git_fetch(tmp_path, 'owner/repo', ['refs/tags/*'], explicit_tags=True)


def test_interrupted_fetch_clears_stale_locks_before_exact_retry(monkeypatch, tmp_path):
    mirror = tmp_path / 'mirror.git'
    (mirror / 'objects/pack').mkdir(parents=True)
    (mirror / 'refs/heads').mkdir(parents=True)
    unrelated = mirror / 'objects/info'
    unrelated.mkdir()
    (unrelated / 'alternates').write_text('retained source metadata\n')
    lock = mirror / 'shallow.lock'
    other_lock = mirror / 'objects/pack/transaction.lock'
    calls = []

    def simulated_fetch(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            lock.write_bytes(b'interrupted')
            other_lock.write_bytes(b'interrupted')
            return subprocess.CompletedProcess(command, 128, stderr='curl 92 CANCEL')
        assert not lock.exists()
        assert not other_lock.exists()
        return subprocess.CompletedProcess(command, 0, stderr='')

    monkeypatch.setattr(pool, '_git_run_fetch', simulated_fetch)
    monkeypatch.setattr(pool.time, 'sleep', lambda _: None)
    pool._git_fetch(mirror, 'owner/repo', ['a'*40])
    assert calls[0] == calls[1]
    assert (unrelated / 'alternates').read_text() == 'retained source metadata\n'


def test_interrupted_fetch_rejects_symlink_lock(monkeypatch, tmp_path):
    mirror = tmp_path / 'mirror.git'
    mirror.mkdir()
    outside = tmp_path / 'foreign-lock'
    outside.write_bytes(b'foreign')
    (mirror / 'shallow.lock').symlink_to(outside)
    monkeypatch.setattr(pool, '_git_run_fetch',
        lambda command, **kw: subprocess.CompletedProcess(command, 128, stderr='curl 18'))
    with pytest.raises(RuntimeError, match='unsafe interrupted Git lock'):
        pool._git_fetch(mirror, 'owner/repo', ['a'*40])
    assert outside.read_bytes() == b'foreign'


def test_parallel_fetches_for_same_mirror_never_interleave(monkeypatch, tmp_path):
    import concurrent.futures
    import threading
    import time
    mirror = tmp_path / 'mirror.git'
    mirror.mkdir()
    active = 0
    highest = 0
    guard = threading.Lock()

    def simulated_fetch(command, **kw):
        nonlocal active, highest
        with guard:
            active += 1
            highest = max(highest, active)
        time.sleep(.05)
        with guard:
            active -= 1
        return subprocess.CompletedProcess(command, 0, stderr='')

    monkeypatch.setattr(pool, '_git_run_fetch', simulated_fetch)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(pool._git_fetch, mirror, 'owner/repo', ['a'*40])
                   for _ in range(2)]
        for future in futures:
            future.result(timeout=3)
    assert highest == 1

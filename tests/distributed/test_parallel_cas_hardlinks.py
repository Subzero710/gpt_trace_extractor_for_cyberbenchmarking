"""Concurrent CAS hardlinks must not invalidate SHA checks via inode ctime."""
from __future__ import annotations

import concurrent.futures
import hashlib
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

import superbench_pool as pool_module


def _cas(pool, data):
    sha = hashlib.sha256(data).hexdigest()
    source = pool.objects / sha[:2] / sha
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(data)
    return sha, source


def test_hardlink_changes_link_count_without_changing_bytes(tmp_path):
    source = tmp_path / 'verified'
    source.write_bytes(b'pinned artifact')
    original = source.stat()
    target = tmp_path / 'archive'
    os.link(source, target)
    current = source.stat()
    assert (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) == (
        original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns)
    assert current.st_nlink == original.st_nlink + 1
    assert target.samefile(source)
    assert source.read_bytes() == b'pinned artifact'


def test_verified_cas_links_are_concurrent_safe_and_do_not_rehash_on_link(tmp_path, monkeypatch):
    stage = tmp_path / 'stage'
    instance = pool_module.Pool(stage)
    try:
        sha, source = _cas(instance, b'verified large pinned archive' * 2000)
        real_digest = pool_module.digest
        calls = []
        def counted_digest(path):
            calls.append(Path(path))
            return real_digest(path)
        monkeypatch.setattr(pool_module, 'digest', counted_digest)
        starts = threading.Barrier(8, timeout=10)
        destinations = []
        def link(index):
            folder = stage / 'archives' / str(index)
            folder.mkdir(parents=True)
            starts.wait()
            destination = folder / 'archive.conda'
            instance.link_verified_object(sha, destination)
            for _ in range(3):
                instance.verify_object(sha)
            return destination
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            destinations = list(executor.map(link, range(8)))
        assert all(dest.samefile(source) for dest in destinations)
        assert all(dest.read_bytes() == source.read_bytes() for dest in destinations)
        assert calls.count(source) == 1
        assert instance.verify_object(sha) == source.stat().st_size
        assert calls.count(source) == 1
    finally:
        instance._pip_cache_context.cleanup()


def test_verified_cas_hardlink_rejects_corruption_and_wrong_destination(tmp_path):
    instance = pool_module.Pool(tmp_path / 'stage')
    try:
        sha, source = _cas(instance, b'verified')
        wrong = tmp_path / 'wrong.conda'
        wrong.write_bytes(b'other artifact')
        with pytest.raises(RuntimeError, match='destination differs'):
            instance.link_verified_object(sha, wrong)
        link = tmp_path / 'link.conda'
        link.symlink_to(source)
        with pytest.raises(RuntimeError, match='unsafe CAS hardlink destination'):
            instance.link_verified_object(sha, link)
        original = source.stat()
        source.write_bytes(b'forged!!')  # Same length as the verified payload.
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert source.stat().st_size == original.st_size
        assert source.stat().st_mtime_ns == original.st_mtime_ns
        with pytest.raises(RuntimeError, match='CAS bytes fail SHA-256'):
            instance.link_verified_object(sha, tmp_path / 'not-created.conda')
        assert not (tmp_path / 'not-created.conda').exists()
    finally:
        instance._pip_cache_context.cleanup()


def test_parallel_conda_targets_share_verified_cas_archive_without_failure(tmp_path, monkeypatch):
    instance = pool_module.Pool(tmp_path / 'stage')
    root = tmp_path / 'native'
    root.mkdir()
    try:
        sha_a, cas_a = _cas(instance, b'python 3.11 verified package')
        sha_b, cas_b = _cas(instance, b'python 3.12 verified package')
        sha_common, cas_common = _cas(instance, b'common verified conda archive' * 10000)
        versions = {sha_a: '3.11.8', sha_b: '3.12.5'}
        artifacts = {}
        for sha, name in ((sha_a, 'python-3.11.8-0.conda'),
                          (sha_b, 'python-3.12.5-0.conda'),
                          (sha_common, 'shared-1-0.conda')):
            artifacts[sha] = {'url': 'https://conda.anaconda.org/example/linux-64/' + name,
                              'version': versions.get(sha, '1')}
        instance.conda_lock = {
            'artifacts': artifacts,
            'environments': {sha: {'transactions': [{
                'key': sha, 'packages': (sha_common, sha)
            }]} for sha in (sha_a, sha_b)},
        }
        runtime = {'root': root, 'env': {}, 'prefixes': {}, 'bootstrapped': True,
                   'conda_install_lock': threading.RLock()}
        monkeypatch.setattr(pool_module, '_native_pool_runtime', lambda _instance: runtime)
        monkeypatch.setattr(pool_module, '_coerce_target', lambda target: target)
        monkeypatch.setattr(instance, 'download', lambda url, category, key, *, sha: sha)
        fake_conda = root / 'conda' / 'bin' / 'conda'
        monkeypatch.setattr(pool_module, '_native_bootstrap', lambda *args: fake_conda)
        def run(argv, _runtime, **kwargs):
            if 'create' in argv:
                prefix = Path(argv[argv.index('--prefix') + 1])
                (prefix / 'bin').mkdir(parents=True)
                (prefix / 'bin' / 'python').write_bytes(b'verified fixture interpreter')
                return b''
            if '-c' in argv:
                return versions[Path(argv[0]).parent.parent.name].encode()
            if '--version' in argv:
                return b'pip fixture'
            raise AssertionError('unexpected native command: ' + str(argv))
        monkeypatch.setattr(pool_module, '_native_run', run)
        targets = [SimpleNamespace(python_artifact_sha256=sha,
                                   python_full_version=versions[sha])
                   for sha in (sha_a, sha_b)]
        barrier = threading.Barrier(2, timeout=10)
        def provision(target):
            barrier.wait()
            return pool_module._native_locked_python(instance, target)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            result = list(executor.map(provision, targets))
        assert len(result) == 2
        assert len(set(result)) == 2
        for target, python in zip(targets, result):
            assert python.is_file()
            archive = root / 'archives' / target.python_artifact_sha256 / sha_common / 'shared-1-0.conda'
            assert archive.samefile(cas_common)
            assert pool_module.digest(archive) == sha_common
        assert len(runtime['prefixes']) == 2
    finally:
        instance._pip_cache_context.cleanup()

"""Identity-scoped real-metadata scheduling, without external downloads."""
from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import superbench_pool as pool


def exercise(tmp_path, metadata_operation, *, populate=None):
    """Preserve the real native orchestration and isolate only external tools."""
    root = tmp_path / 'native'
    root.mkdir()
    runtime = {'root': root, 'env': {}, 'submodule_lock': threading.RLock()}
    candidate = SimpleNamespace(stage=tmp_path)
    target = SimpleNamespace(as_dict=lambda: {'target': 'generated'})
    observed = []
    def external(argv, _runtime, **_kwargs):
        if argv[:2] == ['git', 'clone']:
            Path(argv[-1]).mkdir(parents=True)
        return b''

    def native_metadata(argv, _runtime, _directory):
        report = Path(argv[argv.index('--report') + 1])
        name = report.stem
        metadata_operation(name)
        report.write_text(json.dumps({'install': [{'metadata': {'name': name, 'version': '1.0'}}]}))
        observed.append(report)
        return []

    with patch.object(pool, '_native_pool_runtime', return_value=runtime), \
         patch.object(pool, '_native_locked_python', return_value=Path(sys.executable)), \
         patch.object(pool, '_coerce_target', return_value=target), \
         patch.object(pool, '_native_run', side_effect=external), \
         patch.object(pool, '_native_populate_submodules', side_effect=populate or (lambda *args: None)), \
         patch.object(pool, '_native_metadata_command', side_effect=native_metadata), \
         patch.object(pool, '_native_acquire_build_dependencies', return_value={}), \
         patch.object(pool, '_native_project_requirements',
                      side_effect=lambda metadata, target, extras: ({metadata['name']}, set())):
        yield candidate, target, observed, runtime


def test_unrelated_local_metadata_hooks_overlap(tmp_path):
    reached = threading.Barrier(2, timeout=5)
    identities = []
    def metadata(name):
        identities.append(name)
        reached.wait()

    for candidate, target, reports, runtime in exercise(tmp_path, metadata):
        def acquire(commit):
            return pool._static_native_local_metadata(candidate, target, tmp_path, commit, [], set())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(acquire, 'a')
            second = workers.submit(acquire, 'b')
            results = [first.result(timeout=10), second.result(timeout=10)]
        assert results[0] != results[1]
        assert len(reports) == 2
        assert len(set(reports)) == 2
        assert len(identities) == 2
        assert not runtime['local_metadata_inflight']


def test_identical_metadata_single_flight_and_independent_result_sets(tmp_path):
    started, release = threading.Event(), threading.Event()
    calls = []
    def metadata(name):
        calls.append(name)
        started.set()
        assert release.wait(timeout=5)

    for candidate, target, reports, runtime in exercise(tmp_path, metadata):
        def acquire():
            return pool._native_local_metadata(candidate, target, tmp_path, 'same', [], {'extra'})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            first = workers.submit(acquire)
            assert started.wait(timeout=5)
            more = [workers.submit(acquire) for _ in range(7)]
            release.set()
            results = [future.result(timeout=10) for future in [first, *more]]
        assert len(calls) == 1
        assert len(reports) == 1
        assert len(runtime['local_metadata']) == 1
        assert not runtime['local_metadata_inflight']
        results[0][0].add('mutation')
        assert 'mutation' not in acquire()[0]


def test_failed_metadata_is_not_cached_and_waiters_are_released(tmp_path):
    started, release = threading.Event(), threading.Event()
    count = []
    def metadata(name):
        count.append(name)
        if len(count) == 1:
            started.set()
            assert release.wait(timeout=5)
            raise RuntimeError('verified metadata failure')

    for candidate, target, reports, runtime in exercise(tmp_path, metadata):
        def acquire():
            return pool._native_local_metadata(candidate, target, tmp_path, 'same', [], set())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(acquire)
            assert started.wait(timeout=5)
            second = workers.submit(acquire)
            # The waiter must observe the same failed owner, not create its own
            # checkout during the outstanding attempt.
            with pool._NATIVE_POOL_LOCK:
                assert len(runtime['local_metadata_inflight']) == 1
            release.set()
            with pytest.raises(RuntimeError, match='verified metadata failure'):
                first.result(timeout=10)
            with pytest.raises(RuntimeError, match='verified metadata failure'):
                second.result(timeout=10)
        assert len(count) == 1
        assert not runtime['local_metadata']
        assert len(runtime['local_metadata_inflight']) == 1
        with pytest.raises(RuntimeError, match='verified metadata failure'):
            acquire()
        assert len(count) == 1


def test_submodule_mutations_remain_exclusive(tmp_path):
    active = 0
    peak = 0
    locker = threading.Lock()
    def populate(*args):
        nonlocal active, peak
        with locker:
            active += 1
            peak = max(peak, active)
        time.sleep(0.035)
        with locker:
            active -= 1

    for candidate, target, reports, runtime in exercise(tmp_path, lambda name: None, populate=populate):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
            futures = [workers.submit(pool._native_local_metadata, candidate, target, tmp_path,
                                      str(index), [], set()) for index in range(4)]
            for future in futures:
                future.result(timeout=10)
        assert peak == 1
        assert len(reports) == 4


def test_locked_conda_downloads_overlap_but_prefix_mutations_do_not(tmp_path, request):
    import hashlib

    root = tmp_path / 'native'
    root.mkdir()
    runtime = {'root': root, 'env': {}, 'prefixes': {},
               'conda_install_lock': threading.RLock(), 'bootstrapped': False}
    # Exercise the real CAS API: native provisioning now links through
    # Pool.link_verified_object rather than using raw os.link/digest.
    candidate = pool.Pool(tmp_path)
    request.addfinalizer(candidate._pip_cache_context.cleanup)
    objects = candidate.objects
    artifacts = {}
    shared_content = b'locked shared native dependency'
    shared_sha = hashlib.sha256(shared_content).hexdigest()
    shared_path = objects / shared_sha[:2] / shared_sha
    shared_path.parent.mkdir(exist_ok=True)
    shared_path.write_bytes(shared_content)
    artifacts[shared_sha] = {'name': 'pip', 'version': '1',
                             'url': 'https://example.invalid/pip.conda'}
    target_rows = []
    for name, version in [('alpha', '3.11.11'), ('beta', '3.12.12')]:
        content = name.encode()
        sha = hashlib.sha256(content).hexdigest()
        target_rows.append((sha, version))
        item = {'name': 'python', 'version': version,
                'url': 'https://example.invalid/' + name + '.conda'}
        artifacts[sha] = item
        destination = objects / sha[:2] / sha
        destination.parent.mkdir()
        destination.write_bytes(content)
    lock = {'artifacts': artifacts, 'environments': {
        sha: {'transactions': [{'key': sha, 'packages': [sha, shared_sha]}]}
        for sha, version in target_rows}}
    candidate.conda_lock = lock
    downloader_barrier = threading.Barrier(len(target_rows), timeout=5)
    observed_downloads = []
    condas_running = 0
    peak_condas = 0
    serial = threading.Lock()

    def download(url, category, key, sha):
        if sha in dict(target_rows):
            downloader_barrier.wait()
        observed_downloads.append(sha)
        return sha

    def bootstrap(candidate, runtime):
        runtime['bootstrapped'] = True
        conda = root / 'conda' / 'bin' / 'conda'
        conda.parent.mkdir(parents=True, exist_ok=True)
        conda.write_text('verified installation placeholder')
        return conda

    def run(argv, runtime, **kwargs):
        nonlocal condas_running, peak_condas
        if len(argv) > 3 and argv[1:4] == ['-m', 'conda', 'create']:
            with serial:
                condas_running += 1
                peak_condas = max(peak_condas, condas_running)
            time.sleep(0.025)
            with serial:
                condas_running -= 1
            return b''
        if '-c' in argv:
            sha = str(Path(argv[0]).parent.parent.name)
            version = dict(target_rows)[sha]
            return version.encode()
        return b''

    with patch.object(pool, '_native_pool_runtime', return_value=runtime), \
         patch.object(pool, '_coerce_target', side_effect=lambda t: t), \
         patch.object(pool, '_native_bootstrap', side_effect=bootstrap), \
         patch.object(pool, '_native_conda_package_index', side_effect=lambda *_: {'depends': []}), \
         patch.object(pool, '_native_run', side_effect=run):
        candidate.download = download
        targets = [SimpleNamespace(python_artifact_sha256=sha,
                                   python_full_version=version)
                   for sha, version in target_rows]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(target_rows)) as workers:
            actual = list(workers.map(lambda t: pool._native_locked_python(candidate, t), targets))
        assert len(set(actual)) == len(targets)
        assert peak_condas == 1
        assert set(observed_downloads) == {shared_sha, *(sha for sha, _ in target_rows)}
        assert not runtime['locked_python_inflight']
        assert len(runtime['prefixes']) == len(target_rows)
        for target, interpreter in zip(targets, actual):
            assert interpreter == root / 'envs' / target.python_artifact_sha256 / 'bin' / 'python'
            assert pool._native_locked_python(candidate, target) == interpreter
        assert len(observed_downloads) == len(targets) * 2


def test_static_progress_tracks_actual_completion_without_reordering_results():
    slow_started = threading.Event()
    slow_allowed = threading.Event()
    observed = []

    def analyze(item):
        if item == 'slow':
            slow_started.set()
            assert slow_allowed.wait(timeout=5)
        else:
            assert slow_started.wait(timeout=5)
        return item

    def progress(stage, completed, total, unit):
        observed.append((stage, completed, total, unit))
        if completed == 1:
            slow_allowed.set()

    with patch.object(pool, '_pool_progress', side_effect=progress):
        with pool._static_task_completions(['slow', 'fast'], 2, analyze) as results:
            assert list(results) == ['slow', 'fast']
    assert observed == [
        ('Static task analysis', 1, 2, 'recipes'),
        ('Static task analysis', 2, 2, 'recipes')]


@pytest.fixture
def conda_index_inputs(tmp_path, monkeypatch):
    import hashlib

    candidate = pool.Pool(tmp_path / 'stage')
    runtime = {'root': tmp_path / 'native', 'conda_install_lock': pool._OwnedLock()}
    artifacts = {}
    for name in ('generated-one', 'generated-two'):
        content = name.encode()
        sha = hashlib.sha256(content).hexdigest()
        path = candidate.objects / sha[:2] / sha
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        artifacts[sha] = {'name': name, 'version': '1.0', 'build': 'generated',
                          'url': 'https://example.invalid/' + name + '.conda'}
    candidate.conda_lock = {'artifacts': artifacts}
    downloads = []
    def download(url, category, key, sha):
        downloads.append(sha)
        return candidate.reference(sha, category, key, candidate.verify_object(sha))
    monkeypatch.setattr(candidate, 'download', download)
    monkeypatch.setattr(pool, '_native_bootstrap', lambda *_: tmp_path / 'conda' / 'bin' / 'conda')
    try:
        yield candidate, runtime, artifacts, downloads
    finally:
        candidate._pip_cache_context.cleanup()


@pytest.mark.parametrize('fail', [False, True])
def test_shared_conda_index_has_one_extractor_and_one_outcome(conda_index_inputs, monkeypatch, fail):
    candidate, runtime, artifacts, downloads = conda_index_inputs
    sha = next(iter(artifacts))
    metadata = {key: artifacts[sha][key] for key in ('name', 'version', 'build')}
    metadata['depends'] = []
    entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
    extractions = []
    error = RuntimeError('generated extraction failure')
    original_wait = pool._shared_future_result

    def wait(future):
        waiting.set()
        return original_wait(future)

    def extract(argv, _runtime, **_kwargs):
        archive, destination = map(Path, argv[-2:])
        extractions.append(destination)
        assert archive.samefile(candidate.objects / sha[:2] / sha)
        destination.mkdir()
        entered.set()
        assert release.wait(timeout=5)
        if fail:
            raise error
        return json.dumps(metadata).encode()

    monkeypatch.setattr(pool, '_shared_future_result', wait)
    monkeypatch.setattr(pool, '_native_run', extract)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(pool._native_conda_package_index, candidate, runtime, sha, 'first')
        assert entered.wait(timeout=5)
        second = workers.submit(pool._native_conda_package_index, candidate, runtime, sha, 'second')
        try:
            assert waiting.wait(timeout=5)
            assert not second.done()
        finally:
            release.set()
        for future in (first, second):
            if fail:
                with pytest.raises(RuntimeError) as caught:
                    future.result(timeout=5)
                assert caught.value is error
            else:
                assert future.result(timeout=5) == metadata
    if fail:
        assert not runtime['conda_package_indices']
        with pytest.raises(RuntimeError) as caught:
            pool._native_conda_package_index(candidate, runtime, sha, 'third')
        assert caught.value is error
    else:
        assert not runtime['conda_package_indices_inflight']
        assert pool._native_conda_package_index(candidate, runtime, sha, 'third') == metadata
    assert downloads == [sha]
    assert len(extractions) == 1


def test_distinct_conda_indices_extract_concurrently(conda_index_inputs, monkeypatch):
    candidate, runtime, artifacts, downloads = conda_index_inputs
    rendezvous = threading.Barrier(len(artifacts), timeout=5)

    def extract(argv, _runtime, **_kwargs):
        archive, destination = map(Path, argv[-2:])
        sha = destination.parent.name
        assert archive.samefile(candidate.objects / sha[:2] / sha)
        destination.mkdir()
        rendezvous.wait()
        return json.dumps({key: artifacts[sha][key] for key in ('name', 'version', 'build')}
                          | {'depends': []}).encode()

    monkeypatch.setattr(pool, '_native_run', extract)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(artifacts)) as workers:
        futures = {sha: workers.submit(pool._native_conda_package_index,
                                       candidate, runtime, sha, sha) for sha in artifacts}
        for sha, future in futures.items():
            assert future.result(timeout=10)['name'] == artifacts[sha]['name']
    assert sorted(downloads) == sorted(artifacts)
    assert not runtime['conda_package_indices_inflight']

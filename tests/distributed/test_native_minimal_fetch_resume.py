"""Contract tests for minimal locked metadata runtimes and resumable CAS downloads."""
from __future__ import annotations

import hashlib
import time
import types
from pathlib import Path
from unittest.mock import patch

import pytest

import superbench_pool as pool


class Response:
    def __init__(self, *, url, status, body, headers, interrupted=False):
        self.url, self.status, self.headers = url, status, headers
        self.body, self.interrupted, self.position = body, interrupted, 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count):
        if self.interrupted and self.position >= 3:
            raise TimeoutError('interrupted transfer')
        if self.position == len(self.body):
            return b''
        take = min(count, 3 if self.interrupted else len(self.body))
        result = self.body[self.position:self.position + take]
        self.position += len(result)
        return result


def test_resume_consumes_only_missing_bytes_and_verifies_final_sha(tmp_path):
    url = 'https://conda.anaconda.org/conda-forge/noarch/demo.conda'
    payload = b'abcdefghi' * 2
    actual = hashlib.sha256(payload).hexdigest()
    requests = []

    def open_https(request, **_):
        offset = int(request.get_header('Range').split('=')[1][:-1]) if request.has_header('Range') else 0
        requests.append(offset)
        return Response(url=url, status=206 if offset else 200,
                        body=payload[offset:], interrupted=(offset == 0),
                        headers={'Content-Length': str(len(payload) - offset),
                                 **({'Content-Range': f'bytes {offset}-{len(payload) - 1}/{len(payload)}'}
                                    if offset else {})})

    target = tmp_path / 'download'
    counts = []
    with patch.object(pool, '_open_https', side_effect=open_https), \
         patch.object(pool, '_network_retries', return_value=(2, (0,))):
        assert pool.fetch(url, target, sha=actual, on_block=counts.append) == actual
    assert requests == [0, 3]
    assert target.read_bytes() == payload
    assert sum(counts) == len(payload)


def test_recovery_persists_pinned_partial_into_a_new_private_stage(tmp_path):
    old = tmp_path / 'old'
    new = tmp_path / 'new'
    for stage in old, new:
        for item in ('downloads', 'objects', 'metadata'):
            (stage / item).mkdir(parents=True)
        (stage / 'STAGING').write_text('interrupted')
    url = 'https://conda.anaconda.org/conda-forge/linux-64/demo.conda'
    archive = b'incomplete package bytes plus missing data'
    sha = hashlib.sha256(archive).hexdigest()
    name = hashlib.sha256(url.encode()).hexdigest()
    (old / 'downloads' / name).write_bytes(archive[:11])
    result = pool.salvage_verified_stage(old, new, conda_artifacts={sha: {'url': url}})
    assert result == set()
    assert (new / 'downloads' / name).read_bytes() == archive[:11]
    with (new / 'downloads' / name).open('ab') as stream:
        stream.write(archive[11:])
    assert (old / 'downloads' / name).read_bytes() == archive[:11]
    assert hashlib.sha256((new / 'downloads' / name).read_bytes()).hexdigest() == sha


def test_refuses_resume_without_correct_content_range(tmp_path):
    url = 'https://conda.anaconda.org/conda-forge/noarch/demo.conda'
    path = tmp_path / 'partial'
    path.write_bytes(b'prefix')
    with patch.object(pool, '_open_https', return_value=Response(
            url=url, status=206, body=b'end',
            headers={'Content-Range': 'bytes 1-3/4', 'Content-Length': '3'})):
        with pytest.raises(RuntimeError, match='resume range differs'):
            pool.fetch(url, path, sha=hashlib.sha256(b'prefixend').hexdigest())
    assert path.read_bytes() == b'prefix'


def test_refuses_http_200_when_existing_prefix_is_present(tmp_path):
    url = 'https://conda.anaconda.org/conda-forge/noarch/demo.conda'
    path = tmp_path / 'partial'
    path.write_bytes(b'prefix')
    with patch.object(pool, '_open_https', return_value=Response(
            url=url, status=200, body=b'prefixend', headers={'Content-Length': '9'})):
        with pytest.raises(RuntimeError, match='did not honor byte-range'):
            pool.fetch(url, path, sha=hashlib.sha256(b'prefixend').hexdigest())
    assert path.read_bytes() == b'prefix'


def test_minimal_native_closure_ignores_unrelated_science_stack():
    items = {
        'python': ('a' * 64, ('libffi >=3', 'openssl >=3', '__glibc >=2.17')),
        'pip': ('b' * 64, ('python >=3', 'setuptools >=1')),
        'setuptools': ('c' * 64, ('python >=3',)),
        'wheel': ('d' * 64, ('python >=3',)),
        'libffi': ('e' * 64, ('libgcc-ng >=12',)),
        'openssl': ('f' * 64, ('libgcc-ng >=12',)),
        'libgcc-ng': ('1' * 64, ()),
        'pyspark': ('2' * 64, ('python >=3',)),
        'arrow-cpp': ('3' * 64, ('libgcc-ng >=12',)),
    }
    artifacts = {sha: {'name': name} for name, (sha, _) in items.items()}
    pool_instance = types.SimpleNamespace(conda_lock={
        'artifacts': artifacts,
        'environments': {'one': {'transactions': [
            {'key': 'env-locked', 'packages': [sha for sha, _ in items.values()]}]}}
    })
    acquired = []
    def index(_pool, _runtime, sha, _key):
        acquired.append(sha)
        return {'depends': list(next(deps for _, (key, deps) in items.items() if key == sha))}

    with patch.object(pool, '_native_conda_package_index', side_effect=index):
        key, selected = pool._native_minimal_python_packages(pool_instance, {}, items['python'][0])
    assert key == 'env-locked'
    assert set(selected) == {items[name][0] for name in items if name not in ('pyspark', 'arrow-cpp', 'wheel')}
    assert len(acquired) == len(selected)


def test_large_slow_download_rolls_at_operation_deadline_without_consuming_retries(tmp_path):
    url = 'https://conda.anaconda.org/conda-forge/noarch/deliberate-segments.conda'
    payload = b'x' * 32
    sha = hashlib.sha256(payload).hexdigest()
    offsets = []

    class SlowResponse(Response):
        def read(self, count):
            time.sleep(0.045)
            return super().read(1)

    def open_https(request, **_):
        offset = int(request.get_header('Range').split('=')[1][:-1]) if request.has_header('Range') else 0
        offsets.append(offset)
        return SlowResponse(url=url, status=206 if offset else 200,
            body=payload[offset:], headers={'Content-Length': str(len(payload) - offset),
                **({'Content-Range': f'bytes {offset}-{len(payload) - 1}/{len(payload)}'}
                   if offset else {})})

    target = tmp_path / 'slow-pinned-artifact'
    with patch.object(pool, '_open_https', side_effect=open_https), \
         patch.object(pool, '_network_retries', return_value=(1, ())), \
         patch.object(pool, '_operation_timeout', return_value=2), \
         patch.object(pool, '_conda_progress_interval', return_value=1):
        assert pool.fetch(url, target, sha=sha) == sha
    assert target.read_bytes() == payload
    assert len(offsets) >= 2
    assert offsets == sorted(set(offsets))
    assert offsets[0] == 0


def test_zero_length_interrupted_file_can_restart_without_exclusive_create_failure(tmp_path):
    url = 'https://conda.anaconda.org/conda-forge/noarch/empty-start.conda'
    payload = b'valid-complete-archive'
    path = tmp_path / 'existing-empty-file'
    path.write_bytes(b'')
    with patch.object(pool, '_open_https', return_value=Response(
            url=url, status=200, body=payload,
            headers={'Content-Length': str(len(payload))})):
        assert pool.fetch(url, path, sha=hashlib.sha256(payload).hexdigest()) == hashlib.sha256(payload).hexdigest()
    assert path.read_bytes() == payload

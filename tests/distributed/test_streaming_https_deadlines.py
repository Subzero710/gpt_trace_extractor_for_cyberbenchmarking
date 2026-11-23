"""HTTPS artifact deadlines apply to observed network operations, not the file size."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
import superbench_pool as pool


class _Response:
    def __init__(self, url, payload, *, delay):
        self.url = url
        self.payload = payload
        self.delay = delay
        self.offset = 0
        self.headers = {'Content-Length': str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, amount):
        if self.offset == len(self.payload):
            return b''
        time.sleep(self.delay)
        end = min(len(self.payload), self.offset + amount)
        result = self.payload[self.offset:end]
        self.offset = end
        return result


def test_verified_bytes_extend_only_the_stream_idle_budget(tmp_path, monkeypatch):
    timeout = 1
    payload = b'v' * (4 * 1048576)
    url = 'https://example.test/conda/artifact.conda'
    path = tmp_path / 'verified-download'
    monkeypatch.setattr(pool, '_operation_timeout', lambda: timeout)
    monkeypatch.setattr(pool, '_network_retries', lambda: (1, ()))
    monkeypatch.setattr(pool, '_open_https', lambda *args, **kwargs: _Response(url, payload, delay=0.4))
    monkeypatch.setattr(pool, '_POOL_PROGRESS', None)

    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    monkeypatch.setattr(pool, '_OPERATION_EVENT_FD', write_fd)
    started = time.monotonic()
    try:
        result = pool.fetch(url, path, sha=hashlib.sha256(payload).hexdigest())
        elapsed = time.monotonic() - started
    finally:
        os.close(write_fd)
    with os.fdopen(read_fd, 'rb') as stream:
        events = [json.loads(line) for line in stream]

    assert elapsed > timeout
    assert result == hashlib.sha256(payload).hexdigest()
    assert path.read_bytes() == payload
    assert 'HTTPS attempt' not in [event.get('label') for event in events]
    beginnings = [event for event in events if event['event'] == 'begin']
    assert [e['label'] for e in beginnings] == ['HTTPS download connect'] + ['HTTPS download block'] * 5
    assert all(e['limit'] == timeout for e in beginnings)
    active = {}
    for event in events:
        if event['event'] == 'begin':
            active[event['operation']] = event
        else:
            start = active.pop(event['operation'])
            assert event['event'] == 'end'
            assert event['finished'] - start['started'] < timeout
    assert not active


def test_stalled_stream_fails_and_discards_partial_file(tmp_path, monkeypatch):
    timeout = 1
    url = 'https://example.test/conda/stalled.conda'
    path = tmp_path / 'partial-download'
    monkeypatch.setattr(pool, '_operation_timeout', lambda: timeout)
    monkeypatch.setattr(pool, '_network_retries', lambda: (1, ()))
    monkeypatch.setattr(pool, '_open_https', lambda *args, **kwargs: _Response(url, b'body', delay=timeout + 0.1))
    monkeypatch.setattr(pool, '_POOL_PROGRESS', None)
    with pytest.raises(TimeoutError, match='network attempt exceeded versioned deadline'):
        pool.fetch(url, path, sha=hashlib.sha256(b'body').hexdigest())
    assert not path.exists()


def test_streaming_rejects_wrong_sha_even_with_progress(tmp_path, monkeypatch):
    url = 'https://example.test/conda/wrong.conda'
    path = tmp_path / 'unverified-download'
    monkeypatch.setattr(pool, '_network_retries', lambda: (1, ()))
    monkeypatch.setattr(pool, '_open_https', lambda *args, **kwargs: _Response(url, b'not-the-expected-bytes', delay=0))
    monkeypatch.setattr(pool, '_POOL_PROGRESS', None)
    with pytest.raises(pool.DownloadIntegrityError, match='sha256 mismatch'):
        pool.fetch(url, path, sha=hashlib.sha256(b'expected-bytes').hexdigest())
    assert not path.exists()

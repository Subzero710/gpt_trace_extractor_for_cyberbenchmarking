"""Native pip retries reuse private HTTP bytes and fail fast on observable stalls."""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

import superbench_pool as pool


def _fake_pip(root, body):
    project = root / 'pip'
    project.mkdir()
    (project / '__init__.py').write_text('')
    (project / '__main__.py').write_text(body)
    return {'root': root, 'env': {
        'PATH': os.environ['PATH'], 'PYTHONPATH': str(root),
        'PYTHONDONTWRITEBYTECODE': '1'}}


def test_cached_http_body_is_reused_and_not_published(tmp_path):
    old, new = tmp_path / 'failed', tmp_path / 'new'
    for stage in (old, new):
        stage.mkdir()
        for directory in ('metadata', 'downloads', 'objects'):
            (stage / directory).mkdir()
    pool.write_new(old / 'STAGING', 'failed stage\n')
    previous = pool.Pool(old)
    previous.conda_lock = {'artifacts': {}}
    runtime = pool._native_pool_runtime(previous)
    persistent = Path(runtime['env']['PIP_CACHE_DIR'])
    assert persistent == old / 'pip-http-cache'
    data = b'cached immutable response bytes from a test fixture'
    body = persistent / 'http-v2' / 'a' / 'b' / 'body.body'
    body.parent.mkdir(parents=True)
    body.write_bytes(data)
    runtime['context'].cleanup()  # interrupted worker: scratch is not recovered
    assert body.read_bytes() == data
    pool.salvage_verified_stage(old, new)
    copied = new / 'pip-http-cache' / body.relative_to(persistent)
    assert copied.read_bytes() == data
    assert not copied.samefile(body)
    recovered = pool.Pool(new)
    recovered.conda_lock = {'artifacts': {}}
    active = pool._native_pool_runtime(recovered)
    sha = hashlib.sha256(data).hexdigest()
    assert pool._native_acquired_archive(
        recovered, active, 'https://files.pythonhosted.org/packages/fixture.whl',
        sha, 'python', 'fixture') == sha
    assert (new / 'objects' / 'sha256' / sha[:2] / sha).read_bytes() == data
    pool._native_close(recovered)
    assert not (new / 'pip-http-cache').exists()
    assert (new / 'objects' / 'sha256' / sha[:2] / sha).read_bytes() == data
    previous._pip_cache_context.cleanup()
    recovered._pip_cache_context.cleanup()


def test_native_pip_detects_stall_and_keeps_tail(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'import time\nprint("fixture started",flush=True)\ntime.sleep(15)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (8, 1))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        with pytest.raises(RuntimeError, match='no new output/download bytes') as result:
            pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                             runtime, timeout=8)
        runtime['_pip_byte_progress'].close()
    assert 'fixture started' in str(result.value)


def test_native_pip_active_bytes_reset_stall_budget(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'import time\nfor i in range(1,8):\n'
                                 ' print(f"Progress {i} of 7", flush=True)\n'
                                 ' time.sleep(0.35)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (6, 1))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        result = pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                                  runtime, timeout=6)
        assert runtime['_pip_byte_progress'].snapshot()['bytes'] == 7
        runtime['_pip_byte_progress'].close()
    assert result == b''


def test_native_pip_total_deadline_retains_tail(tmp_path, monkeypatch):
    runtime = _fake_pip(tmp_path, 'import time\nprint("fixture total limit", flush=True)\ntime.sleep(15)\n')
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (1, 10))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            pool._native_run([sys.executable, '-m', 'pip', 'install', 'fixture'],
                             runtime, timeout=20)
        runtime['_pip_byte_progress'].close()
    assert b'fixture total limit' in caught.value.output


def test_versioned_controls_are_restrictive_and_readable():
    total, stalled = pool._native_pip_timeouts()
    assert 0 < stalled < total < 7200


def test_salvage_ignores_abandoned_native_scratch_but_not_other_symlinks(tmp_path):
    old, new = tmp_path / 'old', tmp_path / 'new'
    old.mkdir()
    new.mkdir()
    pool.write_new(old / 'STAGING', 'interrupted\n')
    scratch = old / '.native-pip-interrupted'
    scratch.mkdir()
    (scratch / 'symlink').symlink_to(tmp_path)
    assert pool.salvage_verified_stage(old, new) == set()
    assert not (new / '.native-pip-interrupted').exists()
    (old / 'outside-scratch').symlink_to(tmp_path)
    with pytest.raises(RuntimeError, match='unsafe retained dependency entry'):
        pool.salvage_verified_stage(old, new)


def test_seeded_wheel_is_selected_offline_with_original_pypi_provenance(tmp_path, monkeypatch):
    import json
    from zipfile import ZipFile

    stage = tmp_path / 'stage'
    stage.mkdir()
    (stage / 'metadata').mkdir()
    winner = pool.Pool(stage)
    wheel_name = 'fixture_pkg-1.0-py3-none-any.whl'
    fixture_wheel = tmp_path / wheel_name
    with ZipFile(fixture_wheel, 'w') as archive:
        archive.writestr('fixture_pkg/__init__.py', '')
        archive.writestr('fixture_pkg-1.0.dist-info/METADATA',
                         'Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 1.0\n')
        archive.writestr('fixture_pkg-1.0.dist-info/WHEEL',
                         'Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
        archive.writestr('fixture_pkg-1.0.dist-info/RECORD', '')
    sha = pool.digest(fixture_wheel)
    winner.put(fixture_wheel, 'python', 'fixture', verified_sha=sha)
    original_url = 'https://files.pythonhosted.org/packages/' + wheel_name
    plan = {'packages': [{'kind': 'wheel', 'filename': wheel_name,
                          'sha256': sha, 'url': original_url, 'yanked': False}]}
    pool.write_new(stage / 'metadata' / 'pip-plan-fixture.json', '{}')
    monkeypatch.setattr(pool, '_read_pip_plan_tree', lambda stage, key: {'fixture': plan})
    runtime = {'root': tmp_path / 'runtime'}
    runtime['root'].mkdir()
    wheelhouse = pool._native_seed_wheelhouse(winner, runtime)
    assert (wheelhouse / wheel_name).samefile(winner.objects / sha[:2] / sha)
    report = tmp_path / 'pip-report.json'
    cmd = [sys.executable, '-m', 'pip', 'install', '--no-index', '--dry-run',
           '--ignore-installed', '--find-links', str(wheelhouse), '--report',
           str(report), 'fixture-pkg==1.0']
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    candidate = json.loads(report.read_text())['install'][0]['download_info']
    assert candidate['url'] == (wheelhouse / wheel_name).as_uri()
    reported_sha = candidate['archive_info']['hashes']['sha256']
    assert reported_sha == sha
    assert pool._native_report_origin(winner, runtime, candidate['url'], reported_sha) == (original_url, False)
    with pytest.raises(RuntimeError, match='lacks exact verified'):
        pool._native_report_origin(winner, runtime, candidate['url'], '0' * 64)
    winner._pip_cache_context.cleanup()

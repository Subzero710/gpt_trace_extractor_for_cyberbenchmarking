"""Index/cache correctness for retained pip versions under concurrent closures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from test_superbench_pool import fixture_target, pool as module


def _cas(pool, content):
    sha = hashlib.sha256(content).hexdigest()
    path = pool.objects / sha[:2] / sha
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return sha, path


def _plan(stage, key, name, version, sha, *, legacy=False):
    metadata = stage / 'metadata'
    metadata.mkdir(parents=True, exist_ok=True)
    row = {'name': name, 'version': version, 'sha256': sha}
    payload = {'packages': [] if legacy else [row]}
    if legacy:
        payload['packages'] = 'legacy'
        payload['source_archives'] = [row]
    path = metadata / ('pip-plan-' + key + '.json')
    path.write_text(json.dumps(payload))
    return path


def test_cached_python_versions_scans_each_checkpoint_once_across_many_packages(tmp_path):
    candidate = module.Pool(tmp_path)
    sha, _ = _cas(candidate, b'indexed-artifact')
    plans = [_plan(tmp_path, str(index), f'pkg{index:04d}', '1.0', sha)
             for index in range(150)]
    with patch.object(module.json, 'loads', wraps=module.json.loads) as decoder:
        for _ in range(3):
            for index in range(150):
                assert module._cached_python_versions(candidate, f'pkg{index:04d}') == {'1.0'}
        assert decoder.call_count == len(plans)


def test_cached_python_versions_detects_new_deleted_and_invalid_evidence(tmp_path):
    candidate = module.Pool(tmp_path)
    sha, artifact = _cas(candidate, b'original-artifact')
    first = _plan(tmp_path, 'first', 'demo', '1.0', sha)
    assert module._cached_python_versions(candidate, 'demo') == {'1.0'}

    second = _plan(tmp_path, 'second', 'demo', '1.0', sha)
    assert module._cached_python_versions(candidate, 'DEMO') == {'1.0'}
    first.unlink()
    assert module._cached_python_versions(candidate, 'demo') == {'1.0'}
    second.unlink()
    assert module._cached_python_versions(candidate, 'demo') == set()

    third = _plan(tmp_path, 'later', 'demo', '2.0', sha)
    assert module._cached_python_versions(candidate, 'demo') == {'2.0'}
    artifact.unlink()
    assert module._cached_python_versions(candidate, 'demo') == set()
    artifact.write_bytes(b'original-artifact')
    assert module._cached_python_versions(candidate, 'demo') == {'2.0'}
    third.unlink()
    assert module._cached_python_versions(candidate, 'demo') == set()

    wheelhouse = tmp_path / 'wheels' / 'shared'
    wheelhouse.mkdir(parents=True)
    wheel = wheelhouse / 'demo-3.0-py3-none-any.whl'
    wheel.write_bytes(b'wheel')
    assert module._cached_python_versions(candidate, 'demo') == {'3.0'}
    wheel.unlink()
    wheel.symlink_to(artifact)
    assert module._cached_python_versions(candidate, 'demo') == set()


def test_new_pip_plan_publication_updates_live_index_without_rereading_old_files(tmp_path):
    candidate = module.Pool(tmp_path)
    (tmp_path / 'metadata').mkdir()
    old_sha, _ = _cas(candidate, b'old-wheel')
    existing = _plan(tmp_path, 'existing', 'older', '1.0', old_sha)
    assert module._cached_python_versions(candidate, 'older') == {'1.0'}

    sha, _ = _cas(candidate, b'new-wheel')
    row = {'kind': 'wheel', 'name': 'fresh', 'version': '2.0',
           'filename': 'fresh-2.0-py3-none-any.whl',
           'sha256': sha, 'url': 'https://files.pythonhosted.org/fresh-2.0.whl',
           'requirements': [], 'provides_extra': []}
    target = fixture_target()
    module._write_pip_plan(candidate, target, ['fresh==2.0'], 'new', [row])
    assert existing in candidate._cached_python_version_index['files']['plans']
    published = tmp_path / 'metadata' / 'pip-plan-new.json'
    assert published in candidate._cached_python_version_index['files']['plans']
    with patch.object(module.json, 'loads', wraps=module.json.loads) as decoder:
        assert module._cached_python_versions(candidate, 'fresh') == {'2.0'}
        assert module._cached_python_versions(candidate, 'older') == {'1.0'}
        assert decoder.call_count == 0


def test_invalid_and_legacy_checkpoints_preserve_original_lookup_semantics(tmp_path):
    candidate = module.Pool(tmp_path)
    sha, _ = _cas(candidate, b'legacy-artifact')
    legacy = _plan(tmp_path, 'legacy', 'historic', '0.1', sha, legacy=True)
    invalid = tmp_path / 'metadata' / 'pip-plan-invalid.json'
    invalid.write_text('{not JSON}')
    assert module._cached_python_versions(candidate, 'historic') == {'0.1'}
    legacy.unlink()
    assert module._cached_python_versions(candidate, 'historic') == set()
    assert module._cached_python_versions(candidate, 'absent') == set()

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('common_archive_builder', ROOT / 'scripts/build_local_templates.py')
guest = load('common_archive_guest', ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py')


def test_provenance_uses_only_verified_archive_identities():
    a, b, c = (hashlib.sha256(value).hexdigest() for value in (b'conda', b'pip', b'bootstrap'))
    lock = {'artifacts': {a: {'url': 'https://example.com/a.conda'}}}
    pip = {'b.whl': b}
    npm = [{'url': 'https://example.com/npm', 'sha256': b},
           {'url': 'https://example.org/npm', 'sha256': b}]
    sizes = {a: 5, b: 3, c: 9}
    record = builder.common_archive_provenance(lock, pip, npm, sizes, c)
    assert record == {'schema': 1, 'kind': 'verified-input-archives',
                      'miniconda': {'sha256': c, 'size': 9},
                      'conda': {a: {'url': lock['artifacts'][a]['url'], 'size': 5}},
                      'pip': {'b.whl': {'sha256': b, 'size': 3}},
                      'npm': [{**row, 'size': 3} for row in npm]}
    del sizes[b]
    with pytest.raises(KeyError):
        builder.common_archive_provenance(lock, pip, npm, sizes, c)


def test_common_build_hashes_lock_once_and_preserves_checkpoints(tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'ROOT', tmp_path / 'runtime')
    guest.ROOT.mkdir()
    conda = tmp_path / 'miniconda' / 'bin' / 'conda'
    conda.parent.mkdir(parents=True)
    conda.touch()
    monkeypatch.setattr(guest, 'CONDA', conda)
    rows = {str(i): {'stored_name': 'swegym_' + str(i)} for i in range(3)}
    lock = {'schema': 1, 'kind': 'swe-gym-lite-conda-image-lock',
            'environments': {key: {'transactions': [{}]} for key in rows}}
    raw = json.dumps(lock).encode()
    (guest.ROOT / 'conda-lock.json').write_bytes(raw)
    manifest = guest.ROOT / 'environment-cache-provenance.json'
    proof = {'schema': 1, 'kind': 'verified-input-archives', 'conda': {}}
    manifest.write_text(json.dumps(proof))
    real_sha = hashlib.sha256
    calls = []
    monkeypatch.setattr(guest.hashlib, 'sha256', lambda value: calls.append(value) or real_sha(value))
    def forbidden(*args, **kwargs):
        pytest.fail('common construction must not hash or inventory individual cache files')
    monkeypatch.setattr(guest, 'stream_digest', forbidden)
    monkeypatch.setattr(guest, 'file_inventory', forbidden)
    monkeypatch.setattr(guest, 'install_offline_apt_guard', lambda: None)
    monkeypatch.setattr(guest, 'locked_environment_script', lambda *args: ['create'])
    monkeypatch.setattr(guest, 'validate_isolation', lambda: None)
    monkeypatch.setattr(guest, 'env_inventory', lambda prefix: {'name': prefix.name})
    executions = []
    def shell(commands, **kwargs):
        if commands == ['create']:
            key = kwargs['log'].name.split('.')[0]
            (conda.parent.parent / 'envs' / rows[key]['stored_name']).mkdir(parents=True)
            executions.append(key)
    monkeypatch.setattr(guest, 'shell', shell)
    guest.build_common({'environments': rows})
    assert calls == [raw]
    assert executions == list(rows)
    assert json.loads(manifest.read_text()) == proof
    for key in rows:
        assert json.loads((guest.ROOT / 'environments' / (key + '.recipe.json')).read_text()) == {
            'lock_sha256': real_sha(raw).hexdigest(), 'transactions': 1}
    calls.clear()
    executions.clear()
    guest.build_common({'environments': rows})
    assert calls == [raw]
    assert not executions
    manifest.unlink()
    with pytest.raises(RuntimeError, match='provenance is missing'):
        guest.build_common({'environments': rows})


def test_file_inventory_deduplicates_hardlinks_without_losing_paths(tmp_path, monkeypatch):
    a, b, c = (tmp_path / name for name in ('a', 'b', 'c'))
    a.write_bytes(b'content')
    os.link(a, b)
    c.write_bytes(b'content')
    (tmp_path / 'link').symlink_to('a')
    hashes = []
    original = guest.stream_digest
    monkeypatch.setattr(guest, 'stream_digest', lambda path: hashes.append(path) or original(path))
    record = guest.file_inventory(tmp_path)
    assert hashes == [a, c]
    assert record['a'] == record['b'] == record['c']
    assert record['link'] == {'link': 'a'}
    a.write_bytes(b'changed')
    hashes.clear()
    updated = guest.file_inventory(tmp_path)
    assert updated['a'] == updated['b'] != updated['c']
    assert hashes == [a, c]


def test_file_inventory_rejects_concurrent_mutation(tmp_path, monkeypatch):
    path = tmp_path / 'file'
    path.write_bytes(b'first')
    def changing_digest(file):
        sha = hashlib.sha256(file.read_bytes()).hexdigest()
        file.write_bytes(b'changed')
        return sha
    monkeypatch.setattr(guest, 'stream_digest', changing_digest)
    with pytest.raises(RuntimeError, match='file changed during inventory'):
        guest.file_inventory(tmp_path)


def test_fresh_and_resume_boot_import_provenance_before_build():
    source = (ROOT / 'scripts/build_local_templates.py').read_text()
    copy = 'cp /opt/swe-gym-build/environment-cache-provenance.json /opt/swe-gym-lite/'
    assert source.count(copy) == 2
    for section in source.split(copy)[1:]:
        assert section.index('template_step remove-build-payload') < section.index("module['build_common']")

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from workstation_broker import preparation as broker

ROOT = Path(__file__).resolve().parents[2]


def load_pool():
    spec = importlib.util.spec_from_file_location('apt_real_status_pool', ROOT / 'scripts/superbench_pool.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pool = load_pool()


def stanza(name, version, **fields):
    return (f'Package: {name}\nVersion: {version}\nArchitecture: all\n'
            'Maintainer: Fixture <fixture@example.invalid>\nDescription: Fixture\n'
            + ''.join(f'{key}: {value}\n' for key, value in fields.items()))


def deb(tmp, name, version, **fields):
    directory = tmp / name
    (directory / 'DEBIAN').mkdir(parents=True)
    (directory / 'DEBIAN/control').write_text(stanza(name, version, **fields))
    archive = tmp / (name + '.deb')
    subprocess.run(['dpkg-deb', '--build', str(directory), str(archive)], check=True, capture_output=True)
    return str(archive)


def test_real_apt_preserves_provides_breaks_and_rejects_historical_conflict(tmp_path):
    # Real dpkg metadata, real apt-get, no network and no guest installation.
    status = tmp_path / 'status'
    modern = stanza('fixture-ssl-modern', '4', Status='install ok installed',
                    Provides='fixture-ssl (= 4)', Breaks='fixture-ssl (<< 4)')
    status.write_text(modern + '\n')
    inventory = b'fixture-ssl-modern 4\n'
    pool._verify_golden_dpkg_inventory(tmp_path, inventory)
    with pytest.raises(RuntimeError, match='differs'):
        pool._verify_golden_dpkg_inventory(tmp_path, b'fixture-ssl-modern 3\n')
    old = deb(tmp_path, 'fixture-ssl', '3')
    java = deb(tmp_path, 'fixture-java', '1', Depends='fixture-ssl (>= 3)')
    lists = tmp_path / 'lists'
    lists.mkdir()
    opts = ['-o', 'Dir::State::status=' + str(status), '-o', 'Dir::State::Lists=' + str(lists),
            '-o', 'Dir::Etc::sourcelist=/dev/null', '-o', 'Dir::Etc::sourceparts=-',
            '-o', 'Dir::Etc::preferences=/dev/null', '-o', 'Dir::Etc::preferencesparts=-']
    assert pool._apt_simulate(opts, {java}) == {'fixture-java': '1'}
    with pytest.raises((subprocess.CalledProcessError, RuntimeError)):
        pool._apt_simulate(opts, {java, old})
    # The old four-field model falsely accepts the incompatible archive.
    status.write_text('Package: fixture-ssl-modern\nVersion: 4\nArchitecture: all\nStatus: install ok installed\n\n')
    assert pool._apt_simulate(opts, {java, old}) == {'fixture-java': '1', 'fixture-ssl': '3'}


def test_offline_options_override_signed_sources_and_lists_with_real_apt(tmp_path):
    status = tmp_path / 'status'
    status.write_text(stanza('fixture-provider', '4', Status='install ok installed',
                             Provides='fixture-lib (= 4)') + '\n')
    java = deb(tmp_path, 'fixture-java', '1', Depends='fixture-lib (>= 3)')
    online_lists = tmp_path / 'online-lists'
    online_lists.mkdir()
    offline_lists = tmp_path / 'offline-lists'
    offline_lists.mkdir()
    online_sources = tmp_path / 'signed.list'
    online_sources.write_text('invalid source entry\n')
    opts = ['-o', 'Dir::State::status=' + str(status),
            '-o', 'Dir::State::Lists=' + str(online_lists),
            '-o', 'Dir::Etc::sourcelist=' + str(online_sources),
            '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::Etc::preferences=/dev/null',
            '-o', 'Dir::Etc::preferencesparts=-']
    broken = [value for value in opts if not value.startswith(
        ('Dir::State::Lists=', 'Dir::Etc::sourcelist='))]
    broken += ['-o', 'Dir::State::Lists=' + str(offline_lists),
               '-o', 'Dir::Etc::sourcelist=/dev/null']
    with pytest.raises(subprocess.CalledProcessError) as exc:
        pool._apt_simulate(broken, {java})
    assert 'Option -o requires an argument' in exc.value.output
    assert pool._apt_simulate(pool._apt_offline_options(opts, offline_lists), {java}) == {'fixture-java': '1'}


def compatibility(old):
    key = 'scripts/superbench_pool.py'
    sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
    sources = {name: sha(name) for name in broker.FETCH_SOURCE_FILES}
    adapter = 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/'
    if old:
        sources.pop('scripts/native_requirements.py')
        sources.pop(adapter + 'upstream/dockerfiles.py')
    sources[key] = sha('old fetcher' if old else 'current fetcher')
    sources['infra/workstation/image/apt_downloads.py'] = sha('old helper' if old else 'restored helper')
    return {'fetch_kind': 'download-only-pool-v4', 'pool_schema': 4,
            'pins': {'contract_sha256': sha('contract')}, 'platform': 'linux-64',
            'coverage': {'tasks': 1, 'repos': 1, 'conda_recipes': 1},
            'conda_lock_sha256': sha('lock'),
            'fetcher_sha256': sources[key], 'fetch_sources': sources,
            'golden_dependency': {'apt_package_manifest_sha256': sha('golden')}}


def test_repair_uses_semantic_contract_not_fetcher_revision():
    old, new = compatibility(True), compatibility(False)
    assert broker._native_apt_repair_compatible(old, new)
    assert not broker._native_apt_repair_compatible(new, new)
    assert not broker._native_apt_repair_compatible(old, {**new, 'pool_schema': 5})
    assert not broker._native_apt_repair_compatible(old, {**new, 'pins': {'different': True}})
    assert not broker._native_apt_repair_compatible(old, {**new, 'golden_dependency': {}})
    assert not broker._native_apt_repair_compatible(old, {**new, 'fetch_sources': {**new['fetch_sources'], 'config/preparation.toml': 'e' * 64}})
    assert not broker._native_apt_repair_compatible(old, {**new, 'fetcher_sha256': 'f' * 64})
    later = {**new, 'fetcher_sha256': 'f' * 64, 'fetch_sources': {**new['fetch_sources'], 'scripts/superbench_pool.py': 'f' * 64}}
    assert broker._native_apt_repair_compatible(new, later)
    assert broker._native_apt_repair_compatible(old, later)


def put(folder, relative, data):
    path = folder / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {'path': relative, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def test_apt_repair_reuses_exact_nonapt_inodes_and_replaces_closure(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('root-owned sealed publication required')
    donor, stage = tmp_path / 'ready', tmp_path / 'incoming'
    donor.mkdir(); stage.mkdir()
    payload = b'unchanged dependency'
    sha = hashlib.sha256(payload).hexdigest()
    path = 'objects/sha256/' + sha[:2] + '/' + sha
    old_data = put(donor, path, payload)
    old_data_path = donor / path
    old_data_path.chmod(0o444)
    old_apt = put(donor, 'metadata/apt-closure.json', b'old closure')
    old_native = put(donor, 'metadata/native-pip-inspection.json', b'old report')
    old_deb = put(donor, 'apt/archives/old.deb', b'old archive')
    old_sha = old_deb['sha256']
    old_cas = put(donor, 'objects/sha256/' + old_sha[:2] + '/' + old_sha, b'old archive')
    old = {'schema': 2, 'complete': True, 'issues': [], 'operation_id': 'a'*64,
           'objects': {sha: old_data, old_sha: old_cas},
           'provenance': {'pip': {'x': [sha]}, 'apt': {'old': [old_sha]}},
           'url_index': {'https://example.invalid/pip': sha, 'https://example.invalid/apt': old_sha},
           'files': [old_data, old_apt, old_deb, old_cas, old_native],
           'task_plan': {'task': {}}, 'environment_plan': {}, 'git_plan': {},
           'conda_transactions': {}, 'conda_lock_sha256': 'b'*64}
    candidate = pool.Pool(stage)
    new_archive = stage / 'apt/archives/new.deb'
    new_archive.parent.mkdir(parents=True)
    new_archive.write_bytes(b'new archive')
    new_sha = candidate.put(new_archive, 'apt', 'new')
    put(stage, 'metadata/apt-closure.json', b'new closure')
    put(stage, 'metadata/native-pip-inspection.json', b'new report')
    progress = pool._PoolProgress(io.StringIO(), tty=False, progress_path=stage/'metadata/fetch-progress.json', operation_id='c'*64)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', progress)
    pool._apt_repair_inventory(candidate, old, 'c'*64)
    inventory = json.loads((stage/'inventory.json').read_bytes())
    broker._link_apt_repair_files(stage, inventory, (donor, {}, old))
    assert (stage/path).samefile(old_data_path)
    assert (stage/'metadata/native-pip-inspection.json').read_bytes() == b'new report'
    assert (donor/'metadata/native-pip-inspection.json').read_bytes() == b'old report'
    assert set(inventory['objects']) == {sha, new_sha}
    assert not (stage/'apt/archives/old.deb').exists()
    assert inventory['task_plan'] == old['task_plan']
    assert inventory['provenance']['pip'] == old['provenance']['pip']
    assert (donor/'metadata/apt-closure.json').read_bytes() == b'old closure'
    snapshot = json.loads((stage/'metadata/fetch-progress.json').read_bytes())
    assert snapshot['volume']['complete'] is True
    assert snapshot['volume']['identified_bytes'] == len(payload) + len(b'new archive')
    for record in inventory['files']:
        assert hashlib.sha256((stage/record['path']).read_bytes()).hexdigest() == record['sha256']


@pytest.mark.parametrize('native', [False, True])
def test_prior_publication_is_recoverable_before_and_after_retirement(tmp_path, monkeypatch, native):
    if os.geteuid() != 0:
        pytest.skip('root-owned sealed publication required')
    root = tmp_path / 'pool'
    ready = root / 'ready'
    ready.mkdir(parents=True)
    journals = tmp_path / 'preparations'
    donor_contract = compatibility(not native)
    old_id = hashlib.sha256(broker.canonical(donor_contract)).hexdigest()
    (journals / old_id).mkdir(parents=True)
    raw = json.dumps({'requested': ['fixture-java'], 'resolved': [], 'golden_dpkg_status_sha256': 'd'*64,
                      'golden_package_inventory_sha256': compatibility(True)['golden_dependency']['apt_package_manifest_sha256']}).encode()
    closure = put(ready, 'metadata/apt-closure.json', raw)
    if native:
        put(ready, 'metadata/native-pip-inspection.json', b'prior native report')
    old_inventory = {'schema': 2, 'conda_lock_sha256': compatibility(True)['conda_lock_sha256'],
                     'operation_id': old_id, 'complete': True, 'issues': [], 'files': [closure],
                     'kind': 'download-only-pool', 'tasks': 1, 'repos': 1, 'conda_recipes': 1,
                     'python_versions': ['3.11']}
    proof = {key: old_inventory[key] for key in ('kind','tasks','repos','conda_recipes','python_versions')}
    inventory_raw = json.dumps(old_inventory).encode()
    put(ready, 'inventory.json', inventory_raw)
    proof.update(manifest_sha256=hashlib.sha256(inventory_raw).hexdigest(), runtime_integrated='pending')
    for item in (*ready.rglob('*'), ready):
        item.chmod(0o555 if item.is_dir() else 0o444)
    prior = {'operation_id': old_id, 'compatibility': donor_contract,
             'phase': 'interrupted', 'result': None, 'publication_verified': proof}
    current = compatibility(False)
    current['fetch_sources']['scripts/superbench_pool.py'] = hashlib.sha256(b'next fetcher').hexdigest()
    current['fetcher_sha256'] = current['fetch_sources']['scripts/superbench_pool.py']
    state = {'compatibility': current}
    def read(operation_id):
        assert operation_id == old_id
        return prior
    manager = SimpleNamespace(root=journals, _read=read,
                              _containers=lambda state: [])
    monkeypatch.setattr(broker.JobScope, 'members', lambda state: [])
    unrelated = journals / hashlib.sha256(b'unrelated').hexdigest()
    unrelated.mkdir()
    assert broker._apt_repair_source(manager, root, state) == (ready, prior, old_inventory)
    unrelated.rmdir()
    retired = broker._retired_pool(root, old_id)
    ready.rename(retired)
    assert broker._apt_repair_source(manager, root, state) == (retired, prior, old_inventory)
    assert (retired/'metadata/apt-closure.json').read_bytes() == raw
    assert broker._apt_repair_source(manager, root, {'compatibility': donor_contract}) is None

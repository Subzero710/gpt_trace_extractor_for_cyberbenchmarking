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
    os_manifest = {'artifacts': {}, 'installed_before': {}, 'installed_after': {}}
    (guest.ROOT / 'os-manifest.json').write_text(json.dumps(os_manifest))
    os_payload = json.dumps(os_manifest, sort_keys=True, separators=(',', ':')).encode()
    tools_checks = []
    def load_tools(path):
        assert Path(path) == guest.ROOT / 'os_packages.py'
        return {'require_build_tools': lambda root: tools_checks.append(root)}
    monkeypatch.setattr(guest.runpy, 'run_path', load_tools)
    monkeypatch.setattr(guest, 'verify_native_python_headers', lambda prefix: {})
    elf_checks = []
    monkeypatch.setattr(guest, 'verify_native_elf', lambda prefix: elf_checks.append(prefix) or {})
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
    def sync(*args):
        assert args[:2] == ('sync', '-f') and Path(args[2]).is_dir()
    monkeypatch.setattr(guest, 'run', sync)
    guest.build_common({'environments': rows})
    assert calls == [raw, os_payload]
    assert executions == list(rows)
    assert len(elf_checks) == len(rows)
    assert tools_checks == [guest.ROOT]
    assert json.loads(manifest.read_text()) == proof
    for key in rows:
        assert json.loads((guest.ROOT / 'environments' / (key + '.recipe.json')).read_text()) == {
            'lock_sha256': real_sha(raw).hexdigest(), 'transactions': 1}
    calls.clear()
    executions.clear()
    guest.build_common({'environments': rows})
    assert calls == [raw, os_payload]
    assert not executions
    assert len(elf_checks) == len(rows)
    assert tools_checks == [guest.ROOT, guest.ROOT]
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
    assert source.count(copy + "\n''' + bootstrap_marker + npm_boot + common_tail") == 2
    tail = source.split("common_tail = r'''", 1)[1].split("'''", 1)[0]
    assert tail.index('template_step remove-build-payload') < tail.index("module['build_common']")


@pytest.fixture
def sealed_pool(tmp_path, monkeypatch):
    from gpt_trace_transport import local_templates
    if os.geteuid() != 0:
        # Exercise the real mode/path checks on unprivileged CI-owned fixtures.
        # Only root ownership is substituted for the fixture's current UID.
        def safe(path, *, immutable=False, directory=False):
            path = Path(path).absolute()
            assert not any(parent.is_symlink() for parent in (path, *path.parents))
            assert path.stat().st_uid == os.geteuid()
            assert not path.stat().st_mode & (0o222 if immutable else 0o022)
            assert path.is_dir() if directory else path.is_file()
            return path
        monkeypatch.setattr(local_templates, 'safe', safe)
    folder = tmp_path / 'ready'
    raw = b'verified archive bytes'
    sha = hashlib.sha256(raw).hexdigest()
    relative = 'objects/sha256/' + sha[:2] + '/' + sha
    obj = folder / relative
    obj.parent.mkdir(parents=True)
    obj.write_bytes(raw)
    apt = folder / 'apt/archives/package_1_all.deb'
    apt.parent.mkdir(parents=True)
    os.link(obj, apt)
    record = {'sha256': sha, 'size': len(raw), 'path': relative}
    inventory = {'objects': {sha: record}, 'files': [record, {**record, 'path': apt.relative_to(folder).as_posix()}]}
    for path in sorted(folder.rglob('*'), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    folder.chmod(0o555)
    yield folder, obj, apt, inventory, sha
    for path in [folder, *folder.rglob('*')]:
        if path.is_dir():
            path.chmod(0o755)


def test_published_pool_proof_reused_after_process_restart(sealed_pool, monkeypatch):
    folder, obj, _, inventory, sha = sealed_pool
    original_open = Path.open
    def no_archive_read(path, *args, **kwargs):
        if path == obj:
            pytest.fail('sealed archive must not be read or hashed during resume')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', no_archive_read)
    for _ in range(2):
        fresh = builder.PublishedPoolArchives(folder, inventory)
        assert fresh.archive(sha) == obj
        assert fresh.sizes[sha] == obj.stat().st_size
    invalid = {**inventory, 'files': []}
    with pytest.raises(RuntimeError, match='verified publication'):
        builder.PublishedPoolArchives(folder, invalid).archive(sha)
    obj.chmod(0o644)
    with pytest.raises((ValueError, AssertionError)):
        builder.PublishedPoolArchives(folder, inventory).archive(sha)
    obj.chmod(0o444)


def test_apt_reuses_published_inode_instead_of_copy_or_rehash(sealed_pool, tmp_path, monkeypatch):
    folder, obj, apt, inventory, sha = sealed_pool
    archive_index = builder.PublishedPoolArchives(folder, inventory)
    closure = {'requested': ['package'], 'resolved': [{'sha256': sha, 'package': 'package', 'version': '1', 'architecture': 'all'}]}
    packages = builder.published_apt_archives(archive_index, closure)
    name = apt.name
    destination = tmp_path / 'resolved'
    destination.mkdir()
    (destination / name).write_bytes(b'old independent copy')
    manifest = {'schema_version': 1, 'requested': closure['requested'], 'artifacts': {name: packages[name][1]}}
    monkeypatch.setattr(builder, 'digest', lambda *args: pytest.fail('APT archive was rehashed'))
    builder.bind_os_archives(destination, manifest, closure, packages)
    assert (destination / name).samefile(obj)
    inode = (destination / name).stat().st_ino
    builder.bind_os_archives(destination, manifest, closure, packages)
    assert (destination / name).stat().st_ino == inode
    bad = {**manifest, 'requested': []}
    with pytest.raises(RuntimeError, match='signed APT closure'):
        builder.bind_os_archives(destination, bad, closure, packages)


@pytest.mark.parametrize('mode,root_entries,runtime,legacy', [
    ('bootstrap', set(), set(), False),
    ('bootstrap', {'swe-gym-lite', 'miniconda3'}, set(), False),
    ('legacy-prepared', {'swe-gym-lite', 'miniconda3'}, set(), True),
    ('resume-inputs', {'swe-gym-lite', 'miniconda3', 'swe-gym-build'}, set(), True),
    ('bootstrap-prepared', {'swe-gym-lite', 'miniconda3', 'swe-gym-build'}, {'common-bootstrap-complete.json'}, False),
    ('prepared', {'swe-gym-lite', 'miniconda3', 'swe-gym-build'}, {'common-inputs-complete.json'}, False),
])
def test_common_resume_selects_only_uncommitted_stage(tmp_path, mode, root_entries, runtime, legacy):
    disk = tmp_path / 'common.qcow2'
    disk.touch()
    expected = {'kind': 'common-inputs', 'pool_manifest_sha256': 'pool'}
    def read(_image, path):
        return {**expected, 'kind': 'common-bootstrap'} if 'bootstrap' in path else expected
    actual = builder.common_input_mode(disk, expected, list_directory=lambda _, path: root_entries if path == '/opt' else runtime,
                                       read_json=read, legacy_ready=lambda: legacy)
    assert actual == mode


def test_changed_input_checkpoint_is_not_accepted(tmp_path):
    disk = tmp_path / 'common.qcow2'
    disk.touch()
    with pytest.raises(RuntimeError, match='checkpoint differs'):
        builder.common_input_mode(disk, {'kind': 'common-inputs'},
            list_directory=lambda _, path: {'swe-gym-lite'} if path == '/opt' else {'common-inputs-complete.json'},
            read_json=lambda *_: {}, legacy_ready=lambda: pytest.fail('invalid checkpoint must not be bypassed'))


def test_injection_resumes_only_uncommitted_batches(tmp_path, monkeypatch):
    import subprocess
    import tarfile
    payload = tmp_path / 'swe-gym-build'
    payload.mkdir()
    for name in ('a', 'b', 'c'):
        (payload / name).write_bytes(name.encode())
    disk = tmp_path / 'common.qcow2'
    disk.touch()
    work = tmp_path / 'scratch'
    work.mkdir()
    monkeypatch.setitem(builder._CONTROLS, 'template_payload_batch_members', 1)
    committed, attempts = [], []
    def run(*argv):
        if argv[0] == 'tar':
            subprocess.run(argv, check=True)
            return
        assert argv[0] == 'virt-tar-in'
        with tarfile.open(argv[3]) as tar:
            names = tar.getnames()
        attempts.append(names)
        if len(attempts) == 3:
            raise RuntimeError('interrupted injection')
    def record(done, total):
        committed.append((done, total))
    with pytest.raises(RuntimeError, match='interrupted'):
        builder._inject_payload(disk, payload, work, run, checkpoint=record)
    assert committed == [(1, 4), (2, 4)]
    builder._inject_payload(disk, payload, work, run, completed_batches=committed[-1][0], checkpoint=record)
    assert attempts == [['swe-gym-build'], ['swe-gym-build/a'], ['swe-gym-build/b'], ['swe-gym-build/b'], ['swe-gym-build/c']]
    assert committed[-1] == (4, 4)


def test_guest_checkpoints_are_atomically_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(guest, 'ROOT', tmp_path)
    for kind, name in [('common-bootstrap', 'common-bootstrap-complete.json'), ('common-inputs', 'common-inputs-complete.json')]:
        proof = {'kind': kind, 'pool_manifest_sha256': 'pool'}
        guest.commit_common_inputs(proof)
        assert json.loads((tmp_path / name).read_text()) == proof
        assert not (tmp_path / (name + '.tmp')).exists()

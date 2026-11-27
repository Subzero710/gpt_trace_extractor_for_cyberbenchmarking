from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load(ROOT / 'scripts/native_requirements.py')
packages = load(ADAPTER / 'os_packages.py')
pool = load(ROOT / 'scripts/superbench_pool.py')


def write(path, data=b'#define FIXTURE 1\n'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def link(path, target):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)


class GuestTree:
    def __init__(self, root):
        self.root = root
        self.downloads = []

    def realpath(self, name):
        # Resolve absolute links in the simulated guest, not the test host.
        pending = deque(name.split('/'))
        prefix = []
        followed = 0
        while pending:
            part = pending.popleft()
            if part in ('', '.'):
                continue
            if part == '..':
                if prefix:
                    prefix.pop()
                continue
            p = self.root.joinpath(*prefix, part)
            if p.is_symlink():
                followed += 1
                if followed > 40:
                    raise FileNotFoundError(name)
                target = os.readlink(p)
                if target.startswith('/'):
                    prefix.clear()
                pending.extendleft(reversed(target.split('/')))
            else:
                prefix.append(part)
                if not p.exists():
                    raise FileNotFoundError(name)
        return '/' + '/'.join(prefix)

    def is_file(self, name, *, followsymlinks):
        assert followsymlinks
        try:
            return (self.root / self.realpath(name).lstrip('/')).is_file()
        except FileNotFoundError:
            return False

    def is_dir(self, name, *, followsymlinks):
        assert followsymlinks
        try:
            return (self.root / self.realpath(name).lstrip('/')).is_dir()
        except FileNotFoundError:
            return False

    def tar_out(self, name, destination):
        with tarfile.open(destination, 'w', dereference=False) as archive:
            archive.add(self.root / name.lstrip('/'), arcname='.')

    def download(self, name, destination):
        self.downloads.append(name)
        assert name == self.realpath(name)
        shutil.copyfile(self.root / name.lstrip('/'), destination)


def test_golden_export_preserves_real_external_headers_and_not_host_paths(tmp_path, capsys):
    root = tmp_path / 'guest'
    include = root / 'usr/include'
    profile = native.compiler_profile(shutil.which('gcc'), platform.machine(), timeout=10)
    multiarch = profile['multiarch']
    target = write(root / 'usr/lib/fixture/uapi/errno.h')
    link(include / multiarch / 'asm/errno.h', '../../../lib/fixture/uapi/errno.h')
    link(include / 'absolute.h', '/usr/lib/fixture/uapi/errno.h')
    link(include / 'alias', '/usr/lib/fixture/uapi')
    link(include / 'dangling.h', '/usr/lib/fixture/absent.h')
    link(include / 'host-only.h', '/etc/passwd')
    link(include / 'chain.h', 'absolute.h')
    local = write(include / 'ordinary.h')
    os.link(local, include / 'hard.h')
    guest = GuestTree(root)
    snapshot = tmp_path / 'golden.tar'
    native.export_golden_headers(guest, snapshot, owners={})
    with tarfile.open(snapshot) as archive:
        present = native.visible_header_files(native.archive_file_index(archive), '')
    expected = {multiarch+'/asm/errno.h', 'absolute.h', 'alias/errno.h', 'chain.h', 'ordinary.h', 'hard.h'}
    assert set(present) == expected
    assert guest.downloads == ['/usr/lib/fixture/uapi/errno.h']
    headers = tmp_path / 'system'
    native.extract_golden(snapshot, headers)
    for name in expected:
        assert (headers/name).read_bytes() == target.read_bytes()
        assert not (headers/name).is_symlink()
    assert not (headers/'host-only.h').exists()
    assert 'unavailable Golden header link' in capsys.readouterr().err
    python = tmp_path / 'python' / 'python-fixture'
    write(python/'Python.h', b'#include <asm/errno.h>\n#include <absolute.h>\n#include <crypt.h>\n')
    assert native.missing_python_headers(python.parent, headers, profile, timeout=10)['missing'] == ['crypt.h']


def test_conda_headers_resolve_forward_hardlinks_and_external_targets(tmp_path):
    path = tmp_path / 'fixture.tar.bz2'
    with tarfile.open(path, 'w:bz2') as archive:
        for name, kind, target in [('include/python-fixture/Python.h', tarfile.LNKTYPE, 'include/python-fixture/real.h'),
                                   ('include/python-fixture/outside.h', tarfile.SYMTYPE, '../../share/headers/target.h'),
                                   ('include/python-fixture/directory', tarfile.SYMTYPE, '../../share/headers'),
                                   ('include/python-fixture/missing.h', tarfile.SYMTYPE, '/etc/passwd')]:
            row = tarfile.TarInfo(name); row.type = kind; row.linkname = target
            archive.addfile(row)
        for name, data in [('include/python-fixture/real.h', b'local'), ('share/headers/target.h', b'external')]:
            row = tarfile.TarInfo(name); row.size = len(data)
            archive.addfile(row, io.BytesIO(data))
    result = tmp_path / 'headers'
    native.extract_conda(path, result, filename=path.name)
    prefix = result/'python-fixture'
    assert (prefix/'Python.h').read_bytes() == b'local'
    assert (prefix/'Python.h').samefile(prefix/'real.h')
    assert (prefix/'outside.h').read_bytes() == b'external'
    assert (prefix/'directory/target.h').samefile(prefix/'outside.h')
    assert not (prefix/'missing.h').exists()


def deb(root, output, name, version='1'):
    write(root/'DEBIAN/control', ('Package: '+name+'\nVersion: '+version+'\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: Native header fixture\n').encode())
    subprocess.run(['dpkg-deb', '--build', str(root), str(output)], check=True, capture_output=True)
    return output


def test_real_debian_archives_verify_indexed_links_then_actual_guest_files(tmp_path):
    provider = tmp_path / 'provider'
    target = tmp_path / 'target'
    include = provider / 'usr/include/fixture'
    write(provider/'usr/lib/fixture/inside.h')
    link(include/'internal.h', '../../lib/fixture/inside.h')
    link(include/'external.h', '../../lib/fixture/outside.h')
    link(include/'missing.h', '../../lib/fixture/absent.h')
    link(include/'cycle.h', 'cycle.h')
    write(target/'usr/lib/fixture/outside.h')
    first = deb(provider, tmp_path/'provider.deb', 'fixture-provider')
    second = deb(target, tmp_path/'target.deb', 'fixture-target')
    prefix = 'usr/include/fixture/'
    expected = [prefix+leaf for leaf in ['internal.h', 'external.h', 'missing.h', 'cycle.h', 'unindexed.h']]
    evidence = native.deb_header_entries(first, expected)
    assert set(evidence) == set(expected[:-1])
    assert evidence[prefix+'internal.h']['archive_target'] == 'usr/lib/fixture/inside.h'
    assert evidence[prefix+'external.h']['archive_target'] is None
    assert evidence[prefix+'cycle.h']['archive_target'] is None
    guest = tmp_path/'installed'; guest.mkdir()
    for path in (first, second):
        subprocess.run(['dpkg-deb', '-x', str(path), str(guest)], check=True)
    def record(leaf):
        return {'fixture/'+leaf: {'package': 'fixture-provider', 'paths': [prefix+leaf],
                                  'archive_sha256': hashlib.sha256(first.read_bytes()).hexdigest()}}
    for leaf in ('internal.h', 'external.h'):
        packages.require_native_headers(record(leaf), root=guest)
    for leaf in ('missing.h', 'cycle.h', 'unindexed.h'):
        with pytest.raises(RuntimeError, match='installed native header unavailable'):
            packages.require_native_headers(record(leaf), root=guest)
    # If the other package is missing, the exact same authenticated provider is not sufficient.
    (guest/'usr/lib/fixture/outside.h').unlink()
    with pytest.raises(RuntimeError, match='installed native header unavailable'):
        packages.require_native_headers(record('external.h'), root=guest)


def test_archive_member_ambiguity_and_traversal_fail_closed():
    for names in [('usr/include/a.h', 'usr/include/a.h'), ('../escape.h',)]:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for name in names:
                row = tarfile.TarInfo(name); row.size = 1
                archive.addfile(row, io.BytesIO(b'x'))
        raw.seek(0)
        with tarfile.open(fileobj=raw) as archive, pytest.raises(RuntimeError):
            native.archive_file_index(archive)


def test_signed_apt_plan_recovers_an_unregistered_archive(tmp_path, monkeypatch):
    old = tmp_path/'old'; stage = tmp_path/'new'; apt = stage/'apt'
    name = 'fixture_1_all.deb'; data = b'previously acquired exact bytes'
    retained = write(old/'apt/archives'/name, data)
    (apt/'archives/partial').mkdir(parents=True)
    candidate = pool.Pool(stage)
    candidate.apt_reuse_sources = (old,)
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(pool.subprocess, 'check_output', lambda *args, **kw:
                        f"'https://example.invalid/fixture.deb' {name} {len(data)} SHA256:{digest}\n")
    measurements = []
    monkeypatch.setattr(pool, '_POOL_PROGRESS', object())
    monkeypatch.setattr(pool, '_begin_download_phase', lambda _pool, _label, volume: measurements.append(volume))
    assert pool._apt_archive_volume(candidate, [], {'fixture'}, apt) == {name: digest}
    assert (apt/'archives'/name).read_bytes() == retained.read_bytes()
    assert measurements[0][digest]['retained_bytes'] == len(data)


def test_target_cpython_header_probe_uses_activated_compiler(tmp_path, monkeypatch):
    import sys
    runtime = load(ADAPTER/'guest_runtime.py')
    profile = {'headers': ['/usr/include'], 'libraries': [], 'loader': [], 'missing': []}
    seen = []
    def target_run(*args, **kwargs):
        seen.append(args)
        return ('GPTTRACE_NATIVE_PROFILE ' + json.dumps(profile) + '\n').encode()
    monkeypatch.setattr(runtime, 'run', target_run)
    monkeypatch.setattr(runtime, 'ROOT', ADAPTER)
    prefix = tmp_path/'prefix'
    assert runtime.verify_native_python_headers(prefix) == {}
    assert seen[0][:5] == (str(runtime.CONDA), 'run', '--prefix', str(prefix), '--no-capture-output')
    assert seen[0][5] == str(prefix/'bin/python')
    profile['missing'] = ['nonexistent-fixture-header.h']
    requests = runtime.verify_native_python_headers(prefix)
    assert len(requests) == 1
    key = next(iter(requests))
    assert key.startswith('header:nonexistent-fixture-header.h@')
    assert requests[key] == ['usr/include/nonexistent-fixture-header.h']


def test_signed_index_reused_from_failed_migration_without_a_copy(tmp_path):
    old = tmp_path/'old'
    current = pool.Pool(tmp_path/'new')
    data = b'exact authenticated Contents index bytes'
    sha = hashlib.sha256(data).hexdigest()
    retained = write(old/'objects/sha256'/sha[:2]/sha, data)
    current.apt_reuse_sources = (old,)
    current.apt_repair_source = tmp_path/'sealed-pool'
    destination = current.objects/sha[:2]/sha
    assert pool._reuse_signed_apt_artifact(current, sha, len(data), destination)
    assert destination.samefile(retained)
    assert current.verify_object(sha) == len(data)
    other = b'wrong bytes'
    other_sha = hashlib.sha256(other).hexdigest()
    write(old/'objects/sha256'/other_sha[:2]/other_sha, b'incorrect data')
    with pytest.raises(RuntimeError, match='retained signed APT CAS object differs'):
        pool._reuse_signed_apt_artifact(current, other_sha, len(other), current.objects/other_sha[:2]/other_sha)


def test_conda_absolute_link_is_not_rebased_to_the_prefix(tmp_path):
    archive = tmp_path/'absolute.tar.bz2'
    with tarfile.open(archive, 'w:bz2') as tar:
        member = tarfile.TarInfo('include/python-fixture/absolute.h')
        member.type = tarfile.SYMTYPE; member.linkname = '/share/fixture.h'
        tar.addfile(member)
        data = b'#define WRONG_ROOT 1\n'
        member = tarfile.TarInfo('share/fixture.h'); member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
        member = tarfile.TarInfo('include/python-fixture/relative.h')
        member.type = tarfile.SYMTYPE; member.linkname = '../../share/fixture.h'
        tar.addfile(member)
    output = tmp_path/'headers'
    native.extract_conda(archive, output, filename=archive.name)
    assert not (output/'python-fixture/absolute.h').exists()
    assert (output/'python-fixture/relative.h').read_bytes() == data


def test_merged_debian_namespace_resolves_cross_package_links(tmp_path):
    first = tmp_path/'first'; second = tmp_path/'second'
    link(first/'usr/include/fixture/first.h', '/usr/lib/fixture/first.h')
    write(second/'usr/lib/fixture/first.h', b'#include <second.h>\n')
    write(first/'usr/share/doc/shared', b'a')
    write(second/'usr/share/doc/shared', b'b')
    a=deb(first,tmp_path/'first.deb','fixture-first')
    b=deb(second,tmp_path/'second.deb','fixture-second')
    result = native.merge_header_namespace({'old.h': {'source':'usr/include/old.h','source_owners':[],'alias_owners':[]}}, {'a':native.deb_index(a),'b':native.deb_index(b)})
    assert result == {'fixture/first.h': ('b','usr/lib/fixture/first.h'), 'old.h': (None,'usr/include/old.h')}
    files=tmp_path/'files'
    native.deb_extract_files(b, files, ['usr/lib/fixture/first.h'])
    assert (files/'usr/lib/fixture/first.h').read_bytes() == b'#include <second.h>\n'
    with pytest.raises(RuntimeError, match='ambiguous ownership'):
        native.merge_header_namespace({}, {'a':native.deb_index(a),'b':native.deb_index(b),
                                          'c':{'usr/include/fixture/first.h':('file','')}})


@pytest.mark.parametrize('case', ['transitive','stuck','corrupt'])
def test_apt_native_fixed_point_with_real_compiler_and_archives(tmp_path, monkeypatch, case):
    # Only repository transfer/metadata is simulated. The native header namespace,
    # GCC preprocessor, archive content and SHA verification use real files/tools.
    root=tmp_path/'snapshot'; root.mkdir()
    stage=tmp_path/'stage'; candidate=pool.Pool(stage)
    golden=tmp_path/'golden.tar'
    with tarfile.open(golden,'w') as tar:
        data=b'/* existing system header */\n'
        item=tarfile.TarInfo('base.h');item.size=len(data)
        item.pax_headers['gpttrace.header'] = json.dumps({'source':'usr/include/base.h','source_owners':[],'alias_owners':[]})
        tar.addfile(item,io.BytesIO(data))
    shutil.copyfile(golden, root/'golden-include.tar')
    raw=b'fixture-base 1\n'
    (root/'golden-packages.txt').write_bytes(raw)
    (root/'golden-dpkg-status').write_text('Package: fixture-base\nVersion: 1\nArchitecture: all\nStatus: install ok installed\n\n')
    python=tmp_path/'python.tar.bz2'
    with tarfile.open(python,'w:bz2') as tar:
        data=b'#include <first.h>\n';item=tarfile.TarInfo('include/python-fixture/Python.h');item.size=len(data);tar.addfile(item,io.BytesIO(data))
    sha=hashlib.sha256(python.read_bytes()).hexdigest()
    obj=candidate.objects/sha[:2]/sha;obj.parent.mkdir();shutil.copyfile(python,obj)
    lock={'artifacts':{sha:{'name':'python','version':'3.8.0','build':'fixture','url':'https://example.invalid/python.tar.bz2'}},
          'environments':{'fixture':{'transactions':[{'packages':[sha]}]}}}
    archives={}
    for leaf, data in [('first',b'#include <second.h>\n'),('second',b'#define SECOND 1\n')]:
        path=tmp_path/leaf
        if case=='stuck' and leaf=='first':
            link(path/'usr/include/first.h', '/usr/lib/fixture/nonexistent.h')
        else:
            write(path/'usr/include'/(leaf+'.h'),data)
        archive=deb(path,tmp_path/(leaf+'.deb'),'fixture-'+leaf)
        archives['fixture-'+leaf]=archive
    # A declared root is already installed; the discovered native roots supply the files.
    module=pool._native_requirements_module()
    monkeypatch.setattr(pool,'_native_requirements_module',lambda:module)
    monkeypatch.setattr(pool,'__file__',str(root/'scripts/superbench_pool.py'))
    monkeypatch.setattr(pool,'_operation_timeout',lambda:30)
    monkeypatch.setattr(pool,'_network_retries',lambda:(1,()))
    monkeypatch.setattr(pool,'_golden_target',lambda:SimpleNamespace(architecture=platform.machine()))
    monkeypatch.setattr(pool,'_golden_dependency',lambda:{'apt_package_manifest_sha256':hashlib.sha256(raw).hexdigest()})
    monkeypatch.setattr(pool,'_target_debian_architecture',lambda:'amd64')
    monkeypatch.setattr(pool,'_verify_golden_dpkg_inventory',lambda *args:None)
    key=b'fixture key';keysha=hashlib.sha256(key).hexdigest();write(candidate.objects/keysha[:2]/keysha,key)
    monkeypatch.setattr(candidate,'download',lambda *args,**kw:keysha)
    monkeypatch.setattr(pool,'invoke',lambda *args,**kw:'fpr:::::::::'+pool.KALI_SIGNING_FPR+':\n')
    original_run=pool.subprocess.run
    monkeypatch.setattr(pool.subprocess,'run',lambda args,**kw: subprocess.CompletedProcess(args,0) if args[0]=='gpg' else original_run(args,**kw))
    monkeypatch.setattr(pool,'_apt_missing_roots',lambda *args:set())
    solved=[]
    def simulate(opts, roots):
        if any(str(value).startswith('/') for value in roots):
            return {'fixture-'+Path(value).stem:'1' for value in roots}
        selected=set(roots)&archives.keys();solved.append(selected)
        return {name:'1' for name in selected}
    monkeypatch.setattr(pool,'_apt_simulate',simulate)
    def transfer(args, **kw):
        if 'install' in args:
            for name in set(args)&archives.keys():
                destination=stage/'apt/archives'/archives[name].name
                if not destination.exists():shutil.copyfile(archives[name],destination)
    monkeypatch.setattr(pool,'_run_apt_downloads',transfer)
    monkeypatch.setattr(pool,'_apt_archive_volume',lambda _pool,opts,roots,apt:
        {archives[name].name:hashlib.sha256(archives[name].read_bytes() + (b'corruption' if case=='corrupt' else b'')).hexdigest() for name in set(roots)&archives.keys()})
    def providers(_pool,apt,ring,uri,suite,components,arch,evidence,roots):
        return {header:{'package':'fixture-'+header.removesuffix('.h'),'paths':['usr/include/'+header]} for header in evidence['missing']}
    monkeypatch.setattr(pool,'_signed_header_providers',providers)
    with pool._native_header_context(candidate, lock) as (evidence,probe):
        assert evidence['missing']==['first.h']
        if case != 'transitive':
            expected = 'made no progress' if case=='stuck' else 'SHA-256 differs from signed index'
            with pytest.raises(RuntimeError, match=expected):
                pool.apt_closure(candidate, {'fixture-base'},native_headers=evidence,native_probe=probe,base_roots={'fixture-base'})
            assert not (stage/'metadata/apt-closure.json').exists()
            assert len(solved)==1
            if case=='corrupt':
                assert not candidate.links
            return
        pool.apt_closure(candidate, {'fixture-base'},native_headers=evidence,native_probe=probe,base_roots={'fixture-base'})
    proof=json.loads((stage/'metadata/apt-closure.json').read_bytes())
    assert solved==[{'fixture-first'},{'fixture-first','fixture-second'}]
    assert proof['native_discovery']['missing']==['first.h','second.h']
    assert proof['native_discovery']['interpreters'][sha]['final_missing']==[]
    assert [row['unresolved'] for row in proof['native_discovery']['rounds']]==[['second.h'],[]]
    assert set(proof['native_discovery']['providers'])=={'first.h','second.h'}


def test_golden_package_upgrade_removes_old_headers_and_preserves_external_alias(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('real dpkg installation into disposable root requires root')
    old = tmp_path/'v1'
    write(old/'usr/include/obsolete.h', b'old')
    write(old/'usr/lib/fixture/active.h', b'old version')
    first = deb(old, tmp_path/'first.deb', 'fixture-replaced')
    alias = tmp_path/'alias'
    link(alias/'usr/include/active.h', '/usr/lib/fixture/active.h')
    link(alias/'usr/include/second.h', '/usr/lib/fixture/active.h')
    alias_deb = deb(alias, tmp_path/'alias.deb', 'fixture-alias')
    guest_root = tmp_path/'guest'; guest_root.mkdir()
    (guest_root/'var/lib/dpkg').mkdir(parents=True)
    (guest_root/'var/lib/dpkg/status').touch()
    command = ['dpkg', '--root='+str(guest_root), '--install']
    subprocess.run([*command, str(first), str(alias_deb)], check=True, capture_output=True)
    guest = GuestTree(guest_root)
    metadata_tar = tmp_path/'metadata.tar'
    guest.tar_out('/var/lib/dpkg/info', str(metadata_tar))
    with tarfile.open(metadata_tar, 'r|*') as archive:
        owners = native.dpkg_file_owners(archive, native.installed_packages((guest_root/'var/lib/dpkg/status').read_bytes()))
    snapshot = tmp_path/'golden.tar'
    native.export_golden_headers(guest, snapshot, owners=owners)
    with tarfile.open(snapshot, 'r|*') as archive:
        metadata = native.golden_header_metadata(archive)
    assert metadata['obsolete.h']['source_owners'] == ['fixture-replaced']
    assert metadata['active.h']['alias_owners'] == [['fixture-alias']]
    assert metadata['active.h']['source_owners'] == ['fixture-replaced']
    assert metadata['active.h']['source'] == 'usr/lib/fixture/active.h'
    new = tmp_path/'v2'
    write(new/'usr/lib/fixture/active.h', b'new version')
    second = deb(new, tmp_path/'second.deb', 'fixture-replaced', '2')
    view = native.merge_header_namespace(metadata, {'new': native.deb_index(second)}, replaced_packages={'fixture-replaced'})
    assert view == {'active.h': ('new', 'usr/lib/fixture/active.h'), 'second.h': ('new', 'usr/lib/fixture/active.h')}
    subprocess.run([*command, str(second)], check=True, capture_output=True)
    assert not (guest_root/'usr/include/obsolete.h').exists()
    assert (guest_root/guest.realpath('/usr/include/active.h').lstrip('/')).read_bytes() == b'new version'


def test_golden_hardlinks_remain_independent_after_package_replacement(tmp_path):
    root = tmp_path/'golden'
    first = write(root/'usr/include/first.h', b'old')
    os.link(first, root/'usr/include/second.h')
    snapshot = tmp_path/'golden.tar'
    native.export_golden_headers(GuestTree(root), snapshot, owners={'/usr/include/first.h': {'fixture-first'}})
    with tarfile.open(snapshot, 'r|*') as archive:
        metadata = native.golden_header_metadata(archive)
    view = native.merge_header_namespace(metadata, {'new': {'usr': ('directory',''), 'usr/include': ('directory',''),
                                    'usr/include/first.h': ('file','')}}, replaced_packages={'fixture-first'})
    assert view == {'first.h': ('new','usr/include/first.h'), 'second.h': (None, 'usr/include/second.h')}


def test_debian_hardlink_cannot_bind_to_a_different_payload():
    dirs = {'usr': ('directory',''), 'usr/include': ('directory','')}
    # A hardlink whose payload target does not exist is not made valid by a
    # different package coincidentally owning the same target path.
    entries = {'a': {**dirs, 'usr/include/alias.h': ('hardlink','usr/include/target.h')},
               'b': {**dirs, 'usr/include/target.h': ('file','')}}
    assert native.merge_header_namespace({}, entries) == {'target.h': ('b','usr/include/target.h')}


def test_retained_apt_round_recovers_exact_archive(tmp_path):
    candidate = pool.Pool(tmp_path/'stage')
    data = b'archive retained by a prior APT round'
    sha = hashlib.sha256(data).hexdigest()
    name = 'fixture_1_all.deb'
    retained = write(candidate.stage/'apt/retained'/sha/name, data)
    destination = candidate.stage/'apt/archives'/name
    assert pool._reuse_signed_apt_artifact(candidate, sha, len(data), destination, archive_name=name)
    assert destination.read_bytes() == data
    assert retained.read_bytes() == data


def test_archive_hardlink_to_symlink_retains_relative_target_semantics():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as output:
        for name, kind, target in [('usr/lib/fixture/original.h', tarfile.SYMTYPE, 'target.h'),
                                   ('usr/include/alias.h', tarfile.LNKTYPE, 'usr/lib/fixture/original.h'),
                                   ('usr/include/target.h', tarfile.REGTYPE, ''),
                                   ('usr/lib/fixture/target.h', tarfile.REGTYPE, '')]:
            row = tarfile.TarInfo(name); row.type = kind; row.linkname = target
            output.addfile(row, io.BytesIO(b''))
    raw.seek(0)
    with tarfile.open(fileobj=raw) as archive:
        entries = native.archive_file_index(archive)
    assert native.resolve_archive_path(entries, 'usr/include/alias.h') == ('usr/include/target.h', 'file')
    assert native.merge_header_namespace({}, {'deb': entries})['alias.h'] == ('deb','usr/include/target.h')


def test_distinct_target_lookup_paths_have_distinct_native_identities(monkeypatch):
    runtime = load(ADAPTER/'guest_runtime.py')
    monkeypatch.setattr(runtime, 'ROOT', ADAPTER)
    first = runtime._native_requests(None, {('header', 'fixture.h')},
        profile={'headers': ['/usr/include']})
    second = runtime._native_requests(None, {('header', 'fixture.h')},
        profile={'headers': ['/usr/include/fixture']})
    assert set(first).isdisjoint(second)
    assert list(first.values()) == [['usr/include/fixture.h']]
    assert list(second.values()) == [['usr/include/fixture/fixture.h']]
    validator = load(ADAPTER/'os_packages.py').native_requirement_paths
    assert validator({**first, **second}) == {**first, **second}
    with pytest.raises(RuntimeError, match='identity differs'):
        validator({next(iter(first)): ['usr/include/other/fixture.h']})


def test_loader_and_linker_paths_are_not_interchangeable(monkeypatch):
    runtime = load(ADAPTER/'guest_runtime.py')
    monkeypatch.setattr(runtime, 'ROOT', ADAPTER)
    profile = {'libraries': ['/usr/lib/compiler-fixture'], 'loader': ['/lib/loader-fixture']}
    linked = runtime._native_requests(None, {('library', 'fixture')}, profile=profile)
    loaded = runtime._native_requests(None, {('soname', 'libfixture.so.1')}, profile=profile)
    assert list(linked.values()) == [['usr/lib/compiler-fixture/libfixture.a', 'usr/lib/compiler-fixture/libfixture.so']]
    assert list(loaded.values()) == [['lib/loader-fixture/libfixture.so.1', 'usr/lib/loader-fixture/libfixture.so.1']]


def test_provider_selected_paths_do_not_change_observation_identity(tmp_path):
    paths = ['usr/include/fixture.h', 'usr/include/target/fixture.h']
    identity = 'header:fixture.h@' + hashlib.sha256(json.dumps(paths, separators=(',', ':')).encode()).hexdigest()
    target = write(tmp_path/'usr/lib/fixture/actual.h')
    link(tmp_path/'usr/include/target/fixture.h', '../../lib/fixture/actual.h')
    row = {'package': 'fixture-provider', 'observed_paths': paths,
           'paths': ['usr/include/target/fixture.h']}
    packages.require_native_headers({identity: row}, root=tmp_path)
    with pytest.raises(RuntimeError, match='exceed'):
        packages.require_native_headers({identity: {**row, 'paths': ['usr/include/other/fixture.h']}}, root=tmp_path)
    with pytest.raises(RuntimeError, match='identity differs'):
        packages.require_native_headers({identity: {**row, 'observed_paths': row['paths']}}, root=tmp_path)
    target.unlink()
    with pytest.raises(RuntimeError, match='unavailable'):
        packages.require_native_headers({identity: row}, root=tmp_path)


def test_build_tool_requirement_report_is_bound_to_the_guest_round(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', '/usr/local/bin:/usr/bin:/bin')
    monkeypatch.setenv('GPT_TRACE_NATIVE_ROUND', 'a'*64)
    monkeypatch.setattr(packages.shutil, 'which', lambda name: None)
    with pytest.raises(RuntimeError, match='target native dependency resolution required'):
        packages.require_build_tools(tmp_path)
    report = json.loads((tmp_path/'native-requirements.json').read_bytes())
    assert report['round'] == 'a'*64
    assert packages.native_requirement_paths(report['requirements']) == report['requirements']
    assert list(report['requirements'].values()) == [['bin/ccache','usr/bin/ccache']]


def test_effective_pool_identity_excludes_progress_but_not_payload():
    builder = load(ROOT/'scripts/build_local_templates.py')
    sha = hashlib.sha256(b'fixture').hexdigest()
    row = {'path': 'objects/sha256/'+sha[:2]+'/'+sha, 'sha256': sha, 'size': 7}
    inventory = {'provenance': {'conda': {'fixture': [sha]}}, 'objects': {sha: row},
                 'url_index': {}, 'task_plan': {}, 'environment_plan': {}, 'git_plan': {},
                 'conda_transactions': {}, 'conda_lock_sha256': sha,
                 'files': [row, {'path': 'metadata/fetch-progress.json', 'sha256': sha, 'size': 7}]}
    closure = {'requested': ['fixture'], 'resolved': [{'package': 'fixture', 'architecture': 'all', 'version': '1', 'sha256': sha}],
               'golden_dpkg_status_sha256': sha, 'golden_package_inventory_sha256': sha}
    first = builder.effective_pool_inputs(inventory, closure)
    inventory['files'][-1]['size'] = 8
    closure['historical_suites'] = ['changed transfer metadata']
    assert builder.effective_pool_inputs(inventory, closure) == first
    closure['native_discovery'] = {'providers': {'header:fixture.h': {'paths': ['usr/include/fixture.h']}}}
    proof = builder.effective_pool_inputs(inventory, closure)
    assert proof['pool_inputs_sha256'] == first['pool_inputs_sha256']
    assert proof['apt_validation_sha256'] != first['apt_validation_sha256']
    closure['resolved'][0]['version'] = '2'
    second = builder.effective_pool_inputs(inventory, closure)
    assert second['nonapt_inputs_sha256'] == first['nonapt_inputs_sha256']
    assert second['pool_inputs_sha256'] != first['pool_inputs_sha256']
    inventory['task_plan']['fixture'] = {'repo': 'owner/repo'}
    assert builder.effective_pool_inputs(inventory, closure)['nonapt_inputs_sha256'] != second['nonapt_inputs_sha256']

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import platform
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load(ROOT / 'scripts/native_requirements.py')
pool = load(ROOT / 'scripts/superbench_pool.py')
guest = load(ADAPTER / 'os_packages.py')


def test_pinned_base_and_environment_roots():
    pins = json.loads((ADAPTER / 'pins.json').read_bytes())
    contract = json.loads((ADAPTER / 'contract.json').read_bytes())
    base, environment = pool._declared_apt_roots(ADAPTER, pins, contract['environments'])
    assert {'libffi-dev', 'libtiff-dev', 'python-is-python3', 'locales-all'} <= base
    assert 'openjdk-21-jdk' not in base
    assert not environment
    roots = set()
    for task in contract['tasks'].values():
        roots.update(pool.apt_recipe_operations(task['repo_script_list'])[0])
    assert {'openjdk-17-jdk', 'openjdk-17-jre', 'libpq-dev'} <= roots
    assert not hasattr(guest, 'PACKAGES')
    assert not hasattr(guest, 'resolve')


def test_base_pin_is_mandatory():
    with pytest.raises(RuntimeError, match='pinned harness'):
        native.upstream_base_packages(ADAPTER/'upstream/dockerfiles.py', '0'*64, pool.apt_recipe_operations)


def test_real_preprocessor_discovers_only_active_missing_headers(tmp_path):
    cc = shutil.which('gcc')
    assert cc
    include = tmp_path/'python'/'python3.8'
    include.mkdir(parents=True)
    system = tmp_path/'system'
    system.mkdir()
    (include/'Python.h').write_text('#include "pyconfig.h"\n#if ENABLE\n#include <crypt.h>\n#endif\n#if 0\n#include <unused.h>\n#endif\n')
    (include/'pyconfig.h').write_text('#define ENABLE 1\n')
    profile = native.compiler_profile(cc, platform.machine(), timeout=10)
    assert native.missing_python_headers(include.parent, system, profile, timeout=10)['missing'] == ['crypt.h']
    (system/'crypt.h').write_text('/* provided */\n')
    assert not native.missing_python_headers(include.parent, system, profile, timeout=10)['missing']


def test_signed_contents_provider_is_derived_and_ambiguity_is_fatal(tmp_path):
    archive = tmp_path/'index'
    with gzip.open(archive, 'wt') as output:
        output.write('usr/include/crypt.h libs/libcrypt-dev\nusr/share/doc/crypt.h docs/wrong\n')
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    release = f'Suite: fixture\nArchitectures: amd64\nComponents: main\nSHA256:\n {sha} {archive.stat().st_size} main/Contents-amd64.gz\n'
    indexes = native.signed_contents(release, 'fixture', ['main'], 'amd64')
    assert indexes['main/Contents-amd64.gz']['sha256'] == sha
    candidates = native.candidate_paths(['crypt.h'], 'x86_64-linux-gnu')
    matches = native.query_index(archive, candidates, 'main/Contents-amd64.gz')
    assert native.unique_providers(matches, set())['crypt.h']['package'] == 'libcrypt-dev'
    matches['crypt.h'].append(('unrelated-provider', 'usr/include/crypt.h'))
    with pytest.raises(RuntimeError, match='no unique'):
        native.unique_providers(matches, set())
    with pytest.raises(RuntimeError, match='components differ'):
        native.signed_contents(release, 'fixture', ['main', 'other'], 'amd64')


def test_conda_archive_extracts_only_header_tree(tmp_path):
    archive = tmp_path/'archive.tar.bz2'
    with tarfile.open(archive, 'w:bz2') as output:
        for name, data in [('include/python3.8/Python.h', b'header'), ('bin/python', b'not executed')]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            output.addfile(member, io.BytesIO(data))
    destination = tmp_path/'headers'
    native.extract_conda(archive, destination, filename=archive.name)
    assert (destination/'python3.8/Python.h').read_bytes() == b'header'
    assert not (destination/'bin').exists()


def test_unsafe_archive_member_is_rejected(tmp_path):
    archive = tmp_path/'headers.tar'
    with tarfile.open(archive, 'w') as output:
        member = tarfile.TarInfo('../escape.h')
        member.size = 1
        output.addfile(member, io.BytesIO(b'x'))
    with pytest.raises(RuntimeError, match='unsafe archive member'):
        native.extract_golden(archive, tmp_path/'target')


def test_guest_validates_manifest_roots_not_a_fixed_list():
    inventory = {'fixture:amd64': {'version': '1', 'architecture': 'amd64'}}
    guest.require_requested(['fixture'], inventory)
    guest.require_requested(['fixture:amd64'], inventory)
    with pytest.raises(RuntimeError, match='omitted requested packages'):
        guest.require_requested(['fixture:arm64'], inventory)
    with pytest.raises(RuntimeError, match='invalid requested'):
        guest.require_requested(['fixture', 'fixture'], inventory)


def test_conda_v2_zstd_archive(tmp_path):
    import zipfile
    tar = tmp_path/'payload.tar'
    with tarfile.open(tar, 'w') as output:
        member = tarfile.TarInfo('include/python3.8/Python.h')
        member.size = 6
        output.addfile(member, io.BytesIO(b'header'))
    compressed = tmp_path/'pkg-fixture.tar.zst'
    subprocess.run(['zstd', '-q', str(tar), '-o', str(compressed)], check=True)
    archive = tmp_path/'sha-without-extension'
    with zipfile.ZipFile(archive, 'w') as output:
        output.write(compressed, compressed.name)
    native.extract_conda(archive, tmp_path/'headers', filename='fixture.conda')
    assert (tmp_path/'headers/python3.8/Python.h').read_bytes() == b'header'


def test_signed_release_missing_component_index_is_fatal():
    release = 'Suite: fixture\nArchitectures: amd64\nComponents: main\nSHA256:\n'
    with pytest.raises(RuntimeError, match='signed Contents index missing'):
        native.signed_contents(release, 'fixture', ['main'], 'amd64')


def test_installed_roots_use_actual_dpkg_status():
    status = (b'Package: present\nArchitecture: amd64\nStatus: install ok installed\n\n'
              b'Package: residual\nArchitecture: amd64\nStatus: deinstall ok config-files\n')
    assert native.installed_packages(status) == {'present', 'present:amd64'}


def test_real_elf_in_wheel_reports_dynamic_requirements(tmp_path):
    import zipfile
    source = tmp_path / 'fixture.c'
    source.write_text('#include <stdio.h>\nint f(void) { return puts("fixture"); }\n')
    binary = tmp_path / 'fixture.so'
    subprocess.run(['gcc', '-shared', '-fPIC', '-Wl,-soname,fixture.so',
                    '-Wl,-rpath,$ORIGIN/.libs', str(source), '-o', str(binary)], check=True)
    wheel = tmp_path / 'fixture.whl'
    with zipfile.ZipFile(wheel, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, 'fixture/fixture.so')
        archive.writestr('fixture/__init__.py', '')
    row = native.inspect_wheel(wheel)['fixture/fixture.so']
    assert 'libc.so.6' in row['needed']
    assert row['soname'] == ['fixture.so']
    assert row['runpath'] == ['$ORIGIN/.libs'] or row['rpath'] == ['$ORIGIN/.libs']
    candidates = native.native_candidates({'fixture': {'elf': {'fixture/fixture.so': row}}}, 'x86_64-linux-gnu')
    assert 'usr/lib/x86_64-linux-gnu/libc.so.6' in candidates['apt']['soname:libc.so.6']
    assert 'lib/libc.so.6' in candidates['conda']['soname:libc.so.6']


def test_source_archive_declarations_are_candidates_not_proven_requirements(tmp_path):
    archive = tmp_path / 'fixture.tar.gz'
    members = {'fixture/setup.py': b'from setuptools import Extension\nExtension("x", ["src/x.c"], libraries=["sample"], include_dirs=dynamic())\n',
               'fixture/src/x.c': b'#if 0\n#include <inactive.h>\n#endif\n#include <external.h>\n#include "local.h"\n',
               'fixture/src/local.h': b'/* local */\n',
               'fixture/pyproject.toml': b'[build-system]\nrequires=["setuptools"]\n',
               'fixture/CMakeLists.txt': b'find_package(Sample REQUIRED)\n'}
    with tarfile.open(archive, 'w:gz') as tar:
        for name, content in members.items():
            item = tarfile.TarInfo(name); item.size = len(content)
            tar.addfile(item, io.BytesIO(content))
    report = native.inspect_sdist(archive, archive.name)
    assert report['coverage'].endswith('not-a-build-proof')
    row = report['extensions']['fixture/setup.py'][0]
    assert row['literal']['libraries'] == ['sample']
    assert row['dynamic'] == ['include_dirs']
    candidates = native.native_candidates({'fixture': {'source': report}}, 'x86_64-linux-gnu')
    assert set(candidates['apt']) == {'header:external.h', 'header:inactive.h', 'link:sample'}
    assert 'usr/lib/x86_64-linux-gnu/libsample.so' in candidates['apt']['link:sample']


def test_conda_inventory_reads_only_declared_file_paths(tmp_path):
    path = tmp_path/'fixture.tar.bz2'
    with tarfile.open(path, 'w:bz2') as archive:
        content = b'include/example.h\nlib/libexample.so\n'
        row = tarfile.TarInfo('info/files'); row.size = len(content)
        archive.addfile(row, io.BytesIO(content))
    assert native.conda_inventory(path, path.name) == ['include/example.h', 'lib/libexample.so']


def write_fixture_wheel(path, distribution, version):
    import base64
    import zipfile
    prefix = distribution + '-' + version + '.dist-info/'
    files = {prefix+'METADATA': f'Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n'.encode(),
             prefix+'WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
             distribution+'/__init__.py': b'payload'}
    record = ''.join(name+',sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')+','+str(len(data))+'\n' for name,data in files.items())
    with zipfile.ZipFile(path, 'w') as archive:
        for name,data in files.items():
            archive.writestr(name,data)
        archive.writestr(prefix+'RECORD', record+prefix+'RECORD,,\n')


def test_shared_capture_reuses_verified_wheel_and_no_source_fallback(tmp_path, monkeypatch):
    import os
    runtime = load(ADAPTER/'guest_runtime.py')
    root = tmp_path/'guest'; shared = tmp_path/'shared'; shared.mkdir()
    (root/'caches/pip-index').mkdir(parents=True)
    monkeypatch.setattr(runtime, 'ROOT', root)
    monkeypatch.setattr(runtime, 'SHARED_WARM_CACHE_ROOT', shared)
    monkeypatch.setenv('GPT_TRACE_SHARED_WARM_CACHE', str(shared))
    monkeypatch.setenv('GPT_TRACE_WHEEL_BUILD_CONTEXT', 'a'*64)
    req = tmp_path/'requirements.txt'; req.write_text('fixture==1\n')
    calls = []
    name = 'fixture-1-py3-none-any.whl'
    def wheel(*args, **kwargs):
        calls.append(args)
        folder = Path(args[args.index('--wheel-dir')+1])
        write_fixture_wheel(folder/name, 'fixture', '1')
    monkeypatch.setattr(runtime, '_activated_capture_environment', lambda prefix, env, **kwargs: env)
    monkeypatch.setattr(runtime, 'run', wheel)
    item = {'instance_id': 'fixture'}
    env = {'pip_freeze': 'fixture==1', 'conda_explicit': 'fixture'}
    first = tmp_path/'first'; first.mkdir()
    second = tmp_path/'second'; second.mkdir()
    assert runtime._capture_install_artifacts(item, tmp_path/'prefix', req, first, env) == runtime._capture_install_artifacts(item, tmp_path/'prefix', req, second, env)
    assert len(calls) == 1
    assert (second/name).read_bytes() == (first/name).read_bytes()
    def failure(*args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(runtime, 'run', failure)
    req.write_text('fixture==2\n')
    third = tmp_path/'third'; third.mkdir()
    with pytest.raises(subprocess.CalledProcessError):
        runtime._capture_install_artifacts(item, tmp_path/'prefix', req, third, env)
    assert len(calls) == 2 and all('wheel' in command and 'download' not in command for command in calls)


def test_shared_capture_invalidates_on_environment_and_context(tmp_path):
    runtime = load(ADAPTER/'guest_runtime.py')
    req = tmp_path/'requirements'; req.write_text('fixture==1\n')
    first = runtime._capture_cache_identity('a'*64, req, {'pip_freeze':'a'}, {'CFLAGS':'-O2'})
    assert first != runtime._capture_cache_identity('b'*64, req, {'pip_freeze':'a'}, {'CFLAGS':'-O2'})
    assert first != runtime._capture_cache_identity('a'*64, req, {'pip_freeze':'b'}, {'CFLAGS':'-O2'})
    assert first != runtime._capture_cache_identity('a'*64, req, {'pip_freeze':'a'}, {'CFLAGS':'-O0'})


def test_native_repair_has_no_revision_allowlist():
    import ast
    path = ROOT/'apps/workstation-broker/src/workstation_broker/preparation.py'
    tree = ast.parse(path.read_text())
    node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_native_apt_repair_compatible')
    assert not any(isinstance(item, ast.Constant) and isinstance(item.value, str)
                   and len(item.value) == 64 and all(char in '0123456789abcdef' for char in item.value)
                   for item in ast.walk(node))


def test_independent_capture_persists_exact_successes_before_reporting_failure(tmp_path, monkeypatch):
    runtime = load(ADAPTER/'guest_runtime.py')
    root = tmp_path/'guest'; shared = tmp_path/'shared'; shared.mkdir()
    (root/'caches/pip-index').mkdir(parents=True)
    monkeypatch.setattr(runtime, 'ROOT', root)
    monkeypatch.setattr(runtime, 'SHARED_WARM_CACHE_ROOT', shared)
    monkeypatch.setenv('GPT_TRACE_SHARED_WARM_CACHE', str(shared))
    monkeypatch.setenv('GPT_TRACE_WHEEL_BUILD_CONTEXT', 'a'*64)
    req = tmp_path/'requirements'; req.write_text('alpha==1\nbeta==2\n')
    calls = []
    def wheel(*args, **kwargs):
        requirements = Path(args[args.index('--requirement')+1]).read_text()
        calls.append(requirements)
        folder = Path(args[args.index('--wheel-dir')+1])
        if len(calls) == 1:
            write_fixture_wheel(folder/'alpha-1-py3-none-any.whl', 'alpha', '1')
            return
        if len(calls) == 2:
            raise subprocess.CalledProcessError(1, args)
        write_fixture_wheel(folder/'beta-2-py3-none-any.whl', 'beta', '2')
    monkeypatch.setattr(runtime, '_activated_capture_environment', lambda prefix, env, **kwargs: env)
    monkeypatch.setattr(runtime, 'run', wheel)
    env = {'pip_freeze': 'alpha==1\nbeta==2', 'conda_explicit': 'fixture'}
    item = {'instance_id': 'fixture'}
    first = tmp_path/'first'; first.mkdir()
    with pytest.raises(subprocess.CalledProcessError):
        runtime._capture_install_artifacts(item, tmp_path/'prefix', req, first, env)
    assert len(list((shared/'wheel-capture-v2/records').glob('*.json'))) == 1
    second = tmp_path/'second'; second.mkdir()
    result = runtime._capture_install_artifacts(item, tmp_path/'prefix', req, second, env)
    assert set(result) == {'alpha-1-py3-none-any.whl', 'beta-2-py3-none-any.whl'}
    assert calls == ['alpha==1\n', 'beta==2\n', 'beta==2\n']
    assert len(list((shared/'wheel-capture-v2/records').glob('*.json'))) == 2
    third = tmp_path/'third'; third.mkdir()
    assert runtime._capture_install_artifacts(item, tmp_path/'prefix', req, third, env) == result
    assert len(calls) == 3


def test_capture_rejects_wrong_or_truncated_wheel(tmp_path):
    import zipfile
    runtime = load(ADAPTER/'guest_runtime.py')
    req = runtime._capture_requirements(['alpha==1'])
    wrong = tmp_path/'alpha-2-py3-none-any.whl'
    write_fixture_wheel(wrong, 'alpha', '2')
    with pytest.raises(RuntimeError, match='version differs'):
        runtime._validate_captured_wheel(wrong, req)
    truncated = tmp_path/'alpha-1-py3-none-any.whl'
    truncated.write_bytes(b'PK\x03\x04')
    with pytest.raises(zipfile.BadZipFile):
        runtime._validate_captured_wheel(truncated, req)


def test_compiler_namespace_uses_only_owned_conda_toolchain(tmp_path):
    runtime = load(ADAPTER/'guest_runtime.py')
    prefix = tmp_path/'prefix'; prefix.mkdir()
    compiler = prefix/'bin/gcc'; compiler.parent.mkdir(); compiler.write_bytes(b'compiler')
    records = [{'name':'compiler','version':'1','files':['bin/gcc'],'depends':['runtime >=1']},
               {'name':'runtime','version':'1','files':[],'depends':['__linux']},
               {'name':'unrelated','version':'1','files':[],'depends':[]}]
    initial = runtime._compiler_conda_closure(prefix, records, [compiler])
    assert set(initial) == {'compiler','runtime'}
    records[-1]['version'] = '2'
    assert runtime._compiler_conda_closure(prefix, records, [compiler]) == initial
    records[1]['version'] = '2'
    assert runtime._compiler_conda_closure(prefix, records, [compiler]) != initial
    records[0]['files'] = []
    with pytest.raises(RuntimeError, match='ownership'):
        runtime._compiler_conda_closure(prefix, records, [compiler])


def test_wheel_record_rejects_crc_valid_corruption(tmp_path):
    import zipfile
    runtime = load(ADAPTER/'guest_runtime.py')
    path = tmp_path/'alpha-1-py3-none-any.whl'
    write_fixture_wheel(path, 'alpha', '1')
    req = runtime._capture_requirements(['alpha==1'])
    assert runtime._validate_captured_wheel(path, req) == 'alpha'
    with zipfile.ZipFile(path) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files['alpha/__init__.py'] = b'changed'
    with zipfile.ZipFile(path, 'w') as archive:
        for name,data in files.items(): archive.writestr(name, data)
    with pytest.raises(RuntimeError, match='RECORD content differs'):
        runtime._validate_captured_wheel(path, req)


def test_full_recipe_log_discovers_only_failing_command(tmp_path):
    runtime = load(ADAPTER/'guest_runtime.py')
    marker = 'GPTTRACE_RECIPE_fixture_'
    data = (marker+'0\nfatal error: optional.h: No such file or directory\n'+marker+'1\n'
            'fatal error: required.h: No such file or directory\n'+'x'*20000+'\n').encode()
    assert runtime._recipe_observations(io.BytesIO(data), marker) == {('header','required.h')}

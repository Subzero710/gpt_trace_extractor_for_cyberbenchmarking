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


def write_fixture_wheel(path, distribution, version, *, payload=b'payload'):
    import base64
    import zipfile
    prefix = distribution + '-' + version + '.dist-info/'
    files = {prefix+'METADATA': f'Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n'.encode(),
             prefix+'WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
             distribution+'/__init__.py': payload}
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
    monkeypatch.setattr(runtime, '_installed_wheel_evidence', lambda *args: {'distributions': {}, 'tags': []})
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
    monkeypatch.setattr(runtime, '_installed_wheel_evidence', lambda *args: {'distributions': {}, 'tags': []})
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


def test_cross_context_wheel_reuse_requires_exact_installed_payload(tmp_path, monkeypatch):
    import csv
    import io
    import zipfile
    from packaging.requirements import Requirement
    runtime = load(ADAPTER/'guest_runtime.py')
    wheel = tmp_path/'alpha-1-py3-none-any.whl'
    write_fixture_wheel(wheel, 'alpha', '1')
    root = tmp_path/'installed'; root.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(root)
        record_name, = [name for name in archive.namelist() if name.endswith('/RECORD')]
        rows = {row[0]: row[1:] for row in csv.reader(io.StringIO(archive.read(record_name).decode()))}
    evidence = {'root': str(root), 'version': '1', 'record': rows}
    requirement = Requirement('alpha==1')
    assert runtime._matches_installed_wheel(wheel, wheel.name, requirement, evidence, {'py3-none-any'})
    assert not runtime._matches_installed_wheel(wheel, wheel.name, requirement, evidence, {'cp38-cp38-linux_x86_64'})
    payload = next(name for name in rows if not name.endswith('/RECORD') and not '.dist-info/' in name)
    target = root/payload
    original = target.read_bytes(); target.write_bytes(b'X'*len(original))
    assert not runtime._matches_installed_wheel(wheel, wheel.name, requirement, evidence, {'py3-none-any'})
    target.write_bytes(original)
    evidence['record']['unexpected.py'] = ['', '']
    assert not runtime._matches_installed_wheel(wheel, wheel.name, requirement, evidence, {'py3-none-any'})


def test_target_elf_loader_resolves_transitive_rpath_and_reports_missing(tmp_path):
    import sys
    import os
    runtime = load(ADAPTER/'guest_runtime.py')
    python = Path(sys.executable)
    program = runtime._elf_program(python)
    assert program['interpreter'] and program['dynamic']
    (tmp_path/'leaf.c').write_text('int leaf(void) { return 1; }')
    (tmp_path/'parent.c').write_text('extern int leaf(void); int parent(void) { return leaf(); }')
    (tmp_path/'root.c').write_text('extern int parent(void); void *PyInit_fixture(void) { parent(); return 0; }')
    leaf = tmp_path/'libfixture_leaf.so.1'
    parent = tmp_path/'libfixture_parent.so.1'
    module = tmp_path/'fixture.so'
    subprocess.run(['gcc','-shared','-fPIC',str(tmp_path/'leaf.c'),'-Wl,-soname,'+leaf.name,'-o',str(leaf)],check=True)
    subprocess.run(['gcc','-shared','-fPIC',str(tmp_path/'parent.c'),'-L'+str(tmp_path),'-l:'+leaf.name,
                    '-Wl,-soname,'+parent.name,'-Wl,-rpath,$ORIGIN','-o',str(parent)],check=True)
    subprocess.run(['gcc','-shared','-fPIC',str(tmp_path/'root.c'),'-L'+str(tmp_path),'-l:'+parent.name,
                    '-Wl,-rpath,$ORIGIN','-o',str(module)],check=True)
    assert runtime._elf_exports_python_module(module)
    assert not runtime._elf_exports_python_module(parent)
    env = {key: value for key, value in os.environ.items() if not key.startswith('LD_')}
    assert runtime._elf_loader_missing(program['interpreter'], python, env, extension=module) == set()
    leaf.unlink()
    assert runtime._elf_loader_missing(program['interpreter'], python, env, extension=module) == {('soname', leaf.name)}

    requests = runtime._elf_loader_missing(program['interpreter'], python, env, extension=module, search_paths=True)
    assert len(requests) == 1
    key, = requests
    assert key.startswith('soname:' + leaf.name + '@')
    assert all(path.endswith('/' + leaf.name) for path in requests[key])
    assert load(ADAPTER/'os_packages.py').native_requirement_paths(requests) == requests


def test_actual_pip_install_capture_retains_ephemeral_wheel_bytes(tmp_path):
    import os
    import venv
    from packaging.requirements import Requirement
    runtime = load(ADAPTER/'guest_runtime.py')
    prefix = tmp_path/'prefix'
    venv.EnvBuilder(with_pip=True).create(prefix)
    wheel = tmp_path/'fixture-1-py3-none-any.whl'
    write_fixture_wheel(wheel, 'fixture', '1')
    directory = tmp_path/'capture'
    with runtime._capture_pip_installations(prefix, directory, dict(os.environ)) as env:
        subprocess.run([str(prefix/'bin/python'), '-m', 'pip', 'install', '--no-index',
                        '--no-cache-dir', str(wheel)], env=env, check=True, capture_output=True)
    original = wheel.read_bytes()
    wheel.unlink()
    result = runtime._captured_install_wheel(prefix, directory, 'fixture', Requirement('fixture==1'), tags={'py3-none-any'})
    assert result is not None
    filename, source, record = result
    assert filename == 'fixture-1-py3-none-any.whl'
    assert source.read_bytes() == original
    assert record['sha256'] == hashlib.sha256(original).hexdigest()
    receipt = json.loads((directory/'receipts/fixture.json').read_bytes())
    record_path = prefix/receipt['record']
    installed = record_path.parent.parent/'fixture/__init__.py'
    installed.write_bytes(b'changed')
    assert runtime._captured_install_wheel(prefix, directory, 'fixture', Requirement('fixture==1')) is None
    assert not list(prefix.rglob('gpttrace-capture-*.pth'))


def test_traced_recipe_preserves_shell_state_and_failed_command_diagnostic(tmp_path, monkeypatch):
    import os
    runtime = load(ADAPTER/'guest_runtime.py')
    monkeypatch.setenv('GPTTRACE_TEMPLATE_TRACE', '1')
    monkeypatch.setenv('GPT_TRACE_NATIVE_ROUND', 'a'*64)
    calls = []
    def supervise(argv, *, cwd, env, input, log):
        calls.append(Path(argv[-1]).read_text())
        return subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    monkeypatch.setattr(runtime, '_run_elementary_pip', supervise)
    monkeypatch.setattr(runtime, '_template_operation', lambda *_: __import__('contextlib').nullcontext())
    with pytest.raises(runtime.RecipeFailure) as error:
        runtime.shell(['export FIXTURE=correct', 'test "$FIXTURE" = correct; echo "fatal error: optional.h: No such file or directory"',
                       'echo "fatal error: required.h: No such file or directory"; false'], cwd=tmp_path, env=dict(os.environ))
    assert error.value.native_observations == {('header','required.h')}
    assert len(calls) == 1
    assert 'GPTTRACE_TEMPLATE begin recipe' not in calls[0]


def test_production_capture_never_rebuilds_unproved_installed_distribution(tmp_path, monkeypatch):
    runtime = load(ADAPTER/'guest_runtime.py')
    root = tmp_path/'guest'; shared = tmp_path/'shared'; shared.mkdir()
    (root/'caches/pip-index').mkdir(parents=True)
    prefix = tmp_path/'prefix'; prefix.mkdir()
    capture = tmp_path/'capture'; capture.mkdir()
    monkeypatch.setattr(runtime, 'ROOT', root)
    monkeypatch.setattr(runtime, 'SHARED_WARM_CACHE_ROOT', shared)
    monkeypatch.setenv('GPT_TRACE_SHARED_WARM_CACHE', str(shared))
    monkeypatch.setenv('GPT_TRACE_WHEEL_BUILD_CONTEXT', 'a'*64)
    monkeypatch.setattr(runtime, '_activated_capture_environment', lambda prefix, env, **kwargs: env)
    monkeypatch.setattr(runtime, '_installed_wheel_evidence', lambda *args: {'distributions': {}, 'tags': []})
    def command(*args, **kwargs):
        if '-I' in args:
            return b'["py3-none-any"]'
        folder = Path(args[args.index('--wheel-dir')+1])
        write_fixture_wheel(folder/'fixture-1-py3-none-any.whl','fixture','1')
    monkeypatch.setattr(runtime,'run',command)
    req = tmp_path/'requirements.txt'; req.write_text('fixture==1\n')
    item = {'instance_id':'fixture'}
    inventory = {'pip_freeze':'fixture==1','conda_explicit':'fixture'}
    first = tmp_path/'first'; first.mkdir()
    runtime._capture_install_artifacts(item,prefix,req,first,inventory)
    second = tmp_path/'second'; second.mkdir()
    def forbid(*args, **kwargs):
        if '-I' in args:
            return b'["py3-none-any"]'
        raise AssertionError('rebuilding an unproved installed wheel is forbidden')
    monkeypatch.setattr(runtime,'run',forbid)
    with pytest.raises(RuntimeError,match='no exact wheel evidence'):
        runtime._capture_install_artifacts(item,prefix,req,second,inventory,installed_capture=capture)
    assert not list(second.iterdir())


def test_native_guest_protocol_runs_real_pep517_static_and_dynamic_layers(tmp_path):
    import contextlib
    import os
    import sys
    import venv
    transport = load(ROOT/'scripts/native_guest_execution.py')
    interpreter = tmp_path/'target'
    venv.EnvBuilder(with_pip=True).create(interpreter)
    python = interpreter/'bin/python'
    exchange = tmp_path/'exchange'; exchange.mkdir()
    local = tmp_path/'guest-local'; local.mkdir()
    source = exchange/'project'; source.mkdir()
    (source/'pyproject.toml').write_text('''[build-system]
requires = ["fixture-static-helper==1"]
build-backend = "fixture_backend"
backend-path = ["."]
''')
    (source/'fixture_backend.py').write_text('''from pathlib import Path

def get_requires_for_build_wheel(config_settings=None):
    import fixture_static_helper
    return ["fixture-dynamic-helper==1"]

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    import fixture_static_helper, fixture_dynamic_helper
    target = Path(metadata_directory) / "fixture_project-1.dist-info"
    target.mkdir()
    (target/"METADATA").write_text("Metadata-Version: 2.1\\nName: fixture-project\\nVersion: 1\\nRequires-Dist: fixture-runtime==2\\n")
    (target/"WHEEL").write_text("Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")
    return target.name
''')
    wheels = {}
    for name in ('fixture-static-helper', 'fixture-dynamic-helper'):
        distribution = name.replace('-', '_')
        wheel = exchange/(distribution+'-1-py3-none-any.whl')
        write_fixture_wheel(wheel, distribution, '1', payload=b'VALUE = 1\n')
        wheels[name+'==1'] = str(wheel)
    calls = []
    def resolve(requirements):
        calls.append(requirements)
        return [wheels[requirement] for requirement in requirements]
    active = set()
    @contextlib.contextmanager
    def observe(label, *, limit=None):
        token = object(); active.add(token)
        try: yield
        finally: active.remove(token)
    class LocalGuest:
        def __init__(self): self.children = {}
        def start(self, command):
            index = command.index('/usr/bin/python3')
            process = subprocess.Popen([sys.executable, *command[index+1:]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.children[process.pid] = process
            return process.pid
        def status(self, pid):
            status = self.children[pid].poll()
            return {'exited':status is not None, 'exitcode':status}
        def run(self, command): subprocess.run(command, check=True, timeout=10)
    client = transport.NativeGuestClient('unused', ROOT, os.getuid(), os.getgid(), local, limit=180, cadence=0.01, operation=observe)
    client.agent = LocalGuest()
    report = exchange/'report.json'
    runtime = {'root':exchange, 'env':{'PATH':'/usr/bin:/bin', 'HOME':str(local), 'PIP_NO_INDEX':'1', 'PIP_CONFIG_FILE':'/dev/null', 'LANG':'C.UTF-8'},
               '_native_build_resolver':resolve}
    result = client.run([str(python), '-m', 'pip', 'install', '--dry-run', '--ignore-installed', '--no-deps',
                         '--report', report, source], runtime, interpreter=python,
                        metadata_build=True, capture_build_requirements=True)
    assert calls == [['fixture-static-helper==1'], ['fixture-dynamic-helper==1']]
    assert sorted(result) == [['fixture_dynamic_helper==1'], ['fixture_static_helper==1']]
    assert json.loads(report.read_bytes())['install'][0]['metadata']['requires_dist'] == ['fixture-runtime==2']
    assert not active
    assert all(process.poll() == 0 for process in client.agent.children.values())
    # Real target backend failure must become a durable native lookup request,
    # not an optional package rejection or a controller-side compilation.
    (source/'fixture_backend.py').write_text('''import subprocess

def get_requires_for_build_wheel(config_settings=None):
    return []

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    subprocess.run(["gcc", "-E", "-x", "c", "-"],
                   input=b"#include <gpttrace_fixture_missing_native_header.h>\\n", check=True)
''')
    with pytest.raises(transport.NativeGuestRequired) as error:
        client.run([str(python), '-m', 'pip', 'install', '--dry-run', '--ignore-installed', '--no-deps',
                    '--report', report, source], runtime, interpreter=python,
                   metadata_build=True, capture_build_requirements=True)
    assert len(error.value.requirements) == 1
    key, paths = next(iter(error.value.requirements.items()))
    assert key.startswith('header:gpttrace_fixture_missing_native_header.h@')
    assert 'usr/include/gpttrace_fixture_missing_native_header.h' in paths
    assert not active


def test_sealed_cas_guest_links_only_admitted_immutable_inodes(tmp_path):
    import os
    import socket
    import types
    if os.geteuid() != 0:
        pytest.skip('root-owned sealed CAS fixture required')
    broker = load(ROOT/'scripts/native_guest_broker.py')
    stage = tmp_path/'stage'; stage.mkdir()
    sha = hashlib.sha256(b'fixture').hexdigest()
    original = stage/'objects/sha256'/sha[:2]/sha
    original.parent.mkdir(parents=True)
    original.write_bytes(b'fixture'); original.chmod(0o444)
    scratch = stage/'.native-pip-fixture'; scratch.mkdir()
    path = tmp_path/'links.sock'
    account = types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
    service = broker.SealedCasLinks(path,stage,account,2)
    def link(destination, digest=sha):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(path))
            connection.sendall(json.dumps({'sha256':digest,'destination':destination}).encode()+b'\n')
            with connection.makefile('rb') as wire:
                return json.loads(wire.readline())
    try:
        assert link('.native-pip-fixture/archive') == {'ok':True}
        assert (scratch/'archive').samefile(original)
        assert 'error' in link('../outside')
        assert 'error' in link('.native-pip-fixture/archive')
        (scratch/'outside').symlink_to(tmp_path,target_is_directory=True)
        assert 'error' in link('.native-pip-fixture/outside/forbidden')
        assert not (tmp_path/'forbidden').exists()
        late_sha = hashlib.sha256(b'late').hexdigest()
        late = stage/'objects/sha256'/late_sha[:2]/late_sha
        late.parent.mkdir(exist_ok=True)
        late.write_bytes(b'late'); late.chmod(0o444)
        assert 'error' in link('.native-pip-fixture/late',late_sha)
        assert original.read_bytes() == b'fixture'
    finally:
        service.close()
    assert not service.thread.is_alive()


def test_native_metadata_exception_is_preserved_across_worker_entry(tmp_path, monkeypatch):
    pool = load(ROOT/'scripts/superbench_pool.py')
    transport = pool._native_guest_module()
    assert pool._native_guest_module() is transport
    stage = tmp_path/'stage'; stage.mkdir()
    monkeypatch.setattr(pool,'_NATIVE_STAGE',stage)
    paths = ['usr/include/fixture.h']
    identity = 'header:fixture.h@'+hashlib.sha256(json.dumps(paths,separators=(',',':')).encode()).hexdigest()
    requirements = {identity:paths}
    def fail():
        raise transport.NativeGuestRequired(requirements)
    monkeypatch.setattr(pool,'main',fail)
    monkeypatch.setattr('sys.argv',['superbench_pool.py'])
    with pytest.raises(SystemExit) as failure:
        pool._pool_cli_entry()
    assert failure.value.code == transport.NATIVE_METADATA_EXIT_CODE
    assert json.loads((stage/'metadata/target-metadata-native.json').read_bytes()) == requirements

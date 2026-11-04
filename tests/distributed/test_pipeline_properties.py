"""Generated contracts and real isolated package-tool boundaries.

Network is disabled in package-tool environments. The external programs really
execute; fake downloads below isolate only the transport in CAS unit properties.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

from hypothesis import given, settings, strategies as st
import pytest

import superbench_pool as pool
from workstation_broker import preparation as jobs


def current_target():
    return pool._target_environment_module().capture_current()


@contextlib.contextmanager
def isolated_pool():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / 'metadata').mkdir()
        (root / 'downloads').mkdir()
        candidate = pool.Pool(root)
        try:
            yield candidate
        finally:
            candidate._pip_cache_context.cleanup()


def wheel_bytes(name, version, requirements=(), extras=()):
    raw = io.BytesIO()
    normalized = name.replace('-', '_')
    directory = normalized + '-' + version + '.dist-info/'
    metadata = ['Metadata-Version: 2.1', 'Name: ' + name, 'Version: ' + version]
    metadata += ['Requires-Dist: ' + value for value in requirements]
    metadata += ['Provides-Extra: ' + value for value in extras]
    with zipfile.ZipFile(raw, 'w') as archive:
        archive.writestr(directory + 'METADATA', '\n'.join(metadata) + '\n')
        archive.writestr(directory + 'WHEEL',
                         'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
        archive.writestr(directory + 'RECORD', '')
    return raw.getvalue()


def artifact(candidate, name, *, kind='wheel', build_requirements=()):
    version = '1.0'
    filename = name + '-' + version + '-py3-none-any.whl'
    data = wheel_bytes(name, version)
    path = candidate.stage / 'downloads' / filename
    path.write_bytes(data)
    sha = candidate.put(path, 'python', name)
    return {'name': name, 'version': version, 'filename': filename,
            'kind': kind, 'sha256': sha,
            'url': 'https://files.pythonhosted.org/' + filename,
            'requirements': [], 'provides_extra': [],
            **({'build_requirements': list(build_requirements)} if kind == 'sdist' else {})}


@settings(max_examples=30, deadline=None)
@given(st.binary(max_size=4096), st.integers(min_value=2, max_value=8))
def test_content_identity_deduplicates_concurrent_url_aliases(data, count):
    sha = hashlib.sha256(data).hexdigest()
    with isolated_pool() as candidate:
        calls = []
        barrier = threading.Barrier(count)
        def transfer(url, path, **kwargs):
            calls.append(url)
            time.sleep(0.002)
            Path(path).write_bytes(data)
            return sha
        def download(index):
            barrier.wait(timeout=10)
            return candidate.download('https://example.test/' + str(index),
                                      'generated', str(index), sha=sha)
        with patch.object(pool, 'fetch', side_effect=transfer):
            with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
                results = list(executor.map(download, range(count)))
        assert results == [sha] * count
        assert len(calls) == 1
        assert set(candidate.provenance['generated']) == {str(i) for i in range(count)}
        assert (candidate.objects / sha[:2] / sha).read_bytes() == data


@settings(max_examples=30, deadline=None)
@given(st.binary(max_size=4096), st.sampled_from(('fsync', 'link')),
       st.integers(min_value=1, max_value=2))
def test_atomic_records_are_absent_or_complete_under_io_failure(data, operation, failure_at):
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / 'record.json'
        original = getattr(pool.os, operation)
        calls = 0
        def interrupt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == failure_at:
                raise OSError('generated transaction interruption')
            return original(*args, **kwargs)
        with patch.object(pool.os, operation, side_effect=interrupt):
            try:
                pool.write_new(path, data)
            except OSError:
                pass
        assert not path.exists() or path.read_bytes() == data
        if path.exists():
            with pytest.raises(FileExistsError):
                pool.write_new(path, data + b'changed')
            assert path.read_bytes() == data


def test_process_interruption_cannot_publish_a_partial_record(tmp_path):
    destination = tmp_path / 'record'
    script = '''import os,sys
sys.path.insert(0,sys.argv[1])
import superbench_pool as p
def boundary(*a,**kw):
    print('prepared',flush=True)
    sys.stdin.readline()
p.os.link=boundary
p.write_new(sys.argv[2], b'durable bytes')
'''
    process = subprocess.Popen([sys.executable, '-c', script, str(Path(pool.__file__).parent),
                                str(destination)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'prepared'
        process.terminate()
        process.wait(timeout=10)
        assert not destination.exists()
        pool.write_new(destination, b'durable bytes')
        assert destination.read_bytes() == b'durable bytes'
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


@settings(max_examples=30, deadline=None)
@given(st.lists(st.from_regex(r'[a-z][a-z0-9]{0,7}', fullmatch=True),
                min_size=1, max_size=8, unique=True))
def test_plan_identity_is_order_independent_and_requirement_sensitive(names):
    target = current_target()
    requirements = [name + '>=1' for name in names]
    identity = pool.pip_group_key(target, requirements)
    assert identity == pool.pip_group_key(target, list(reversed(requirements)) + requirements)
    assert identity != pool.pip_group_key(target, [*requirements, 'additional-generated-input==2'])


@settings(max_examples=30, deadline=None)
@given(st.lists(st.from_regex(r'[a-z][a-z0-9]{0,7}', fullmatch=True), max_size=5, unique=True),
       st.booleans(), st.sampled_from(('pip', 'python -m pip')), st.booleans())
def test_local_install_contract_is_independent_of_frontend_spelling(extras, editable, frontend, no_deps):
    target = '.' + ('[' + ','.join(extras) + ']' if extras else '')
    command = frontend + ' install ' + ('--no-deps ' if no_deps else '')
    command += ('--editable ' if editable else '') + target
    specs, files, vcs, issues, parsed_extras, constraints, steps = pool.pip_commands([command])
    assert not specs and not files and not vcs and not issues and not constraints
    assert parsed_extras == set(extras)
    assert len(steps) == 1 and steps[0]['local_project'] is True
    assert steps[0]['no_deps'] is no_deps


@settings(max_examples=12, deadline=None)
@given(st.integers(min_value=1, max_value=5))
def test_checkpoint_reuse_verifies_the_entire_build_graph(depth):
    target = current_target()
    with isolated_pool() as candidate:
        child = None
        for index in range(depth):
            name = 'generated' + str(index)
            requirement = name + '==1.0'
            key = pool.pip_group_key(target, [requirement])
            record = artifact(candidate, name, kind='sdist' if child else 'wheel',
                              build_requirements=[[child[1]]] if child else [])
            children = {child[0]: pool.digest(pool._pip_plan_path(candidate.stage, child[0]))} if child else {}
            pool._write_pip_plan(candidate, target, [requirement], key, [record], build_plans=children)
            child = key, requirement
        assert pool.reuse_pip_plan(candidate, target, [child[1]], child[0])
        retained = {path: path.read_bytes() for path in candidate.stage.rglob('*') if path.is_file()}
        for path in sorted(candidate.objects.glob('*/*')):
            old = path.read_bytes()
            path.write_bytes(old + b'changed')
            with pytest.raises(RuntimeError):
                pool.reuse_pip_plan(candidate, target, [child[1]], child[0])
            path.write_bytes(old)
        assert all(path.read_bytes() == data for path, data in retained.items())
        if depth > 1:
            root = pool._pip_plan_path(candidate.stage, child[0])
            data = json.loads(root.read_bytes())
            data['build_plans'] = {}
            root.write_text(json.dumps(data))
            with pytest.raises(RuntimeError):
                pool.reuse_pip_plan(candidate, target, [child[1]], child[0])


def test_only_inactive_requirements_admit_an_empty_plan():
    target = current_target()
    inactive = 'generated; python_version != ' + json.dumps(target.python_version)
    active = 'generated; python_version == ' + json.dumps(target.python_version)
    with isolated_pool() as candidate:
        key = pool.pip_group_key(target, [inactive])
        pool._write_pip_plan(candidate, target, [inactive], key, [])
        assert pool.reuse_pip_plan(candidate, target, [inactive], key)
        with pytest.raises(RuntimeError):
            pool._write_pip_plan(candidate, target, [active], 'active', [])


def test_build_requirement_cycles_fail_without_deadlock():
    target = current_target()
    with isolated_pool() as candidate:
        def recursive(instance, key, group):
            return pool.acquire_pip_group(instance, key, group)
        with patch.object(pool, '_native_pip_group_locked', side_effect=recursive):
            with pytest.raises(RuntimeError, match='cyclic'):
                pool.acquire_pip_group(candidate, 'generated', {'target': target.as_dict()})


def test_concurrent_build_graph_cycles_release_all_waiters():
    with isolated_pool() as candidate:
        barrier = threading.Barrier(2)
        errors = []
        def resolve(instance, key, group):
            if len(instance._native_group_context.stack) == 1:
                barrier.wait(timeout=5)
            return pool.acquire_pip_group(instance, 'right' if key == 'left' else 'left', group)
        def worker(key):
            try:
                pool.acquire_pip_group(candidate, key, {})
            except RuntimeError as error:
                errors.append(error)
        with patch.object(pool, '_native_pip_group_locked', side_effect=resolve):
            threads = [threading.Thread(target=worker, args=(key,), daemon=True)
                       for key in ('left', 'right')]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads), 'dependency cycle deadlocked'
        assert len(errors) == len(threads)
        assert all('cyclic' in str(error) for error in errors)
        assert not any(candidate._native_group_edges.values())


def metadata_project(tmp_path):
    index = tmp_path / 'index'; index.mkdir()
    project = tmp_path / 'project'; project.mkdir()
    names = ('contract_static', 'contract_dynamic')
    for name in names:
        (index / (name + '-1.0-py3-none-any.whl')).write_bytes(wheel_bytes(name, '1.0'))
    (project / 'pyproject.toml').write_text(
        '[build-system]\nrequires=["' + names[0] + '==1.0"]\n'
        'build-backend="backend"\nbackend-path=["."]\n')
    (project / 'backend.py').write_text('''from pathlib import Path
def get_requires_for_build_wheel(config_settings=None):
    return ['contract_dynamic==1.0']
def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    target = Path(metadata_directory) / 'contract-1.0.dist-info'
    target.mkdir()
    (target / 'METADATA').write_text('Metadata-Version: 2.1\\nName: contract\\nVersion: 1.0\\n')
    return target.name
def build_wheel(*args, **kwargs):
    raise RuntimeError('metadata operation must not build')
''')
    return names, project, index


def test_real_pip_captures_static_and_dynamic_build_requirements(tmp_path):
    names, project, index = metadata_project(tmp_path)
    report = tmp_path / 'report.json'
    runtime = {'root': tmp_path, 'env': {
        'PATH': os.environ['PATH'], 'HOME': str(tmp_path),
        'PIP_NO_INDEX': '1', 'PIP_FIND_LINKS': str(index),
        'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}}
    observed = pool._native_metadata_command([
        sys.executable, '-m', 'pip', 'install', '--dry-run', '--ignore-installed',
        '--report', report, project], runtime, tmp_path)
    assert {value for group in observed for value in group} == {name + '==1.0' for name in names}
    assert json.loads(report.read_text())['install'][0]['metadata']['name'] == 'contract'


def test_real_npm_uses_isolated_configuration_and_lock_only_mode(tmp_path, monkeypatch):
    npm = shutil.which('npm')
    if npm is None or shutil.which('node') is None:
        pytest.skip('real npm and Node.js executables are unavailable')
    package = Path(npm).resolve().parents[1]
    metadata = json.loads((package/'package.json').read_bytes())
    archive = tmp_path/'cli.tgz'
    with tarfile.open(archive, 'w:gz', dereference=True) as output:
        output.add(package, arcname='package')
    with isolated_pool() as candidate:
        sha = candidate.put(archive, 'contract', 'observed-npm-cli')
        # Acquisition metadata is the explicit unit boundary. The actual host
        # npm distribution, archive extraction, Node and CLI execute for real.
        monkeypatch.setattr(pool, '_pinned_npm_version', lambda: metadata['version'])
        monkeypatch.setattr(pool, 'npm_cli_artifact', lambda *args: (
            sha, {'engine': metadata['engines']['node']}))
        project = tmp_path/'project'; project.mkdir()
        (project/'package.json').write_text(json.dumps({'name': 'generated-contract', 'version': '1.0.0',
            'scripts': {'install': 'node -e "process.exit(37)"'}}))
        env = {'PATH': os.environ['PATH'], 'HOME': str(tmp_path),
               'NPM_CONFIG_USERCONFIG': os.devnull, 'NPM_CONFIG_GLOBALCONFIG': os.devnull,
               'npm_config_cache': str(tmp_path/'cache')}
        pool._run_pinned_npm(candidate, ['install', '--package-lock-only', '--ignore-scripts',
            '--offline', '--no-audit', '--no-fund'], cwd=project, env=env)
        assert json.loads((project/'package-lock.json').read_bytes())['packages']['']['name'] == 'generated-contract'
        assert not (project/'node_modules').exists()


def test_markers_and_extras_match_real_pip(tmp_path):
    index = tmp_path / 'index'; index.mkdir()
    root = 'contract_root'; extra = 'additional'
    nested = 'nested'
    requirements = ['contract_base==1.0; extra == ""',
                    root + '[' + nested + ']; extra == ' + json.dumps(extra),
                    'contract_extra==1.0; extra == ' + json.dumps(nested)]
    for name, requires in [(root, requirements), ('contract_base', []), ('contract_extra', [])]:
        (index / (name + '-1.0-py3-none-any.whl')).write_bytes(
            wheel_bytes(name, '1.0', requires, [extra, nested] if name == root else []))
    report = tmp_path / 'report.json'
    env = dict(os.environ, PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1')
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--find-links', str(index),
                    '--dry-run', '--ignore-installed', '--report', str(report),
                    root + '[' + extra + ']'], env=env, check=True, capture_output=True)
    installed = {item['metadata']['name'] for item in json.loads(report.read_text())['install']}
    roots, remote = pool._native_project_requirements(
        {'name': root, 'version': '1.0', 'requires_dist': requirements}, current_target(), [extra])
    expected = {pool._parse_registry_requirement(value).name for value in roots}
    assert not remote and all(pool._parse_registry_requirement(value).marker is None for value in roots)
    assert installed == {root, *expected}


@settings(max_examples=20, deadline=None)
@given(st.binary(min_size=1, max_size=512))
def test_publication_proof_binds_exact_bytes_and_operation(payload):
    if os.geteuid() != 0:
        pytest.skip('publication ownership contract requires root')
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        operation = hashlib.sha256(payload).hexdigest()
        inventory = {'kind': 'download-only-pool', 'complete': True, 'issues': [],
                     'operation_id': operation}
        raw = jobs.canonical(inventory)
        path = folder / 'inventory.json'; path.write_bytes(raw); path.chmod(0o444)
        folder.chmod(0o555)
        proof = {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'kind': inventory['kind']}
        try:
            assert jobs.verify_published_inventory(folder, {'operation_id': operation}, proof) == inventory
            with pytest.raises(RuntimeError):
                jobs.verify_published_inventory(folder, {'operation_id': operation + 'changed'}, proof)
            with pytest.raises(RuntimeError):
                jobs.verify_published_inventory(folder, {'operation_id': operation},
                    {**proof, 'manifest_sha256': hashlib.sha256(raw + payload).hexdigest()})
        finally:
            folder.chmod(0o700)


@settings(max_examples=20, deadline=None)
@given(st.integers(min_value=1, max_value=10), st.integers(min_value=0, max_value=3), st.booleans())
def test_publication_retries_preserve_one_sealed_generation(attempt, interruptions, renamed):
    if os.geteuid() != 0:
        pytest.skip('publication ownership contract requires root')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        base = root/'base'; base.write_bytes(b'unchanged base')
        directory = root/'dependency-pool'; directory.mkdir()
        operation = hashlib.sha256(jobs.canonical([attempt, interruptions, renamed])).hexdigest()
        original = directory/('incoming-' + operation + '-' + str(attempt))
        original.mkdir()
        inventory = {'kind': 'download-only-pool', 'complete': True, 'operation_id': operation}
        raw = jobs.canonical(inventory)
        (original/'inventory.json').write_bytes(raw)
        (original/'inventory.json').chmod(0o444)
        original.chmod(0o555)
        ready = directory/'ready'
        if renamed: original.rename(ready)
        proof = {'kind': inventory['kind'], 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
                 'runtime_integrated': 'pending'}
        calls = []
        def integrate(manager, state, folder, result):
            assert folder == ready and result == proof
            assert state['publication_attempt'] == attempt
            calls.append(state['attempt'])
            if len(calls) <= interruptions:
                raise OSError('generated integration interruption')
            return {**result, 'runtime_integrated': True}
        state = {'operation_id': operation, 'attempt': attempt, 'publication_verified': proof,
                 'publication_attempt': attempt}
        manager = SimpleNamespace(base=base)
        account = SimpleNamespace(pw_uid=1, pw_gid=os.getgid())
        try:
            with patch('pwd.getpwnam', return_value=account), \
                    patch.object(jobs, '_integrate_published_pool', side_effect=integrate):
                for retry in range(interruptions + 1):
                    state['attempt'] = attempt + retry + 1
                    if retry < interruptions:
                        with pytest.raises(OSError, match='interruption'):
                            jobs._prepare(manager, state)
                    else:
                        assert jobs._prepare(manager, state)['runtime_integrated'] is True
            assert (ready/'inventory.json').read_bytes() == raw
            assert not original.exists()
            assert sorted(path.name for path in directory.iterdir()) == ['ready']
            assert base.read_bytes() == b'unchanged base'
        finally:
            for path in directory.iterdir():
                if path.is_dir(): path.chmod(0o700)

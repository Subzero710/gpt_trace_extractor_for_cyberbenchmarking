from __future__ import annotations

import hashlib
import subprocess
import json
import os
from pathlib import Path
import sys
import zipfile

import pytest

import superbench_pool as pool


def _wheel(folder, name):
    path = folder / (name + '-1.0-py3-none-any.whl')
    info = name + '-1.0.dist-info'
    files = {
        name + '.py': 'value = 1\n',
        info + '/METADATA': 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n',
        info + '/WHEEL': 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    files[info + '/RECORD'] = ''.join(name + ',,\n' for name in files) + info + '/RECORD,,\n'
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return path


def test_actual_pip_static_and_dynamic_build_layers(tmp_path, monkeypatch):
    wheels = {name: _wheel(tmp_path, name) for name in ('fixture_static', 'fixture_dynamic')}
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'pyproject.toml').write_text('''[build-system]
requires = ["fixture_static==1.0"]
build-backend = "fixture_backend"
backend-path = ["."]
''')
    (source / 'fixture_backend.py').write_text('''from pathlib import Path
import fixture_static

def get_requires_for_build_wheel(config_settings=None):
    assert fixture_static.value == 1
    return ["fixture_dynamic==1.0"]

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    import fixture_dynamic
    assert fixture_dynamic.value == 1
    root = Path(metadata_directory) / "fixture_project-1.0.dist-info"
    root.mkdir()
    (root / "METADATA").write_text("Metadata-Version: 2.1\\nName: fixture_project\\nVersion: 1.0\\nRequires-Dist: fixture_dynamic==1.0\\n")
    return root.name
''')
    runtime = {'root': tmp_path, 'env': {
        'PATH': os.environ['PATH'], 'HOME': str(tmp_path), 'PIP_CONFIG_FILE': '/dev/null',
        'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
        '_pip_byte_progress': pool._NativePipByteProgress(1)}
    requests = []
    def resolve(requirements):
        requests.append(requirements)
        return [str(wheels[row.split('==')[0]]) for row in requirements]
    runtime['_native_build_resolver'] = resolve
    monkeypatch.setattr(pool, '_native_interpreter_has_stdlib_distutils', lambda *_: False)
    report = tmp_path / 'report.json'
    interpreter = tmp_path / 'interpreter'
    subprocess.run([sys._base_executable, '-m', 'venv', str(interpreter)],
                   check=True, timeout=pool._operation_timeout())
    python = interpreter / 'bin' / 'python'
    try:
        observed = pool._native_metadata_command(
            [python, '-m', 'pip', 'install', '--use-pep517', '--dry-run',
             '--ignore-installed', '--no-deps', '--report', report, source], runtime, tmp_path)
    finally:
        runtime['_pip_byte_progress'].close()
    assert requests == [['fixture_static==1.0'], ['fixture_dynamic==1.0']]
    assert {frozenset(group) for group in observed} == {
        frozenset({'fixture_static==1.0'}), frozenset({'fixture_dynamic==1.0'})}
    assert json.loads(report.read_bytes())['install'][0]['metadata']['requires_dist'] == ['fixture_dynamic==1.0']


def _declared(project, setup, config='', *, extras=(), python='3.8.20'):
    from types import SimpleNamespace
    target = SimpleNamespace(python_full_version=python, markers={
        'python_version': '.'.join(python.split('.')[:2]), 'python_full_version': python})
    files = {'pyproject.toml': project, 'setup.py': setup, 'setup.cfg': config}
    return pool._declarative_local_metadata(lambda name, required=False: files.get(name),
        target, extras, ['python -m pip install -e .'])


_BUILD_SYSTEM = '''[build-system]
requires = ["setuptools>=61", "wheel", "compiler-helper>=1"]
'''
_PROJECT = '''
[project]
name = "generated"
dynamic = ["version"]
requires-python = ">=3.8"
dependencies = ["base>=1", "legacy; python_version<'3.10'", "modern; python_version>='3.10'"]
[project.optional-dependencies]
outer = ["generated[inner]", "outer-only; extra == 'outer'", "excluded; extra != 'outer'"]
inner = ["extra-lib>=1"]
'''
_SETUP = '''from setuptools import setup
if __name__ == '__main__':
    setup(version=external_version(), ext_modules=expensive_compilation(), cmdclass=commands())
'''


def test_declarative_pep621_version_and_extensions_do_not_require_backend():
    result = _declared(_BUILD_SYSTEM + _PROJECT, _SETUP, '[flake8]\nmax-line-length=88', extras={'outer'})
    assert result == ({'base>=1', 'legacy', 'outer-only', 'extra-lib>=1'}, set(),
                      ('compiler-helper>=1', 'setuptools>=61', 'wheel'))
    modern, _, _ = _declared(_BUILD_SYSTEM + _PROJECT, _SETUP, python='3.11.10')
    assert modern == {'base>=1', 'modern'}


def test_declarative_legacy_setup_cfg_with_non_dependency_setup_arguments():
    result = _declared(_BUILD_SYSTEM, _SETUP, '''[metadata]
name = generated
[options]
python_requires = >=3.8
install_requires =
    base>=1
    legacy; python_version<'3.10'
[options.extras_require]
test = pytest>=7
''', extras={'test'})
    assert result == ({'base>=1', 'legacy', 'pytest>=7'}, set(),
                      ('compiler-helper>=1', 'setuptools>=61', 'wheel'))


@pytest.mark.parametrize('setup', [
    'from setuptools import setup\nsetup(install_requires=unknown())',
    'from setuptools import setup\nsetup(setup_requires=["build-plugin"])',
    'from setuptools import setup\nsetup(**unknown())',
    'from setuptools import setup\nsetup(extras_require={"test": ["extra"]})',
])
def test_setup_dependency_overrides_remain_native(setup):
    assert _declared(_BUILD_SYSTEM + _PROJECT, setup) is None


def test_dynamic_dependencies_and_competing_metadata_remain_native():
    assert _declared(_BUILD_SYSTEM + _PROJECT.replace('"version"', '"dependencies"'), _SETUP) is None
    assert _declared(_BUILD_SYSTEM + _PROJECT, _SETUP, '[options]\ninstall_requires=other') is None
    assert _declared(_BUILD_SYSTEM + 'build-backend="custom_backend"\n' + _PROJECT, _SETUP) is None
    assert _declared(_BUILD_SYSTEM, _SETUP, '[metadata]\nname=generated\n[options]\ninstall_requires=file: reqs.txt') is None


def test_build_dependency_producer_uses_verified_cas_and_reuses_exact_selection(tmp_path, monkeypatch):
    instance = pool.Pool(tmp_path / 'stage')
    target = pool._target_environment_module().capture_current()
    runtime = {'root': tmp_path / 'native'}
    path = _wheel(tmp_path, 'fixture_static')
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    instance.put(path, 'python', 'fixture')
    record = {'kind': 'wheel', 'name': 'fixture_static', 'version': '1.0',
              'filename': path.name, 'sha256': sha, 'requirements': [], 'provides_extra': []}
    seen = []
    def resolve(candidate, selected, roots, constraints, key, *, resolver_cache):
        assert candidate is instance and selected == target
        assert roots == ('fixture_static==1.0',) and not constraints
        assert 'metadata_executor' not in resolver_cache
        seen.append(key)
        return [record]
    monkeypatch.setattr(pool, '_resolve_registry_plan', resolve)
    try:
        first = pool._native_build_wheels(instance, target, runtime, ['fixture_static==1.0'])
        second = pool._native_build_wheels(instance, target, runtime, ['fixture_static==1.0'])
        assert first == second and len(seen) == 1
        assert Path(first[0]).samefile(instance.objects / sha[:2] / sha)
    finally:
        instance._pip_cache_context.cleanup()


@pytest.mark.parametrize('installer_api', ['finder', 'for_req'])
def test_launcher_uses_common_build_environment_entrypoint(monkeypatch, installer_api):
    import socket
    from types import SimpleNamespace
    from pip._internal import build_env
    from pip._internal.cli import main as cli
    from pip._internal.utils import subprocess as pip_subprocess

    class LegacyEnvironment:
        def install_requirements(self, finder, requirements, prefix_as_string, *, kind):
            raise AssertionError('original installer must not execute')

    class ModernEnvironment:
        def install_requirements(self, requirements, prefix_as_string, *, kind, for_req=None):
            raise AssertionError('original installer must not execute')

    environment_type = LegacyEnvironment if installer_api == 'finder' else ModernEnvironment
    environment = environment_type()
    prefix = SimpleNamespace(path='/fixture/prefix', setup=False)
    empty = SimpleNamespace(path='/fixture/empty', setup=False)
    environment._prefixes = {'overlay': prefix, 'normal': empty}
    calls = []
    monkeypatch.setattr(build_env, 'BuildEnvironment', environment_type)
    monkeypatch.setattr(build_env, 'get_runnable_pip', lambda: '/fixture/pip')
    monkeypatch.setattr(pip_subprocess, 'call_subprocess',
                        lambda argv, **kwargs: calls.append(argv))
    parent, child = socket.socketpair()
    with parent, child:
        parent.sendall(b'["/fixture/one.whl", "/fixture/two.whl"]\n')
        fd = child.detach()
        monkeypatch.setattr(sys, 'argv', ['launcher', str(fd), 'install', '.'])

        def main():
            def invoke(requirements, layer):
                if installer_api == 'finder':
                    environment.install_requirements(object(), requirements, layer, kind='build')
                else:
                    environment.install_requirements(requirements, layer, kind='build', for_req=object())
            invoke([], 'normal')
            invoke(['one', 'two', 'one'], 'overlay')
            return 0

        monkeypatch.setattr(cli, 'main', main)
        with pytest.raises(SystemExit) as error:
            exec(pool._NATIVE_PIP_BUILD_LAUNCHER, {})
        assert error.value.code == 0
        assert json.loads(parent.makefile('rb').readline()) == {'requirements': ['one', 'two']}
    assert prefix.setup and empty.setup
    assert len(calls) == 2
    for argv, wheel in zip(calls, ['one.whl', 'two.whl']):
        assert argv[:3] == [sys.executable, '/fixture/pip', 'install']
        assert argv[argv.index('--prefix') + 1] == prefix.path
        assert {'--no-index', '--no-deps', '--no-compile'} <= set(argv)
        assert argv[-1] == '/fixture/' + wheel

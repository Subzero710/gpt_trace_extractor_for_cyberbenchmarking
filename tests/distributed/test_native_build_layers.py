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


@pytest.mark.parametrize('interpreter_source', ['ci-pip', 'ensurepip'])
def test_actual_pip_static_and_dynamic_build_layers(tmp_path, monkeypatch, interpreter_source):
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
    creation = [sys._base_executable, '-m', 'venv']
    if interpreter_source == 'ci-pip':
        creation.append('--without-pip')
    subprocess.run([*creation, str(interpreter)], check=True, timeout=pool._operation_timeout())
    python = interpreter / 'bin' / 'python'
    if interpreter_source == 'ci-pip':
        import importlib.metadata
        import shutil
        import pip
        destination = Path(subprocess.check_output([
            python, '-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
            text=True, timeout=pool._operation_timeout()).strip())
        distribution = importlib.metadata.distribution('pip')
        metadata, = (distribution.locate_file(path).parent for path in distribution.files
                     if path.name == 'METADATA' and path.parent.name.endswith('.dist-info'))
        package = Path(pip.__file__).parent
        shutil.copytree(package, destination / package.name)
        shutil.copytree(metadata, destination / metadata.name)
        assert subprocess.check_output([python, '-I', '-c', 'import pip; print(pip.__version__)'],
                                       text=True, timeout=pool._operation_timeout()).strip() == pip.__version__
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


def _declared(project, setup, config='', *, extras=(), python='3.8.20', commands=None):
    from types import SimpleNamespace
    target = SimpleNamespace(python_full_version=python, markers={
        'python_version': '.'.join(python.split('.')[:2]), 'python_full_version': python})
    files = {'pyproject.toml': project, 'setup.py': setup, 'setup.cfg': config}
    return pool._declarative_local_metadata(lambda name, required=False: files.get(name),
        target, extras, ['python -m pip install -e .'] if commands is None else commands)


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


_MESON_BUILD_SYSTEM = """[build-system]
requires = ["meson-python", "meson", "Cython", "numpy"]
build-backend = "mesonpy"
"""


def test_meson_nonisolated_install_reads_only_pinned_pep621_dependencies():
    commands = ['python -m pip install "numpy<2"; '
                'python -m pip install -ve .[outer] --no-build-isolation -Ceditable-verbose=true']
    result = _declared(_MESON_BUILD_SYSTEM + _PROJECT,
                       'raise AssertionError("setup.py is not a Meson metadata source")',
                       '[options]\ninstall_requires=unrelated',
                       extras={'outer'}, python='3.10.14', commands=commands)
    assert result == ({'base>=1', 'modern', 'outer-only', 'extra-lib>=1'}, set(), ())
    _, _, _, issues, _, _, steps = pool.pip_commands(commands)
    assert not issues
    assert not steps[0]['no_build_isolation'] and not steps[0]['local_project']
    assert steps[1]['no_build_isolation'] and steps[1]['local_project']



def test_meson_declarative_analysis_never_reads_setuptools_files():
    from types import SimpleNamespace
    target = SimpleNamespace(python_full_version='3.10.15', markers={
        'python_version': '3.10', 'python_full_version': '3.10.15'})
    def read(name):
        assert name == 'pyproject.toml'
        return _MESON_BUILD_SYSTEM + _PROJECT
    assert pool._declarative_local_metadata(read, target, (), [
        'pip install . --no-build-isolation']) == ({'base>=1', 'modern'}, set(), ())


def test_meson_static_version_and_target_python_validation():
    project = _PROJECT.replace('dynamic = ["version"]', 'version = "1.0"')
    commands = ['pip install . --no-build-isolation']
    assert _declared(_MESON_BUILD_SYSTEM + project, '', commands=commands) == (
        {'base>=1', 'legacy'}, set(), ())
    with pytest.raises(RuntimeError, match='Requires-Python rejects target'):
        _declared(_MESON_BUILD_SYSTEM + project, '', python='3.7.17', commands=commands)


@pytest.mark.parametrize('commands', [
    ['pip install -e .'],
    ['pip install --no-build-isolation compiler; pip install -e .'],
    ['pip install -e . --config-settings --no-build-isolation'],
    ['pip install -e . --no-build-isolation; pip install .'],
    ['pip install -e . --no-build-isolation --no-use-pep517'],
    ['python setup.py develop; pip install -e . --no-build-isolation'],
    ['python setup.py egg_info; pip install -e . --no-build-isolation'],
    ['echo "--no-build-isolation"; pip install .'],
])
def test_meson_requires_explicit_nonisolated_pep517_recipe(commands):
    assert _declared(_MESON_BUILD_SYSTEM + _PROJECT, '', commands=commands) is None


@pytest.mark.parametrize('project', [
    _PROJECT.replace('"version"', '"dependencies"'),
    _PROJECT.replace('"version"', '"version", "optional-dependencies"'),
    _PROJECT.replace('"version"', '"version", "requires-python"'),
    _PROJECT.replace('dynamic = ["version"]', ''),
    _PROJECT.replace('dynamic = ["version"]', 'version = "1.0"\ndynamic = ["version"]'),
    _PROJECT.replace('"generated[inner]"', '"generated[inner]==1.0"'),
])
def test_meson_requires_complete_declarative_dependency_metadata(project):
    assert _declared(_MESON_BUILD_SYSTEM + project, '', extras={'outer'},
                     commands=['pip install -e .[outer] --no-build-isolation']) is None


def test_meson_with_backend_path_or_missing_project_is_not_declarative():
    commands = ['pip install -e . --no-build-isolation']
    assert _declared(_MESON_BUILD_SYSTEM, '', commands=commands) is None
    assert _declared(_MESON_BUILD_SYSTEM + 'backend-path = ["."]\n' + _PROJECT,
                     '', commands=commands) is None


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


@pytest.mark.parametrize('installer_api', ['legacy', 'subprocess', 'inprocess', 'venv'])
def test_launcher_uses_verified_build_environment_installer(monkeypatch, installer_api):
    import abc
    import socket
    from types import SimpleNamespace
    from pip._internal import build_env
    from pip._internal.cli import main as cli
    from pip._internal.utils import subprocess as pip_subprocess

    class LegacyEnvironment:
        def install_requirements(self, finder, requirements, prefix_as_string, *, kind):
            raise AssertionError('original installer must not execute')

    class ModernEnvironment(abc.ABC):
        @abc.abstractmethod
        def install_requirements(self, requirements, prefix_as_string, *, kind, for_req=None):
            raise AssertionError('abstract base is not an installer')

    class SubprocessInstaller:
        def install(self, requirements, prefix, *, kind, for_req):
            raise AssertionError('original subprocess installer must not execute')

    class InprocessInstaller:
        def install(self, requirements, prefix, *, kind, for_req):
            raise AssertionError('original inprocess installer must not execute')

    class VirtualEnvironment(ModernEnvironment):
        def install_requirements(self, requirements, prefix_as_string, *, kind, for_req=None):
            prefix = self._prefixes[prefix_as_string]
            assert not prefix.setup
            prefix.setup = True
            if requirements:
                self.installer.install(requirements, prefix, kind=kind, for_req=for_req)

    if installer_api == 'legacy':
        monkeypatch.setattr(build_env, 'BuildEnvironment', LegacyEnvironment)
        environment = LegacyEnvironment()
    else:
        monkeypatch.setattr(build_env, 'BuildEnvironment', ModernEnvironment)
        monkeypatch.setattr(build_env, 'SubprocessBuildEnvironmentInstaller', SubprocessInstaller, raising=False)
        monkeypatch.setattr(build_env, 'InprocessBuildEnvironmentInstaller', InprocessInstaller, raising=False)
        environment = VirtualEnvironment()
        environment.installer = InprocessInstaller() if installer_api == 'inprocess' else SubprocessInstaller()
    prefix = SimpleNamespace(path='/fixture/prefix', setup=False)
    if installer_api == 'venv':
        prefix.venv_executable = '/fixture/venv/bin/python'
    empty = SimpleNamespace(path='/fixture/empty', setup=False)
    environment._prefixes = {'overlay': prefix, 'normal': empty}
    calls = []
    monkeypatch.delattr(build_env, 'get_runnable_pip', raising=False)
    monkeypatch.setattr(pip_subprocess, 'call_subprocess',
                        lambda argv, **kwargs: calls.append(argv))
    parent, child = socket.socketpair()
    with parent, child:
        parent.sendall(b'["/fixture/one.whl", "/fixture/two.whl"]\n')
        fd = child.detach()
        monkeypatch.setattr(sys, 'argv', ['launcher', str(fd), 'install', '.'])

        def main():
            def invoke(requirements, layer):
                if installer_api == 'legacy':
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
        with parent.makefile('rb') as reply:
            assert json.loads(reply.readline()) == {'requirements': ['one', 'two']}
            assert reply.read() == b''
    assert prefix.setup and empty.setup
    assert len(calls) == 2
    command = [sys.executable, '-I', '-m', 'pip']
    if installer_api == 'venv':
        command.extend(['--python', prefix.venv_executable])
    for argv, wheel in zip(calls, ['one.whl', 'two.whl']):
        assert argv[:len(command) + 1] == [*command, 'install']
        assert argv[argv.index('--prefix') + 1] == prefix.path
        assert {'--no-index', '--no-deps', '--no-compile'} <= set(argv)
        assert argv[-1] == '/fixture/' + wheel

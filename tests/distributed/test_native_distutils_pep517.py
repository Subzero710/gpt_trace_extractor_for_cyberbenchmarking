"""Regression: isolated PEP 517 metadata must use the target CPython's distutils."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import pytest
import superbench_pool as pool


def test_vendored_distutils_export_gap_is_exact_nameerror():
    # This is the import pattern used by historical numpy.distutils.
    # The module's __all__ controls whether the CCompiler symbol is visible.
    import types
    import sys as _sys
    fake = types.ModuleType('distutils.ccompiler')
    fake.CCompiler = type('CCompiler', (), {})
    fake.__all__ = ['new_compiler']
    fake.new_compiler = object()
    namespace = {}
    with patch.dict(_sys.modules, {'distutils.ccompiler': fake}):
        exec('from distutils.ccompiler import *', namespace)
        with pytest.raises(NameError, match='CCompiler'):
            exec('from distutils.ccompiler import *\nCCompiler', {})
    assert 'CCompiler' not in namespace
    assert 'new_compiler' in namespace


@pytest.mark.parametrize(('available', 'expected_flag'),
                         [(True, 'stdlib'), (False, None)])
def test_native_metadata_uses_real_interpreter_capability_only(available, expected_flag):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime = {'root': root, 'env': {'HOME': str(root), 'PATH': os.defpath}}
        original = dict(runtime['env'])
        seen = []
        def run(argv, selected_runtime, *, interpreter=None, **_kwargs):
            seen.append((list(argv), dict(selected_runtime['env']), interpreter))
            if argv[1] == '-c':
                assert selected_runtime['env']['SETUPTOOLS_USE_DISTUTILS'] == 'stdlib'
                return b'usable\n' if available else b'absent\n'
            return b''
        with patch.object(pool, '_native_run', side_effect=run), \
             patch.object(pool, '_native_build_requirements', return_value=[]):
            python = Path(sys.executable)
            for _ in range(2):
                assert pool._native_metadata_command([python, '-m', 'pip', 'install', 'pkg'], runtime, root) == []
        assert len(seen) == 3  # Capability is checked only once per locked interpreter.
        assert seen[0][2] == python
        assert seen[0][0][1] == '-c'
        for _argv, environment, selected in seen[1:]:
            assert selected == python
            assert ('SETUPTOOLS_USE_DISTUTILS' in environment) == available
            assert environment.get('SETUPTOOLS_USE_DISTUTILS') == expected_flag
            assert Path(environment['TMPDIR']).name.startswith('build-metadata-')
            assert environment['PYTHONUNBUFFERED'] == '1'
            assert _argv[-1] == '--no-clean'
            assert '--verbose' in _argv
        assert runtime['env'] == original


def test_broken_locked_stdlib_distutils_is_fatal():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime = {'root': root, 'env': {'HOME': str(root), 'PATH': os.defpath}}
        with patch.object(pool, '_native_run', return_value=b'broken\n'):
            with pytest.raises(RuntimeError, match='does not export CCompiler'):
                pool._native_interpreter_has_stdlib_distutils(runtime, Path(sys.executable))


def test_actual_absent_stdlib_does_not_force_legacy_distutils():
    import subprocess
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        runtime={'root':root,'env':{'HOME':str(root),'PATH':os.defpath}}
        result=pool._native_interpreter_has_stdlib_distutils(runtime,Path(sys.executable))
        import sysconfig
        expected=(Path(sysconfig.get_path('stdlib'))/'distutils'/'ccompiler.py').is_file()
        assert result is expected


def test_real_pep517_build_hook_output_is_visible_to_native_reader(tmp_path, monkeypatch):
    """A real, offline PEP 517 hook must reach the pip reader, not pip's hidden log."""
    import contextlib
    import io
    import subprocess

    project = tmp_path / 'hook-project'
    project.mkdir()
    (project / 'pyproject.toml').write_text(
        '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n')
    marker = 'native-pep517-hook-emitted-output'
    (project / 'backend.py').write_text(
        'from pathlib import Path\n'
        'def get_requires_for_build_wheel(config_settings=None):\n'
        f'    print({marker!r}, flush=True)\n'
        '    return []\n'
        'def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n'
        '    folder = Path(metadata_directory) / "native_probe-1.0.dist-info"\n'
        '    folder.mkdir()\n'
        '    (folder / "METADATA").write_text("Metadata-Version: 2.1\\nName: native-probe\\nVersion: 1.0\\n")\n'
        '    (folder / "WHEEL").write_text("Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")\n'
        '    return folder.name\n')
    runtime = {'root': tmp_path, 'env': {
        'HOME': str(tmp_path), 'PATH': os.environ['PATH'],
        'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        'PIP_NO_INPUT': '1', 'PYTHONDONTWRITEBYTECODE': '1'}}
    command = [sys.executable, '-m', 'pip', 'install', '--use-pep517',
               '--dry-run', '--ignore-installed', '--no-deps', '--no-index', str(project)]

    # Verify the actual pip subprocess hides the hook output at normal verbosity.
    hidden = subprocess.run([*command, '--no-clean'], cwd=tmp_path, env=runtime['env'],
                            capture_output=True, timeout=45, check=True)
    assert marker.encode() not in hidden.stdout + hidden.stderr

    seen = []
    original = pool._native_run

    def inspect(argv, local, **kwargs):
        value = original(argv, local, **kwargs)
        if '--verbose' in argv:
            seen.append(value)
        return value

    monkeypatch.setattr(pool, '_native_run', inspect)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            assert pool._native_metadata_command(command, runtime, tmp_path) == []
        finally:
            if '_pip_byte_progress' in runtime:
                runtime['_pip_byte_progress'].close()
    assert len(seen) == 1
    assert marker.encode() in seen[0]


def test_real_silent_buffered_pep517_hook_stays_observable(tmp_path, monkeypatch):
    import contextlib
    import io
    import textwrap

    project = tmp_path / 'hook-project'
    project.mkdir()
    (project / 'pyproject.toml').write_text(
        '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n')
    (project / 'backend.py').write_text(textwrap.dedent('''\
        import time
        from pathlib import Path

        def get_requires_for_build_wheel(config_settings=None):
            for step in range(8):
                print(f"cython progress {step}")
                time.sleep(0.55)
            return []

        def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
            folder = Path(metadata_directory) / "native_probe-1.0.dist-info"
            folder.mkdir()
            (folder / "METADATA").write_text(
                "Metadata-Version: 2.1\\nName: native-probe\\nVersion: 1.0\\n")
            (folder / "WHEEL").write_text(
                "Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")
            return folder.name
        '''))
    runtime = {'root': tmp_path, 'env': {
        'HOME': str(tmp_path), 'PATH': os.environ['PATH'],
        'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        'PIP_NO_INPUT': '1', 'PYTHONDONTWRITEBYTECODE': '1'}}
    command = [sys.executable, '-m', 'pip', 'install', '--use-pep517',
               '--dry-run', '--ignore-installed', '--no-deps', '--no-index', str(project)]
    runtime['_pip_byte_progress'] = pool._NativePipByteProgress(1)
    monkeypatch.setattr(pool, '_native_pip_timeouts', lambda: (15, 3))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 1)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            assert pool._native_metadata_command(command, runtime, tmp_path) == []
        finally:
            runtime['_pip_byte_progress'].close()
    assert 'PYTHONUNBUFFERED' not in runtime['env']

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
            assert _argv[-1] == '--no-clean'
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

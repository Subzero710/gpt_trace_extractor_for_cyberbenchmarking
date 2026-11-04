"""Generic real-process contracts for isolated native package-tool execution.

Only disposable prefixes are used; no package/version, network origin, host
installation or historical incident is encoded in this suite.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import os
from pathlib import Path
import sys
import tempfile

import pytest

import superbench_pool as pool


def _fixture(root):
    root = Path(root)
    base = root / 'conda' / 'bin'
    base.mkdir(parents=True)
    (base / 'python').symlink_to(Path(sys.executable).resolve())
    entry = root / 'native-entrypoint'
    entry.write_text('#!/usr/bin/env python\nimport shutil\nprint(shutil.which("python"))\n')
    entry.chmod(0o700)
    runtime = {'root': root, 'env': {'PATH': os.defpath, 'HOME': str(root)}}
    return runtime, entry, base / 'python'


def test_native_entrypoint_resolution_is_private_and_target_specific():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime, entry, base_python = _fixture(root)
        original = dict(runtime['env'])
        target = root / 'locked' / hashlib.sha256(os.fsencode(directory)).hexdigest() / 'bin'
        target.mkdir(parents=True)
        python = target / 'python'
        python.symlink_to(Path(sys.executable).resolve())
        for selected, expected in ((None, base_python), (python, python)):
            found = Path(pool._native_run([entry], runtime, interpreter=selected).decode().strip())
            assert found == expected
            assert found.samefile(expected)
            assert runtime['env'] == original


def test_native_versioned_interpreter_has_private_python_alias():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime, entry, _ = _fixture(root)
        named = root / 'target' / 'bin'
        named.mkdir(parents=True)
        binary = named / ('python' + '.'.join(map(str, sys.version_info[:2])))
        binary.symlink_to(Path(sys.executable).resolve())
        resolved = Path(pool._native_run([entry], runtime, interpreter=binary).decode().strip())
        assert resolved.name == 'python'
        assert resolved.parent.is_relative_to(root / 'python-launchers')
        assert resolved.is_symlink() and resolved.resolve() == binary.resolve()
        assert runtime['env']['PATH'] == os.defpath


def test_concurrent_targets_never_share_process_environment():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime, entry, _ = _fixture(root)
        names = []
        for index in range(4):
            folder = root / 'targets' / hashlib.sha256(str(index).encode()).hexdigest() / 'bin'
            folder.mkdir(parents=True)
            python = folder / 'python'
            python.symlink_to(Path(sys.executable).resolve())
            names.append(python)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(names)) as executor:
            found = list(executor.map(
                lambda selected: Path(pool._native_run([entry], runtime, interpreter=selected).decode().strip()),
                names * 3))
        assert found == names * 3
        assert runtime['env']['PATH'] == os.defpath


def test_metadata_subprocess_binds_its_explicit_interpreter():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime, entry, _ = _fixture(root)
        target = root / 'target' / 'bin'
        target.mkdir(parents=True)
        python = target / 'python'
        python.symlink_to(Path(sys.executable).resolve())
        recorded = root / 'seen'
        command = ('import pathlib,subprocess; '
                   + 'with_target = subprocess.check_output([' + repr(str(entry)) + ']); '
                   + 'pathlib.Path(' + repr(str(recorded)) + ').write_bytes(with_target)')
        assert pool._native_metadata_command([python, '-c', command], runtime, root) == []
        assert recorded.read_text().strip() == str(python)


def test_native_build_closure_reads_metadata_not_unrelated_entrypoint_symlinks():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        # Test fixture names are temporary and not live package identities.
        layer = root / 'pip-build-env-fixture'
        metadata = layer / 'overlay' / 'lib' / 'site-packages' / 'generated-1.0.dist-info' / 'METADATA'
        metadata.parent.mkdir(parents=True)
        metadata.write_text('Metadata-Version: 2.1\nName: generated\nVersion: 1.0\n')
        executable = layer / 'overlay' / 'bin' / 'tool'
        executable.parent.mkdir(parents=True)
        executable.symlink_to(Path(sys.executable).resolve())
        assert pool._native_build_requirements(root) == [['generated==1.0']]
        metadata.unlink()
        metadata.symlink_to(executable)
        with pytest.raises(RuntimeError):
            pool._native_build_requirements(root)

"""Offline source syntax classification tests, without network or VM."""
from __future__ import annotations
import io
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import superbench_pool as pool


def _make_tar(path, setup, *, pyproject=None):
    with tarfile.open(path, 'w:gz') as archive:
        for name, content in [('pkg/setup.py', setup),
                              *(([('pkg/pyproject.toml', pyproject)] if pyproject is not None else []))]:
            payload = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_target_python_rejects_historical_python2_setup(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    _make_tar(archive, "print 'legacy python2 setup'\n")
    with pytest.raises(pool._IncompatibleSourceSyntax, match='line 1'):
        pool._check_legacy_setup_syntax(archive, sys.executable)


def test_valid_old_setup_is_not_rejected(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    _make_tar(archive, 'from setuptools import setup\nsetup()\n')
    pool._check_legacy_setup_syntax(archive, sys.executable)


def test_syntax_check_skips_backend_that_does_not_execute_setup_py(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    _make_tar(archive, "print 'python2 syntax'\n", pyproject='''[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n''')
    pool._check_legacy_setup_syntax(archive, sys.executable)


def test_setuptools_build_backend_does_check_setup_py(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    _make_tar(archive, "print 'legacy python2'\n", pyproject='''[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n''')
    with pytest.raises(pool._IncompatibleSourceSyntax):
        pool._check_legacy_setup_syntax(archive, sys.executable)


def test_zip_sdist_same_semantics(tmp_path):
    archive = tmp_path / 'pkg-0.5.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('pkg/setup.py', "print 'legacy python2'\n")
    with pytest.raises(pool._IncompatibleSourceSyntax):
        pool._check_legacy_setup_syntax(archive, sys.executable)


def test_corrupt_archive_is_not_misclassified_as_unusable_candidate(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    archive.write_bytes(b'corrupt')
    with pytest.raises(tarfile.TarError):
        pool._check_legacy_setup_syntax(archive, sys.executable)


def test_python_invocation_failure_is_fatal_not_a_candidate_rejection(tmp_path):
    archive = tmp_path / 'pkg-0.5.tar.gz'
    _make_tar(archive, "print 'legacy python2'\n")
    with pytest.raises(FileNotFoundError):
        pool._check_legacy_setup_syntax(archive, tmp_path/'nonexistent')

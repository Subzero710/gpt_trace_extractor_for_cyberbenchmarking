"""Source candidate admission with verified archive and target metadata evidence."""
from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest
import superbench_pool as pool


@pytest.fixture(scope='module')
def interpreter(tmp_path_factory):
    import pip
    root = tmp_path_factory.mktemp('interpreter')
    subprocess.run([sys._base_executable, '-m', 'venv', '--without-pip', str(root)],
                   check=True, timeout=pool._operation_timeout())
    python = root / 'bin' / 'python'
    purelib = Path(subprocess.check_output([
        python, '-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
        text=True, timeout=pool._operation_timeout()).strip())
    dist = importlib.metadata.distribution('pip')
    metadata, = (dist.locate_file(path).parent for path in dist.files
                 if path.name == 'METADATA' and path.parent.name.endswith('.dist-info'))
    shutil.copytree(Path(pip.__file__).parent, purelib / 'pip')
    shutil.copytree(metadata, purelib / metadata.name)
    return python


def source_fixture(tmp_path, monkeypatch, name, version, *, interpreter):
    filename = 'fixture_project-1.0.tar.gz'
    source = tmp_path / filename
    project = '''[build-system]
requires = []
build-backend = "fixture_backend"
backend-path = ["."]
'''
    metadata = f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nRequires-Dist: dependency>=1\n'
    backend = f'''from pathlib import Path

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    folder = Path(metadata_directory) / {name.replace('-', '_') + '-' + version + '.dist-info'!r}
    folder.mkdir()
    (folder / 'METADATA').write_text({metadata!r})
    return folder.name
'''
    with tarfile.open(source, 'w:gz') as archive:
        for path, data in [('pyproject.toml', project), ('fixture_backend.py', backend)]:
            payload = data.encode()
            member = tarfile.TarInfo('fixture_project-1.0/' + path)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    instance = pool.Pool(tmp_path / 'stage')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    instance.put(source, 'python-source', 'fixture')
    url = 'https://files.pythonhosted.org/packages/' + filename
    candidate = {'kind': 'sdist', 'name': 'fixture-project', 'version': '1.0',
                 'filename': filename, 'item': {'url': url, 'digests': {'sha256': sha}}}
    def download(actual_url, category, key, *, sha):
        assert actual_url == url
        return instance.reference(sha, category, key, instance.verify_object(sha))
    monkeypatch.setattr(instance, 'download', download)
    runtime = {'root': tmp_path / 'native', 'env': {
        'PATH': os.environ['PATH'], 'HOME': str(tmp_path), 'PIP_CONFIG_FILE': '/dev/null',
        'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
        '_pip_byte_progress': pool._NativePipByteProgress(1)}
    runtime['root'].mkdir()
    monkeypatch.setattr(pool, '_native_pool_runtime', lambda _: runtime)
    monkeypatch.setattr(pool, '_native_locked_python', lambda *_: interpreter)
    target = pool._target_environment_module().capture_current()
    return instance, candidate, target, runtime


@pytest.mark.parametrize('name,version,accepted', [
    ('Fixture_Project', '1.0.0', True),
    ('another-project', '1.0', False),
    ('fixture-project', '2.0', False),
])
def test_real_target_pip_source_identity(tmp_path, monkeypatch, interpreter, name, version, accepted):
    instance, candidate, target, runtime = source_fixture(
        tmp_path, monkeypatch, name, version, interpreter=interpreter)
    try:
        if accepted:
            result = pool._native_source_candidate_metadata(instance, candidate, 'fixture', target)
            assert result['name'] == name
            assert result['version'] == version
            assert result['requirements'] == ['dependency>=1']
        else:
            with pytest.raises(pool._IncompatibleSourceIdentity) as error:
                pool._native_source_candidate_metadata(instance, candidate, 'fixture', target)
            assert f'declares {name!r}=={version!r}' in str(error.value)
            assert "expected 'fixture-project'=='1.0'" in str(error.value)
            assert candidate['item']['digests']['sha256'] in str(error.value)
    finally:
        runtime['_pip_byte_progress'].close()
        instance._pip_cache_context.cleanup()


@pytest.mark.parametrize('metadata,wrong_origin,match', [
    ({'name': None, 'version': '1.0'}, False, 'invalid native single-source metadata fields'),
    ({'name': 'other', 'version': 'invalid'}, False, 'invalid native single-source version identity'),
    ({'name': 'other', 'version': '1.0', 'requires_dist': ''}, False, 'invalid native single-source metadata fields'),
    ({'name': 'other', 'version': '1.0', 'requires_dist': ['not a requirement']}, False, 'invalid source dependency metadata'),
    ({'name': 'other', 'version': '1.0', 'provides_extra': [False]}, False, 'invalid native single-source metadata fields'),
    ({'name': 'other', 'version': '1.0'}, True, 'report differs from verified CAS input'),
])
def test_malformed_or_unverified_report_remains_fatal(tmp_path, monkeypatch, metadata, wrong_origin, match):
    instance, candidate, target, runtime = source_fixture(
        tmp_path, monkeypatch, 'fixture-project', '1.0', interpreter=Path(sys.executable))
    def command(argv, local, root):
        report = Path(argv[argv.index('--report') + 1])
        archive = Path(argv[-1])
        origin = archive.with_name('other.tar.gz') if wrong_origin else archive
        report.write_text(json.dumps({'install': [{'metadata': metadata,
            'download_info': {'url': origin.as_uri()}}]}))
        return []
    monkeypatch.setattr(pool, '_native_metadata_command', command)
    try:
        with pytest.raises(RuntimeError, match=match) as error:
            pool._native_source_candidate_metadata(instance, candidate, 'fixture', target)
        assert not isinstance(error.value, pool._IncompatibleSourceCandidate)
    finally:
        runtime['_pip_byte_progress'].close()
        instance._pip_cache_context.cleanup()

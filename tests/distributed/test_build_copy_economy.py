"""Local-copy regression tests: no network or KVM required."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('builder_copy_economy', ROOT / 'scripts/build_local_templates.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_git_mirror_reuses_objects_but_never_shares_mutable_refs(tmp_path):
    source = tmp_path / 'verified.git'
    destination = tmp_path / 'private.git'
    subprocess.run(['git', 'init', '--bare', '--quiet', str(source)], check=True)
    oid = subprocess.check_output(
        ['git', '--git-dir', str(source), 'hash-object', '-w', '--stdin'],
        input=b'object with no reference', text=False).decode().strip()
    # An unreferenced object MUST survive: fetch pins commits by SHA, not refs.
    builder.copy_git_mirror(source, destination)
    assert subprocess.run(['git', '--git-dir', str(destination), 'cat-file', '-e', oid],
                          check=False).returncode == 0
    source_object = source / 'objects' / oid[:2] / oid[2:]
    destination_object = destination / 'objects' / oid[:2] / oid[2:]
    assert source_object.stat().st_ino == destination_object.stat().st_ino
    assert source_object.stat().st_dev == destination_object.stat().st_dev
    assert (source / 'HEAD').stat().st_ino != (destination / 'HEAD').stat().st_ino
    (destination / 'HEAD').write_text('ref: refs/heads/test-only\n')
    assert (source / 'HEAD').read_text() != (destination / 'HEAD').read_text()


def test_git_mirror_links_pack_objects_without_sharing_configuration(tmp_path):
    source = tmp_path / 'verified.git'
    destination = tmp_path / 'private.git'
    subprocess.run(['git', 'init', '--bare', '--quiet', str(source)], check=True)
    blob = subprocess.check_output(
        ['git', '--git-dir', str(source), 'hash-object', '-w', '--stdin'],
        input=b'full pack object', text=False).decode().strip()
    subprocess.run(['git', '--git-dir', str(source), 'pack-objects',
                    str(source / 'objects' / 'pack' / 'pack')],
                   input=(blob + '\n').encode(), check=True, capture_output=True)
    builder.copy_git_mirror(source, destination)
    packs = list((source / 'objects' / 'pack').glob('*.pack'))
    assert packs
    for pack in packs:
        copy = destination / 'objects' / 'pack' / pack.name
        assert pack.stat().st_ino == copy.stat().st_ino
    assert (source / 'config').stat().st_ino != (destination / 'config').stat().st_ino


def test_prepared_cache_proof_binds_only_real_warm_output():
    item={'base_commit':'a'*40,'env_hash':'b'*64}
    sha='c'*64
    proof=builder.prepared_setup_proof(item,{'sha256':sha})
    assert proof=={'schema':builder.TASK_RUNTIME_SCHEMA,
                   'base_commit':item['base_commit'],
                   'env_hash':item['env_hash'],
                   'setup_cache_sha256':sha,
                   'network_isolated':True}
    assert 'offline' not in proof


def test_unverified_warm_cache_cannot_produce_setup_proof():
    import pytest
    with pytest.raises(RuntimeError,match='unverified task setup cache'):
        builder.prepared_setup_proof({'base_commit':'a'*40,'env_hash':'b'*64},
                                     {'sha256':'not-a-digest'})

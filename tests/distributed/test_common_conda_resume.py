import hashlib
import json
import runpy
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
runtime = runpy.run_path(str(ADAPTER / 'guest_runtime.py'))
ready = runtime['common_environment_ready']


@pytest.fixture
def checkpoint(tmp_path, monkeypatch):
    envs = tmp_path / 'miniconda' / 'envs'
    envs.mkdir(parents=True)
    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    prefix = envs / 'swegym_abc'
    inventory = metadata / 'abc.json'
    recipe = metadata / 'abc.recipe.json'
    proof = json.dumps({'lock_sha256': hashlib.sha256(b'lock').hexdigest(), 'transactions': 1}, sort_keys=True)
    actual = {'conda_explicit': '@EXPLICIT\n', 'pip_freeze': 'pkg==1\n'}
    monkeypatch.setitem(ready.__globals__, 'env_inventory', lambda path: actual)
    return prefix, inventory, recipe, proof, actual


def test_verified_environment_is_retained(checkpoint):
    prefix, inventory, recipe, proof, actual = checkpoint
    prefix.mkdir()
    marker = prefix / 'installed'
    marker.write_text('data')
    inventory.write_text(json.dumps(actual))
    recipe.write_text(proof)
    assert ready(prefix, inventory, recipe, proof)
    assert marker.read_text() == 'data'


@pytest.mark.parametrize('state', ['prefix-only', 'inventory-written', 'temporary-proof'])
def test_uncommitted_environment_can_restart(checkpoint, monkeypatch, state):
    prefix, inventory, recipe, proof, actual = checkpoint
    prefix.mkdir()
    (prefix / 'partial').write_text('incomplete')
    sibling = prefix.with_name('swegym_def')
    sibling.mkdir()
    (sibling / 'installed').write_text('keep')
    if state != 'prefix-only':
        inventory.write_text(json.dumps(actual))
    if state == 'temporary-proof':
        recipe.with_suffix('.json.tmp').write_text(proof)
    assert not ready(prefix, inventory, recipe, proof)
    assert not inventory.exists()
    assert not recipe.with_suffix('.json.tmp').exists()
    monkeypatch.setitem(ready.__globals__, 'CONDA', prefix.parent.parent / 'bin' / 'conda')
    original = ['conda create python=3.11']
    sha = hashlib.sha256(b'archive').hexdigest()
    record = {'stored_name': prefix.name, 'original_script': original}
    lock = {'environments': {'abc': {'recipe_sha256': hashlib.sha256(json.dumps(original, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), 'transactions': [{'python': '3.11', 'packages': [sha]}]}},
            'artifacts': {sha: {'sha256': sha, 'url': 'https://example.invalid/package.conda'}}}
    commands = runtime['locked_environment_script']('abc', record, lock)
    cleanup = next(command for command in commands if command.startswith('rm -rf '))
    assert shlex.split(cleanup)[-1] == str(prefix)
    assert commands.index(cleanup) > next(i for i, command in enumerate(commands) if command.startswith('test -f '))
    subprocess.run(shlex.split(cleanup), check=True)
    assert not prefix.exists()
    assert (sibling / 'installed').read_text() == 'keep'


@pytest.mark.parametrize('damage', ['wrong-proof', 'wrong-inventory', 'missing-inventory', 'missing-prefix'])
def test_committed_checkpoint_never_rebuilt(checkpoint, damage):
    prefix, inventory, recipe, proof, actual = checkpoint
    if damage != 'missing-prefix':
        prefix.mkdir()
    if damage != 'missing-inventory':
        inventory.write_text(json.dumps({} if damage == 'wrong-inventory' else actual))
    recipe.write_text('bad' if damage == 'wrong-proof' else proof)
    with pytest.raises(RuntimeError, match='committed Conda checkpoint differs'):
        ready(prefix, inventory, recipe, proof)
    assert recipe.exists()


@pytest.mark.parametrize('target', ['prefix', 'inventory', 'recipe', 'temporary'])
def test_symlink_is_never_used(checkpoint, tmp_path, target):
    prefix, inventory, recipe, proof, _ = checkpoint
    victim = tmp_path / 'victim'
    victim.write_text('keep')
    path = {'prefix': prefix, 'inventory': inventory, 'recipe': recipe,
            'temporary': recipe.with_suffix('.json.tmp')}[target]
    path.symlink_to(victim)
    with pytest.raises(RuntimeError, match='untrusted Conda checkpoint path'):
        ready(prefix, inventory, recipe, proof)
    assert victim.read_text() == 'keep'

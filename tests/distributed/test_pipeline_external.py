"""Opt-in real package-tool contracts in disposable host prefixes.

GPT_TRACE_NETWORK_TESTS=1 permits downloads from the configured upstreams.
These tests do not start services, modify a host prefix or claim Kali/KVM proof.
The interpreter matrix is the smallest committed transaction for each minor;
all other lock transactions still need full execution-host validation.
"""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

import superbench_pool as pool
from test_pipeline_properties import metadata_project


pytestmark = pytest.mark.skipif(
    os.environ.get('GPT_TRACE_NETWORK_TESTS') != '1',
    reason='real upstream acquisition requires GPT_TRACE_NETWORK_TESTS=1')
ROOT = Path(pool.__file__).resolve().parents[1]
ADAPTER = ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
LOCK, _LOCK_SHA = pool.load_conda_lock(
    ADAPTER, json.loads((ADAPTER/'pins.json').read_bytes()),
    json.loads((ADAPTER/'contract.json').read_bytes()))


def transaction_matrix():
    choices = {}
    for environment, value in sorted(LOCK['environments'].items()):
        for transaction in value['transactions']:
            candidate = (len(transaction['packages']), environment, transaction['key'])
            minor = transaction['python']
            if minor not in choices or candidate < choices[minor]:
                choices[minor] = candidate
    return [(minor, *choices[minor][1:]) for minor in sorted(choices)]


@pytest.fixture(scope='module')
def native_pool(tmp_path_factory):
    stage = tmp_path_factory.mktemp('native-package-contracts')
    (stage/'metadata').mkdir()
    (stage/'downloads').mkdir()
    candidate = pool.Pool(stage)
    candidate.conda_lock = LOCK
    # Optional read-only seed from an earlier disposable test acquisition.
    # Every copied object is independently rehashed; no plan or interpreter
    # is reused and the supplied directory is never modified.
    seed = os.environ.get('GPT_TRACE_TEST_CAS')
    if seed is not None:
        source_root = Path(seed).resolve(strict=True)
        for source in sorted(source_root.glob('*/*')):
            if source.is_symlink() or not source.is_file() or not pool.SHA.fullmatch(source.name):
                pytest.fail('invalid test CAS seed entry: ' + str(source))
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != source.name:
                pytest.fail('corrupted test CAS seed entry: ' + str(source))
            target = candidate.objects/source.name[:2]/source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    try:
        yield candidate
    finally:
        pool._native_close(candidate)
        candidate._pip_cache_context.cleanup()


@pytest.mark.parametrize('minor,environment,transaction', transaction_matrix(),
                         ids=[row[0] for row in transaction_matrix()])
def test_locked_interpreter_and_native_build_metadata(native_pool, tmp_path, minor, environment, transaction):
    module = pool._target_environment_module()
    target = module.locked_transaction_target(
        LOCK, environment, transaction, base_target=module.capture_current())
    assert target.python_version == minor
    python = pool._native_locked_python(native_pool, target)
    runtime = pool._native_pool_runtime(native_pool)
    assert pool._native_locked_python(native_pool, target) == python
    assert pool._native_bootstrap(native_pool, runtime).is_file()
    names, project, index = metadata_project(tmp_path)
    report = tmp_path/'metadata.json'
    offline = {**runtime, 'env': {**runtime['env'], 'PIP_NO_INDEX': '1', 'PIP_FIND_LINKS': str(index)}}
    observed = pool._native_metadata_command([python, '-m', 'pip', 'install', '--use-pep517',
        '--dry-run', '--ignore-installed', '--report', report, project], offline, tmp_path)
    assert {item for group in observed for item in group} == {name + '==1.0' for name in names}
    assert json.loads(report.read_bytes())['install'][0]['metadata']['name'] == 'contract'


def test_native_registry_resolution_acquisition_and_reuse(native_pool):
    _minor, environment, transaction = min(transaction_matrix(), key=lambda row: len(next(
        item['packages'] for item in LOCK['environments'][row[1]]['transactions'] if item['key'] == row[2])))
    module = pool._target_environment_module()
    target = module.locked_transaction_target(
        LOCK, environment, transaction, base_target=module.capture_current())
    selected = next(row for row in LOCK['environments'][environment]['transactions']
                    if row['key'] == transaction)
    # pip itself is a package with a version declared by this exact transaction.
    installer = next(LOCK['artifacts'][sha] for sha in selected['packages']
                     if LOCK['artifacts'][sha]['name'] == 'pip')
    requirements = [installer['name'] + '==' + installer['version']]
    key = pool.pip_group_key(target, requirements)
    group = {'target': target.as_dict(), 'requirements': requirements,
             'constraints': [], 'no_deps': False, 'required': True}
    assert pool.acquire_pip_group(native_pool, key, group) == 'acquired'
    before = dict(native_pool.links)
    assert pool.acquire_pip_group(native_pool, key, group) == 'reused'
    assert native_pool.links == before
    records = pool._read_pip_plan_tree(native_pool.stage, key)
    assert records[key]['target'] == target.as_dict()
    for row in records[key]['packages']:
        assert pool.digest(native_pool.objects/row['sha256'][:2]/row['sha256']) == row['sha256']


def test_native_npm_lock_only_ignores_install_scripts(native_pool, tmp_path, monkeypatch):
    npm = shutil.which('npm')
    if npm is None or shutil.which('node') is None:
        pytest.fail('real npm and Node.js executables are required')
    for scope in ('user', 'global'):
        (tmp_path/(scope + '.npmrc')).write_bytes(b'')
    environment = {'PATH': os.environ['PATH'], 'HOME': str(tmp_path),
                   'NPM_CONFIG_USERCONFIG': str(tmp_path/'user.npmrc'),
                   'NPM_CONFIG_GLOBALCONFIG': str(tmp_path/'global.npmrc'),
                   'npm_config_cache': str(tmp_path/'cache')}
    observed = subprocess.check_output([npm, '--version'], env=environment, text=True).strip()
    # Only the Golden identity boundary is a fixture; registry, SRI, archive
    # extraction, Node.js and the selected npm CLI all execute for real.
    monkeypatch.setattr(pool, '_pinned_npm_version', lambda: observed)
    (tmp_path/'package.json').write_text(json.dumps({
        'name': 'generated-contract', 'version': '1.0.0',
        'scripts': {'install': 'node -e "process.exit(37)"'}}))
    pool._run_pinned_npm(native_pool, ['install', '--package-lock-only', '--ignore-scripts',
                                     '--offline', '--no-audit', '--no-fund'],
                         cwd=tmp_path, env=environment)
    lock = json.loads((tmp_path/'package-lock.json').read_bytes())
    assert lock['packages']['']['name'] == 'generated-contract'
    assert not (tmp_path/'node_modules').exists()


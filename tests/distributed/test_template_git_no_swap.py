from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('no_swap_builder', 'scripts/build_local_templates.py')
guest = load('task_git_guest', 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py')


@pytest.mark.parametrize('with_vcs', [False, True])
def test_warm_git_configuration_without_home(tmp_path, monkeypatch, with_vcs):
    runtime, task = tmp_path / 'runtime', tmp_path / 'task'
    runtime.mkdir()
    task.mkdir()
    monkeypatch.setattr(guest, 'ROOT', runtime)
    monkeypatch.setattr(guest, 'TASK_INPUT_ROOT', task)
    rows = []
    url = 'https://github.com/example/project.git'
    if with_vcs:
        repo = tmp_path / 'repo'
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Test', '-c', 'user.email=test@example.com',
                        'commit', '--allow-empty', '-qm', 'test'], check=True)
        commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        archive = hashlib.sha256((url + '@' + commit).encode()).hexdigest() + '.git'
        (task / 'vcs').mkdir()
        subprocess.run(['git', 'clone', '-q', '--bare', str(repo), str(task / 'vcs' / archive)], check=True)
        rows.append({'url': url, 'commit': commit, 'archive': archive})
    (task / 'vcs-index.json').write_text(json.dumps(rows))
    for key in ('HOME', 'XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GPTTRACE_TEMPLATE_TRACE'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('GIT_ALLOW_PROTOCOL', 'file')
    config = runtime / 'attempt-vcs.gitconfig'
    config.write_text('[protocol "file"]\n\tallow = never\n')
    for _ in range(2):
        guest.seed_pool_vcs({})
        assert os.environ['GIT_CONFIG_GLOBAL'] == str(config)
        assert subprocess.check_output(['git', 'config', '--global', 'protocol.file.allow'], text=True).strip() == 'always'
        if with_vcs:
            assert subprocess.check_output(['git', 'ls-remote', url, 'HEAD'], text=True).split()[0] == commit
            assert len(subprocess.check_output(['git', 'config', '--global', '--get-regexp', 'insteadOf'], text=True).splitlines()) == 2


@pytest.mark.parametrize('trim', [False, True])
@pytest.mark.parametrize('shared', [False, True])
def test_firstboot_never_allocates_or_enables_swap(trim, shared):
    script = builder.firstboot('true', trim=trim, shared_warm_cache=shared)
    subprocess.run(['bash', '-n'], input=script, text=True, check=True)
    assert 'swapon' not in script
    assert 'mkswap' not in script
    assert 'fallocate' not in script
    assert 'swapoff -a' in script
    assert 'remove-legacy-swap rm --' in script
    assert ('filesystem-trim fstrim -av' in script) is trim
    assert ('template_step cache-mount mount' in script) is shared


def test_task_boot_preserves_native_stderr():
    tree = ast.parse((ROOT / 'scripts/build_local_templates.py').read_text())
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'task_boot')
    golden = hashlib.sha256(b'fixture golden').hexdigest()
    pool_manifest = hashlib.sha256(b'fixture pool manifest').hexdigest()
    namespace = {'TASK_RUNTIME_SCHEMA': builder.TASK_RUNTIME_SCHEMA, 'TASK_COMPLETION': builder.TASK_COMPLETION,
                 'job': {'compatibility': {'golden_sha256': golden}},
                 'publication': {'manifest_sha256': pool_manifest},
                 'digest': builder.digest, 'GUEST': builder.GUEST}
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<task_boot>', 'exec'), namespace)
    script, _ = namespace['task_boot']({'instance_id': 'sample'}, {}, mode='warm')
    python = script.split("<<'PY_GUEST'\n", 1)[1].rsplit('\nPY_GUEST', 1)[0]
    compile(python, '<guest>', 'exec')
    warm_calls = [call for call in ast.walk(ast.parse(python)) if isinstance(call, ast.Call)
                  and isinstance(call.func, ast.Subscript) and isinstance(call.func.slice, ast.Constant)
                  and call.func.slice.value == 'warm_task']
    assert len(warm_calls) == 1
    identity = next(kw.value for kw in warm_calls[0].keywords if kw.arg == 'common_identity')
    assert ast.literal_eval(identity) == {'golden_sha256': golden, 'pool_manifest_sha256': pool_manifest,
                                          'runtime_sha256': builder.digest(builder.GUEST)}
    handler = python[python.index('except BaseException as exc:'):]
    with pytest.raises(RuntimeError, match=r'fatal: \$HOME not set'):
        exec('try:\n    raise subprocess.CalledProcessError(128, ["git"], stderr=b"fatal: $HOME not set")\n' + handler,
             {'subprocess': subprocess})

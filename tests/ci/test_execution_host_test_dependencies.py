"""Fossil's distributed-test venv must include runner test extras, not its runtime."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _builder():
    spec = importlib.util.spec_from_file_location(
        'execution_host_build_dependency_contract', ROOT / 'scripts/build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(root, test_items, runtime_items):
    path = root / 'apps/runner/pyproject.toml'
    path.parent.mkdir(parents=True, exist_ok=True)
    import json
    path.write_text('[project]\n'
        + 'dependencies = ' + json.dumps(runtime_items) + '\n'
        + '[project.optional-dependencies]\n'
        + 'test = ' + json.dumps(test_items) + '\n', encoding='utf-8')
    return path


def test_runner_test_extras_derive_from_manifest_without_runtime_dependencies(tmp_path):
    declared = ['generated-test-one>=2', 'generated-test-two<3']
    _manifest(tmp_path, declared, ['generated-runtime-never-installed>=5'])
    assert _builder().runner_test_requirements(tmp_path) == tuple(declared)


def test_missing_or_empty_runner_test_extras_fail_closed(tmp_path):
    build = _builder()
    with pytest.raises(RuntimeError, match='missing trusted runner'):
        build.runner_test_requirements(tmp_path)
    _manifest(tmp_path, [], ['generated-runtime>=1'])
    with pytest.raises(RuntimeError, match='nonempty list'):
        build.runner_test_requirements(tmp_path)


def test_host_build_installs_runner_test_extras_only_in_disposable_test_venv(tmp_path, monkeypatch):
    declared = ['generated-test-one>=2', 'generated-test-two<3']
    runtime = ['generated-runtime-never-installed>=5']
    _manifest(tmp_path, declared, runtime)
    build = _builder()
    commands = []
    monkeypatch.setattr(build, 'run', lambda argv, **kwargs: commands.append(tuple(map(str, argv))))
    monkeypatch.setattr(build.subprocess, 'run',
                        lambda argv, **kwargs: commands.append(tuple(map(str, argv))))

    build.build_host_broker(tmp_path)

    installs = [args for args in commands if len(args) >= 4 and args[1:4] == ('-m', 'pip', 'install')]
    assert len(installs) == 2
    broker_python = str(tmp_path / '.venv-workstation-broker/bin/python')
    test_python = str(tmp_path / '.venv-execution-tests/bin/python')
    broker_install = next(args for args in installs if args[0] == broker_python)
    test_install = next(args for args in installs if args[0] == test_python)
    assert not any(item in broker_install for item in declared)
    assert test_install[-len(declared):] == tuple(declared)
    assert not any(item in test_install for item in runtime)
    assert not any('apps/runner' in item for item in test_install)
    assert (test_python, '-m', 'pip', 'check') in commands

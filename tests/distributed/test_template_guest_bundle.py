from __future__ import annotations

import importlib.util
import json
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('template_guest_bundle_builder', ROOT / 'scripts/build_local_templates.py')
packages = load('template_guest_bundle_packages', ROOT /
                'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/os_packages.py')


def controls():
    policy = tomllib.loads((ROOT / 'config/preparation.toml').read_text())['acquisition']
    return {'progress_interval_seconds': policy['progress_interval_seconds'],
            'cleanup_timeout_seconds': policy['broker_read_timeout_seconds']}


@pytest.mark.parametrize('previous', [{}, {'progress_interval_seconds': 1, 'cleanup_timeout_seconds': 1}])
def test_uploads_current_controls_and_supervisors_without_changing_golden_identity(tmp_path, previous):
    original = {'schema': 2, 'source': 'installed-source', 'packages': ['installed-package'], **previous}
    installed = dict(original)
    current = {**controls(), 'source': 'different-source', 'packages': ['different-package']}
    uploads = builder.template_bundle_upload_arguments(tmp_path, installed, current)
    files = dict((guest, Path(host)) for flag, spec in zip(uploads[::2], uploads[1::2])
                 for host, guest in [spec.split(':', 1)] if flag == '--upload')
    assert installed == original
    assert json.loads(files['/opt/gpt-trace/bundle/guest-contract.json'].read_bytes()) == {**original, **controls()}
    for guest_name, source_name in (('apt_downloads.py', 'apt_downloads.py'),
                                    ('conda_trace.py', 'template_conda_trace.py')):
        assert files['/opt/gpt-trace/bundle/' + guest_name] == ROOT / 'infra/workstation/image' / source_name
    assert len(files) == 3


@pytest.mark.parametrize('key', ['cleanup_timeout_seconds', 'progress_interval_seconds'])
def test_missing_current_control_fails_closed(tmp_path, key):
    current = controls()
    del current[key]
    with pytest.raises(KeyError, match=key):
        builder.template_bundle_upload_arguments(tmp_path, {}, current)
    assert not (tmp_path / 'guest-contract.json').exists()


@pytest.mark.parametrize('key', ['cleanup_timeout_seconds', 'progress_interval_seconds'])
def test_invalid_current_control_fails_closed(tmp_path, key):
    current = controls()
    current[key] = builder._versioned_host_subprocess_timeout() + 1
    with pytest.raises(RuntimeError, match='invalid template guest operation controls'):
        builder.template_bundle_upload_arguments(tmp_path, {}, current)


def test_actual_offline_installer_consumes_updated_contract(tmp_path, monkeypatch):
    legacy = {'schema': 2, 'packages': []}
    (tmp_path / 'guest-contract.json').write_text(json.dumps(legacy))
    monkeypatch.setattr(packages, 'Path', lambda value: tmp_path if str(value) == '/opt/gpt-trace/bundle' else Path(value))
    monkeypatch.setenv('GPTTRACE_TEMPLATE_TRACE', '1')
    monkeypatch.setenv('GPTTRACE_TEMPLATE_TIMEOUT', str(builder._versioned_host_subprocess_timeout()))
    command = ['unshare', '--net', 'apt-get', 'install', '/local/package.deb']
    with pytest.raises(KeyError, match='cleanup_timeout_seconds'):
        packages._install_archives(command, None)
    builder.template_bundle_upload_arguments(tmp_path, legacy, controls())
    observed = []
    monkeypatch.setattr(packages.runpy, 'run_path', lambda path: {
        'run_install': lambda args, **kwargs: observed.append((path, args, kwargs))})
    packages._install_archives(command, None)
    path, arguments, kwargs = observed.pop()
    assert path == str(tmp_path / 'apt_downloads.py')
    assert arguments == command[3:]
    assert kwargs['launcher'] == command[:2]
    assert kwargs['limit'] == builder._versioned_host_subprocess_timeout()
    assert kwargs['cadence'] == controls()['progress_interval_seconds']
    assert kwargs['env']['DEBIAN_FRONTEND'] == 'noninteractive'


def test_golden_constructor_is_masked_offline_even_without_completion_marker(tmp_path):
    import shutil
    import subprocess

    root = tmp_path / 'guest'
    units = root / 'etc/systemd/system'
    wants = units / 'multi-user.target.wants'
    wants.mkdir(parents=True)
    source = ROOT / 'infra/workstation/systemd/gpt-trace-golden-build.service'
    unit = units / source.name
    shutil.copyfile(source, unit)
    enabled = wants / source.name
    enabled.symlink_to(Path('..') / source.name)
    marker = root / 'etc/gpt-trace-image-build-complete'
    marker.write_text('ok\n')
    original = source.read_bytes()
    flag, command = builder.template_golden_isolation_arguments(root)
    assert flag == '--run-command'
    for _ in range(2):
        subprocess.run(['sh', '-ec', command], check=True, capture_output=True)
        assert unit.is_symlink() and unit.readlink() == Path('/dev/null')
        assert not enabled.is_symlink()
        status = subprocess.run(['systemctl', '--root=' + str(root), 'is-enabled', source.name],
                                capture_output=True, text=True)
        assert status.stdout.strip() == 'masked'
        marker.unlink(missing_ok=True)
    assert source.read_bytes() == original


def test_template_boot_does_not_append_previous_attempt_log():
    script = builder.firstboot('true')
    assert 'exec > /var/log/swe-gym-lite-builder.log 2>&1' in script
    assert 'exec >> /var/log/swe-gym-lite-builder.log' not in script
    assert 'template_step reset-completion rm -f' in script


def test_golden_mask_precedes_firstboot_registration_and_repo_runtime_refresh():
    import ast

    tree = ast.parse((ROOT / 'scripts/build_local_templates.py').read_text())
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    calls = [node for node in ast.walk(functions['provision']) if isinstance(node, ast.Call)
             and any(isinstance(arg, ast.Constant) and arg.value == '--firstboot' for arg in node.args)]
    assert len(calls) == 1
    arguments = calls[0].args
    mask = next(i for i, arg in enumerate(arguments) if isinstance(arg, ast.Starred)
                and isinstance(arg.value, ast.Call) and isinstance(arg.value.func, ast.Name)
                and arg.value.func.id == 'template_golden_isolation_arguments')
    boot = next(i for i, arg in enumerate(arguments) if isinstance(arg, ast.Constant) and arg.value == '--firstboot')
    assert mask < boot
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == 'template_golden_isolation_arguments'
               for node in ast.walk(functions['refresh_overlay_runtime']))

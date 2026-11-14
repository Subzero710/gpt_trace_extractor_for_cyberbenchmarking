"""Regression contract: all host preparation waits require finite deadlines."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOST_FILES = (
    'scripts/superbench_pool.py',
    'scripts/verified_resolver_bridge.py',
    'scripts/distributed.py',
    'scripts/build.py',
    'scripts/burn_fetch_zombies.py',
    'scripts/build_local_templates.py',
    'scripts/generate_swegym_conda_lock.py',
    'scripts/down.py',
    'scripts/throw_volumes.py',
    'scripts/tunnels.py',
    'apps/workstation-broker/src/workstation_broker/server.py',
    'apps/workstation-broker/src/workstation_broker/preparation.py',
    'infra/workstation/image/build.py',
)


def test_no_unbounded_host_subprocess_calls():
    for relative in HOST_FILES:
        tree = ast.parse((ROOT / relative).read_text(), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == 'subprocess'
                    and function.attr in {'run', 'check_output', 'check_call'}):
                assert any(k.arg == 'timeout' for k in node.keywords), (relative, node.lineno)


def test_preparation_waits_are_bounded():
    for relative in ('scripts/superbench_pool.py',
                     'scripts/verified_resolver_bridge.py',
                     'apps/workstation-broker/src/workstation_broker/preparation.py'):
        tree = ast.parse((ROOT / relative).read_text(), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not isinstance(function, ast.Attribute):
                continue
            name = ast.unparse(function)
            if name == 'concurrent.futures.as_completed':
                assert any(k.arg == 'timeout' for k in node.keywords), (relative, node.lineno)
            if function.attr == 'result' and isinstance(function.value, (ast.Name, ast.Subscript)):
                assert any(k.arg == 'timeout' for k in node.keywords), (relative, node.lineno)
            if name in {'process.wait', 'child.wait', 'thread.join', 'reader.join', 'self.thread.join'}:
                assert any(k.arg == 'timeout' for k in node.keywords), (relative, node.lineno)


def test_mandatory_native_deadline_and_independent_parent_watchdog():
    bridge = (ROOT / 'scripts/verified_resolver_bridge.py').read_text()
    rust = (ROOT / 'rust/verified-resolver/src/main.rs').read_text()
    parent = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
    assert 'wire.send_int(0, 8)' not in bridge
    assert 'deadline: Instant' in rust
    assert 'deadline: Option<Instant>' not in rust
    assert 'mandatory_deadline(deadline_seconds)?' in rust
    assert 'manager._progress(state)' in parent
    assert 'os.killpg(child.pid, signal.SIGKILL)' in parent


def test_no_whole_acquisition_deadline():
    policy = (ROOT / 'config/preparation.toml').read_text()
    assert 'job_timeout_hours' not in policy
    assert 'pip_total_timeout_seconds' in policy
    for relative in ('scripts/superbench_pool.py', 'scripts/distributed.py',
                     'apps/workstation-broker/src/workstation_broker/preparation.py'):
        source = (ROOT / relative).read_text()
        assert 'job_timeout_hours' not in source
    parent = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
    assert 'child.wait(timeout=cadence)' in parent
    assert 'acquisition made no verified progress' in parent

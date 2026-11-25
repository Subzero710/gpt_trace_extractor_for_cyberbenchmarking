from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tomllib
from pathlib import Path

import pytest

import distributed as dispatcher
from workstation_broker import preparation
from workstation_broker.fetch_egress import source_network


def test_dns_configuration_preserves_unrelated_settings():
    original = 'debug = true\n[dns]\nsearchDomains = ["home"]\nnameservers = ["192.0.2.1"]\n[worker.oci]\nmax-parallelism = 2\n'
    result = dispatcher._builder_dns_config(original, ['192.0.2.42', '192.0.2.42'])
    assert tomllib.loads(result) == {'debug': True, 'dns': {'searchDomains': ['home'],
        'nameservers': ['192.0.2.42']}, 'worker': {'oci': {'max-parallelism': 2}}}
    assert dispatcher._builder_dns_config(result, ['192.0.2.42']) == result
    assert tomllib.loads(dispatcher._builder_dns_config('debug = true', ['192.0.2.42'])) == {
        'debug': True, 'dns': {'nameservers': ['192.0.2.42']}}
    with pytest.raises(RuntimeError, match='usable DNS'):
        dispatcher._builder_dns_config(original, [])


@pytest.mark.parametrize('existing,active,mutated', [(False, False, True), (True, False, False), (True, True, False), (False, True, False)])
def test_dedicated_builder_dns_reconciliation(monkeypatch, existing, active, mutated):
    name = source_network()
    container = 'buildx_buildkit_fixture-node'
    identity = 'b'*64
    config = '[dns]\nnameservers = ["192.0.2.42"]' if existing else 'debug = true'
    changes = []

    def run(argv, *, capture=False, timeout):
        assert timeout > 0
        if argv[:3] == ['ip', 'netns', 'exec']:
            assert argv[3] == name
            return 'nameserver 192.0.2.42\n'
        if argv[:3] == ['docker', 'buildx', 'inspect']:
            assert argv[-1] == name
            return f'Name: {name}\nDriver: docker-container\nNodes:\nName: fixture-node\n'
        if argv[:2] == ['docker', 'inspect']:
            assert argv[-1] == container
            return json.dumps([{'Name': '/' + container, 'Id': identity,
                'State': {'Running': True}, 'HostConfig': {'NetworkMode': name}, 'Args': []}])
        if argv[:2] == ['docker', 'exec']:
            assert argv[2] == identity
            return config
        assert argv == ['docker', 'restart', identity]
        changes.append('restart')

    def write(argv, *, input, text, check, timeout):
        assert argv[:4] == ['docker', 'exec', '-i', identity]
        assert tomllib.loads(input)['dns']['nameservers'] == ['192.0.2.42']
        assert text and check and timeout > 0
        changes.append('write')

    monkeypatch.setattr(dispatcher, 'run', run)
    monkeypatch.setattr(dispatcher.subprocess, 'run', write)
    if active and not existing:
        with pytest.raises(RuntimeError, match='owns the build slot'):
            dispatcher.configure_fetch_builder_dns(allow_change=False)
    else:
        assert dispatcher.configure_fetch_builder_dns(allow_change=not active) == ['192.0.2.42']
    assert changes == (['write', 'restart'] if mutated else [])


def _final_progress(operation):
    return {'schema': 2, 'operation_id': operation, 'stage': 'Final inventory',
            'completed': 5, 'total': 5, 'unit': 'files', 'details': '', 'stage_epoch': 8,
            'network_bytes': 100, 'pip_bytes': 0, 'pip_active': 0, 'rx_bytes': 120,
            'volume': {'identified_bytes': 100, 'acquired_bytes': 100, 'artifacts': 2, 'complete': True}}


def test_sealing_does_not_reopen_worker_snapshot(tmp_path):
    operation = 'a'*64
    folder = tmp_path/'dependency-pool'/f'incoming-{operation}-1'/'metadata'
    folder.mkdir(parents=True)
    path = folder/'fetch-progress.json'
    final = _final_progress(operation)
    path.write_text(json.dumps(final)); path.chmod(0o600)
    manager = object.__new__(preparation.PreparationManager)
    manager.base = tmp_path/'golden.qcow2'
    state = {'operation_id': operation, 'attempt': 1, 'phase': 'running'}
    assert manager._progress(state) == final
    progress = preparation._integration_progress(final, 'Publication du pool')
    state['integration_progress'] = progress
    path.chmod(0o444)
    assert manager._progress(state) == progress
    path.unlink()
    assert manager._progress(state) == progress
    assert progress['volume'] == final['volume']


def test_published_pool_can_resume_with_inventory_bound_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(preparation, "safe", lambda path, **kwargs: Path(path))
    operation = 'a'*64
    ready = tmp_path/'ready'; (ready/'metadata').mkdir(parents=True)
    progress = _final_progress(operation)
    raw = json.dumps(progress).encode()
    snapshot = ready/'metadata/fetch-progress.json'
    snapshot.write_bytes(raw); snapshot.chmod(0o444)
    proof = {'kind': 'download-only-pool', 'tasks': 1, 'repos': 1, 'conda_recipes': 1, 'python_versions': ['3.12']}
    inventory = {**proof, 'operation_id': operation, 'complete': True, 'issues': [],
                 'files': [{'path': 'metadata/fetch-progress.json', 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}]}
    encoded = json.dumps(inventory).encode()
    (ready/'inventory.json').write_bytes(encoded); (ready/'inventory.json').chmod(0o444)
    ready.chmod(0o555)
    proof['manifest_sha256'] = hashlib.sha256(encoded).hexdigest()
    state = {'operation_id': operation, 'attempt': 2}
    assert preparation._published_progress(ready, state, proof) == progress
    # A fresh attempt observes the published pool without requiring the old incoming path.
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    step = preparation._integration_progress(progress, 'Construction des templates', 1, 3, 'étapes', 'test')
    view.update('validating', step)
    assert '1/3 étapes' in view.previous and 'Construction des templates' in view.previous
    assert 'restant 0.000' in view.volume_line
    snapshot.chmod(0o644); snapshot.write_bytes(raw+b' '); snapshot.chmod(0o444)
    with pytest.raises(RuntimeError, match='differs from its verified inventory'):
        preparation._published_progress(ready, state, proof)


def test_buildkit_failure_decodes_actual_vertex_output(monkeypatch):
    monkeypatch.setattr(dispatcher, '_buildkit_controls', lambda: (10, 5, 1))
    vertex = {'digest': 'one', 'name': '[1/2] RUN apt-get update', 'started': 'observed'}
    rows = [{'vertexes': [vertex]}, {'logs': [{'vertex': 'one', 'data': base64.b64encode(b"Temporary failure resolving 'deb.debian.org'\nE: Unable to locate package git\n").decode()}]},
            {'vertexes': [{**vertex, 'completed': 'observed', 'error': 'exit code: 100'}]}]
    code = '\n'.join(f'print({json.dumps(row)!r}, flush=True)' for row in rows) + '\nraise SystemExit(1)'
    seen = []
    with pytest.raises(RuntimeError, match="Temporary failure resolving 'deb.debian.org'"):
        dispatcher._run_buildkit([sys.executable, '-c', code], progress=lambda *args: seen.append(args))
    assert seen[0][:2] == (0, 2)


@pytest.mark.parametrize('stale', [True, False])
def test_up_restarts_only_stale_broker(tmp_path, monkeypatch, stale):
    from gpt_trace_transport import local_templates
    monkeypatch.setattr(local_templates, 'safe', lambda path, **kwargs: Path(path))
    cfg = {'paths': {'broker_runtime_directory': tmp_path}, 'deployment': {'control_id': 'control', 'execution_id': 'execution'}}
    record = tmp_path/'broker-process.json'
    expected = 'a'*64
    def publish(identity):
        record.write_text(json.dumps({'broker_identity': {'pid': 123}, 'source_sha256': identity, 'deployment': cfg['deployment']}))
        record.chmod(0o600)
    publish('b'*64 if stale else expected)
    commands = []
    def run(argv, **kwargs):
        commands.append(argv[1])
        if argv[1] == 'restart':
            publish(expected)
        if argv[1] == 'show':
            return '123'
    monkeypatch.setattr(dispatcher, 'run', run)
    monkeypatch.setattr(dispatcher, '_wait_local_broker', lambda _cfg: None)
    monkeypatch.setattr(dispatcher, '_broker_source_identity', lambda: expected)
    dispatcher._start_current_broker(cfg)
    assert commands.count('restart') == int(stale)

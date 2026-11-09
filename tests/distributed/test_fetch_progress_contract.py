"""Fetch terminal shows only the latest verified stage counters; errors remain in logs."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import distributed as dispatcher
import superbench_pool as pool
from workstation_broker import preparation as preparation


def _state(stage, operation_id, attempt=1):
    return {'schema': 1, 'operation_id': operation_id,
            'stage': stage, 'completed': 60, 'total': 296,
            'unit': 'closures', 'network_bytes': 2 * 1048576,
            'pip_bytes': 4 * 1048576, 'pip_active': 4}


def test_atomic_observed_counters_are_current_and_exact(tmp_path):
    directory = tmp_path/'metadata'
    directory.mkdir()
    operation_id = 'a'*64
    path = directory/'fetch-progress.json'
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=3600,
                              progress_path=path, operation_id=operation_id)
    view.update('Verified recovery')
    view.update('Pip closures', 0, 296, 'closures')
    view.update('Pip closures', 60, 296, 'closures')
    observed = json.loads(path.read_text())
    assert observed['operation_id'] == operation_id
    assert observed['completed'] == 60
    assert observed['total'] == 296
    assert observed['stage'] == 'Pip closures'
    assert path.stat().st_mode & 0o077 == 0
    view.update('Pip closures', 61, 296, 'closures')
    assert json.loads(path.read_text())['completed'] == 61


def test_broker_reads_only_valid_snapshot_and_does_not_need_log(tmp_path):
    manager = object.__new__(preparation.PreparationManager)
    manager.base = tmp_path/'golden.qcow2'
    manager.root = tmp_path/'preparations'
    operation_id = 'b'*64
    stage = tmp_path/'dependency-pool'/f'incoming-{operation_id}-1'/'metadata'
    stage.mkdir(parents=True)
    path = stage/'fetch-progress.json'
    payload = _state('Pip closures', operation_id)
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    state = {'operation_id': operation_id, 'attempt': 1, 'phase': 'running'}
    assert manager._progress(state) == payload
    result = manager._public(state)
    assert result['progress'] == payload
    assert 'live_log' not in result
    path.unlink()
    target = stage/'other.json'
    target.write_text(json.dumps(payload))
    path.symlink_to(target)
    with pytest.raises(RuntimeError, match='symlink'):
        manager._progress(state)


def test_terminal_shows_exact_ratio_without_debug_or_worker_log():
    output = io.StringIO()
    view = dispatcher._FetchBar(output)
    progress = _state('Pip closures', 'c'*64)
    view.update('running', progress)
    view.update('running', dict(progress, completed=61))
    view.finish(False)
    shown = output.getvalue()
    assert shown.count('\n') == 1
    assert '61/296 closures' in shown
    assert '(20.6%)' in shown
    assert '6.0 MiB reçus' in shown
    assert 'ÉCHEC' in shown
    assert 'WARNING' not in shown
    assert 'Traceback' not in shown
    assert 'required pip closure' not in shown


def test_unknown_total_has_no_fake_global_percent():
    output = io.StringIO()
    view = dispatcher._FetchBar(output)
    value = dict(_state('VCS dependency resolution', 'd'*64),
                 completed=123, total=None)
    view.update('running', value)
    view.finish(True)
    assert 'total non mesuré' in output.getvalue()
    assert '%' not in output.getvalue()
    assert 'TERMINÉ' in output.getvalue()

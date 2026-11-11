"""Fetch terminal shows only the latest verified stage counters; errors remain in logs."""
from __future__ import annotations

import io
import json
from types import SimpleNamespace
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


def test_fetch_download_speed_is_recent_observed_throughput(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    initial = dict(_state('Pip closures', 'e'*64), network_bytes=0,
                   pip_bytes=0, completed=0, pip_active=2)
    view.update('running', initial)
    assert '0.00 MiB/s' in view.previous
    clock[0] += 5
    transferred = dict(initial, network_bytes=8*1048576)
    view.update('running', transferred)
    assert '1.60 MiB/s' in view.previous
    assert '8.0 MiB reçus' in view.previous
    clock[0] += 2
    view.update('running', transferred)
    assert '1.14 MiB/s' in view.previous
    clock[0] += 12
    view.update('running', transferred)
    assert '0.00 MiB/s' in view.previous


def test_fetch_rate_uses_completed_work_when_no_download_is_active(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    initial = dict(_state('Static task analysis', 'f'*64), completed=0,
                   total=230, unit='recipes', network_bytes=0, pip_bytes=0,
                   pip_active=0)
    view.update('running', initial)
    clock[0] += 5
    view.update('running', dict(initial, completed=4))
    assert '48.0 recipes/min' in view.previous
    assert '4/230 recipes' in view.previous
    clock[0] += 12
    view.update('running', dict(initial, completed=4))
    # Work throughput is a trailing-minute average, so a short idle gap
    # does not instantly erase completed work.
    assert '14.1 recipes/min' in view.previous
    view.update('running', dict(initial, completed=5, stage='VCS dependency resolution'))
    assert '48.0 recipes/min' not in view.previous
    assert len(view.work_samples) == 1


def test_fetch_rate_resets_on_new_attempt_and_rejects_other_operation(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    initial = dict(_state('Pip closures', 'a'*64), completed=0,
                   network_bytes=0, pip_bytes=0, pip_active=1)
    view.update('running', initial)
    clock[0] += 5
    view.update('running', dict(initial, network_bytes=10*1048576))
    assert '2.00 MiB/s' in view.previous
    with pytest.raises(RuntimeError, match='changed operation'):
        view.update('running', dict(initial, operation_id='b'*64))
    view.reset()
    view.update('running', dict(initial, operation_id='b'*64))
    assert '0.00 MiB/s' in view.previous
    assert '2.00 MiB/s' not in view.previous


def test_live_download_rate_fits_normal_terminal(monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self):
            return True
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    # Rebind only the dispatcher's module reference: pytest also uses the
    # global shutil module, including get_terminal_size(fallback=...).
    monkeypatch.setattr(dispatcher, 'shutil', SimpleNamespace(
        get_terminal_size=lambda *args, **kwargs:
            __import__('os').terminal_size((100, 24))))
    stream = Terminal()
    view = dispatcher._FetchBar(stream, window_seconds=10)
    initial = dict(_state('Pip closures', 'a'*64), completed=27,
                   pip_bytes=0, network_bytes=0, pip_active=1)
    view.update('running', initial)
    clock[0] += 5
    view.update('running', dict(initial, network_bytes=42*1048576))
    assert '8.40 MiB/s' in view.previous
    assert '42.0 MiB reçus' in view.previous
    assert '27/296 closures (9.1%)' in view.previous
    assert len(view.previous) <= 99


def test_fetch_rate_counts_both_transfer_sources_without_estimates(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    first = dict(_state('Pip closures', 'a'*64), network_bytes=0,
                 pip_bytes=0, completed=0, pip_active=1)
    view.update('running', first)
    clock[0] += 5
    view.update('running', dict(first, network_bytes=2*1048576,
                                pip_bytes=3*1048576))
    assert '1.00 MiB/s' in view.previous
    assert '5.0 MiB reçus' in view.previous
    clock[0] += 12
    view.update('running', None)
    assert '0.00 MiB/s' in view.previous
    clock[0] += 5
    view.update('running', dict(first, network_bytes=2*1048576,
                                pip_bytes=3*1048576,
                                stage='Verifying final pool inventory',
                                completed=None, total=None, pip_active=0))
    assert '1.00 MiB/s' not in view.previous
    assert len(view.byte_samples) == 1


def test_transfer_and_recipe_rates_remain_distinct_during_same_stage(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    initial = dict(_state('Static task analysis', 'a'*64), completed=0,
                   total=230, unit='recipes', network_bytes=0, pip_bytes=0,
                   pip_active=0)
    view.update('running', initial)
    assert '0.0 recipes/min' in view.previous
    clock[0] += 5
    view.update('running', dict(initial, completed=4,
                                network_bytes=5*1048576, pip_active=1))
    assert '1.00 MiB/s' in view.previous
    assert '48.0 recipes/min' in view.previous
    clock[0] += 2
    view.update('running', dict(initial, completed=4,
                                network_bytes=5*1048576, pip_active=0))
    assert '0.71 MiB/s' in view.previous
    assert '34.3 recipes/min' in view.previous
    clock[0] += 12
    view.update('running', dict(initial, completed=4,
                                network_bytes=5*1048576, pip_active=0))
    assert '0.00 MiB/s' in view.previous
    assert '12.6 recipes/min' in view.previous
    assert view.previous.index('MiB/s') < view.previous.index('recipes/min')


def test_pip_closure_rate_does_not_replace_download_rate_when_idle(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    initial = dict(_state('Pip closures', 'b'*64), completed=0,
                   network_bytes=0, pip_bytes=0, pip_active=1)
    view.update('running', initial)
    assert '0.00 MiB/s' in view.previous
    assert '0.0 closures/min' in view.previous
    clock[0] += 5
    view.update('running', dict(initial, completed=5,
                                pip_active=0, network_bytes=10*1048576))
    assert '2.00 MiB/s' in view.previous
    assert '60.0 closures/min' in view.previous
    clock[0] += 12
    view.update('running', dict(initial, completed=5,
                                pip_active=0, network_bytes=10*1048576))
    assert '0.00 MiB/s' in view.previous
    assert '17.6 closures/min' in view.previous


def test_work_rate_uses_trailing_minute_not_byte_sampling_window(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(dispatcher.time, 'monotonic', lambda: clock[0])
    view = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    progress = dict(_state('Static task analysis', 'c'*64), completed=0,
                    total=230, unit='recipes', network_bytes=0, pip_bytes=0,
                    pip_active=0)
    view.update('running', progress)
    clock[0] += 5
    view.update('running', dict(progress, completed=10))
    assert '120.0 recipes/min' in view.previous
    clock[0] += 15
    view.update('running', dict(progress, completed=10))
    assert '30.0 recipes/min' in view.previous
    clock[0] += 41
    view.update('running', dict(progress, completed=10))
    assert '0.0 recipes/min' in view.previous


def test_both_rate_units_remain_visible_on_narrow_tty(monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(dispatcher, 'shutil', SimpleNamespace(
        get_terminal_size=lambda *args, **kwargs:
            __import__('os').terminal_size((80, 24))))
    view = dispatcher._FetchBar(Terminal(), window_seconds=10)
    progress = dict(_state('Static task analysis', 'd'*64), completed=76,
                    total=230, unit='recipes', pip_active=0)
    view.update('running', progress)
    assert '76/230' in view.previous
    assert '0.00 MiB/s' in view.previous
    assert '0.0 recipes/min' in view.previous
    assert len(view.previous) <= 79


def test_received_volume_and_both_units_fit_100_columns(monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(dispatcher, 'shutil', SimpleNamespace(
        get_terminal_size=lambda *args, **kwargs:
            __import__('os').terminal_size((100, 24))))
    view = dispatcher._FetchBar(Terminal(), window_seconds=10)
    progress = dict(_state('Static task analysis', 'e'*64), completed=76,
                    total=230, unit='recipes', network_bytes=42*1048576,
                    pip_bytes=0, pip_active=0)
    view.update('running', progress)
    assert '42.0 MiB reçus' in view.previous
    assert '0.00 MiB/s' in view.previous
    assert '0.0 recipes/min' in view.previous
    assert len(view.previous) <= 99

import pytest
from gpt_trace_transport.local_templates import namespace_rx_bytes, namespace_rx_delta, fetch_download_limit


def counters(eth, loop):
    return ('header\nheader\n' +
            'eth0: ' + ' '.join(map(str, [eth] + [0] * 15)) + '\n' +
            'lo: ' + ' '.join(map(str, [loop] + [0] * 15)) + '\n')


def test_network_budget_uses_received_bytes_and_ignores_loopback():
    before = namespace_rx_bytes(counters(20, 5))
    after = namespace_rx_bytes(counters(200, 1000000))
    assert namespace_rx_delta(before, after) == 180
    with pytest.raises(RuntimeError, match='reset'):
        namespace_rx_delta(after, before)
    with pytest.raises(RuntimeError, match='identity'):
        namespace_rx_delta(before, {'other': 300})


def test_download_limit_is_required_configured_gib():
    assert fetch_download_limit({'max_download_gib': 200}) == 214748364800
    for value in (0, -1, True, '200', 1.5):
        with pytest.raises(RuntimeError):
            fetch_download_limit({'max_download_gib': value})
    with pytest.raises(KeyError):
        fetch_download_limit({})


def test_terminal_phase_progress_uses_gib_not_raw_byte_counts():
    import io
    import distributed
    view = distributed._FetchBar(io.StringIO(), window_seconds=10)
    view.update('running', {'schema': 1, 'operation_id': 'a'*64,
                'stage': 'Pip materialization', 'completed': 3*1024**3,
                'total': 12*1024**3, 'unit': 'bytes', 'network_bytes': 3*1024**3,
                'pip_bytes': 0, 'pip_active': 4})
    assert '3.000/12.000 GiB (25.0%)' in view.previous
    assert 'bytes/min' not in view.previous


def test_worker_budget_callback_uses_sealed_policy_and_live_rx(monkeypatch, capsys):
    from pathlib import Path
    import tomllib
    import superbench_pool as pool
    from gpt_trace_transport.local_templates import FETCH_BUDGET_EXIT_CODE

    root = Path(pool.__file__).resolve().parents[1]
    with (root / 'config/preparation.toml').open('rb') as stream:
        limit = fetch_download_limit(tomllib.load(stream)['acquisition'])
    original_read_text = Path.read_text
    received = 20

    def read_text(path, *args, **kwargs):
        if path == Path('/proc/net/dev'):
            return counters(received, 0)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read_text)
    check = pool._fetch_download_budget(root, namespace_rx_bytes(counters(received, 0)))
    check(limit)
    received += 1
    check(limit - 1)
    with pytest.raises(SystemExit) as error:
        check(limit)
    assert error.value.code == FETCH_BUDGET_EXIT_CODE
    assert 'planned archive download exceeds fetch budget' in capsys.readouterr().err

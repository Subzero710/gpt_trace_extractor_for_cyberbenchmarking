"""Meaningful stage/byte progress without periodic unchanged log dumps."""
import io
import sys

import pytest
import superbench_pool as pool


def test_nontty_stage_milestones_without_repeated_heartbeat():
    stream=io.StringIO()
    view=pool._PoolProgress(stream,tty=False,interval=3600)
    view.update('Static task analysis',0,230,'recipes')
    for done in range(1,231):
        view.update('Static task analysis',done,230,'recipes')
        view.update('Static task analysis',done,230,'recipes')
    lines=stream.getvalue().splitlines()
    assert len(lines)<=12
    assert any('115/230 recipes' in line for line in lines)
    assert lines[-1].startswith('[pool] Static task analysis 230/230 recipes')
    assert not any('Pip transfers:' in line for line in lines)
    assert not any('\x1b' in line for line in lines)


def test_only_known_download_bytes_have_percentage():
    view=pool._PoolProgress(io.StringIO(),tty=False,interval=3600)
    view.update('Pip closures',0,10,'closures')
    assert '%' not in view._render()
    view.network_start('item','download',4*1024*1024)
    view.network_advance('item',1024*1024)
    assert '25.0% du fichier' in view._render()
    assert '1.0 MiB reçus' in view._render()
    view.network_end('item')
    assert '%' not in view._render()
    view.pip_update({'bytes':2048,'jobs':1,'file':None})
    assert '%' not in view._render()


def test_pip_status_is_integrated_with_current_stage():
    stream=io.StringIO()
    view=pool._PoolProgress(stream,tty=False,interval=1)
    view.update('Static task analysis',115,230,'recipes')
    view.pip_update({'bytes':1024*1024,'jobs':1,'file':('task',1024*1024,4*1024*1024)})
    assert 'Static task analysis 115/230 recipes' in view._render()
    assert '1 pip actifs' in view._render()
    assert '25.0% du fichier' in view._render()


def test_successful_subprocess_does_not_dump_logs(monkeypatch):
    stream=io.StringIO()
    view=pool._PoolProgress(stream,tty=False,interval=3600)
    monkeypatch.setattr(pool,'_POOL_PROGRESS',view)
    view.update('Static task analysis',1,3,'recipes')
    output=pool.invoke([sys.executable,'-c','print("test data")'],capture=True)
    assert output == 'test data\n'
    assert 'test data' not in stream.getvalue()


def test_failed_subprocess_reports_tail(monkeypatch,capsys):
    view=pool._PoolProgress(io.StringIO(),tty=False,interval=3600)
    monkeypatch.setattr(pool,'_POOL_PROGRESS',view)
    with pytest.raises(Exception):
        pool.invoke([sys.executable,'-c','import sys; print("failure detail"); sys.exit(2)'])
    assert 'failure detail' in capsys.readouterr().err

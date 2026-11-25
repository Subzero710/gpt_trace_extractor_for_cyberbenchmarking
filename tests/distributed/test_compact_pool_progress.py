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
    assert '%' not in view._render()
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
    assert '%' not in view._render()


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


@pytest.mark.parametrize('variants', [1, 2])
def test_global_pip_progress_tracks_distinct_passes_and_recursive_closures(tmp_path, monkeypatch, variants):
    import hashlib
    import json
    import threading
    from types import SimpleNamespace
    import distributed as dispatcher

    target = pool._target_environment_module().capture_current()
    def group(requirements):
        return {'target': target.as_dict(), 'requirements': requirements,
                'constraints': [], 'preferred_versions': {}, 'no_deps': False,
                'required': True, 'tasks': [], 'steps': []}

    groups = {pool.pip_group_key(target, rows): group(rows)
              for rows in (['demo>=1'], ['demo>=2'])}
    child = pool.pip_group_key(target, ['build-helper>=1'])
    candidate = pool.Pool(tmp_path)
    (tmp_path / 'metadata').mkdir()
    snapshots = []
    path = tmp_path / 'fetch-progress.json'
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=3600,
                              progress_path=path, operation_id='a' * 64)
    monkeypatch.setattr(pool, '_POOL_PROGRESS', view)
    report = pool._pool_progress
    def observe(*args, **kwargs):
        report(*args, **kwargs)
        snapshots.append(json.loads(path.read_bytes()))
    monkeypatch.setattr(pool, '_pool_progress', observe)
    monkeypatch.setattr(pool, '_pip_worker_controls', lambda: (2, 2))
    monkeypatch.setattr(pool, '_global_pip_policy', lambda: variants)
    calls = []
    lock = threading.Lock()

    def acquire(_pool, key, info, *, phase, selection, preferences_override):
        with lock:
            calls.append((key, phase, preferences_override is not None))
        if phase == 'publish':
            for row in selection['packages']:
                identity = object()
                view.network_start(identity, row['filename'], row['download_size'], sha=row['sha256'])
                view.network_advance(identity, row['download_size'])
                view.network_end(identity)
        if phase != 'plan':
            return selection
        name = 'build-helper' if key == child else 'demo'
        version = '2' if info['requirements'] == ['demo>=2'] else '1'
        kind = 'sdist' if info['requirements'] == ['demo>=1'] else 'wheel'
        sha = hashlib.sha256(f'{name}/{version}/{kind}'.encode()).hexdigest()
        return {'status': 'planned', 'packages': [
            {'name': name, 'version': version, 'kind': kind, 'sha256': sha,
             'build_requirements': [['build-helper>=1']] if kind == 'sdist' else [],
             'filename': f'{name}-{version}', 'url': f'https://files.pythonhosted.org/{name}-{version}',
             'download_size': 1024}]}

    monkeypatch.setattr(pool, 'acquire_pip_group', acquire)
    pool.acquire_pip_groups(candidate, groups)
    expected = len(groups) + 1
    by_stage = {}
    terminal = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
    for snapshot in snapshots:
        terminal.update('running', snapshot)
        by_stage.setdefault(snapshot['stage'], []).append(snapshot)
    # Polling can miss an entire short intervening stage. Even then a stage's
    # completed-work count must never go backwards across recursive frontiers.
    for stage, records in by_stage.items():
        sampled = dispatcher._FetchBar(io.StringIO(), window_seconds=10)
        for record in records:
            sampled.update('running', record)
        counts = [record['completed'] for record in records]
        assert counts == sorted(counts), stage
        assert all(record['completed'] <= record['total'] for record in records)
        assert records[-1]['completed'] == records[-1]['total']
    assert by_stage['Pip planning'][-1]['completed'] == expected
    assert by_stage['Pip source evidence'][-1]['completed'] == expected
    assert by_stage['Pip materialization'][-1]['unit'] == 'bytes'
    assert by_stage['Pip materialization'][-1]['completed'] == expected * 1024
    assert ('Pip alternatives' in by_stage) == (variants > 1)
    if variants > 1:
        assert by_stage['Pip alternatives'][-1]['completed'] == len(groups)
    assert sum(phase == 'plan' and not alternative for _, phase, alternative in calls) == expected
    assert sum(alternative for _, _, alternative in calls) == (len(groups) if variants > 1 else 0)
    assert sum(phase == 'sources' for _, phase, _ in calls) == expected
    assert sum(phase == 'publish' for _, phase, _ in calls) == expected


def test_phase_bytes_are_deduplicated_and_resumed_without_counting_old_traffic():
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=3600)
    view.begin_artifact_phase('Pip materialization', {
        'a'*64: {'size': 400, 'retained_bytes': 100, 'cached': False},
        'b'*64: {'size': 600, 'retained_bytes': 0, 'cached': False},
        'c'*64: {'size': 1000, 'retained_bytes': 0, 'cached': True}})
    assert view.phase_counts() == (100, 1000, 'bytes')
    view.network_start('first', 'a', 400, sha='a'*64, offset=100)
    view.network_advance('first', 100)
    view.network_end('first')
    view.network_start('retry', 'a', 400, sha='a'*64, offset=200)
    view.network_start('other', 'b', 600, sha='b'*64)
    view.network_advance('retry', 200)
    view.network_advance('other', 100)
    assert view.phase_counts() == (500, 1000, 'bytes')
    assert view.network_bytes == 400
    assert '50.0% de la phase' in view._render()
    assert 'du fichier' not in view._render()
    with pytest.raises(RuntimeError, match='size differs'):
        view.network_start('invalid', 'b', 601, sha='b'*64)


def test_global_volume_deduplicates_sha_across_phases_and_resolves_unknown_sizes():
    view = pool._PoolProgress(io.StringIO(), tty=False, interval=3600)
    a, b = 'a'*64, 'b'*64
    view.begin_artifact_phase('Pip materialization', {
        a: {'size': 400, 'retained_bytes': 100, 'cached': False}})
    view.network_start('pip', 'a', 400, sha=a, offset=100)
    view.network_advance('pip', 300)
    view.network_end('pip')
    view.artifact_verified(a,400)
    view.begin_artifact_phase('Conda archives', {
        a: {'size': 400, 'retained_bytes': 0, 'cached': True},
        b: {'size': None, 'retained_bytes': 0, 'cached': False}})
    assert view._volume()['identified_bytes'] == 400
    assert view.phase_counts()[2] == 'archives'
    assert '1 tailles à découvrir' in view._phase_details()
    view.network_start('conda','b',600,sha=b)
    view.network_advance('conda',200)
    assert view.phase_counts() == (200,600,'bytes')
    assert view._volume() == {'identified_bytes':1000,'acquired_bytes':600,'artifacts':2,'complete':False}
    view.network_advance('conda',400)
    view.network_end('conda')
    view.artifact_verified(b,600)
    view.close_volume({a:{'size':400},b:{'size':600}})
    assert view._volume() == {'identified_bytes':1000,'acquired_bytes':1000,'artifacts':2,'complete':True}
    assert view.network_bytes == 900


def test_inventory_freezes_progress_snapshot_before_hashing(tmp_path, monkeypatch):
    import json
    (tmp_path/'metadata').mkdir()
    candidate=pool.Pool(tmp_path)
    progress=tmp_path/'metadata'/'fetch-progress.json'
    view=pool._PoolProgress(io.StringIO(),tty=False,progress_path=progress,operation_id='a'*64)
    monkeypatch.setattr(pool,'_POOL_PROGRESS',view)
    view.update('Pip planning',0,1,'closures')
    with pytest.raises(RuntimeError,match='incomplete dependency closure'):
        pool.audit_inventory(candidate,{},{},{},'a'*64)
    inventory=json.loads((tmp_path/'inventory.json').read_bytes())
    row=next(row for row in inventory['files'] if row['path']=='metadata/fetch-progress.json')
    view.finish()
    assert row['sha256']==pool.digest(progress)
    assert row['size']==progress.stat().st_size


def test_apt_print_uris_volume_tracks_native_partial_and_completed_files(tmp_path, monkeypatch):
    import hashlib
    (tmp_path/'apt'/'archives'/'partial').mkdir(parents=True)
    view=pool._PoolProgress(io.StringIO(),tty=False,interval=3600)
    monkeypatch.setattr(pool,'_POOL_PROGRESS',view)
    candidate=pool.Pool(tmp_path)
    sha=hashlib.sha256(b'abcdef').hexdigest()
    archive='example_1_all.deb'
    def output(command, **kwargs):
        assert '--print-uris' in command and 'Acquire::ForceHash=SHA256' in command
        assert '--no-remove' in command
        return f"'https://example.invalid/{archive}' {archive} 6 SHA256:{sha}\n"
    monkeypatch.setattr(pool.subprocess,'check_output',output)
    apt=tmp_path/'apt'
    partial=apt/'archives'/'partial'/archive
    partial.write_bytes(b'ab')
    budget=[]
    candidate.download_budget=budget.append
    expected=pool._apt_archive_volume(candidate,[],{'example'},apt)
    assert expected=={archive:sha}
    assert view.phase_counts()==(2,6,'bytes')
    assert budget==[4]
    partial.write_bytes(b'abcdef')
    partial.rename(apt/'archives'/archive)
    pool._observe_apt_archives(apt,expected)
    assert view.phase_counts()==(6,6,'bytes')
    assert view.network_bytes==0  # Native APT network bytes come from namespace RX.

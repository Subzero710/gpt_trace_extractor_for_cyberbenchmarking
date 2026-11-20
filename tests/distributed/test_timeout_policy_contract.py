"""Regression contract: all host preparation waits require finite deadlines."""
from __future__ import annotations

import ast
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

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
    assert 'CLOCK_PROCESS_CPUTIME_ID' in rust
    assert 'resource.RLIMIT_CPU' in bridge
    assert 'manager._progress(state)' in parent
    assert 'os.killpg(child.pid, signal.SIGKILL)' in parent


def test_no_whole_acquisition_deadline():
    policy = (ROOT / 'config/preparation.toml').read_text()
    assert 'job_timeout_hours' not in policy
    assert 'pip_total_timeout_seconds' not in policy
    for relative in ('scripts/superbench_pool.py', 'scripts/distributed.py',
                     'apps/workstation-broker/src/workstation_broker/preparation.py'):
        source = (ROOT / relative).read_text()
        assert 'job_timeout_hours' not in source
    parent = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
    assert 'child.wait(timeout=cleanup_timeout)' in parent
    assert 'acquisition worker blocked outside a registered operation' in parent


def test_fetch_watchdog_allows_many_completed_operations_and_checks_each_owner(monkeypatch):
    from workstation_broker import preparation

    now = 1.0
    monkeypatch.setattr(preparation.time, 'monotonic', lambda: now)
    watch = preparation._FetchOperationWatch(os.getpid(), 180, 5)
    thread = threading.get_native_id()

    def send(kind, operation, **fields):
        record = dict(event=kind, operation=operation, thread=thread, **fields)
        watch.feed(json.dumps(record).encode() + b'\n')

    for operation in range(1, 6):
        send('begin', operation, label='verified read', started=now, limit=180,
             process=None, supervised=False)
        now += 179
        watch.inspect(idle_limit=180, descendants=set())
        send('end', operation, finished=now)

    send('begin', 6, label='blocked verification', started=now, limit=180,
         process=None, supervised=False)
    now += 178
    send('begin', 7, label='independent write', started=now, limit=180,
         process=None, supervised=False)
    now += 2
    with pytest.raises(TimeoutError, match='blocked verification'):
        watch.inspect(idle_limit=180, descendants=set())


def test_fetch_watchdog_rejects_orphaned_work(monkeypatch, tmp_path):
    from workstation_broker import preparation

    clock = 1.0
    monkeypatch.setattr(preparation.time, 'monotonic', lambda: clock)
    monkeypatch.setattr(preparation, 'PROC', tmp_path)
    watch = preparation._FetchOperationWatch(5, 180, 5)
    event = dict(event='begin', operation=1, thread=5, label='orphaned write',
                 started=clock, limit=180, process=None, supervised=False)
    watch.feed(json.dumps(event).encode() + b'\n')
    with pytest.raises(RuntimeError, match='no live thread'):
        watch.inspect(idle_limit=180, descendants=set())


def test_fetch_watchdog_rejects_late_success_even_with_local_supervision(monkeypatch):
    from workstation_broker import preparation

    now = 1.0
    monkeypatch.setattr(preparation.time, 'monotonic', lambda: now)
    watch = preparation._FetchOperationWatch(os.getpid(), 180, 5)
    thread = threading.get_native_id()
    event = dict(event='begin', operation=1, thread=thread, label='local subprocess',
                 started=now, limit=180, process=None, supervised=True)
    watch.feed(json.dumps(event).encode() + b'\n')
    now += 180
    event = dict(event='end', operation=1, thread=thread, finished=now)
    with pytest.raises(TimeoutError, match='local subprocess'):
        watch.feed(json.dumps(event).encode() + b'\n')


def test_fetch_watchdog_releases_finished_identity_and_rejects_reuse(monkeypatch):
    from workstation_broker import preparation

    now = 1.0
    monkeypatch.setattr(preparation.time, 'monotonic', lambda: now)
    watch = preparation._FetchOperationWatch(os.getpid(), 180, 5)
    thread = threading.get_native_id()
    began = dict(event='begin', operation=1, thread=thread, label='local subprocess',
                 started=now, limit=180, process=None, supervised=True)
    watch.feed(json.dumps(began).encode() + b'\n')
    now += 1
    event = dict(event='end', operation=1, thread=thread, finished=now)
    watch.feed(json.dumps(event).encode() + b'\n')
    assert not watch.active
    with pytest.raises(RuntimeError, match='invalid acquisition operation registration'):
        watch.feed(json.dumps(began).encode() + b'\n')


def test_fetch_watchdog_does_not_extend_a_live_subprocess_deadline(monkeypatch):
    from workstation_broker import preparation

    now = 1.0
    monkeypatch.setattr(preparation.time, 'monotonic', lambda: now)
    watch = preparation._FetchOperationWatch(os.getpid(), 180, 5)
    event = dict(event='begin', operation=1, thread=threading.get_native_id(), label='ordinary subprocess',
                 started=now, limit=900, process=os.getpid(), supervised=True)
    with pytest.raises(RuntimeError, match='invalid acquisition operation registration'):
        watch.feed(json.dumps(event).encode() + b'\n')
    event['limit'] = 180
    watch.feed(json.dumps(event).encode() + b'\n')
    now += 180
    with pytest.raises(TimeoutError, match='ordinary subprocess'):
        watch.inspect(idle_limit=180, descendants={os.getpid()})


def test_verified_preparation_cleanup_reaches_a_descendant_in_its_own_session(tmp_path, monkeypatch):
    from workstation_broker import preparation

    marker = tmp_path / 'descendant'
    launcher = ('from pathlib import Path; import subprocess, sys; '
                'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True); '
                'Path(sys.argv[1]).write_text(str(child.pid)); child.wait()')
    process = subprocess.Popen([sys.executable, '-c', launcher, str(marker)], start_new_session=True)
    identities = []
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() or not marker.stat().st_size:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        identities = [preparation.process_identity(pid) for pid in (process.pid, int(marker.read_text()))]
        assert identities[0]['session'] != identities[1]['session']
        monkeypatch.setattr(preparation.JobScope, 'members', lambda _: [
            stamp for stamp in identities if preparation.same_process(stamp)])
        preparation._kill_verified_fetch_descendants({}, timeout=5, cadence=0.01)
        assert process.wait(timeout=1) == -signal.SIGKILL
        assert not any(preparation.same_process(stamp) for stamp in identities)
    finally:
        for stamp in identities:
            if preparation.same_process(stamp):
                os.kill(stamp['pid'], signal.SIGKILL)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)


def test_apt_queued_transfers_and_native_retries_get_independent_deadlines(monkeypatch):
    from contextlib import ExitStack
    from urllib.parse import quote
    import superbench_pool as pool

    now = 0.0
    observed = []
    monkeypatch.setattr(pool.time, 'monotonic', lambda: now)

    def registered(label, *, process, started):
        observed.append((label, process, started))
        return ExitStack()

    def event(direction, code, operation, uri):
        content = quote(' URI ' + operation + '\nURI: ' + uri, safe=':')
        return f' {direction} https:{code}{content}'.encode()

    precursor, dependency = ('https://packages.example/first', 'https://packages.example/second')
    with ExitStack() as scope:
        watch = pool._apt_download_module().AptDownloads(SimpleNamespace(pid=1234), 180, scope, registered)
        watch.feed(event('->', 600, 'Acquire', precursor))
        watch.feed(event('->', 600, 'Acquire', dependency))
        now += 179
        assert watch.remaining() == 1
        watch.feed(event('<-', 400, 'Failure', precursor))
        watch.feed(event('->', 600, 'Acquire', precursor))
        now += 179
        assert watch.remaining() == 1
        watch.feed(event('<-', 201, 'Done', dependency))
        now += 179
        assert watch.remaining() == 1
        watch.feed(event('<-', 201, 'Done', precursor))
        assert not watch.active
    assert observed == [('APT https item', 1234, started) for started in (0, 179, 358)]


def test_apt_activity_lines_do_not_extend_one_stalled_transfer(monkeypatch):
    from contextlib import ExitStack
    import superbench_pool as pool

    now = 0.0
    monkeypatch.setattr(pool.time, 'monotonic', lambda: now)
    with ExitStack() as scope:
        watch = pool._apt_download_module().AptDownloads(SimpleNamespace(pid=1234), 180, scope, pool._registered_operation)
        assert watch.feed(b' -> https:600%20URI%20Acquire%0aURI:%20https://packages.example/pkg')
        now += 179
        assert not watch.feed(b'10% display update')
        assert watch.remaining() == 1
        now += 1
        with pytest.raises(TimeoutError, match='APT operation exceeded'):
            watch.remaining()


def test_buildkit_statuses_pause_only_their_actual_parent_and_never_extend_themselves(monkeypatch):
    from scripts import distributed

    clock = 0.0
    monkeypatch.setattr(distributed.time, 'monotonic', lambda: clock)
    watch = distributed._BuildKitWatch(180)
    watch.feed({'vertexes': [{'digest': 'parent', 'name': 'export', 'started': 'timestamp'}]})
    clock += 20
    for layer in ('one', 'two', 'three'):
        item = {'vertex': 'parent', 'id': layer, 'name': layer, 'started': 'timestamp'}
        watch.feed({'statuses': [item]})
        clock += 179
        watch.feed({'statuses': [{**item, 'current': 5}]})
        assert watch.remaining() == 1
        watch.feed({'statuses': [{**item, 'completed': 'timestamp'}]})
    assert watch.remaining() == 160
    clock += 160
    with pytest.raises(TimeoutError, match='export'):
        watch.remaining()


def test_buildkit_separate_vertices_have_independent_deadlines(monkeypatch):
    from scripts import distributed

    clock = 0.0
    monkeypatch.setattr(distributed.time, 'monotonic', lambda: clock)
    watch = distributed._BuildKitWatch(180)
    for phase in ('fetch', 'build', 'export'):
        row = {'digest': phase, 'name': phase, 'started': 'timestamp'}
        watch.feed({'vertexes': [row]})
        clock += 179
        assert watch.remaining() == 1
        watch.feed({'vertexes': [{**row, 'completed': 'timestamp'}]})
    assert not watch.vertices and clock > 180
    row = {'digest': 'blocked', 'name': 'waiting on network', 'started': 'timestamp'}
    watch.feed({'vertexes': [row]})
    clock += 180
    watch.feed({'logs': [{'vertex': 'blocked', 'data': 'dGVzdA=='}]})
    with pytest.raises(TimeoutError, match='waiting on network'):
        watch.remaining()


@pytest.mark.parametrize('blocked', [False, True])
def test_compose_bake_supervision_consumes_raw_json_and_reaps_its_client(monkeypatch, tmp_path, blocked):
    from scripts import distributed

    service = 'runner'
    versioned_plan = json.dumps({'target': {service: {'context': '.'}}})
    started = []
    original_popen = subprocess.Popen
    original_log = tempfile.NamedTemporaryFile

    def compose(*args, capture, timeout):
        assert args == ('build', '--print', service)
        assert capture and timeout == 1
        return versioned_plan

    def launch(command, **kwargs):
        assert command == ['docker', 'buildx', 'bake', '--builder', 'default', '--file', '-',
                           '--progress', 'rawjson', '--load', service]
        assert kwargs['start_new_session']
        assert kwargs['stdin'].read() == versioned_plan.encode()
        kwargs['stdin'].seek(0)
        worker = """
import json, sys, time
for name in ('load', 'build', 'export'):
    row = {'digest': name, 'name': name, 'started': 'observed'}
    print(json.dumps({'vertexes': [row]}), flush=True)
    time.sleep(60 if sys.argv[1] == 'blocked' else 0.45)
    print(json.dumps({'vertexes': [{**row, 'completed': 'observed'}]}), flush=True)
"""
        child = original_popen([sys.executable, '-c', worker, 'blocked' if blocked else 'complete'], **kwargs)
        started.append(child)
        return child

    monkeypatch.setattr(distributed, '_compose_controls', lambda: (1, 1, 0.02))
    monkeypatch.setattr(distributed, 'compose', compose)
    monkeypatch.setattr(distributed.subprocess, 'Popen', launch)
    monkeypatch.setattr(distributed.tempfile, 'NamedTemporaryFile',
                        lambda **options: original_log(dir=tmp_path, **options))
    if blocked:
        with pytest.raises(RuntimeError, match='deadline: load'):
            distributed._build_compose_services('default', (service,))
        log, = tmp_path.glob('gpttrace-buildkit-*.log')
        assert '"name": "load"' in log.read_text()
    else:
        distributed._build_compose_services('default', (service,))
        assert not tuple(tmp_path.glob('gpttrace-buildkit-*.log'))
    assert started[0].poll() is not None


@pytest.mark.parametrize('exit_code', [0, 3])
def test_compose_job_observes_original_container_and_removes_only_success(monkeypatch, exit_code):
    from scripts import distributed

    identity = 'a' * 64
    operations = []
    observations = 0
    name = None
    clock = 0

    def compose(*args, capture, timeout):
        nonlocal name
        assert args[:4] == ('run', '--detach', '--no-deps', '--name')
        assert args[5:] == ('runner', 'superbench-run')
        assert capture and timeout == 180
        name = args[4]
        return identity

    def docker(args, *, capture, timeout):
        nonlocal observations
        assert capture and timeout == 15
        operations.append(tuple(args))
        if args[2] == 'rm':
            return identity
        assert args == ['docker', 'container', 'inspect', name]
        observations += 1
        state = {'Status': 'running'} if observations <= 100 else {'Status': 'exited', 'ExitCode': exit_code}
        return json.dumps([{'Id': identity, 'Name': '/' + name, 'State': state, 'Config': {'Labels': {
            'com.docker.compose.project': distributed.PROJECT,
            'com.docker.compose.service': 'runner',
            'com.docker.compose.oneoff': 'True',
        }}}])

    def sleep(seconds):
        nonlocal clock
        clock += seconds

    def wait(*, timeout):
        assert timeout == 15
        return 0

    monkeypatch.setattr(distributed, 'compose', compose)
    monkeypatch.setattr(distributed, 'run', docker)
    monkeypatch.setattr(distributed.time, 'sleep', sleep)
    monkeypatch.setattr(distributed.subprocess, 'Popen',
                        lambda *args, **kwargs: SimpleNamespace(poll=lambda: 0, returncode=0, wait=wait))
    if exit_code:
        with pytest.raises(RuntimeError, match='Compose job .* failed') as error:
            distributed._run_compose_job('runner', 'superbench-run')
        assert isinstance(error.value.__cause__, subprocess.CalledProcessError)
    else:
        distributed._run_compose_job('runner', 'superbench-run')
    assert clock == 200
    assert (('docker', 'container', 'rm', identity) in operations) == (exit_code == 0)


def test_compose_launch_timeout_does_not_restart_an_unobservable_job(monkeypatch):
    from scripts import distributed

    commands = []

    def launch(*args, capture, timeout):
        commands.append(args)
        raise subprocess.TimeoutExpired(args, timeout)

    def inspect(name, service, *, timeout):
        commands.append((name, service, timeout))
        raise RuntimeError('Docker status unavailable')

    monkeypatch.setattr(distributed, 'compose', launch)
    monkeypatch.setattr(distributed, '_compose_job_state', inspect)
    with pytest.raises(RuntimeError, match='stop unconfirmed.*reconcile --compose-job'):
        distributed._run_compose_job('runner', 'superbench-run')
    assert len(commands) == 3
    assert commands[0][4] == commands[1][0] == commands[2][0]


@pytest.mark.parametrize('stop_acknowledged', [True, False])
def test_compose_log_failure_reconciles_original_running_job(monkeypatch, stop_acknowledged):
    from scripts import distributed

    identity = 'a' * 64
    statuses = iter(['running', 'running', 'exited'])
    commands = []
    monkeypatch.setattr(distributed, 'compose', lambda *args, **kwargs: identity)
    monkeypatch.setattr(distributed, '_compose_job_state',
                        lambda *args, **kwargs: (identity, {'Status': next(statuses)}))
    monkeypatch.setattr(distributed.subprocess, 'Popen',
                        lambda *args, **kwargs: SimpleNamespace(poll=lambda: 1, returncode=1))

    def docker(args, *, capture, timeout):
        commands.append(args)
        if not stop_acknowledged:
            raise subprocess.TimeoutExpired(args, timeout)
        return identity

    monkeypatch.setattr(distributed, 'run', docker)
    with pytest.raises(RuntimeError, match='log stream failed.*container stop verified'):
        distributed._run_compose_job('runner', 'superbench-run')
    _, probe, _ = distributed._compose_controls()
    assert commands == [['docker', 'container', 'stop', '--time', str(probe), identity]]


def test_compose_reconciliation_preserves_a_replacement_container(monkeypatch):
    from scripts import distributed

    identity = 'a' * 64
    monkeypatch.setattr(distributed, '_compose_job_state',
                        lambda *args, **kwargs: ('b' * 64, {'Status': 'running'}))
    monkeypatch.setattr(distributed, 'run', lambda *args, **kwargs: pytest.fail('replacement was modified'))
    budget, probe, interval = distributed._compose_controls()
    with pytest.raises(RuntimeError, match='identity changed'):
        distributed._reconcile_compose_job('job', 'runner', identity, budget=budget, probe=probe, interval=interval)


def test_compose_starts_dependencies_and_gives_each_service_its_own_readiness_budget(monkeypatch):
    from scripts import distributed

    clock = 0.0
    started = []
    config = tomllib.loads((ROOT / 'config/preparation.toml').read_text())
    budget = config['acquisition']['timeout_seconds']
    probe_budget = config['compose']['status_timeout_seconds']
    identity = 'a' * 64

    def compose(*args, capture=False, timeout=None):
        nonlocal clock
        if args[0] == 'up':
            assert args[1:4] == ('--detach', '--no-deps', '--no-build')
            assert timeout == budget
            started.append(args[-1])
            clock += budget - 1
            return ''
        assert args == ('ps', '--all', '--quiet', started[-1])
        assert capture and timeout == probe_budget
        clock += 1
        return identity

    def inspect(args, *, capture, timeout):
        nonlocal clock
        assert args == ['docker', 'container', 'inspect', identity]
        assert capture and timeout == probe_budget
        clock += 1
        return json.dumps([{'Id': identity, 'Config': {'Labels': {
            'com.docker.compose.project': distributed.PROJECT,
            'com.docker.compose.service': started[-1],
            'com.docker.compose.oneoff': 'False',
        }}, 'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}])

    monkeypatch.setattr(distributed.time, 'monotonic', lambda: clock)
    monkeypatch.setattr(distributed, 'compose', compose)
    monkeypatch.setattr(distributed, 'run', inspect)
    distributed._start_compose_services(('storage', 'teacher-browser-tunnel'))
    assert started == ['postgres', 'storage', 'teacher-browser', 'teacher-browser-tunnel']
    assert clock > len(started) * budget


def test_compose_reports_readiness_expiration_without_restarting_container(monkeypatch):
    from scripts import distributed

    clock = 0.0
    probes = []

    def sleep(seconds):
        nonlocal clock
        clock += seconds

    def observe(*args, **kwargs):
        probes.append(args)
        return ''

    monkeypatch.setattr(distributed.time, 'monotonic', lambda: clock)
    monkeypatch.setattr(distributed.time, 'sleep', sleep)
    monkeypatch.setattr(distributed, 'compose', observe)
    with pytest.raises(TimeoutError, match='readiness expired: storage'):
        distributed._wait_compose_service('storage', budget=3, probe_timeout=2, interval=1)
    assert probes == [('ps', '--all', '--quiet', 'storage')] * 3


def test_host_helper_observes_independent_native_operations(monkeypatch):
    from gpt_trace_transport.operation_watch import HOST_PREFIX, OperationWatch

    clock = 1.0
    monkeypatch.setattr(time, "monotonic", lambda: clock)
    limit = 180
    watch = OperationWatch(limit, prefix=HOST_PREFIX, description="execution helper", requires_proof=False)

    def send(record):
        watch.feed(HOST_PREFIX + record.encode() + b"\n")

    for label in ("read-active-state", "read-main-pid", "inventory"):
        send("begin " + label)
        clock += limit - 1
        assert watch.check() == 1
        send("end " + label)
    send("shutdown complete")
    watch.require_complete()

    blocked = OperationWatch(limit, prefix=HOST_PREFIX, description="execution helper", requires_proof=False)
    blocked.feed(HOST_PREFIX + b"begin inventory\n")
    clock += limit
    with pytest.raises(TimeoutError, match="inventory"):
        blocked.check()

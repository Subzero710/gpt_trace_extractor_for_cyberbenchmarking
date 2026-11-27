from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


class GuestAgent:
    def __init__(self, path, limit, cadence):
        self.path = str(path)
        self.limit = limit
        self.cadence = cadence
        self.lock = threading.RLock()

    def call(self, command, arguments=None, *, deadline=None):
        deadline = time.monotonic() + self.limit if deadline is None else deadline
        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError('metadata guest agent operation exceeded deadline')
            return value
        if not self.lock.acquire(timeout=remaining()):
            raise TimeoutError('metadata guest agent channel is busy')
        try:
            return self._call(command, arguments, remaining)
        finally:
            self.lock.release()

    def _call(self, command, arguments, remaining):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining())
            connection.connect(self.path)
            with connection.makefile('rwb') as wire:
                # QGA may retain a partial response from the previous client.
                # Synchronize the stream before sending a new command.
                token = secrets.randbits(53)
                wire.write(b'\xff' + json.dumps({'execute': 'guest-sync-delimited', 'arguments': {'id': token}}).encode() + b'\n')
                wire.flush()
                while True:
                    connection.settimeout(remaining())
                    line = wire.readline(1048576)
                    if not line:
                        raise TimeoutError('metadata guest agent synchronization failed')
                    if b'\xff' in line:
                        reply = json.loads(line.rsplit(b'\xff', 1)[1])
                        if reply.get('return') == token:
                            break
                request = {'execute': command}
                if arguments is not None:
                    request['arguments'] = arguments
                connection.settimeout(remaining())
                wire.write(json.dumps(request, separators=(',', ':')).encode() + b'\n')
                wire.flush()
                connection.settimeout(remaining())
                raw = wire.readline(1048576)
                if not raw or not raw.endswith(b'\n'):
                    raise RuntimeError('metadata guest agent returned incomplete response')
                response = json.loads(raw)
                if 'return' not in response or 'error' in response:
                    raise RuntimeError('metadata guest agent refused ' + command + ': ' + repr(response))
                return response['return']

    def start(self, argv, *, deadline=None):
        if not argv or not all(isinstance(arg, str) for arg in argv):
            raise ValueError('invalid guest execution command')
        result = self.call('guest-exec', {'path': argv[0], 'arg': argv[1:], 'capture-output': False}, deadline=deadline)
        pid = result.get('pid')
        if type(pid) is not int or pid <= 0:
            raise RuntimeError('metadata guest agent returned invalid process identity')
        return pid

    def status(self, pid, *, deadline=None):
        result = self.call('guest-exec-status', {'pid': pid}, deadline=deadline)
        if type(result.get('exited')) is not bool:
            raise RuntimeError('invalid metadata guest execution status')
        return result

    def run(self, argv):
        deadline = time.monotonic() + self.limit
        pid = self.start(argv, deadline=deadline)
        while True:
            result = self.status(pid, deadline=deadline)
            if result['exited']:
                if result.get('exitcode') != 0:
                    raise RuntimeError('metadata guest administration failed: ' + repr(argv) + ': ' + repr(result))
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('metadata guest administration exceeded elementary deadline')
            time.sleep(min(self.cadence, remaining))


NATIVE_METADATA_EXIT_CODE = 76


class NativeGuestRequired(BaseException):
    def __init__(self, requirements):
        super().__init__('target metadata native dependency resolution required')
        self.requirements = requirements


class NativeGuestClient:
    def __init__(self, socket_path, source, uid, gid, local, *, limit, cadence, operation):
        self.agent = GuestAgent(socket_path, limit, min(cadence, 0.1))
        self.source = Path(source)
        self.uid, self.gid = uid, gid
        self.local = Path(local)
        self.limit, self.cadence = limit, min(cadence, 0.1)
        self.operation = operation
        self.script = self.source / 'scripts/native_guest_execution.py'

    def run(self, argv, runtime, *, timeout=None, interpreter=None, metadata_build=False,
            input=None, install_apt=False, capture_build_requirements=False):
        root = Path(runtime['root'])
        with tempfile.TemporaryDirectory(prefix='guest-command-', dir=root) as temporary:
            job = Path(temporary)
            request = {'schema': 1, 'source': str(self.source), 'argv': [str(arg) for arg in argv],
                       'root': str(root), 'env': runtime['env'], 'interpreter': str(interpreter) if interpreter is not None else None,
                       'timeout': timeout, 'metadata_build': metadata_build, 'install_apt': install_apt,
                       'capture_build_requirements': capture_build_requirements,
                       'has_input': input is not None, 'build_resolver': callable(runtime.get('_native_build_resolver')),
                       'context': runtime.get('_native_source_context'), 'local': str(self.local)}
            if input is not None:
                (job / 'input').write_bytes(input)
            atomic_json(job / 'request.json', request)
            command = ['/usr/bin/python3', '-I', '-B', str(self.script), '--execute', str(job)]
            if not install_apt:
                command = ['/usr/bin/setpriv', '--reuid', str(self.uid), '--regid', str(self.gid), '--clear-groups', '--no-new-privs', *command]
            active = {}
            position = 0
            buffered = b''
            last = time.monotonic()
            sequence = 0
            pid = None
            reaped = False
            result_path = job / 'result.json'
            event_path = job / 'events.jsonl'

            def drain_events():
                nonlocal position, buffered, last
                if not event_path.exists():
                    return
                with event_path.open('rb') as stream:
                    stream.seek(position)
                    data = stream.read()
                    position = stream.tell()
                buffered += data
                while b'\n' in buffered:
                    line, buffered = buffered.split(b'\n', 1)
                    event = json.loads(line)
                    identity = event['operation']
                    if event['event'] == 'begin':
                        if identity in active or not 1 <= event['limit'] <= self.limit:
                            raise RuntimeError('invalid target metadata operation')
                        scope = self.operation('guest: ' + event['label'], limit=event['limit'])
                        scope.__enter__()
                        active[identity] = scope
                    elif event['event'] in {'end', 'failed'} and identity in active:
                        scope = active.pop(identity)
                        if event['event'] == 'failed':
                            error = RuntimeError('target metadata operation failed')
                            scope.__exit__(type(error), error, None)
                        else:
                            scope.__exit__(None, None, None)
                    else:
                        raise RuntimeError('unbalanced target metadata operation events')
                    last = time.monotonic()

            try:
                with self.operation('start target metadata command'):
                    pid = self.agent.start(command)
                while True:
                    drain_events()
                    build_request = job / ('build-' + str(sequence) + '.json')
                    if build_request.exists() and not active:
                        resolve = runtime.get('_native_build_resolver')
                        if not callable(resolve):
                            raise RuntimeError('unexpected target build dependency request')
                        payload = json.loads(build_request.read_bytes())
                        paths = resolve(payload)
                        atomic_json(job / ('reply-' + str(sequence) + '.json'), paths)
                        sequence += 1
                        last = time.monotonic()
                    if result_path.exists() or (not active and time.monotonic() - last >= self.limit):
                        status = self.agent.status(pid)
                        if status['exited']:
                            reaped = True
                            drain_events()
                            if active or buffered or status.get('exitcode') != 0 or not result_path.is_file():
                                raise RuntimeError('target metadata command has incomplete operation evidence: ' + repr(status))
                            result = json.loads(result_path.read_bytes())
                            if result.get('ok') is True:
                                if capture_build_requirements:
                                    return result['build_requirements']
                                return (job / 'stdout').read_bytes()
                            if result.get('requirements'):
                                raise NativeGuestRequired(result['requirements'])
                            raise RuntimeError('target metadata command failed: ' + result['error'])
                        if not active and time.monotonic() - last >= self.limit:
                            raise TimeoutError('target metadata orchestration stalled outside an elementary operation')
                    time.sleep(self.cadence)
            finally:
                try:
                    if pid is not None and not reaped:
                        with self.operation('cancel target metadata command'):
                            status = self.agent.status(pid)
                            if not status['exited']:
                                self.agent.run(['/usr/bin/kill', '-TERM', str(pid)])
                                deadline = time.monotonic() + self.limit
                                while not self.agent.status(pid)['exited']:
                                    if time.monotonic() >= deadline:
                                        raise TimeoutError('target metadata command remained active after cancellation')
                                    time.sleep(self.cadence)
                finally:
                    for scope in active.values():
                        error = RuntimeError('target metadata command aborted')
                        scope.__exit__(type(error), error, None)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def execute(job):
    job = Path(job)
    request = json.loads((job / 'request.json').read_bytes())
    source = Path(request['source'])
    pool = _load(source / 'scripts/superbench_pool.py', 'native_guest_pool')
    adapter = source / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    local = Path(request['local'])
    events = os.open(job / 'events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    pool._OPERATION_EVENT_FD = events
    runtime = {'root': Path(request['root']), 'env': request['env'], 'guest_local': local,
               '_native_source_context': request['context'], '_guest_execution': True}
    sequence = 0
    def resolve(requirements):
        nonlocal sequence
        atomic_json(job / ('build-' + str(sequence) + '.json'), requirements)
        reply = job / ('reply-' + str(sequence) + '.json')
        # Waiting for the host's verified graph producer is orchestration, not
        # an elementary build action. The host owns its finite operations.
        while not reply.exists():
            time.sleep(min(pool._conda_progress_interval(), 0.1))
        result = json.loads(reply.read_bytes())
        sequence += 1
        return result
    if request['build_resolver']:
        runtime['_native_build_resolver'] = resolve
    result = {'ok': False}
    def canceled(_signum, _frame):
        raise InterruptedError('target metadata command canceled')
    signal.signal(signal.SIGTERM, canceled)
    runtime_module = _load(adapter / 'guest_runtime.py', 'native_guest_runtime')
    runtime_module.ROOT = adapter
    runtime_module.CONDA = local / 'conda/bin/conda'
    runtime['_native_diagnostics'] = runtime_module._native_diagnostics
    try:
        if request['install_apt']:
            os_packages = _load(adapter / 'os_packages.py', 'native_guest_os_packages')
            # Reuse the exact guest installer and elementary dpkg supervision.
            os_packages._template_operation = pool._registered_operation
            os_packages.digest = pool.digest
            def install(command, log):
                helper = _load(source / 'infra/workstation/image/apt_downloads.py', 'native_guest_apt')
                offset = command.index('apt-get')
                helper.run_install(command[offset + 1:], launcher=command[:offset],
                    limit=pool._operation_timeout(), cadence=pool._conda_progress_interval(),
                    observe=pool._registered_operation,
                    terminate=lambda p: pool._stop_native_process_group(p, cleanup_limit=pool._operation_timeout(), cadence=pool._conda_progress_interval()),
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}, stdout=log, stderr=subprocess.STDOUT)
            os_packages._install_archives = install
            os_packages.resolve_from_pool(local / 'os-artifacts', Path(request['argv'][0]))
            with pool._registered_operation('inspect target root partition'):
                root_device = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '/'], text=True, timeout=pool._operation_timeout()).strip()
                fstype = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '/'], text=True, timeout=pool._operation_timeout()).strip()
                parent = subprocess.check_output(['lsblk', '-n', '-o', 'PKNAME', root_device], text=True, timeout=pool._operation_timeout()).strip()
                partition = subprocess.check_output(['lsblk', '-n', '-o', 'PARTN', root_device], text=True, timeout=pool._operation_timeout()).strip()
            if fstype != 'ext4' or not parent or not partition.isdecimal():
                raise RuntimeError('unsupported target root partition layout')
            with pool._registered_operation('grow target root partition'):
                growth = subprocess.run(['growpart', '/dev/' + parent, partition], capture_output=True, text=True, timeout=pool._operation_timeout())
                if growth.returncode and not (growth.returncode == 1 and growth.stdout.startswith('NOCHANGE:')):
                    raise RuntimeError('target partition growth failed: ' + growth.stdout + growth.stderr)
            with pool._registered_operation('grow target root filesystem'):
                subprocess.run(['resize2fs', root_device], check=True, timeout=pool._operation_timeout())
            output = b''
        else:
            interpreter = request['interpreter']
            if interpreter is not None and Path(interpreter).is_relative_to(local / 'envs'):
                prefix = Path(interpreter).parent.parent
                activate = local / 'conda/etc/profile.d/conda.sh'
                with pool._registered_operation('activate exact metadata Conda prefix'):
                    raw = subprocess.check_output(['/bin/bash', '-c', 'set -e; source "$1"; conda activate "$2"; env -0', 'activate', str(activate), str(prefix)],
                                                  env=runtime['env'], timeout=pool._operation_timeout())
                runtime['env'] = dict(field.decode().split('=', 1) for field in raw.split(b'\0') if field)
            if request['capture_build_requirements']:
                scratch = local / 'metadata-scratch'
                scratch.mkdir(exist_ok=True)
                builds = pool._native_metadata_command(request['argv'], runtime, scratch)
                result['build_requirements'] = builds
                output = b''
            else:
                output = pool._native_run(request['argv'], runtime, timeout=request['timeout'], interpreter=interpreter,
                                          metadata_build=request['metadata_build'], input=(job / 'input').read_bytes() if request['has_input'] else None)
        (job / 'stdout').write_bytes(output)
        result['ok'] = True
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        if request['metadata_build'] and request['interpreter'] is not None:
            observations = getattr(exc, 'native_observations', None)
            if observations:
                try:
                    with pool._registered_operation('target native compiler diagnostic'):
                        prefix = Path(request['interpreter']).parent.parent
                        profile = runtime_module._native_profile(prefix,
                            loader_needed=any(kind == 'soname' for kind, _ in observations),
                            interpreter=request['interpreter'], environment=runtime['env'])
                        result['requirements'] = runtime_module._native_requests(prefix, observations, profile=profile)
                except BaseException as diagnostic:
                    result['error'] += '; native diagnostics: ' + str(diagnostic)
    finally:
        os.close(events)
        atomic_json(job / 'result.json', result)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--execute':
        raise SystemExit('metadata guest execution requires a bound job directory')
    execute(sys.argv[2])

"""Finite preparation ownership: one delegated cgroup and labelled source containers.

The only writable cgroup names are derived from a verified durable job ID and
attempt. No task/RPC supplies a filesystem path or executable. Direct libguestfs
children inherit the cgroup, including children that create another session.
"""
from __future__ import annotations
import json
import os
import re
import signal
import subprocess
from pathlib import Path

MOUNT = Path('/sys/fs/cgroup')
UNIT = MOUNT / 'system.slice/gpt-trace-distributed-broker.service'
PROJECT = 'gpt-trace-extractor'
LABEL = 'io.gpttrace.'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def _jobs():
    from workstation_broker import preparation
    return preparation


def _directory(path):
    path = Path(path)
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        if not candidate.is_dir() or candidate.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('untrusted preparation cgroup directory')
    return path


def _write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if os.fstat(fd).st_uid != 0: raise RuntimeError('foreign cgroup control file')
        raw = text.encode()
        if os.write(fd, raw) != len(raw): raise RuntimeError('partial cgroup control write')
    finally: os.close(fd)


class JobScope:
    @staticmethod
    def name(operation_id, attempt):
        _jobs().identifier(operation_id)
        if type(attempt) is not int or attempt < 1: raise ValueError('invalid preparation attempt')
        return f'prep-{operation_id}-{attempt}'

    @classmethod
    def create(cls, operation_id, attempt):
        # Existing unit only: no independent service, slice, supervisor or daemon.
        _directory(MOUNT)
        if not (MOUNT / 'cgroup.controllers').is_file():
            raise RuntimeError('Acer preparation requires the existing broker unit on cgroup v2')
        _directory(UNIT)
        name = cls.name(operation_id, attempt)
        path = UNIT / name
        path.mkdir(mode=0o700)
        _directory(path)
        return {'schema': 1, 'name': name, 'boot_id': _jobs().boot_id(), 'closed': False}

    @classmethod
    def path(cls, state):
        value = state.get('scope')
        if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'boot_id', 'closed'}
                or value['schema'] != 1 or type(value['closed']) is not bool
                or value['name'] != cls.name(state['operation_id'], state['attempt'])
                or not isinstance(value['boot_id'], str) or not value['boot_id']):
            raise RuntimeError('unverified durable preparation cgroup')
        return UNIT / value['name']

    @classmethod
    def members(cls, state):
        path = cls.path(state)
        value = state['scope']
        if value['boot_id'] != _jobs().boot_id():
            # A host reboot proves the old kernel's processes are gone. Docker
            # resources are independently inspected, including after reboot.
            if path.exists(): raise RuntimeError('old-boot preparation cgroup name reused; preserved')
            return []
        if value['closed']:
            if path.exists(): raise RuntimeError('closed preparation cgroup unexpectedly exists')
            return []
        _directory(path)
        directories = [path, *sorted(p for p in path.rglob('*') if p.is_dir())]
        members = {}
        for directory in directories:
            _directory(directory)
            for raw in (directory / 'cgroup.procs').read_text().split():
                if not raw.isdigit(): raise RuntimeError('invalid cgroup process membership')
                current = _jobs().process_identity(int(raw))
                if current is not None and current['state'] != 'Z':
                    members[current['pid']] = current
        events = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
        if events.get('populated') not in {'0', '1'}: raise RuntimeError('invalid cgroup population proof')
        if events['populated'] == '1' and not members:
            # Allow an exited zombie only after a second, fresh empty event.
            again = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
            if again.get('populated') != '0': raise RuntimeError('cgroup still populated; absence unconfirmed')
        return list(members.values())

    @classmethod
    def attach(cls, state, pid):
        path = cls.path(state)
        _directory(path)
        if cls.members(state): raise RuntimeError('preparation scope already populated')
        _write(path / 'cgroup.procs', str(int(pid)))
        if pid not in {p['pid'] for p in cls.members(state)}:
            raise RuntimeError('worker cgroup assignment not confirmed')

    @classmethod
    def require_current(cls, state):
        if os.getpid() not in {p['pid'] for p in cls.members(state)}:
            raise RuntimeError('local builder is outside its verified preparation cgroup')
        if os.environ.get('LIBGUESTFS_BACKEND') != 'direct':
            raise RuntimeError('local preparation requires inherited direct libguestfs ownership')

    @classmethod
    def terminate(cls, state):
        # A pidfd avoids signalling a recycled PID between identity and signal.
        for stamp in cls.members(state):
            try: fd = os.pidfd_open(stamp['pid'])
            except ProcessLookupError: continue
            try:
                if _jobs().same_process(stamp): signal.pidfd_send_signal(fd, signal.SIGTERM)
            finally: os.close(fd)

    @classmethod
    def kill(cls, state):
        if cls.members(state): _write(cls.path(state) / 'cgroup.kill', '1')

    @classmethod
    def close(cls, state):
        path = cls.path(state)
        if cls.members(state): raise RuntimeError('owned preparation descendants remain')
        if state['scope']['closed']: return state
        if state['scope']['boot_id'] == _jobs().boot_id():
            for child in sorted((p for p in path.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                _directory(child).rmdir()
            path.rmdir()
        return {**state, 'scope': {**state['scope'], 'closed': True}}

    @classmethod
    def audit_unknown(cls, states):
        _directory(MOUNT)
        if not (MOUNT / 'cgroup.controllers').is_file():
            raise RuntimeError('cgroup v2 inventory is unavailable; absence unconfirmed')
        if not UNIT.exists(): return
        _directory(UNIT)
        known = {cls.path(state).name for state in states if not state['scope']['closed']}
        for child in UNIT.iterdir():
            if child.name.startswith('prep-'):
                _directory(child)
                if child.name not in known:
                    raise RuntimeError('preparation cgroup has no verified durable job; preserved')


def source_container_arguments(state):
    _jobs().identifier(state['operation_id'])
    name = f"gpt-trace-source-{state['operation_id'][:24]}-{state['attempt']}"
    values = {'project': PROJECT, 'role': 'source-fetch', 'preparation': state['operation_id'],
              'execution_id': state['deployment']['execution_id'], 'attempt': str(state['attempt'])}
    result = ['--name', name]
    for key, value in values.items(): result += ['--label', LABEL + key + '=' + value]
    return result


def source_containers(deployment):
    def discover():
        raw = subprocess.check_output(['docker', 'ps', '--no-trunc', '-aq', '--filter',
            'label=' + LABEL + 'project=' + PROJECT, '--filter', 'label=' + LABEL + 'role=source-fetch'], timeout=15)
        ids = raw.decode().split()
        if len(ids) != len(set(ids)) or any(HEX.fullmatch(x) is None for x in ids):
            raise RuntimeError('invalid temporary source-container inventory')
        return ids
    # A disappeared --rm container is accepted only by a fresh positive listing.
    ids = discover()
    result = []
    for container_id in ids:
        try:
            rows = json.loads(subprocess.check_output(['docker', 'inspect', container_id], timeout=15))
        except subprocess.CalledProcessError:
            if container_id not in discover(): continue
            raise
        if not isinstance(rows, list) or len(rows) != 1: raise RuntimeError('invalid source-container inspection')
        row = rows[0]
        labels = row.get('Config', {}).get('Labels', {})
        operation_id = labels.get(LABEL + 'preparation')
        _jobs().identifier(operation_id)
        attempt = labels.get(LABEL + 'attempt', '')
        if (row.get('Id') != container_id or labels.get(LABEL + 'project') != PROJECT
                or labels.get(LABEL + 'role') != 'source-fetch'
                or labels.get(LABEL + 'execution_id') != deployment['execution_id']
                or not isinstance(attempt, str) or not re.fullmatch('[1-9][0-9]*', attempt)
                or row.get('Name') != f'/gpt-trace-source-{operation_id[:24]}-{attempt}'):
            raise RuntimeError('temporary container ownership differs; preserved')
        result.append({'id': container_id, 'operation_id': operation_id})
    return result


def remove_source_containers(deployment, known_operations):
    for row in source_containers(deployment):
        if row['operation_id'] not in known_operations:
            raise RuntimeError('source container has no verified durable job; preserved')
        # Revalidate immediately before mutation; Docker IDs are immutable.
        if row not in source_containers(deployment): continue
        try: subprocess.run(['docker', 'stop', '--time', '15', row['id']], check=True, timeout=30)
        except subprocess.CalledProcessError:
            if row not in source_containers(deployment): continue
            raise
        if row in source_containers(deployment):
            try: subprocess.run(['docker', 'rm', row['id']], check=True, timeout=15)
            except subprocess.CalledProcessError:
                if row in source_containers(deployment): raise
    if source_containers(deployment): raise RuntimeError('owned source containers remain')

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
from pathlib import Path, PurePosixPath


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _qemu_value(path):
    value = str(path)
    if any(char in value for char in ('\0', '\n', '\r', ',')):
        raise RuntimeError('ambiguous metadata guest storage path')
    return value


def _open_dir(root, components):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in components:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class SealedCasLinks:
    """Admit links to read-only, previously verified CAS bytes, never arbitrary files."""
    def __init__(self, path, stage, account, limit):
        self.stage, self.uid, self.limit = Path(stage), account.pw_uid, limit
        self.admitted = {}
        for artifact in (self.stage/'objects'/'sha256').glob('*/*'):
            info = artifact.lstat()
            if info.st_uid == 0 and not info.st_mode & 0o222 and stat.S_ISREG(info.st_mode):
                self.admitted[artifact.name] = (info.st_dev, info.st_ino)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o600)
        self.socket.listen()
        self.socket.settimeout(0.2)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def link(self, value):
        if not isinstance(value, dict) or set(value) != {'sha256', 'destination'}:
            raise ValueError('invalid sealed CAS link request')
        sha = value['sha256']
        if not isinstance(sha, str) or len(sha) != 64 or any(char not in '0123456789abcdef' for char in sha):
            raise ValueError('invalid sealed CAS SHA-256')
        raw = value['destination']
        relative = PurePosixPath(raw)
        parts = relative.parts
        if (not parts or relative.is_absolute() or '..' in parts or relative.as_posix() != raw
                or not (parts[0].startswith('.native-pip-') or parts[0] == 'downloads' or parts[0] == 'objects')):
            raise ValueError('sealed CAS link destination is outside acquisition scratch')
        source = _open_dir(self.stage, ('objects', 'sha256', sha[:2]))
        try:
            info = os.stat(sha, dir_fd=source, follow_symlinks=False)
            if (info.st_uid != 0 or info.st_mode & 0o222 or not stat.S_ISREG(info.st_mode)
                    or self.admitted.get(sha) != (info.st_dev, info.st_ino)):
                raise ValueError('sealed CAS link source is not an immutable root-owned object')
            destination = _open_dir(self.stage, parts[:-1])
            try:
                os.link(sha, parts[-1], src_dir_fd=source, dst_dir_fd=destination, follow_symlinks=False)
                actual = os.stat(parts[-1], dir_fd=destination, follow_symlinks=False)
                if (actual.st_dev, actual.st_ino) != self.admitted[sha]:
                    os.unlink(parts[-1], dir_fd=destination)
                    raise ValueError('sealed CAS source changed during linking')
            finally:
                os.close(destination)
        finally:
            os.close(source)

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            with connection:
                connection.settimeout(self.limit)
                try:
                    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != self.uid:
                        raise ValueError('unadmitted sealed CAS link peer')
                    with connection.makefile('rb') as wire:
                        raw = wire.readline(8192)
                    if not raw.endswith(b'\n'):
                        raise ValueError('incomplete sealed CAS link request')
                    self.link(json.loads(raw))
                    response = {'ok': True}
                except (OSError, ValueError, TypeError) as exc:
                    response = {'error': str(exc)}
                try:
                    connection.sendall(json.dumps(response).encode() + b'\n')
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.thread.join(self.limit)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError('sealed CAS link service did not terminate')


def seed_sealed_cas(stage, donor, inventory, account, *, seed_git=True):
    from gpt_trace_transport.local_templates import safe
    stage, donor = Path(stage), Path(donor)
    for sha, record in inventory['objects'].items():
        relative = 'objects/sha256/' + sha[:2] + '/' + sha
        if record['path'] != relative or record['sha256'] != sha:
            raise RuntimeError('invalid sealed donor CAS inventory')
        original = safe(donor / relative, immutable=True)
        if original.stat().st_size != record['size']:
            raise RuntimeError('sealed donor CAS size differs')
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        for directory in (target.parent, target.parent.parent, target.parent.parent.parent):
            os.chown(directory, account.pw_uid, account.pw_gid)
            directory.chmod(0o700)
        os.link(original, target)
    # Git refs and configuration are mutable, but existing Git object bytes
    # need not be copied or transferred again.
    for kind in ('git', 'git-extra') if seed_git else ():
        original = donor / kind
        if not original.is_dir():
            continue
        target = stage / kind
        def transfer(src, dst):
            src, dst = Path(src), Path(dst)
            safe(src, immutable=True)
            parts = src.relative_to(original).parts
            if len(parts) >= 4 and parts[1] == 'objects':
                os.link(src, dst)
            else:
                shutil.copyfile(src, dst)
                os.chown(dst, account.pw_uid, account.pw_gid)
                dst.chmod(0o600)
        shutil.copytree(original, target, copy_function=transfer)
        for directory in (target, *(path for path in target.rglob('*') if path.is_dir())):
            os.chown(directory, account.pw_uid, account.pw_gid)
            directory.chmod(0o700)


@contextlib.contextmanager
def metadata_guest(manager, stage, source, account, *, donor=None, reuse=None, retained=()):
    from gpt_trace_transport.local_templates import safe
    root = Path(manager.source_root)
    controls = tomllib.loads((root / 'config/preparation.toml').read_text())
    limit = controls['acquisition']['timeout_seconds']
    cadence = controls['acquisition']['progress_interval_seconds']
    cleanup = controls['acquisition']['broker_read_timeout_seconds']
    if not (1 <= cadence <= limit <= 180 and 1 <= cleanup <= limit):
        raise RuntimeError('invalid target metadata guest supervision controls')
    builder = _load(root / 'scripts/build_local_templates.py', 'native_guest_builder')
    transport = _load(source / 'scripts/native_guest_execution.py', 'native_guest_transport')
    stage.mkdir(mode=0o700)
    os.chown(stage, account.pw_uid, account.pw_gid)
    marker = stage / 'STAGING'
    with marker.open('x') as stream:
        os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
        os.fchmod(stream.fileno(), 0o600)
        stream.write('Uncommitted, verified-resumable dependency acquisition.\n')
        stream.flush()
        os.fsync(stream.fileno())
    from gpt_trace_transport.local_templates import sync_directory
    sync_directory(stage)
    sync_directory(stage.parent)
    if donor is not None:
        seed_sealed_cas(stage, donor[0], donor[2], account, seed_git=reuse is None)
        hints = stage/'retained-urls.json'
        with hints.open('x') as stream:
            json.dump(donor[2]['url_index'], stream, sort_keys=True, separators=(',', ':'))
        os.chown(hints, account.pw_uid, account.pw_gid)
        hints.chmod(0o400)
    for previous_stage in sorted(set(retained) | ({reuse} if reuse is not None else set())):
        # A failed candidate can contain protected links inherited from a
        # previous sealed pool. Admit only those exact immutable CAS inodes.
        for path in (previous_stage/'objects'/'sha256').glob('*/*'):
            info = path.lstat()
            if info.st_uid != 0:
                continue
            sha = path.name
            if (len(sha) != 64 or any(char not in '0123456789abcdef' for char in sha)
                    or path.parent.name != sha[:2] or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o222
                    or any(parent.is_symlink() for parent in path.parents)):
                raise RuntimeError('unsafe protected retained CAS object')
            destination = stage/'objects'/'sha256'/sha[:2]/sha
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            for directory in (destination.parent, destination.parent.parent, destination.parent.parent.parent):
                os.chown(directory, account.pw_uid, account.pw_gid)
                directory.chmod(0o700)
            os.link(path, destination)
    with tempfile.TemporaryDirectory(prefix='gpttrace-metadata-', dir='/run') as directory:
        control = Path(directory)
        os.chown(control, 0, account.pw_gid)
        control.chmod(0o750)
        # Image is disposable, not a persistent template or a donor volume.
        with tempfile.TemporaryDirectory(prefix='.native-guest-', dir=manager.base.parent) as temporary:
            image = Path(temporary) / 'metadata.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(safe(manager.base, immutable=True)), str(image)], check=True, timeout=limit)
            subprocess.run(['virt-customize', '--no-network', '-a', str(image),
                            *builder.template_golden_isolation_arguments(),
                            *builder.offline_service_mask_arguments('gpt-trace-workstation-agent.service')],
                           check=True, timeout=limit)
            # Resize only the disposable overlay; the actual Golden stays read-only.
            virtual_gib = controls['build']['virtual_disk_gib']
            info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)], timeout=limit))
            if info['virtual-size'] < virtual_gib * 1024**3:
                subprocess.run(['qemu-img', 'resize', str(image), str(virtual_gib) + 'G'], check=True, timeout=limit)
            os.chown(image, account.pw_uid, account.pw_gid)
            image.chmod(0o600)
            os.chown(temporary, 0, account.pw_gid)
            Path(temporary).chmod(0o750)
            # QEMU opens the immutable backing and private overlay as root, then
            # drops to the same unprivileged identity as the acquisition worker.
            memory, vcpus = builder.guest_resources()
            available, = [int(line.split()[1]) // 1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')]
            memory = min(memory, ((available - controls['build']['memory_reserve_mb']
                                  - controls['acquisition']['pip_solver_worker_memory_mb']) // 256) * 256)
            if memory < controls['build']['memory_min_mb']:
                raise RuntimeError('insufficient available memory for the target guest and verified resolver')
            agent_path = control / 'agent.sock'
            link_path = control / 'links.sock'
            serial = Path(temporary) / 'serial.log'
            argv = [builder.qemu_system_binary(), '-machine', 'accel=kvm', '-cpu', 'host',
                    '-m', str(memory), '-smp', str(vcpus), '-run-with', 'user=' + account.pw_name,
                    '-drive', 'file=' + _qemu_value(image) + ',format=qcow2,if=virtio,cache=writeback,discard=unmap',
                    '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot',
                    '-serial', 'file:' + str(serial), '-device', 'virtio-serial-pci',
                    '-chardev', 'socket,id=agent,path=' + str(agent_path) + ',server=on,wait=off',
                    '-device', 'virtserialport,chardev=agent,name=org.qemu.guest_agent.0']
            for tag, path, readonly in (('native-stage', stage, False), ('native-source', source, True)):
                argv.extend(['-fsdev', 'local,id=' + tag + ',path=' + _qemu_value(path) + ',security_model=none' + (',readonly=on' if readonly else ''),
                             '-device', 'virtio-9p-pci,fsdev=' + tag + ',mount_tag=' + tag])
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, start_new_session=True,
                                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
            links = None
            try:
                deadline = time.monotonic() + limit
                while not agent_path.is_socket():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('metadata guest failed to expose its agent socket')
                    time.sleep(min(cadence, 0.1))
                os.chown(agent_path, account.pw_uid, account.pw_gid)
                os.chmod(agent_path, 0o600)
                agent = transport.GuestAgent(agent_path, limit, min(cadence, 0.1))
                while True:
                    try:
                        agent.call('guest-ping', deadline=min(deadline, time.monotonic() + cadence))
                        break
                    except (TimeoutError, ConnectionError):
                        # The QEMU socket can exist before the guest agent has
                        # started. Only the side-effect-free readiness probe
                        # may be repeated, under the original boot deadline.
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise
                        time.sleep(min(cadence, max(0, deadline - time.monotonic())))
                for tag, path, readonly in (('native-stage', stage, False), ('native-source', source, True)):
                    agent.run(['/usr/bin/mkdir', '-p', str(path)])
                    agent.run(['/usr/bin/mount', '-t', '9p', '-o', 'trans=virtio,version=9p2000.L,cache=none,' + ('ro' if readonly else 'rw'), tag, str(path)])
                local = '/var/tmp/gpttrace-native-metadata'
                account_setup = """import grp, pwd, subprocess, sys
uid, gid, name = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
try:
    grp.getgrgid(gid)
except KeyError:
    subprocess.run(['groupadd', '--gid', str(gid), name], check=True)
try:
    pwd.getpwuid(uid)
except KeyError:
    subprocess.run(['useradd', '--uid', str(uid), '--gid', str(gid), '--no-create-home', '--shell', '/usr/sbin/nologin', name], check=True)
"""
                agent.run(['/usr/bin/python3', '-I', '-c', account_setup, str(account.pw_uid), str(account.pw_gid), account.pw_name])
                agent.run(['/usr/bin/mkdir', '-p', local])
                agent.run(['/usr/bin/chown', str(account.pw_uid) + ':' + str(account.pw_gid), local])
                # Grow the guest filesystem using the existing builder's exact
                # root-device logic, not assumptions about partition numbers.
                links = SealedCasLinks(link_path, stage, account, cleanup)
                yield {'GPT_TRACE_NATIVE_GUEST_AGENT': str(agent_path), 'GPT_TRACE_NATIVE_GUEST_UID': str(account.pw_uid),
                       'GPT_TRACE_NATIVE_GUEST_GID': str(account.pw_gid), 'GPT_TRACE_NATIVE_GUEST_LOCAL': local,
                       'GPT_TRACE_SEALED_CAS_LINKS': str(link_path)}
            finally:
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=cleanup)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=cleanup)
                finally:
                    if links is not None:
                        links.close()

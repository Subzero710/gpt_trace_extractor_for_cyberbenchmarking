# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
"""Finite admin-only local preparation jobs. Durable identity, no command RPC.

One inherited flock protects the whole build across broker restarts. The child
claims its PID/start-time/session before constructing anything. A lost response
is rediscovered by ID; only an explicit later fetch may retry a proved-dead job.
"""
from __future__ import annotations
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import logging
import math
import os
import select
import shutil
import signal
import subprocess
import stat
import struct
import sys
import time
import tomllib
import types
from pathlib import Path
from types import SimpleNamespace

from gpt_trace_transport.operation_watch import host_operation
from gpt_trace_transport.local_templates import (ROOT, SHA, atomic_json, canonical,
    compatibility, file_signature, golden_dependency_identity, safe, source_contract,
    verify_local_validation, verify_manifest, activate, FETCH_SOURCE_FILES, fetch_runtime_executables, fetch_runtime_build_identity_path,
    verify_fetch_runtime_build_identity, pool_contract, seal,
    sync_directory, namespace_rx_bytes, namespace_rx_delta, fetch_download_limit, FETCH_BUDGET_EXIT_CODE, NATIVE_METADATA_EXIT_CODE)

from workstation_broker.preparation_resources import JobScope, source_containers, remove_source_containers

TERMINAL = frozenset({"ready", "failed", "interrupted", "canceled"})
PHASES = TERMINAL | {"starting", "running", "validating"}

def locked_python_minors(source_root):
    lock = Path(source_root) / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/conda-lock.json"
    payload = json.loads(lock.read_bytes())
    values = sorted({".".join(str(item["version"]).split(".")[:2])
                     for item in payload.get("artifacts", {}).values()
                     if item.get("name") == "python"})
    if not values:
        raise RuntimeError("pinned Conda lock has no Python identities")
    return values


def contract_counts(source_root):
    contract = json.loads((Path(source_root) / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json").read_bytes())
    tasks = contract.get("tasks", {})
    repos = {row.get("repo") for row in tasks.values()}
    environments = contract.get("environments", {})
    if not tasks or not repos or not environments:
        raise RuntimeError("pinned benchmark contract is empty")
    return len(tasks), len(repos), len(environments)


def trusted_fetch_python():
    """Return the root-owned system interpreter used after dropping privileges."""
    executable = shutil.which("python3", path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise RuntimeError("trusted system Python for dependency fetch is unavailable")
    interpreter = Path(executable).resolve(strict=True)
    info = interpreter.stat()
    if (not interpreter.is_file() or not info.st_mode & 0o111 or info.st_uid != 0
            or info.st_mode & 0o022):
        raise RuntimeError("trusted system Python for dependency fetch is unavailable")
    for parent in interpreter.parents:
        parent_info = parent.stat()
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise RuntimeError("trusted system Python path is writable by a non-root principal")
    probe = subprocess.run(
        [str(interpreter), "-I", "-B", "-m", "pip", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if probe.returncode != 0:
        detail = (probe.stderr.strip() or probe.stdout.strip())[:500]
        raise RuntimeError(
            "trusted system Python cannot import pip required by dependency fetch"
            + (": " + detail if detail else "")
        )
    return interpreter


def stage_fetch_sources(manager, pool_root, operation_id=None, attempt=None, golden_dependency=None, *, expected_sources=None, native_requests=None):
    """Copy exact worker inputs plus the verified dependency target into a sealed snapshot."""
    repository = manager.source_root.resolve(strict=True)
    expected_sources = pool_contract(repository)['fetch_sources'] if expected_sources is None else expected_sources
    if set(expected_sources) != set(FETCH_SOURCE_FILES):
        raise RuntimeError('admitted fetch source contract is incomplete')
    if operation_id is None or attempt is None:
        snapshot = pool_root / "source"
    else:
        snapshot = pool_root / ("source-"+identifier(operation_id)+"-"+str(attempt))
    if snapshot.exists() or snapshot.is_symlink():
        raise RuntimeError("per-attempt source snapshot already exists; refusing overwrite: " + str(snapshot))
    snapshot.mkdir(mode=0o755)
    for relative in FETCH_SOURCE_FILES:
        source = manager.source_root / relative
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("missing/untrusted fetch source: " + relative)
        resolved = source.resolve(strict=True)
        if not resolved.is_relative_to(repository):
            raise RuntimeError("fetch source escapes repository: " + relative)
        target = snapshot / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sources[relative]:
            raise RuntimeError('fetch source changed after admission: '+relative)
        target.write_bytes(data)
        os.chown(target, 0, 0)
        target.chmod(0o444)
    # Fossil-only artifact and build attestation: neither is required on Acer.
    # Re-derive the source and executable digests in the installed tree.
    verify_fetch_runtime_build_identity(repository)
    binaries = fetch_runtime_executables(repository)
    identity_relative = fetch_runtime_build_identity_path(repository)
    for relative in (*binaries, identity_relative):
        executable = repository / relative
        if executable.is_symlink() or not executable.is_file():
            raise RuntimeError('mandatory Fossil Rust build artifact is missing: ' + relative)
        resolved = executable.resolve(strict=True)
        if not resolved.is_relative_to(repository):
            raise RuntimeError('Fossil Rust build artifact escapes source repository')
        info = executable.stat()
        is_binary = relative in binaries
        if (info.st_uid != 0 or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o022 or (is_binary and not info.st_mode & 0o111)
                or (not is_binary and info.st_mode & 0o222)):
            raise RuntimeError('mandatory Fossil Rust build artifact has untrusted permissions')
        target = snapshot / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if ((before.st_uid != 0 or not stat.S_ISREG(before.st_mode)
                 or before.st_mode & 0o022 or (is_binary and not before.st_mode & 0o111)
                 or (not is_binary and before.st_mode & 0o222))):
                raise RuntimeError('Fossil Rust build artifact changed permissions before staging')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                data = stream.read()
            after = os.fstat(descriptor)
            if ((before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns)):
                raise RuntimeError('Fossil Rust build artifact changed while staging')
        finally:
            os.close(descriptor)
        target.write_bytes(data)
        os.chown(target, 0, 0)
        target.chmod(0o555 if is_binary else 0o444)
    verify_fetch_runtime_build_identity(snapshot)
    dependency = golden_dependency_identity(manager.base, manager.source_root) if golden_dependency is None else golden_dependency
    if dependency != golden_dependency_identity(manager.base, manager.source_root):
        raise RuntimeError("golden dependency identity changed before fetch source staging")
    target = snapshot / "golden-dependency.json"
    target.write_bytes(canonical(dependency) + b"\n")
    os.chown(target, 0, 0)
    target.chmod(0o444)
    # Stage the ACTUAL golden package inventory, not an Ubuntu host guess.
    packages = safe(manager.base.parent / "kali-packages.txt", immutable=True)
    if hashlib.sha256(packages.read_bytes()).hexdigest() != dependency["apt_package_manifest_sha256"]:
        raise RuntimeError("sealed golden APT package inventory differs")
    inventory = snapshot / "golden-packages.txt"
    inventory.write_bytes(packages.read_bytes())
    os.chown(inventory, 0, 0)
    inventory.chmod(0o444)
    # Read the complete dpkg database from the authenticated immutable image.
    # The unprivileged fetcher never opens a host QCOW2 or the host dpkg database.
    controls = tomllib.loads((manager.source_root / 'config/preparation.toml').read_text())['acquisition']
    limit = controls['timeout_seconds']
    if type(limit) is not int or not 1 <= limit <= 180:
        raise RuntimeError('invalid golden dpkg status extraction deadline')
    status = subprocess.check_output(['virt-cat', '--format=qcow2', '-a',
        str(safe(manager.base, immutable=True)), '/var/lib/dpkg/status'], timeout=limit)
    if not status:
        raise RuntimeError('empty Golden dpkg status')
    for name, data in (('golden-dpkg-status', status),
                       ('native-requests.json', canonical(native_requests if native_requests is not None else {}) + b"\n")):
        exported = snapshot / name
        with exported.open('xb') as stream:
            stream.write(data)
        os.chown(exported, 0, 0)
        exported.chmod(0o444)
    for directory in sorted((p for p in snapshot.rglob("*") if p.is_dir()),
                            key=lambda p: len(p.parts), reverse=True):
        os.chown(directory, 0, 0)
        directory.chmod(0o555)
    os.chown(snapshot, 0, 0)
    snapshot.chmod(0o555)
    return snapshot, snapshot / "scripts/superbench_pool.py"


def remove_fetch_sources(snapshot):
    """Remove only the finite source snapshot after a successful worker exit."""
    snapshot = Path(snapshot)
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise RuntimeError("unsafe fetch source snapshot")
    for item in (snapshot, *snapshot.rglob("*")):
        if item.is_symlink():
            raise RuntimeError("unsafe symlink in fetch source snapshot")
    for item in sorted(snapshot.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if item.is_dir(): item.chmod(0o700)
        else: item.chmod(0o600)
    snapshot.chmod(0o700)
    shutil.rmtree(snapshot)


def pre_download_fetch_retryable(state, base):
    """Allow explicit retry only for known failures before any pool byte exists."""
    if state.get("phase") not in {"failed", "interrupted"} or state.get("result") is not None:
        return False
    error = state.get("error")
    known = (
        isinstance(error, str)
        and (
            (
                error.startswith("PermissionError: [Errno 13] Permission denied:")
                and "/.venv-workstation-broker/bin/python" in error
            )
            or error.startswith(
                "RuntimeError: trusted system Python for dependency fetch is unavailable"
            )
            or error.startswith(
                "RuntimeError: trusted system Python path is writable by a non-root principal"
            )
            or error.startswith(
                "RuntimeError: trusted system Python cannot import pip required by dependency fetch"
            )
        )
    )
    if not known:
        return False
    pool = Path(base).parent / "dependency-pool"
    if pool.is_symlink() or not pool.is_dir() or pool.stat().st_uid != 0:
        return False
    return not any(pool.iterdir())

def configured_base_image():
    source = ROOT / "config/distributed.toml"
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("missing/unsafe distributed configuration")
    with source.open("rb") as stream:
        config = tomllib.load(stream)
    value = config.get("paths", {}).get("base_image")
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise RuntimeError("config/distributed.toml paths.base_image must be an absolute path")
    return Path(value)


BASE = configured_base_image()
PROC = Path("/proc")  # Fixed host process table; never configurable through RPC.


def identifier(value):
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ValueError("invalid preparation ID")
    return value


def boot_id():
    return (PROC / "sys/kernel/random/boot_id").read_text().strip()


def process_identity(pid):
    try:
        raw = (PROC / str(pid) / "stat").read_text()
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ESRCH):
            return None
        raise
    tail = raw[raw.rfind(")") + 2:].split()
    if len(tail) < 20: raise RuntimeError("invalid process identity record")
    return {"boot_id": boot_id(), "pid": int(pid), "start_ticks": int(tail[19]),
            "pgid": int(tail[2]), "session": int(tail[3]), "state": tail[0]}


def same_process(stamp):
    if not isinstance(stamp, dict) or not {"boot_id", "pid", "start_ticks", "pgid", "session"} <= set(stamp):
        raise ValueError("unverified preparation process identity")
    if stamp["boot_id"] != boot_id(): return False
    current = process_identity(stamp["pid"])
    return current is not None and current["state"] != "Z" and all(current[k] == stamp[k]
        for k in ("boot_id", "pid", "start_ticks", "pgid", "session"))


def group_members(stamp, operation_id):
    """Audit only the recorded session/group; never signal an unowned process."""
    if stamp["boot_id"] != boot_id(): return []
    if stamp["pgid"] != stamp["pid"] or stamp["session"] != stamp["pid"]:
        raise RuntimeError("preparation is not a private process session")
    members = []
    for path in PROC.iterdir():
        if not path.name.isdigit(): continue
        current = process_identity(int(path.name))
        if current is None or current["state"] == "Z" or current["pgid"] != stamp["pgid"]:
            continue
        if current["session"] != stamp["session"] or current["start_ticks"] < stamp["start_ticks"]:
            raise RuntimeError("preparation group ownership is uncertain")
        try:
            owner = path.stat().st_uid
            environment = (path / "environ").read_bytes().split(b"\0")
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                continue
            raise
        if owner != 0 or ("GPT_TRACE_PREPARATION_ID=" + operation_id).encode() not in environment:
            raise RuntimeError("foreign process in recorded preparation group; preserved")
        members.append(current)
    return members


def state_path(operation_id):
    return BASE.parent / "preparations" / identifier(operation_id) / "state.json"


def verify_worker_claim(operation_id):
    operation_id = identifier(operation_id)
    if os.geteuid() != 0 or os.environ.get("GPT_TRACE_PREPARATION_ID") != operation_id:
        raise RuntimeError("template construction requires its authenticated administrative job")
    path = safe(state_path(operation_id))
    state = json.loads(path.read_bytes())
    stamp = state.get("worker")
    if state.get("operation_id") != operation_id or not same_process(stamp) or stamp["pid"] != os.getpid():
        raise RuntimeError("local builder does not own the recorded preparation")
    if state["phase"] not in {"running", "validating"}:
        raise RuntimeError("local preparation is not authorized to build")
    JobScope.require_current(state)
    return state


def record_built_generation(operation_id, generation):
    state = verify_worker_claim(operation_id)
    identifier(generation)
    atomic_json(state_path(operation_id), {**state, "phase": "validating",
        "built_generation": generation, "updated_at": time.time()}, 0o600)


def record_rejected_generation(operation_id, generation):
    state = verify_worker_claim(operation_id)
    if state.get('built_generation') != identifier(generation):
        raise RuntimeError('rejected generation does not match the recorded candidate')
    atomic_json(state_path(operation_id), {**state, 'phase': 'running',
        'built_generation': None, 'rejected_generation': generation,
        'updated_at': time.time()}, 0o600)


def generation_signature(root, base, generation):
    folder = safe(Path(root) / "swe-gym-lite/generations" / identifier(generation), immutable=True, directory=True)
    result = {}
    for path in sorted(folder.rglob("*")):
        safe(path, immutable=True, directory=path.is_dir())
        result[path.relative_to(folder).as_posix()] = list(file_signature(path))
    result["."] = list(file_signature(folder))
    for path in (base, base.with_suffix(".provenance.json"), base.parent / "kali-packages.txt", base.parent / "kali-python-packages.txt"):
        safe(path, immutable=True)
        result["golden:" + path.name] = list(file_signature(path))
    return result


class _PreparationSnapshotEvents:
    """Wait on named atomic publications without polling workers or holding locks."""

    _MOVED_TO = 0x00000080
    _CREATE = 0x00000100
    _DELETE = 0x00000200
    _ATTRIB = 0x00000004
    _DELETE_SELF = 0x00000400
    _MOVE_SELF = 0x00000800
    _Q_OVERFLOW = 0x00004000
    _IGNORED = 0x00008000
    _WATCH_MASK = (_MOVED_TO | _CREATE | _DELETE | _ATTRIB |
                   _DELETE_SELF | _MOVE_SELF)

    def __init__(self, root, pool_root, operation_id, attempt):
        stage_name = 'incoming-' + operation_id + '-' + str(attempt)
        stage = pool_root / stage_name
        self.paths = (
            (root / operation_id, b'state.json'),
            (pool_root, os.fsencode(stage_name)),
            (stage, b'metadata'),
            (stage / 'metadata', b'fetch-progress.json'),
        )
        self.api = ctypes.CDLL(None, use_errno=True)
        self.api.inotify_init1.argtypes = [ctypes.c_int]
        self.api.inotify_init1.restype = ctypes.c_int
        self.api.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.api.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.api.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        self.watches = {}
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

    def __enter__(self):
        try:
            self.refresh()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, _type, _value, _traceback):
        os.close(self.fd)

    def refresh(self):
        for directory, name in self.paths:
            if directory in self.watches:
                continue
            if directory.is_symlink():
                raise RuntimeError('untrusted preparation progress watch directory')
            if not directory.is_dir():
                continue
            watch_id = self.api.inotify_add_watch(
                self.fd, os.fsencode(directory), self._WATCH_MASK)
            if watch_id < 0:
                code = ctypes.get_errno()
                if code == errno.ENOENT:
                    continue
                raise OSError(code, os.strerror(code), str(directory))
            self.watches[directory] = (watch_id, name)

    def changed(self, seconds):
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            ready = self.poller.poll(max(1, int(remaining * 1000)))
            if not ready:
                return False
            if any(mask & (select.POLLERR | select.POLLHUP | select.POLLNVAL)
                   for _descriptor, mask in ready):
                raise RuntimeError('preparation inotify observation failed')
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            offset = 0
            watched_names = {number: name for number, name in self.watches.values()}
            while offset < len(events):
                if len(events) - offset < 16:
                    raise RuntimeError('truncated preparation inotify event')
                watch_id, mask, _cookie, length = struct.unpack_from('iIII', events, offset)
                offset += 16
                if offset + length > len(events):
                    raise RuntimeError('invalid preparation inotify event size')
                name = events[offset:offset + length].split(b'\0', 1)[0]
                offset += length
                if mask & self._IGNORED:
                    for directory, (number, _wanted) in tuple(self.watches.items()):
                        if number == watch_id:
                            del self.watches[directory]
                    return True
                if mask & (self._Q_OVERFLOW | self._DELETE_SELF | self._MOVE_SELF):
                    return True
                if (watch_id in watched_names and name == watched_names[watch_id]
                        and mask & (self._MOVED_TO | self._CREATE |
                                    self._DELETE | self._ATTRIB)):
                    return True

def _validate_fetch_progress(data, operation_id, reject, observed=None):
    required = {
        'schema', 'operation_id', 'stage', 'completed', 'total', 'unit',
        'network_bytes', 'pip_bytes', 'pip_active'
    }
    if isinstance(data,dict) and data.get('schema') == 2:
        required |= {'details','stage_epoch','volume','rx_bytes'}
        volume=data.get('volume')
        if (not isinstance(volume,dict) or set(volume)!={'identified_bytes','acquired_bytes','artifacts','complete'}
                or any(type(volume[key]) is not int or volume[key]<0 for key in ('identified_bytes','acquired_bytes','artifacts'))
                or type(volume['complete']) is not bool or volume['acquired_bytes']>volume['identified_bytes']
                or volume['complete'] and volume['acquired_bytes']!=volume['identified_bytes']
                or type(data.get('stage_epoch')) is not int or data['stage_epoch']<0
                or type(data.get('rx_bytes')) is not int or data['rx_bytes']<0
                or not isinstance(data.get('details'),str) or len(data['details'])>1024
                or any(ord(ch)<32 for ch in data['details'])):
            reject('invalid fetch volume or phase identity','volume_validation',rejected_payload=data)
    if (not isinstance(data, dict) or set(data) != required
            or data['schema'] not in (1,2) or data['operation_id'] != operation_id
            or not isinstance(data['stage'], str) or not 0 < len(data['stage']) <= 160
            or not isinstance(data['unit'], str) or len(data['unit']) > 64
            or any(ord(ch) < 32 for ch in data['stage'] + data['unit'])
            or any(type(data[key]) is not int or data[key] < 0
                   for key in ('network_bytes', 'pip_bytes', 'pip_active'))
            or any(data[key] is not None and (type(data[key]) is not int or data[key] < 0)
                   for key in ('completed', 'total'))
            or (data['completed'] is not None and data['total'] is not None
                and data['completed'] > data['total'])):
        reject('invalid verified fetch progress data', 'payload_validation',
               rejected_payload=data, expected_keys=sorted(required),
               expected_operation_id=operation_id, opened=observed)
    return data


class PreparationManager:
    def __init__(self, base, template_root, templates, *, source_root=ROOT, deployment=None):
        self.base, self.template_root, self.templates = Path(base), Path(template_root), templates
        self.source_root = Path(source_root)
        self.root = self.base.parent / "preparations"
        self.deployment = deployment if deployment is not None else {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
            "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}
        if os.geteuid() != 0: raise RuntimeError("preparations require execution host root")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe(self.root, directory=True)
        if self.root.stat().st_mode & 0o077: raise ValueError("preparation root must be private")
        self._children = {}

    @contextlib.contextmanager
    def lock(self):
        fd = self._lock_file("manager.lock")
        try:
            with host_operation("preparation-manager-lock"):
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally: os.close(fd)

    def _lock_file(self, name):
        fd = os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077:
            os.close(fd)
            raise RuntimeError("untrusted preparation lock")
        return fd

    def slot_busy(self):
        fd = self._lock_file("build-slot.lock")
        try:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: return True
            return False
        finally: os.close(fd)

    def expected(self):
        # Control/execution agree on versioned acquisition sources. The execution
        # host then binds the operation to the exact immutable golden target/npm
        # identity that changes dependency resolution.
        from gpt_trace_transport.local_templates import pool_contract
        return {**pool_contract(self.source_root),
                "golden_dependency": golden_dependency_identity(self.base, self.source_root)}

    def probe(self, payload):
        from gpt_trace_transport.local_templates import pool_contract
        source_contract = pool_contract(self.source_root)
        if set(payload) != {"source_contract"} or payload["source_contract"] != source_contract:
            raise ValueError("control/execution pinned preparation sources differ")
        expected = self.expected()
        return {"operation_id": hashlib.sha256(canonical(expected)).hexdigest(),
                "compatibility": expected, "deployment": self.deployment}

    def _path(self, operation_id):
        return self.root / identifier(operation_id) / "state.json"

    def _read(self, operation_id):
        path = self._path(operation_id)
        if not path.exists():
            if path.is_symlink(): raise ValueError("unsafe preparation state")
            return None
        safe(path)
        state = json.loads(path.read_bytes())
        if (state.get("schema") != 1 or state.get("operation_id") != operation_id or state.get("phase") not in PHASES
                or state.get("deployment") != self.deployment or type(state.get("attempt")) is not int
                or state["attempt"] < 1 or hashlib.sha256(canonical(state.get("compatibility"))).hexdigest() != operation_id):
            raise ValueError("unexpected durable preparation state")
        JobScope.path(state)
        return state

    def _write(self, state):
        atomic_json(self._path(state["operation_id"]), {**state, "updated_at": time.time()}, 0o600)

    def _progress(self, state):
        """Read a verified atomic snapshot, retrying only a proven inode replacement."""
        attempt = state.get('attempt')
        operation_id = state.get('operation_id')
        if type(attempt) is not int or attempt < 1 or not isinstance(operation_id, str):
            return None
        logger = logging.getLogger(__name__)

        def reject(message, reason, **values):
            logger.error('fetch progress snapshot rejected: operation_id=%s '
                         'attempt=%s reason=%s rejected_values=%r',
                         operation_id, attempt, reason, values)
            raise RuntimeError(message)

        if 'integration_progress' in state:
            return _validate_fetch_progress(state['integration_progress'], operation_id, reject)
        stage = self.base.parent/'dependency-pool'/('incoming-'+identifier(operation_id)+'-'+str(attempt))
        metadata = stage/'metadata'
        if (not stage.is_dir() or stage.is_symlink()
                or not metadata.is_dir() or metadata.is_symlink()):
            return None
        path = metadata/'fetch-progress.json'
        owner = stage.stat().st_uid
        def attributes(info):
            return {'device': info.st_dev, 'inode': info.st_ino,
                    'uid': info.st_uid, 'gid': info.st_gid,
                    'mode': oct(stat.S_IMODE(info.st_mode)),
                    'regular': stat.S_ISREG(info.st_mode),
                    'links': info.st_nlink, 'size': info.st_size}

        try:
            named = path.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(named.st_mode):
            reject('untrusted fetch progress symlink', 'symlink',
                   current=attributes(named), expected_uid=owner)

        retry_deadline = None
        while True:
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError as exc:
                reject('untrusted fetch progress snapshot', 'open_failed',
                       errno=exc.errno, error=str(exc), expected_uid=owner)
            try:
                info = os.fstat(descriptor)
                observed = attributes(info)
                if (not stat.S_ISREG(info.st_mode)
                        or info.st_uid != owner
                        or info.st_mode & 0o077
                        or info.st_size > 8192
                        or info.st_nlink not in (0, 1)):
                    reject('untrusted fetch progress snapshot', 'file_attributes',
                           opened=observed, expected_uid=owner,
                           expected_mode='owner-only', expected_links=1,
                           maximum_size=8192)

                if info.st_nlink == 0:
                    # os.replace() unlinks the previously named inode. The open
                    # descriptor can legitimately observe zero links. Never accept
                    # that descriptor: prove a different trusted inode is now
                    # published, then reopen it and repeat every security check.
                    try:
                        current = path.lstat()
                    except OSError as exc:
                        reject('untrusted fetch progress snapshot',
                               'detached_inode_without_replacement',
                               opened=observed, errno=exc.errno, error=str(exc))
                    replacement = attributes(current)
                    if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                            or current.st_uid != owner or current.st_mode & 0o077
                            or current.st_size > 8192
                            or (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)):
                        reject('untrusted fetch progress snapshot',
                               'invalid_replacement_inode', opened=observed,
                               current=replacement, expected_uid=owner)
                    if retry_deadline is None:
                        policy = self.source_root / 'config/preparation.toml'
                        if policy.is_symlink() or not policy.is_file():
                            raise RuntimeError('missing versioned broker read controls')
                        with policy.open('rb') as stream:
                            read_seconds = tomllib.load(stream)['acquisition']['broker_read_timeout_seconds']
                        if type(read_seconds) is not int or read_seconds < 1:
                            raise RuntimeError('invalid versioned broker read timeout')
                        retry_deadline = time.monotonic() + read_seconds
                        logger.warning('fetch progress snapshot inode replaced during read: '
                                       'operation_id=%s attempt=%s opened=%r current=%r',
                                       operation_id, attempt, observed, replacement)
                    if time.monotonic() >= retry_deadline:
                        reject('untrusted fetch progress snapshot',
                               'replacement_did_not_stabilize_before_broker_read_deadline',
                               opened=observed, current=replacement)
                    continue

                with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                    value = stream.read(8193)
            finally:
                os.close(descriptor)
            break

        if not value or len(value) > 8192:
            reject('invalid fetch progress snapshot size', 'payload_size',
                   read_bytes=len(value), opened=observed, payload=value)
        try:
            data = json.loads(value)
        except (ValueError, UnicodeError) as exc:
            reject('invalid verified fetch progress data', 'json_decode',
                   error_type=type(exc).__name__, error=str(exc), payload=value)
        return _validate_fetch_progress(data, operation_id, reject, observed)

    def _public(self, state):
        if state['phase'] == 'ready' and (JobScope.members(state) or self._containers(state)):
            state = {**state, 'phase': 'validating'}  # Wait for the finite worker/helpers to exit.
        result = {k: state[k] for k in ("operation_id", "phase", "attempt", "created_at", "updated_at",
            "result", "error", "deployment") if k in state}
        progress = self._progress(state)
        if progress is not None:
            result["progress"] = progress
        # Read-only, bounded tail of the durable child log. No mutations, no
        # additional RPC, and no guessed progress based on wall-clock time.
        if isinstance(state.get("attempt"), int):
            log = self._path(state["operation_id"]).parent / f"attempt-{state['attempt']:04d}.log"
            if log.is_file() and not log.is_symlink():
                info = log.stat()
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise RuntimeError("untrusted preparation log permissions")
                start = max(0, info.st_size - 65536)
                with log.open("rb") as stream:
                    stream.seek(start)
                    raw = stream.read(65536)
                result["live_log"] = {"start": start, "end": start + len(raw),
                                      "total": info.st_size,
                                      "content_b64": __import__("base64").b64encode(raw).decode("ascii")}
        return result

    def _reap(self):
        for pid, process in list(self._children.items()):
            if process.poll() is not None: del self._children[pid]

    def _containers(self, state):
        return [row for row in source_containers(self.deployment) if row['operation_id'] == state['operation_id']]

    def _reconcile(self, state):
        self._reap()
        stamp = state.get('worker')
        members = JobScope.members(state)
        containers = self._containers(state)
        if members or containers:
            if stamp is not None and not same_process(stamp) and state['phase'] not in TERMINAL:
                state = {**state, 'phase': 'interrupted', 'error':
                    'preparation leader died; owned descendants/containers remain; make down must reconcile them before retry'}
                self._write(state)
            return state
        if stamp is None and state['phase'] == 'starting' and self.slot_busy():
            if time.time() - state['updated_at'] > 30:
                raise RuntimeError('preparation spawn has no claimed identity; slot is still held; no duplicate permitted')
            return state
        # Recovery is allowed ONLY for an already-verified, atomically
        # published result. Only its small inventory is rehashed; no downloads,
        # process restart or full CAS scan is performed by status.
        proof = state.get('publication_verified')
        if state.get('native_publication') is not None:
            # A recorded two-rename transition belongs to the next explicit
            # attempt. Status cannot treat the old or new bytes as READY.
            closed = JobScope.close({**state, 'phase': 'interrupted',
                                     'error': 'verified native publication transition remains pending'})
            self._write(closed)
            return closed
        if state['phase'] in {'running', 'validating', 'interrupted', 'canceled'} and isinstance(proof, dict):
            ready = self.base.parent / 'dependency-pool' / 'ready'
            retired = _retired_pool(ready.parent,state['operation_id'])
            publication = retired if retired.exists() or retired.is_symlink() else ready
            if publication.exists() or publication.is_symlink():
                inventory = verify_published_inventory(publication, state, proof)
                if (proof.get('kind') != 'download-only-pool' or proof.get('complete') is not True
                        or proof.get('pool_directory') != str(ready)
                        or inventory.get('operation_id') != state['operation_id']
                        or inventory.get('complete') is not True
                        or inventory.get('tasks') != proof.get('tasks')
                        or inventory.get('repos') != proof.get('repos')
                        or inventory.get('conda_recipes') != proof.get('conda_recipes')):
                    raise RuntimeError('published pool does not match the durable verified publication record')
                if proof.get('runtime_integrated') is not True:
                    if state['phase'] not in TERMINAL:
                        state = {**state, 'phase': 'interrupted',
                                 'error': state.get('error') or 'runtime integration remains incomplete; sealed pool retained'}
                        self._write(state)
                else:
                    if proof.get('prepared_setups') is not True or not isinstance(proof.get('generation'), str):
                        raise RuntimeError('published pool does not match the durable verified publication record')
                    state = {**state, 'phase': 'ready', 'result': proof, 'error': None}
                    self._write(state)
        if state['phase'] not in TERMINAL:
            if self.slot_busy(): raise RuntimeError('unidentified active build slot; outcome unconfirmed')
            state = {**state, 'phase': 'interrupted', 'error': 'worker/descendants absent; interrupted preparation retained'}
        closed = JobScope.close(state)
        if closed != state or state['phase'] not in TERMINAL: self._write(closed)
        # Also persist an interrupted state even when its scope was already closed.
        if closed['phase'] == 'interrupted': self._write(closed)
        return closed

    def _verify_ready(self, state):
        """Rebind the inventory proof without rescanning sealed pool artifacts."""
        result = state.get("result")
        task_count, repo_count, env_count = contract_counts(self.source_root)
        if (not isinstance(result, dict) or result.get("kind") != "download-only-pool"
                or result.get("complete") is not True or result.get("tasks") != task_count
                or result.get("repos") != repo_count or result.get("conda_recipes") != env_count
                or result.get("python_versions") != locked_python_minors(self.source_root)
                or result.get("runtime_integrated") is not True
                or result.get("prepared_setups") is not True
                or not isinstance(result.get("generation"), str)
                or state.get("compatibility") != self.expected()):
            self._write({**state, "phase": "failed", "error": "invalid pool publication record"})
            return {**state, "phase": "failed", "error": "invalid pool publication record"}
        # Sealed artifacts are immutable; verify the inventory's exact identity.
        folder = self.base.parent / "dependency-pool" / "ready"
        verify_published_inventory(folder, state, result)
        return state

    def _status_now(self, operation_id):
        with self.lock():
            state = self._read(operation_id)
            if state is None:
                return {"operation_id": operation_id, "phase": "not_started",
                        "deployment": self.deployment}
            if (state['phase'] in {'starting', 'running', 'validating'}
                    and JobScope.leader_active(state)):
                return self._public(state)
            state = self._reconcile(state)
            if state['phase'] == 'ready':
                state = self._verify_ready(state)
            return self._public(state)

    @staticmethod
    def _status_observation(status):
        return {field: status.get(field) for field in ('phase', 'attempt', 'progress')}

    def status(self, payload):
        """Wait for a newly published progress or state event via inotify."""
        if set(payload) not in ({'operation_id'}, {'operation_id', 'after'}):
            raise ValueError('invalid preparation status fields')
        operation_id = identifier(payload['operation_id'])
        if 'after' not in payload:
            return self._status_now(operation_id)
        after = payload['after']
        if (not isinstance(after, dict) or set(after) != {'phase', 'attempt', 'progress'}
                or after['phase'] not in {'starting', 'running', 'validating'}
                or type(after['attempt']) is not int or after['attempt'] < 1
                or after['progress'] is not None and not isinstance(after['progress'], dict)
                or len(canonical(after)) > 8192):
            raise ValueError('invalid preparation progress observation')
        policy = self.source_root / 'config/preparation.toml'
        if policy.is_symlink() or not policy.is_file():
            raise RuntimeError('missing versioned preparation observation policy')
        with policy.open('rb') as stream:
            acquisition = tomllib.load(stream)['acquisition']
        interval = acquisition['progress_interval_seconds']
        read_timeout = acquisition['broker_read_timeout_seconds']
        if (type(interval) is not int or interval < 1
                or type(read_timeout) is not int or read_timeout <= 1):
            raise RuntimeError('invalid versioned preparation observation controls')
        deadline = time.monotonic() + min(interval, read_timeout / 2)
        with _PreparationSnapshotEvents(self.root, self.base.parent / 'dependency-pool',
                                        operation_id, after['attempt']) as events:
            while True:
                latest = self._status_now(operation_id)
                if (self._status_observation(latest) != after
                        or latest['phase'] not in {'starting', 'running', 'validating'}):
                    return latest
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return latest
                if events.changed(remaining):
                    events.refresh()


    def start(self, payload):
        if set(payload) != {"operation_id", "compatibility", "retry"} or type(payload["retry"]) is not bool:
            raise ValueError("invalid preparation start fields")
        expected = self.expected()
        operation_id = identifier(payload["operation_id"])
        if payload["compatibility"] != expected or operation_id != hashlib.sha256(canonical(expected)).hexdigest():
            raise ValueError("preparation identity is not the exact local recipe/golden")
        with self.lock():
            previous = self._read(operation_id)
            if previous is not None:
                previous = self._reconcile(previous)
                if previous["phase"] == "ready":
                    previous = self._verify_ready(previous)
                if previous["phase"] == "ready" or previous["phase"] not in TERMINAL:
                    return self._public(previous)
                # An explicit operator retry is safe only after _reconcile
                # verified the previous worker and all descendants are absent.
                pending_integration = (isinstance(previous.get('publication_verified'), dict)
                    and previous['publication_verified'].get('runtime_integrated') != True)
                if not (payload['retry'] and previous['phase'] in {'failed','interrupted','canceled'}
                        and previous.get('result') is None
                        and (previous.get('publication_verified') is None or pending_integration)
                        and (pending_integration or not (self.base.parent/'dependency-pool'/'ready').exists()
                             or _apt_repair_source(self,self.base.parent/'dependency-pool',previous,
                                                   compatible=_metadata_artifact_compatible) is not None)):
                    raise RuntimeError('explicit retry of failed/unpublished preparation required')
                if JobScope.members(previous) or self._containers(previous):
                    raise RuntimeError("previous preparation process group remains; duplicate blocked")
            elif payload["retry"]:
                raise ValueError("cannot retry an operation that has never been started")
            slot = self._lock_file("build-slot.lock")
            try:
                try: fcntl.flock(slot, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise RuntimeError("another local preparation is active; no duplicate build") from None
                # Audit every inherited scope before allocating another job.
                states = [self._read(identifier(p.name)) for p in self.root.iterdir() if p.is_dir()]
                if any(s is None for s in states): raise RuntimeError('unowned preparation directory')
                JobScope.audit_unknown(states)
                for directory in self.root.iterdir():
                    if not directory.is_dir(): continue
                    other = self._read(identifier(directory.name))
                    if other is None: raise RuntimeError("unowned partial preparation directory; preserved")
                    if JobScope.members(other) or self._containers(other):
                        raise RuntimeError("owned preparation children remain; reconcile before a new build")
                directory = self._path(operation_id).parent
                directory.mkdir(mode=0o700, exist_ok=True)
                safe(directory, directory=True)
                now = time.time()
                attempt = (previous["attempt"] + 1) if previous is not None else 1
                if previous is not None:
                    atomic_json(directory / f"attempt-{previous['attempt']:04d}.json", previous, 0o600)
                state = {"schema": 1, "operation_id": operation_id, "compatibility": expected,
                    "deployment": self.deployment, "attempt": attempt, "phase": "starting",
                    "created_at": previous["created_at"] if previous else now, "updated_at": now,
                    "worker": None, "result": None, "error": None,
                    "scope": JobScope.create(operation_id, attempt),
                    "publication_verified": previous.get("publication_verified") if previous else None,
                    **({"publication_attempt": previous.get("publication_attempt", previous["attempt"])}
                       if previous and previous.get("publication_verified") else {}),
                    "built_generation": previous.get("built_generation") if previous else None,
                    **({key: previous[key] for key in ('native_requests', 'native_pending', 'native_publication', 'metadata_pending', 'metadata_resume')
                        if key in previous} if previous else {})}
                self._write(state)
                environment = dict(os.environ, GPT_TRACE_PREPARATION_ID=operation_id, LIBGUESTFS_BACKEND="direct")
                python = self.source_root / ".venv-workstation-broker/bin/python"
                script = self.source_root / "scripts/prepare_local_templates.py"
                with (directory / f"attempt-{attempt:04d}.log").open("ab") as log:
                    process = subprocess.Popen([str(python), "-B", str(script), operation_id, "--slot-fd", str(slot)],
                        cwd=self.source_root, env=environment, stdin=subprocess.DEVNULL,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True, pass_fds=(slot,))
                self._children[process.pid] = process
                # The child waits for this manager lock before claiming/building.
                # Attach before unlocking; an unassigned child can never build.
                try:
                    deadline = time.monotonic() + 3
                    stamp = process_identity(process.pid)
                    while stamp is None and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                        stamp = process_identity(process.pid)
                    if stamp is None or stamp['pgid'] != process.pid or stamp['session'] != process.pid:
                        raise RuntimeError('spawned preparation has no verified private identity')
                    JobScope.attach(state, process.pid)
                    state = {**state, 'worker': stamp}
                    self._write(state)
                except BaseException:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                    raise
                return self._public(state)
            except BaseException as exc:
                # A failed spawn has no child. Keep a durable explicit error.
                current = self._read(operation_id)
                if current is not None and current["phase"] == "starting":
                    self._write({**current, "phase": "failed", "error": "spawn rejected: " + str(exc)})
                raise
            finally: os.close(slot)

    def inventory(self):
        self._reap()
        active = []
        with self.lock():
            for directory in self.root.iterdir():
                if directory.is_symlink(): raise ValueError("symlink in preparation root")
                if not directory.is_dir(): continue
                state = self._read(identifier(directory.name))
                if state is None: raise ValueError("unowned preparation directory")
                state = self._reconcile(state)
                members = JobScope.members(state)
                containers = self._containers(state)
                if members or containers or state["phase"] not in TERMINAL:
                    active.append({"operation_id": state["operation_id"], "phase": state["phase"],
                                   "processes": [{k: p[k] for k in ("pid", "start_ticks", "pgid")} for p in members],
                                   "source_containers": containers})
            known = {identifier(p.name) for p in self.root.iterdir() if p.is_dir()}
            JobScope.audit_unknown([self._read(operation_id) for operation_id in known])
            if any(row['operation_id'] not in known for row in source_containers(self.deployment)):
                raise RuntimeError('source container has no durable verified preparation; preserved')
            if self.slot_busy() and not active:
                raise RuntimeError("build slot held without a verified job; absence unconfirmed")
        return active

    def cancel_all(self):
        """Drain only verified preparation cgroups and labelled source containers."""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with self.lock():
                waiting = [self._read(identifier(p.name)) for p in self.root.iterdir() if p.is_dir()]
                unclaimed = any(s and s["phase"] == "starting" and s.get("worker") is None for s in waiting)
            if not unclaimed: break
            time.sleep(0.05)

        # No process is treated as absent when cgroup.events still says populated.
        # The exceptional value permits force-killing this exact validated scope
        # only during the authenticated shutdown barrier, not status/retry.
        def busy(state):
            try:
                return bool(JobScope.members(state))
            except RuntimeError as exc:
                if str(exc) == 'cgroup still populated; absence unconfirmed':
                    return True
                raise

        with self.lock():
            states = [self._read(identifier(p.name)) for p in self.root.iterdir() if p.is_dir()]
            for state in states:
                if state is None: raise RuntimeError("unowned preparation state")
                forced_drain = False
                try:
                    state = self._reconcile(state)
                except RuntimeError as exc:
                    if str(exc) != 'cgroup still populated; absence unconfirmed':
                        raise
                    forced_drain = True

                if state.get('worker') is None and state['phase'] not in TERMINAL:
                    raise RuntimeError('unclaimed spawning job; outcome unconfirmed')
                try:
                    members = JobScope.members(state)
                except RuntimeError as exc:
                    if str(exc) != 'cgroup still populated; absence unconfirmed':
                        raise
                    members = []
                    forced_drain = True
                if members:
                    with host_operation("terminate-preparation-scope"):
                        JobScope.terminate(state)
                        deadline = time.monotonic() + 30
                        while busy(state) and time.monotonic() < deadline:
                            self._reap()
                            time.sleep(0.1)
                if busy(state):
                    # The cgroup path comes only from the durable operation ID,
                    # attempt and current boot and is checked before signalling.
                    forced_drain = True
                    with host_operation("reap-preparation-scope"):
                        JobScope.kill(state)
                        deadline = time.monotonic() + 10
                        while busy(state) and time.monotonic() < deadline:
                            self._reap()
                            time.sleep(0.1)
                if busy(state):
                    raise RuntimeError('owned preparation cgroup remained populated after kill')
                state = self._reconcile(self._read(state['operation_id']))
                containers = self._containers(state)
                if forced_drain or members or containers or state['phase'] not in TERMINAL:
                    state = {**self._read(state['operation_id']), 'phase': 'canceled',
                        'error': 'canceled by make down; stages and diagnostics preserved', 'result': None}
                self._write(JobScope.close(state))
            known = {s['operation_id'] for s in states}
            remove_source_containers(self.deployment, known)
        if self.inventory(): raise RuntimeError("preparation absence unconfirmed")


    def throw_persistent_storage(self, payload):
        """Explicit THROW-only destruction of persistent SWE-Gym template state."""
        if payload != {"confirmation": "THROW"}:
            raise ValueError("persistent template deletion requires explicit THROW confirmation")
        if self.slot_busy():
            raise RuntimeError("template build slot is active; drain/cancel before THROW")
        if self.inventory():
            raise RuntimeError("active template preparation remains; drain before THROW")
        namespace = self.template_root / "swe-gym-lite"
        if namespace.exists() or namespace.is_symlink():
            if namespace.is_symlink() or not namespace.is_dir():
                raise RuntimeError("unsafe SWE-Gym template namespace")
            for item in (namespace, *namespace.rglob("*")):
                if item.is_symlink() or item.is_mount():
                    raise RuntimeError("unsafe persistent template entry; refusing THROW")
            # This is intentionally the sole persistent-template tree deletion.
            for directory in sorted((p for p in namespace.rglob("*") if p.is_dir()),
                                    key=lambda p: len(p.parts), reverse=True):
                directory.chmod(0o700)
            namespace.chmod(0o700)
            shutil.rmtree(namespace)
        with self.lock():
            for directory in list(self.root.iterdir()):
                if not directory.is_dir():
                    continue
                state = self._read(identifier(directory.name))
                if state is None or JobScope.members(state) or self._containers(state):
                    raise RuntimeError("preparation history is still active; refusing THROW")
                shutil.rmtree(directory)
        return {"thrown": True, "template_namespace": str(namespace)}



# GPT_TRACE_SWEGYM_VERIFIED_RESUME_V1
# Select only a terminal predecessor with the same persisted pool layout. The
# new worker re-verifies every reusable byte against the CURRENT lock/plan.
def _salvage_identity(value):
    """Return only compatibility fields that govern retained-stage layout.

    Contract, resolver, fetch-source and golden identities may change between
    attempts. They determine what the new worker may *use*, not whether old
    content-addressed bytes are safe to re-verify and salvage.
    """
    if not isinstance(value,dict):
        raise ValueError('invalid preparation compatibility identity')
    return {key:value.get(key) for key in ('fetch_kind','pool_schema','platform')}


def _retained_stage_score(path):
    """Prefer the retained stage with the largest structurally valid CAS corpus."""
    path=Path(path);count=0;size=0
    cas=path/'objects'/'sha256'
    if cas.is_dir() and not cas.is_symlink():
        for prefix in cas.iterdir():
            try:prefix_info=prefix.lstat()
            except FileNotFoundError:continue
            if not stat.S_ISDIR(prefix_info.st_mode) or stat.S_ISLNK(prefix_info.st_mode):
                continue
            for obj in prefix.iterdir():
                try:info=obj.lstat()
                except FileNotFoundError:continue
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or SHA.fullmatch(obj.name) is None or prefix.name!=obj.name[:2]):
                    continue
                count+=1;size+=info.st_size
    return (count,size,path.stat().st_mtime_ns,str(path))


def retained_dependency_stage(manager, pool_root, state, account, *, all_stages=False):
    # Recovery copies only SHA-verified CAS bytes and mutable Git mirrors into a
    # fresh stage. Logical plans remain separately schema/target/requirement keyed.
    wanted=_salvage_identity(state['compatibility'])
    candidates=[]
    for entry in manager.root.iterdir():
        if not entry.is_dir() or entry.is_symlink() or SHA.fullmatch(entry.name) is None:
            continue
        latest = manager._read(entry.name)
        if latest is None:
            raise RuntimeError('missing retained preparation state')
        histories = [latest]
        for attempt in range(1, latest['attempt']):
            journal = safe(entry / f'attempt-{attempt:04d}.json')
            previous = json.loads(journal.read_bytes())
            if (previous.get('schema') != 1 or previous.get('operation_id') != entry.name
                    or previous.get('attempt') != attempt or previous.get('deployment') != manager.deployment
                    or hashlib.sha256(canonical(previous.get('compatibility'))).hexdigest() != entry.name):
                raise RuntimeError('invalid retained preparation attempt journal')
            histories.append(previous)
        for previous in histories:
            if (previous['phase'] not in TERMINAL or previous.get('result') is not None
                    or previous.get('native_publication') is not None
                    or (previous.get('publication_verified') and not previous.get('native_pending')) or
                    _salvage_identity(previous['compatibility']) != wanted):
                continue
            if JobScope.members(previous) or manager._containers(previous):
                raise RuntimeError('retained dependency stage has active owners')
            candidates.append((previous, pool_root / 'incoming'))
            candidates.append((previous, pool_root / ('incoming-' + entry.name + '-' + str(previous['attempt']))))
    matches=[]
    for previous,path in candidates:
        if path.is_symlink():raise RuntimeError('unsafe retained dependency stage symlink')
        if not path.exists():continue
        info=path.stat()
        if (not path.is_dir() or info.st_uid!=account.pw_uid or info.st_mode & 0o077 or
                (path/'STAGING').is_symlink() or not (path/'STAGING').is_file()):
            raise RuntimeError('untrusted retained dependency stage')
        if path.name=='incoming':
            # The legacy stage has no recorded ID. A surviving source snapshot
            # ties it to the verified old fetcher hash where available.
            snapshot=pool_root/'source'/'scripts'/'superbench_pool.py'
            if snapshot.is_file() and not snapshot.is_symlink():
                if hashlib.sha256(snapshot.read_bytes()).hexdigest()!=previous['compatibility']['fetcher_sha256']:
                    continue
        matches.append(path)
    matches = tuple(sorted(set(matches)))
    if all_stages:
        return matches
    return max(matches, key=_retained_stage_score) if matches else None

def verify_published_inventory(folder, state, proof):
    """Bind every reused publication to its durable byte and operation identity."""
    safe(folder, immutable=True, directory=True)
    raw = safe(Path(folder) / 'inventory.json', immutable=True).read_bytes()
    if (not isinstance(proof, dict) or
            hashlib.sha256(raw).hexdigest() != proof.get('manifest_sha256')):
        raise RuntimeError('published pool inventory differs from its publication proof')
    inventory = json.loads(raw)
    if (inventory.get('operation_id') != state['operation_id'] or
            inventory.get('complete') is not True or inventory.get('issues') or
            any(inventory.get(key) != proof.get(key)
                for key in ('kind', 'tasks', 'repos', 'conda_recipes', 'python_versions'))):
        raise RuntimeError('published pool identity differs from its publication proof')
    return inventory


def _native_apt_repair_compatible(previous, current):
    """Reuse sealed non-APT plans within the same semantic pool contract.

    Code hashes authorize an acquisition, not its reusable data format. Changes
    to non-APT plan semantics require a new pool schema; changing a fetcher
    implementation alone does not invalidate a verified publication.
    """
    if not isinstance(previous, dict) or not isinstance(current, dict) or previous == current:
        return False
    required = {'fetch_kind', 'pool_schema', 'pins', 'platform', 'coverage',
                'conda_lock_sha256', 'golden_dependency', 'fetcher_sha256', 'fetch_sources'}
    if set(previous) != required or set(current) != required:
        return False
    if any(previous[key] != current[key] for key in required - {'fetcher_sha256', 'fetch_sources'}):
        return False
    if current['fetch_kind'] != 'download-only-pool-v4' or current['pool_schema'] != 4:
        return False
    if not isinstance(current['golden_dependency'], dict) or not isinstance(current['pins'], dict):
        return False
    if not isinstance(current['coverage'], dict) or set(current['coverage']) != {'tasks', 'repos', 'conda_recipes'}:
        return False
    if any(type(value) is not int or value <= 0 for value in current['coverage'].values()):
        return False
    if not isinstance(current['platform'], str) or not current['platform'] or not SHA.fullmatch(str(current['conda_lock_sha256'])):
        return False
    old_sources, new_sources = previous['fetch_sources'], current['fetch_sources']
    fetcher = 'scripts/superbench_pool.py'
    for record, sources in ((previous, old_sources), (current, new_sources)):
        if (not isinstance(sources, dict) or record['fetcher_sha256'] != sources.get(fetcher)
                or any(not isinstance(name, str) or not isinstance(sha, str) or SHA.fullmatch(sha) is None
                       for name, sha in sources.items())):
            return False
    adapter = 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/'
    apt_inputs = {'infra/workstation/image/apt_downloads.py', 'scripts/native_requirements.py',
                  adapter + 'upstream/dockerfiles.py', adapter + 'os_packages.py'}
    implementation = {fetcher, 'shared/gpt_trace_transport/local_templates.py'}
    # Non-APT solver inputs and policies must still match exactly. A historical
    # schema-4 publication predating native discovery lacks the two added files.
    if set(new_sources) != set(FETCH_SOURCE_FILES):
        return False
    if set(old_sources) not in (set(new_sources), set(new_sources) - {
            'scripts/native_requirements.py', adapter + 'upstream/dockerfiles.py'}):
        return False
    stable = set(new_sources) - apt_inputs - implementation
    return all(old_sources[name] == new_sources[name] for name in stable)


def _retired_pool(root, operation_id):
    return root / ('retired-'+identifier(operation_id))


def _metadata_artifact_compatible(previous, current):
    # Only immutable artifact bytes cross this boundary. Neither old resolver
    # decisions nor old build-layer observations authorize target metadata.
    keys = {'fetch_kind', 'pool_schema', 'pins', 'platform', 'coverage',
            'conda_lock_sha256', 'golden_dependency'}
    return (isinstance(previous, dict) and isinstance(current, dict)
            and previous != current and keys <= previous.keys() and keys <= current.keys()
            and all(previous[key] == current[key] for key in keys))


def _metadata_retained_stage(root, state, account):
    record = state.get('metadata_resume')
    if record is None:
        return None
    if (not isinstance(record, dict) or set(record) != {'attempt', 'requests_sha256'}
            or type(record['attempt']) is not int or not 1 <= record['attempt'] <= state['attempt']):
        raise RuntimeError('invalid target metadata recovery record')
    operation = identifier(state['operation_id'])
    attempt = str(record['attempt'])
    name = 'metadata-retained-' + operation + '-' + attempt + '-' + identifier(record['requests_sha256'])
    retained = root / name
    original = root / ('incoming-' + operation + '-' + attempt)
    if not retained.exists():
        if retained.is_symlink() or original.is_symlink() or not original.is_dir():
            raise RuntimeError('target metadata recovery source is unavailable')
        if (original.stat().st_uid != account.pw_uid or original.stat().st_mode & 0o077
                or not (original/'STAGING').is_file() or (original/'STAGING').is_symlink()):
            raise RuntimeError('unsafe target metadata recovery source')
        os.rename(original, retained)
        sync_directory(root)
    if (retained.is_symlink() or not retained.is_dir() or retained.stat().st_uid != account.pw_uid
            or retained.stat().st_mode & 0o077 or not (retained/'STAGING').is_file()
            or (retained/'STAGING').is_symlink()):
        raise RuntimeError('unsafe target metadata retained stage')
    return retained


def _apt_repair_source(manager, root, state, *, compatible=_native_apt_repair_compatible):
    ready = root/'ready'
    candidates = []
    if ready.exists() or ready.is_symlink():
        safe(ready, immutable=True, directory=True)
        published = json.loads(safe(ready/'inventory.json', immutable=True).read_bytes())
        prior_id = identifier(published['operation_id'])
        # The inventory names its actual owner. Never pair ready with an unrelated journal.
        directories = [(prior_id, ready)]
    else:
        directories = [(entry.name, _retired_pool(root, entry.name))
                       for entry in manager.root.iterdir()
                       if entry.is_dir() and not entry.is_symlink() and SHA.fullmatch(entry.name)]
    for prior_id, candidate in directories:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        prior = manager._read(prior_id)
        if prior is None or prior['operation_id'] != prior_id:
            raise RuntimeError('published pool has no authenticated preparation owner')
        if not compatible(prior['compatibility'], state['compatibility']):
            continue
        proof = prior.get('publication_verified')
        if prior['phase'] not in TERMINAL or not isinstance(proof, dict):
            continue
        if prior['phase'] == 'ready':
            if (prior.get('result') != proof or proof.get('runtime_integrated') is not True
                    or proof.get('prepared_setups') is not True or not SHA.fullmatch(str(proof.get('generation', '')))):
                raise RuntimeError('ready predecessor has an invalid integration proof')
        elif prior.get('result') is not None or proof.get('runtime_integrated') != 'pending':
            continue
        if JobScope.members(prior) or manager._containers(prior):
            raise RuntimeError('APT repair predecessor still has active owners')
        inventory = verify_published_inventory(candidate, prior, proof)
        current = state['compatibility']
        if (inventory.get('schema') != 2 or inventory.get('kind') != 'download-only-pool'
                or inventory.get('conda_lock_sha256') != current['conda_lock_sha256']
                or any(inventory.get(key) != value for key, value in current['coverage'].items())):
            raise RuntimeError('prior inventory differs from the current pool contract')
        raw = safe(candidate/'metadata/apt-closure.json', immutable=True).read_bytes()
        rows = [row for row in inventory['files'] if row['path'] == 'metadata/apt-closure.json']
        closure = json.loads(raw)
        if (len(rows) != 1 or rows[0]['sha256'] != hashlib.sha256(raw).hexdigest()
                or rows[0]['size'] != len(raw)
                or not SHA.fullmatch(str(closure.get('golden_dpkg_status_sha256', '')))
                or closure.get('golden_package_inventory_sha256') != current['golden_dependency']['apt_package_manifest_sha256']):
            raise RuntimeError('prior APT closure does not match repair contract')
        candidates.append((candidate, prior, inventory))
    if len(candidates) > 1:
        raise RuntimeError('ambiguous sealed APT repair predecessor')
    return candidates[0] if candidates else None


def _link_apt_repair_files(stage, inventory, migration):
    donor,prior,previous=migration
    # The worker cannot make hardlinks to protected root-owned inodes. Only
    # the broker links the exact immutable entries authorized by the old proof.
    original={row['path']:row for row in previous['files']}
    for item in stage.rglob('*'):
        if item.is_symlink() or item.is_mount() or not (item.is_file() or item.is_dir()):
            raise RuntimeError('unsafe APT repair candidate entry: '+str(item))
    verified_inodes={}
    for row in inventory['files']:
        relative=row['path']
        if (not isinstance(relative,str) or not relative or Path(relative).is_absolute()
                or '..' in Path(relative).parts):
            raise RuntimeError('unsafe APT repair inventory path')
        target=stage/relative
        if target.exists() or target.is_symlink():
            continue
        if (row!=original.get(relative) or relative.startswith('apt/')
                or relative in ('metadata/apt-closure.json','metadata/apt-policy.json','metadata/native-pip-inspection.json','metadata/fetch-progress.json')):
            raise RuntimeError('APT repair attempted to import an unapproved file')
        source=safe(donor/relative,immutable=True)
        if source.stat().st_size!=row['size']:
            raise RuntimeError('retained APT repair input size differs')
        # Candidate paths are exclusively broker-owned after the downloader exits.
        for ancestor in (target.parent,*target.parent.parents):
            if ancestor.is_symlink():raise RuntimeError('unsafe APT repair destination')
            if ancestor==stage:break
        target.parent.mkdir(parents=True,exist_ok=True)
        os.link(source,target)
        info=target.stat()
        verified_inodes[(info.st_dev,info.st_ino)]=row['sha256']
    # All old non-APT logical decisions must remain byte-for-byte identical.
    for key in ('task_plan','environment_plan','git_plan','conda_transactions','conda_lock_sha256'):
        if inventory[key]!=previous[key]:raise RuntimeError('APT repair changed non-APT plan: '+key)
    if {k:v for k,v in inventory['provenance'].items() if k!='apt'}!={k:v for k,v in previous['provenance'].items() if k!='apt'}:
        raise RuntimeError('APT repair changed non-APT provenance')
    retained={sha for category,groups in previous['provenance'].items() if category!='apt'
              for hashes in groups.values() for sha in hashes}
    for sha in retained:
        if inventory['objects'].get(sha)!=previous['objects'][sha]:
            raise RuntimeError('APT repair changed non-APT CAS identity')
    return verified_inodes


def _published_progress(ready, state, proof):
    inventory = verify_published_inventory(ready, state, proof)
    relative = 'metadata/fetch-progress.json'
    entries = [row for row in inventory['files'] if row['path'] == relative]
    if len(entries) != 1:
        raise RuntimeError('published pool lacks its final progress inventory entry')
    raw = safe(Path(ready) / relative, immutable=True).read_bytes()
    if len(raw) != entries[0]['size'] or hashlib.sha256(raw).hexdigest() != entries[0]['sha256']:
        raise RuntimeError('published pool progress differs from its verified inventory')
    def reject(message, _reason, **_values):
        raise RuntimeError(message)
    progress = _validate_fetch_progress(json.loads(raw), state['operation_id'], reject)
    if (progress.get('operation_id') != state['operation_id'] or progress.get('schema') != 2
            or progress.get('volume', {}).get('complete') is not True):
        raise RuntimeError('published pool lacks final measured acquisition progress')
    return progress


def _integration_progress(prior, stage, completed=None, total=None, unit='', details=''):
    if (completed is not None and (type(completed) is not int or completed < 0)
            or total is not None and (type(total) is not int or total < 0)
            or completed is not None and total is not None and completed > total):
        raise RuntimeError('invalid integration progress counters')
    return {**prior, 'stage': stage, 'completed': completed, 'total': total, 'unit': unit,
            'details': ''.join(ch for ch in details if ch.isprintable())[:1024],
            'stage_epoch': prior['stage_epoch'] + int((stage, unit) != (prior['stage'], prior['unit'])),
            'pip_active': 0}


class NativeResolutionRequired(RuntimeError):
    def __init__(self, requirements):
        super().__init__('target native requirements require another signed acquisition round')
        self.requirements = requirements


def _native_requirements(manager, requirements):
    import runpy
    adapter = manager.source_root / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    return runpy.run_path(str(adapter/'os_packages.py'))['native_requirement_paths'](requirements)


def _native_retired(root, state, proof):
    return root / ('native-retired-' + identifier(state['operation_id']) + '-' + identifier(proof['manifest_sha256']))


def _finish_native_publication(manager, state, ready):
    """Replay the two renames from an fsynced journal, including interrupted rounds."""
    pending = state['native_publication']
    if not isinstance(pending, dict) or set(pending) != {'proof', 'attempt'}:
        raise RuntimeError('invalid native publication journal')
    old = state['publication_verified']
    new = pending['proof']
    attempt = pending['attempt']
    if type(attempt) is not int or not 1 <= attempt <= state['attempt']:
        raise RuntimeError('invalid native acquisition publication attempt')
    stage = ready.parent / ('incoming-' + identifier(state['operation_id']) + '-' + str(attempt))
    retired = _native_retired(ready.parent, state, old)
    if retired.is_symlink() or stage.is_symlink() or ready.is_symlink():
        raise RuntimeError('unsafe native publication path')
    if not retired.exists():
        verify_published_inventory(ready, state, old)
        verify_published_inventory(stage, state, new)
        os.rename(ready, retired)
        sync_directory(ready.parent)
    else:
        verify_published_inventory(retired, state, old)
    if stage.exists():
        if ready.exists() or ready.is_symlink():
            raise RuntimeError('native acquisition publication has two candidates')
        verify_published_inventory(stage, state, new)
        os.rename(stage, ready)
        sync_directory(ready.parent)
    verify_published_inventory(ready, state, new)
    updated = {**state, 'phase': 'validating', 'publication_verified': new,
               'publication_attempt': attempt, 'native_pending': False}
    updated.pop('native_publication')
    manager._write(updated)
    return updated


def _integrate_published_pool(manager, state, ready, result):
    """Build/validate templates from an already sealed pool after a crash."""
    operation_id = state['operation_id']
    with manager.lock():
        state = manager._read(operation_id)
        progress = _published_progress(ready, state, result)
        state = {**state, 'phase': 'validating', 'integration_progress':
                 _integration_progress(progress, 'Construction des templates')}
        manager._write(state)

    def report(stage, completed=None, total=None, unit='', details=''):
        with manager.lock():
            current = manager._read(operation_id)
            if current['attempt'] != state['attempt'] or current['phase'] not in {'running', 'validating'}:
                raise RuntimeError('template progress no longer belongs to the active preparation')
            prior = current['integration_progress']
            updated = _integration_progress(prior, stage, completed, total, unit, details)
            if updated != prior:
                manager._write({**current, 'integration_progress': updated})

    builder_path = manager.source_root / "scripts/build_local_templates.py"
    spec = importlib.util.spec_from_file_location("swegym_integrated_builder", builder_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("integrated template builder is unavailable")
    builder = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = builder
    spec.loader.exec_module(builder)
    args = types.SimpleNamespace(
        operation_id=operation_id, virtual_gib=builder.VIRTUAL_GIB,
        free_space_gib=builder.FREE_SPACE_GIB,
    )
    try:
        final = builder.build(args, progress=report)
    except NativeResolutionRequired as demand:
        discovered = _native_requirements(manager, demand.requirements)
        with manager.lock():
            current = manager._read(operation_id)
            if current['attempt'] != state['attempt'] or current['publication_verified'] != result:
                raise RuntimeError('native requirement belongs to a different publication') from demand
            if any(member['pid'] != os.getpid() for member in JobScope.members(current)) or manager._containers(current):
                raise RuntimeError('native resolution requires a stopped guest and no remaining build descendants') from demand
            prior = _native_requirements(manager, current.get('native_requests', {}))
            merged = {**prior, **discovered}
            if not discovered or merged == prior:
                raise RuntimeError('target native resolution cannot progress: ' + ', '.join(sorted(discovered))) from demand
            updated = {**current, 'phase': 'running', 'native_pending': True,
                       'native_requests': merged}
            updated.pop('integration_progress', None)
            manager._write(updated)
        return None
    generation = Path(final).name
    integrated = {**result, "runtime_integrated": True, "generation": generation,
                  "prepared_setups": True, "pool_directory": str(ready)}
    with manager.lock():
        current = manager._read(operation_id)
        manager._write({**current, "phase": "validating", "publication_verified": integrated,
                        "built_generation": generation, 'integration_progress':
                        _integration_progress(current['integration_progress'], 'Templates intégrés')})
    return integrated


def _broker_cleanup_timeout(source_root):
    source = Path(source_root) / 'config/preparation.toml'
    if source.is_symlink() or not source.is_file():
        raise RuntimeError('missing versioned broker cleanup timeout')
    with source.open('rb') as stream:
        seconds = tomllib.load(stream)['acquisition']['broker_read_timeout_seconds']
    if type(seconds) is not int or seconds < 1:
        raise RuntimeError('invalid versioned broker cleanup timeout')
    return seconds


def _kill_verified_fetch_descendants(state, timeout, cadence):
    # Rust and metadata subprocesses can start their own sessions. Killing only
    # the downloader PGID does not prove that those scoped descendants exited.
    deadline = time.monotonic() + timeout
    while True:
        members = [stamp for stamp in JobScope.members(state) if stamp['pid'] != os.getpid()]
        if not members:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('verified preparation descendants survived cleanup deadline')
        for stamp in members:
            try:
                descriptor = os.pidfd_open(stamp['pid'])
            except ProcessLookupError:
                continue
            try:
                if same_process(stamp):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        time.sleep(min(remaining, cadence))


class _FetchOperationWatch:
    def __init__(self, pid, maximum, cleanup_limit):
        self.pid = pid
        self.maximum = maximum
        self.cleanup_limit = cleanup_limit
        self.active = {}
        self.latest_by_thread = {}
        self.last_transition = time.monotonic()
        self.pending = bytearray()
        self.missing = {}

    def feed(self, chunk):
        self.pending.extend(chunk)
        while b'\n' in self.pending:
            line, _, remainder = self.pending.partition(b'\n')
            self.pending = bytearray(remainder)
            if len(line) > 4096:
                raise RuntimeError('oversized acquisition operation event')
            event = json.loads(line)
            if not isinstance(event, dict):
                raise RuntimeError('invalid acquisition operation event')
            kind, operation, thread = (event.get(name) for name in ('event', 'operation', 'thread'))
            if type(operation) is not int or operation < 1 or type(thread) is not int or thread < 1:
                raise RuntimeError('invalid acquisition operation identity')
            if kind == 'begin':
                started, limit = event.get('started'), event.get('limit')
                label, process = event.get('label'), event.get('process')
                supervised = event.get('supervised')
                if (set(event) != {'event', 'operation', 'thread', 'label', 'started', 'limit', 'process', 'supervised'}
                        or operation in self.active or operation <= self.latest_by_thread.get(thread, 0)
                        or not isinstance(label, str)
                        or not label or len(label) > 512 or type(started) is not float
                        or not math.isfinite(started) or started > time.monotonic()
                        or type(limit) is not int or not 1 <= limit <= self.maximum
                        or (process is not None and (type(process) is not int or process < 1))
                        or type(supervised) is not bool):
                    raise RuntimeError('invalid acquisition operation registration')
                self.active[operation] = event
                self.latest_by_thread[thread] = operation
            elif kind in {'end', 'failed'}:
                owner = self.active.pop(operation, None)
                self.missing.pop(operation, None)
                finished = event.get('finished')
                if (set(event) != {'event', 'operation', 'thread', 'finished'}
                        or owner is None or owner['thread'] != thread or type(finished) is not float
                        or not owner['started'] <= finished <= time.monotonic()):
                    raise RuntimeError('unmatched acquisition operation result')
                if (finished >= owner['started'] + owner['limit']
                        and (kind == 'end' or not owner['supervised'])):
                    raise TimeoutError('acquisition operation exceeded its deadline: ' + owner['label'])
            else:
                raise RuntimeError('unknown acquisition operation transition')
            self.last_transition = time.monotonic()
        if len(self.pending) > 4096:
            raise RuntimeError('oversized acquisition operation event')

    def deadline(self, event):
        reaping = event['process'] is None or event['operation'] in self.missing
        cleanup = self.cleanup_limit if event['supervised'] and reaping else 0
        return event['started'] + event['limit'] + cleanup

    def next_deadline(self, ordinary_check):
        return min(ordinary_check, min(map(self.deadline, self.active.values()), default=ordinary_check))

    def inspect(self, *, idle_limit, descendants):
        now = time.monotonic()
        for operation, event in self.active.items():
            owner = PROC / str(self.pid) / 'task' / str(event['thread'])
            if not owner.is_dir():
                raise RuntimeError('acquisition operation has no live thread: ' + event['label'])
            if event['process'] is not None and event['process'] not in descendants:
                # The supervising thread may still be reaping an exited leaf.
                absent_since = self.missing.setdefault(operation, now)
                if now - absent_since >= self.cleanup_limit:
                    raise RuntimeError('acquisition operation lost its process: ' + event['label'])
            else:
                self.missing.pop(operation, None)
            if now >= self.deadline(event):
                raise TimeoutError('acquisition operation exceeded its deadline: ' + event['label'])
        if not self.active and now - self.last_transition >= idle_limit:
            raise TimeoutError('acquisition worker blocked outside a registered operation')


def _prepare(manager, state):
    # Host acquisition plus broker-owned, offline target metadata execution.
    import pwd
    import grp

    name = "gpttrace-fetch"
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        # Administrative one-time account provisioning happens in the broker,
        # not in the unprivileged dependency downloader.
        subprocess.run(["useradd", "--system", "--no-create-home",
                        "--shell", "/usr/sbin/nologin", name], check=True,
                       timeout=_broker_cleanup_timeout(manager.source_root))
        account = pwd.getpwnam(name)
    if account.pw_uid == 0:
        raise RuntimeError("refusing root pool download account")
    root = manager.base.parent / "dependency-pool"
    root.mkdir(mode=0o770, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != 0:
        raise RuntimeError("untrusted dependency pool root")
    os.chown(root, 0, account.pw_gid)
    # Sticky root-owned directory: workers can create a new stage, but cannot
    # delete/replace root-owned sealed pool files from a previous fetch.
    root.chmod(0o1770)
    ready = root / "ready"
    stage = root / ('incoming-'+state['operation_id']+'-'+str(state['attempt']))
    pending = state.get("publication_verified")
    if state.get('native_publication') is not None:
        with manager.lock():
            state = _finish_native_publication(manager, state, ready)
        return _integrate_published_pool(manager, state, ready, state['publication_verified'])
    native_round = state.get('native_pending') is True
    if isinstance(pending, dict) and pending.get("runtime_integrated") != True and not native_round and not state.get('metadata_pending'):
        if not ready.exists() and not ready.is_symlink():
            acquisition_attempt = state.get('publication_attempt', state['attempt'])
            if type(acquisition_attempt) is not int or not 1 <= acquisition_attempt <= state['attempt']:
                raise RuntimeError('invalid original publication attempt')
            sealed = root / ('incoming-'+state['operation_id']+'-'+str(acquisition_attempt))
            verify_published_inventory(sealed, state, pending)
            os.rename(sealed, ready)
            sync_directory(root)
        verify_published_inventory(ready, state, pending)
        return _integrate_published_pool(manager, state, ready, pending)
    if native_round:
        previous = verify_published_inventory(ready, state, pending)
        migration = (ready, state, previous)
    else:
        migration = _apt_repair_source(manager,root,state, compatible=_metadata_artifact_compatible)
    if migration is not None and not native_round:
        # The old operation may have observed native requirements which never
        # reached its next acquisition. Its admitted target/lock are identical.
        prior_requests = _native_requirements(manager, migration[1].get('native_requests', {}))
        current_requests = _native_requirements(manager, state.get('native_requests', {}))
        if any(key in current_requests and current_requests[key] != paths for key, paths in prior_requests.items()):
            raise RuntimeError('retained native observation conflicts with current preparation')
        merged = {**prior_requests, **current_requests}
        if merged != current_requests:
            with manager.lock():
                state = {**manager._read(state['operation_id']), 'native_requests': merged}
                manager._write(state)
    if (ready.exists() or ready.is_symlink()) and (migration is None or migration[0]!=ready):
        raise RuntimeError("dependency pool already published; manual version migration required")
    metadata_retained = _metadata_retained_stage(root, state, account)
    if stage.exists() or stage.is_symlink():
        raise RuntimeError('candidate stage already exists; preserve for manual reconciliation')
    retained = retained_dependency_stage(manager, root, state, account, all_stages=True)
    if metadata_retained is not None:
        retained = tuple(sorted(set(retained) | {metadata_retained}))
    reuse = max(retained, key=_retained_stage_score) if retained else None
    source_program = manager.source_root / "scripts/superbench_pool.py"
    if source_program.is_symlink() or not source_program.is_file():
        raise RuntimeError("missing/untrusted download-only fetch worker")
    interpreter = trusted_fetch_python()
    current = manager.expected()
    if state['compatibility'] != current:
        raise RuntimeError("preparation dependency identity changed after admission")
    # The legacy call shape ``stage_fetch_sources(manager, root)`` remains a
    # documented read-only fixture; production passes the durable identity.
    try:
        source_root, program = stage_fetch_sources(
            manager, root, state['operation_id'], state['attempt'],
            state['compatibility']['golden_dependency'], expected_sources=current['fetch_sources'],
            native_requests=_native_requirements(manager, state.get('native_requests', {})))
    except BaseException:
        controls = tomllib.loads((manager.source_root / 'config/preparation.toml').read_text())['acquisition']
        _kill_verified_fetch_descendants(state, _broker_cleanup_timeout(manager.source_root),
                                         controls['progress_interval_seconds'])
        raise
    # Strict allowlist: administrative bearer tokens, service credentials,
    # cloud tunnel configuration and deployment secrets must never reach the
    # unprivileged downloader or any of its subprocesses. No proxy/auth env.
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(root),
        "XDG_CACHE_HOME": str(stage / "metadata"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_NO_CACHE_DIR": "1",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
    }

    # Use only the local audited worker file, with fixed validated arguments.
    # The broker owns the offline metadata VM; the acquisition worker owns no host VM.
    policy = manager.source_root / 'config/preparation.toml'
    if policy.is_symlink() or not policy.is_file():
        raise RuntimeError('missing versioned preparation watchdog policy')
    with policy.open('rb') as stream:
        acquisition = tomllib.load(stream)['acquisition']
    cadence = acquisition['progress_interval_seconds']
    idle_limit = acquisition['unregistered_work_timeout_seconds']
    elementary_limit = acquisition['timeout_seconds']
    cleanup_timeout = _broker_cleanup_timeout(manager.source_root)
    if (type(cadence) is not int or type(idle_limit) is not int or not 1 <= cadence < idle_limit <= 180
            or type(elementary_limit) is not int or not 1 <= elementary_limit <= 180):
        raise RuntimeError('invalid versioned preparation watchdog controls')
    from workstation_broker.fetch_egress import FETCH_WORKER_UMASK, fetch_worker_command, source_network
    download_limit = fetch_download_limit(acquisition)
    def received():
        with host_operation('read-fetch-namespace-rx'):
            result = subprocess.run(['ip', 'netns', 'exec', source_network(), 'cat', '/proc/net/dev'],
                                    capture_output=True, text=True, check=True, timeout=cleanup_timeout)
        return namespace_rx_bytes(result.stdout)
    baseline = state.get('native_rx_baseline')
    if baseline is None:
        baseline = received()
        with manager.lock():
            state = {**manager._read(state['operation_id']), 'native_rx_baseline': baseline}
            manager._write(state)
    def enforce_download_limit():
        amount = namespace_rx_delta(baseline, received())
        if amount >= download_limit:
            raise RuntimeError('fetch download budget reached: %.3f/%.3f GiB received in fetch namespace' %
                               (amount / 1024 ** 3, download_limit / 1024 ** 3))
    guest_path = source_root / 'scripts/native_guest_broker.py'
    guest_spec = importlib.util.spec_from_file_location('metadata_guest_broker', guest_path)
    guest_broker = importlib.util.module_from_spec(guest_spec)
    guest_spec.loader.exec_module(guest_broker)
    with guest_broker.metadata_guest(manager, stage, source_root, account, donor=migration, reuse=reuse, retained=retained) as guest_env:
        env.update(guest_env)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            try:
                child = subprocess.Popen(fetch_worker_command(account, interpreter,
                                [str(program), "--repo-root", str(source_root), "--stage", str(stage),
                                 "--operation-id", state["operation_id"], "--operation-events-fd", str(write_fd),
                                 "--network-rx-baseline", json.dumps(baseline, sort_keys=True),
                                 *(["--reuse-from", str(reuse)] if reuse is not None else []),
                                 *(value for retained_stage in retained for value in ("--reuse-apt-from", str(retained_stage)))]),
                               cwd=source_root, env=env, pass_fds=(write_fd,),
                               stdin=subprocess.DEVNULL, start_new_session=True,
                               umask=FETCH_WORKER_UMASK)
            finally:
                os.close(write_fd)
            watch = _FetchOperationWatch(child.pid, elementary_limit, cleanup_timeout)
            last_observation = None
            next_check = time.monotonic() + cadence
            try:
                while True:
                    check_at = watch.next_deadline(next_check)
                    readable, _, _ = select.select([read_fd], [], [], max(0, check_at - time.monotonic()))
                    if readable:
                        chunk = os.read(read_fd, 65536)
                        if chunk:
                            watch.feed(chunk)
                        else:
                            exitcode = child.wait(timeout=cleanup_timeout)
                            enforce_download_limit()
                            if exitcode == 0 and (watch.active or watch.pending):
                                raise RuntimeError('acquisition worker exited with unresolved operation records')
                            break
                    if time.monotonic() < watch.next_deadline(next_check):
                        continue
                    enforce_download_limit()
                    progress = manager._progress(state)
                    if progress is not None:
                        observation = (progress['stage'], progress['completed'],
                                       progress['network_bytes'], progress['pip_bytes'])
                        if observation != last_observation:
                            last_observation = observation
                            watch.last_transition = time.monotonic()
                    descendants = {stamp['pid'] for stamp in JobScope.members(state)}
                    watch.inspect(idle_limit=idle_limit, descendants=descendants)
                    next_check = time.monotonic() + cadence
            except BaseException:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    child.wait(timeout=cleanup_timeout)
                except subprocess.TimeoutExpired as exc:
                    raise RuntimeError('download worker remained unreaped after group SIGKILL; stage preserved') from exc
                _kill_verified_fetch_descendants(state, cleanup_timeout, cadence)
                raise
        finally:
            os.close(read_fd)
    if exitcode != 0:
        _kill_verified_fetch_descendants(state, cleanup_timeout, cadence)
        if exitcode == NATIVE_METADATA_EXIT_CODE:
            report_path = stage / 'metadata/target-metadata-native.json'
            if (report_path.is_symlink() or not report_path.is_file()
                    or report_path.stat().st_uid != account.pw_uid or report_path.stat().st_size > 1048576):
                raise RuntimeError('missing or unsafe target metadata native requirement report')
            requested = _native_requirements(manager, json.loads(report_path.read_bytes()))
            with manager.lock():
                current = manager._read(state['operation_id'])
                prior = _native_requirements(manager, current.get('native_requests', {}))
                if not requested or any(key in prior and prior[key] != paths for key, paths in requested.items()):
                    raise RuntimeError('invalid target metadata native requirement transition')
                merged = {**prior, **requested}
                if merged == prior:
                    raise RuntimeError('target metadata native resolution made no progress')
                updated = {**current, 'phase': 'running', 'metadata_pending': True,
                           'native_requests': merged, 'metadata_resume': {'attempt': state['attempt'],
                               'requests_sha256': hashlib.sha256(canonical(merged)).hexdigest()}}
                manager._write(updated)
                _metadata_retained_stage(root, updated, account)
            remove_fetch_sources(source_root)
            return None
        if exitcode == FETCH_BUDGET_EXIT_CODE:
            progress = manager._progress(state)
            if (progress is None or progress['unit'] != 'bytes' or progress['total'] is None
                    or progress['completed'] is None):
                raise RuntimeError('download budget refusal lacks measured archive volume')
            remaining = progress['total'] - progress['completed']
            amount = namespace_rx_delta(baseline, received())
            raise RuntimeError('planned archive download exceeds fetch budget: %.3f GiB received + '
                               '%.3f GiB remaining > %.3f GiB limit' %
                               (amount / 1024**3, remaining / 1024**3, download_limit / 1024**3))
        raise subprocess.CalledProcessError(exitcode, child.args)
    # Package build backends may spawn children. A successful downloader exit
    # cannot authorize publication while any descendant can still write bytes.
    if any(member['pid'] != os.getpid() for member in JobScope.members(state)):
        _kill_verified_fetch_descendants(state, cleanup_timeout, cadence)
        raise RuntimeError('acquisition descendants remain; pool publication refused')
    remove_fetch_sources(source_root)
    inventory_path = stage / "inventory.json"
    if inventory_path.is_symlink() or not inventory_path.is_file():
        raise RuntimeError("download worker returned no pool inventory")
    raw = inventory_path.read_bytes()
    inventory = json.loads(raw)
    task_count, repo_count, env_count = contract_counts(manager.source_root)
    if (inventory.get("schema") != 2 or inventory.get("complete") is not True
            or inventory.get("tasks") != task_count or inventory.get("repos") != repo_count
             or inventory.get("conda_recipes") != env_count
            or inventory.get("operation_id") != state["operation_id"]
             or inventory.get("conda_lock_sha256") != state["compatibility"].get("conda_lock_sha256")
             or inventory.get("python_versions") != locked_python_minors(manager.source_root)
             or inventory.get("issues") or not isinstance(inventory.get("files"),list)
             or not isinstance(inventory.get("task_plan"),dict)
             or len(inventory["task_plan"]) != task_count
             or not isinstance(inventory.get("objects"),dict)):
        raise RuntimeError("incomplete/unverified downloaded dependency pool")
    checked_inodes = {}
    expected = set()
    for entry in inventory["files"]:
        relative = entry["path"]
        if (not isinstance(relative,str) or not relative or Path(relative).is_absolute()
                or ".." in Path(relative).parts or relative in expected):
            raise RuntimeError("unsafe/duplicate pool entry")
        expected.add(relative)
        item = stage / relative
        if entry.get("type") == "symlink":
            if (not item.is_symlink() or os.readlink(item) != entry.get("target")
                    or os.path.isabs(os.readlink(item))
                    or not (item.parent / os.readlink(item)).resolve().is_relative_to(stage.resolve())):
                raise RuntimeError("unsafe pool symlink: " + relative)
            continue
        if item.is_symlink() or not item.is_file() or item.stat().st_size != entry["size"]:
            raise RuntimeError("pool artifact mismatch: " + relative)
        ino = (item.stat().st_dev, item.stat().st_ino)
        actual = checked_inodes.get(ino)
        if actual is None:
            digest = hashlib.sha256()
            with item.open("rb") as stream:
                for block in iter(lambda: stream.read(1048576), b""):
                    digest.update(block)
            actual = digest.hexdigest()
            checked_inodes[ino] = actual
        if actual != entry["sha256"]:
            raise RuntimeError("pool artifact digest mismatch: " + relative)
    # The worker inventory must cover every file in the stage, with no
    # concealed unlisted payload. inventory.json was created last by the worker.
    actual_files = set()
    for item in stage.rglob("*"):
        if item.is_symlink() or (not item.is_file() and not item.is_dir()):
            raise RuntimeError("unexpected pool filesystem entry: " + str(item))
        if item.is_file(): actual_files.add(item.relative_to(stage).as_posix())
    if actual_files != expected | {"inventory.json"}:
        raise RuntimeError("unlisted/missing pool artifacts: " +
                           str(sorted(actual_files ^ (expected | {"inventory.json"}))[:12]))
    # Status reads hold the same lock. Stop reading worker-owned metadata before
    # any ownership, mode or inode changes during deduplication and sealing.
    with manager.lock():
        state = manager._read(state['operation_id'])
        final_progress = manager._progress(state)
        if (final_progress is None or final_progress.get('schema') != 2
                or final_progress.get('volume', {}).get('complete') is not True):
            raise RuntimeError('completed fetch lacks its final measured progress')
        state = {**state, 'integration_progress':
                 _integration_progress(final_progress, 'Publication du pool')}
        manager._write(state)
    # Canonicalize equal bytes into one inode while this stage is still new.
    # Only this uncommitted candidate is touched; no prior ready/zombie data.
    import secrets
    canonical_by_sha = {}
    for entry in inventory["files"]:
        path = stage / entry["path"]
        sha = entry["sha256"]
        reference = canonical_by_sha.setdefault(sha, path)
        if path == reference or path.samefile(reference):
            continue
        temporary = path.parent / (".dedup-" + secrets.token_hex(16))
        os.link(reference, temporary)
        try:
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
    # Seal as root. The unprivileged worker is not allowed to publish/mutate a
    # ready pool: it only downloads into an append-only staging namespace.
    for item in sorted(stage.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if item.is_symlink():
            if os.path.isabs(os.readlink(item)) or not (item.parent / os.readlink(item)).resolve().is_relative_to(stage.resolve()):
                raise RuntimeError("escaping pool symlink: " + str(item))
            os.chown(item, 0, 0, follow_symlinks=False)
            continue
        mode=0o555 if item.is_dir() else 0o444
        info=item.stat()
        if (info.st_uid,info.st_gid)!=(0,0):
            os.chown(item,0,0)
        if stat.S_IMODE(info.st_mode)!=mode:
            item.chmod(mode)
    os.chown(stage, 0, 0)
    stage.chmod(0o555)
    # File contents, directory entries and permission changes must all be
    # durable before a state record can authorize recovery of this generation.
    seal(stage)
    # Write a durable verified-publication record BEFORE the atomic rename.
    # If the process dies after rename, reconciliation can acknowledge the
    # ALREADY VERIFIED immutable result without retrying or rehashing files.
    result = {"kind": "download-only-pool", "complete": True,
              "tasks": task_count, "repos": repo_count, "conda_recipes": env_count,
              "python_versions": inventory["python_versions"],
              "file_count": len(inventory["files"]),
              "manifest_sha256": hashlib.sha256(raw).hexdigest(),
              "pool_directory": str(ready), "runtime_integrated": "pending"}
    state = {**state, "publication_attempt": state['attempt'], "metadata_pending": False}
    state.pop("metadata_resume", None)
    with manager.lock():
        if native_round:
            state = {**state, 'native_publication': {'proof': result, 'attempt': state['attempt']}}
            manager._write(state)
            state = _finish_native_publication(manager, state, ready)
        elif migration is not None and migration[0]==ready:
            retired=_retired_pool(root,migration[1]['operation_id'])
            if retired.exists() or retired.is_symlink():
                raise RuntimeError('APT repair predecessor archive already exists')
            os.rename(ready,retired)
            sync_directory(root)
        if not native_round:
            manager._write({**state, "phase": "validating", "publication_verified": result})
            os.rename(stage, ready)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    # A dependency pool is an internal checkpoint, never a user-visible READY
    # state. Continue in the same authenticated job through template creation
    # and fresh offline replay before returning success.
    return _integrate_published_pool(manager, state, ready, result)


def worker(operation_id, slot_fd):
    operation_id = identifier(operation_id)
    if os.geteuid() != 0 or os.environ.get("GPT_TRACE_PREPARATION_ID") != operation_id:
        raise RuntimeError("unauthorized local preparation worker")
    # The descriptor must be the private fixed slot inherited from the broker.
    slot_path = safe(BASE.parent / "preparations/build-slot.lock")
    held, expected_slot = os.fstat(slot_fd), slot_path.lstat()
    if ((held.st_dev, held.st_ino) != (expected_slot.st_dev, expected_slot.st_ino)
            or held.st_uid != 0 or held.st_mode & 0o077):
        raise RuntimeError("worker has no inherited build slot")
    fcntl.flock(slot_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    from workstation_broker.templates import TemplateRegistry
    templates = TemplateRegistry(BASE.parent / "templates", BASE, lambda p: {})
    manager = PreparationManager(BASE, templates.root, templates)
    stamp = process_identity(os.getpid())
    if stamp is None: raise RuntimeError("execution host process identity is unavailable; no construction permitted")
    if stamp["pgid"] != os.getpid() or stamp["session"] != os.getpid():
        raise RuntimeError("worker has no private process session")
    with manager.lock():
        state = manager._read(operation_id)
        if (state is None or state["phase"] != "starting"
                or (state["worker"] is not None and any(state['worker'][key] != stamp[key]
                    for key in ('pid', 'boot_id', 'start_ticks', 'pgid', 'session')))):
            raise RuntimeError("worker cannot claim an existing preparation")
        JobScope.require_current(state)
        from workstation_broker.admission import read_barrier
        marker = BASE.parent / "broker-drain.json"
        if marker.exists():
            read_barrier(marker, manager.deployment)
            manager._write({**state, "phase": "canceled", "worker": stamp,
                "error": "broker drain established before worker construction"})
            os.close(slot_fd)
            return
        manager._write({**state, "phase": "running", "worker": stamp})
    try:
        state = verify_worker_claim(operation_id)
        result = _prepare(manager, state)
        while result is None:
            state = verify_worker_claim(operation_id)
            if state.get('native_pending') is not True and state.get('metadata_pending') is not True:
                raise RuntimeError('native resolution iteration lacks its durable request')
            result = _prepare(manager, state)
        state = verify_worker_claim(operation_id)
        manager._write({**state, "phase": "ready", "result": result, "error": None})
    except BaseException as exc:
        state = manager._read(operation_id)
        # Every template-build failure preserves durable bytes/checkpoints.  A later
        # explicit fetch may continue after code/network/operator repair.
        manager._write({**state, "phase": "interrupted", "result": None,
            "error": type(exc).__name__ + ": " + str(exc)[:3000]})
        raise
    finally: os.close(slot_fd)

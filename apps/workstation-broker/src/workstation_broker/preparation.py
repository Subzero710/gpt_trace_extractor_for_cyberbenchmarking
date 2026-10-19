# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
"""Finite admin-only local preparation jobs. Durable identity, no command RPC.

One inherited flock protects the whole build across broker restarts. The child
claims its PID/start-time/session before constructing anything. A lost response
is rediscovered by ID; only an explicit later fetch may retry a proved-dead job.
"""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

from gpt_trace_transport.local_templates import (ROOT, SHA, atomic_json, canonical,
    compatibility, file_signature, safe, source_contract, verify_local_validation,
    verify_manifest, activate)

from workstation_broker.preparation_resources import JobScope, source_containers, remove_source_containers

TERMINAL = frozenset({"ready", "failed", "interrupted", "canceled"})
PHASES = TERMINAL | {"starting", "running", "validating"}
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
    except FileNotFoundError:
        return None
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
        except FileNotFoundError:
            continue
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
        return self.templates.expected()

    def probe(self, payload):
        if set(payload) != {"source_contract"} or payload["source_contract"] != source_contract(self.source_root):
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

    def _public(self, state):
        if state['phase'] == 'ready' and (JobScope.members(state) or self._containers(state)):
            state = {**state, 'phase': 'validating'}  # Wait for the finite worker/helpers to exit.
        result = {k: state[k] for k in ("operation_id", "phase", "attempt", "created_at", "updated_at",
            "result", "error", "deployment") if k in state}
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
        if state['phase'] not in TERMINAL:
            if self.slot_busy(): raise RuntimeError('unidentified active build slot; outcome unconfirmed')
            state = {**state, 'phase': 'interrupted', 'error': 'worker/descendants absent; interrupted preparation retained'}
        closed = JobScope.close(state)
        if closed != state or state['phase'] not in TERMINAL: self._write(closed)
        # Also persist an interrupted state even when its scope was already closed.
        if closed['phase'] == 'interrupted': self._write(closed)
        return closed

    def _verify_ready(self, state):
        try:
            result = state["result"]
            registry = safe(self.template_root / "swe-gym-lite/registry.json", immutable=True)
            if (json.loads(registry.read_bytes()) != {"schema_version": 2, "generation": result["generation"]}
                    or state["compatibility"] != self.expected()
                    or result["verified_signature"] != generation_signature(self.template_root, self.base, result["generation"])):
                raise ValueError("activated generation or verified immutable bytes changed")
        except (OSError, ValueError, KeyError) as exc:
            state = {**state, "phase": "failed", "error": "ready generation invalid: " + str(exc), "result": None}
            self._write(state)
        return state

    def status(self, payload):
        if set(payload) != {"operation_id"}: raise ValueError("invalid preparation status fields")
        operation_id = identifier(payload["operation_id"])
        with self.lock():
            state = self._read(operation_id)
            if state is None: return {"operation_id": operation_id, "phase": "not_started", "deployment": self.deployment}
            state = self._reconcile(state)
            if state["phase"] == "ready":
                state = self._verify_ready(state)
            return self._public(state)

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
                # failed/interrupted/canceled are resumable only after a new explicit fetch.
                if not payload["retry"]:
                    return self._public(previous)
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
                    "built_generation": previous.get("built_generation") if previous else None}
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
                    JobScope.terminate(state)
                    deadline = time.monotonic() + 30
                    while busy(state) and time.monotonic() < deadline:
                        self._reap()
                        time.sleep(0.1)
                if busy(state):
                    # The cgroup path comes only from the durable operation ID,
                    # attempt and current boot and is checked before signalling.
                    forced_drain = True
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


def _prepare(manager, state):
    from workstation_broker.templates import TemplateRegistry
    expected = compatibility(manager.base, manager.source_root)
    if expected != state["compatibility"]: raise RuntimeError("golden/recipe changed since preparation was identified")
    root = manager.template_root
    namespace = root / "swe-gym-lite"

    checked_images = {}
    def image_info(path):
        value = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", str(path)], timeout=60))
        signature = file_signature(path)
        if checked_images.get(path) != signature:
            subprocess.run(["qemu-img", "check", str(path)], check=True, timeout=3600)
            checked_images[path] = signature
        return value

    def factory(template_root, base):
        return TemplateRegistry(template_root, base, image_info, source_root=manager.source_root)

    selected = state.get("built_generation")
    if selected is not None:
        activate(root, manager.base, identifier(selected), factory, manager.source_root)
        return selected, True
    candidates = []
    registry_path = namespace / "registry.json"
    if registry_path.exists():
        safe(registry_path, immutable=True)
        current = json.loads(registry_path.read_bytes())
        if set(current) != {"schema_version", "generation"} or current["schema_version"] != 2:
            raise RuntimeError("invalid existing local registry; preserved")
        folder = namespace / "generations" / identifier(current["generation"])
        manifest = json.loads(safe(folder / "manifest.json", immutable=True).read_bytes())
        validation = json.loads(safe(folder / "local-validation.json", immutable=True).read_bytes())
        # Existing local generations remain protected even if a new compatible
        # recipe is now requested. Corruption never authorizes replacement.
        verify_manifest(folder, validation["compatibility"], source_root=manager.source_root)
        verify_local_validation(folder, manifest, expected=validation["compatibility"])
        from gpt_trace_transport.local_templates import compatible_template_identity
        if compatible_template_identity(validation["compatibility"], expected): candidates.append(current["generation"])
    generations = namespace / "generations"
    if generations.exists():
        safe(generations, directory=True)
        for folder in sorted(generations.iterdir()):
            safe(folder, immutable=True, directory=True)
            identifier(folder.name)
            validation_path = folder / "local-validation.json"
            if not validation_path.exists(): raise RuntimeError("unvalidated permanent generation; preserved")
            validation = json.loads(safe(validation_path, immutable=True).read_bytes())
            from gpt_trace_transport.local_templates import compatible_template_identity
            if compatible_template_identity(validation.get("compatibility"), expected) and folder.name not in candidates:
                candidates.append(folder.name)
    if candidates:
        selected = candidates[0]
        record_built_generation(state["operation_id"], selected)
        activate(root, manager.base, selected, factory, manager.source_root)
        return selected, True
    spec = __import__("importlib.util", fromlist=["util"]).spec_from_file_location(
        "gpt_trace_local_lite_builder", manager.source_root / "scripts/build_local_templates.py")
    module = __import__("importlib.util", fromlist=["util"]).module_from_spec(spec)
    spec.loader.exec_module(module)
    final = module.build(SimpleNamespace(operation_id=state["operation_id"], free_space_gib=module.FREE_SPACE_GIB,
        virtual_gib=module.VIRTUAL_GIB, build_timeout_hours=module.BUILD_TIMEOUT_HOURS))
    return identifier(final.name), False


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
        generation, reused = _prepare(manager, state)
        # Activation has completed and all bytes/QCOW2 chains were validated.
        signature = generation_signature(templates.root, BASE, generation)
        state = verify_worker_claim(operation_id)
        manager._write({**state, "phase": "ready", "result": {"generation": generation, "reused": reused,
            "verified_signature": signature, "invariants": {"tasks": 230, "repos": 11, "env_hashes": 25}}, "error": None})
    except BaseException as exc:
        state = manager._read(operation_id)
        # Every template-build failure preserves durable bytes/checkpoints.  A later
        # explicit fetch may continue after code/network/operator repair.
        manager._write({**state, "phase": "interrupted", "result": None,
            "error": type(exc).__name__ + ": " + str(exc)[:3000]})
        raise
    finally: os.close(slot_fd)

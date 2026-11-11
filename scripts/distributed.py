#!/usr/bin/env python3
# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
"""Historical operations dispatched exclusively by config/distributed.toml."""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
import platform
import secrets
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
from gpt_trace_transport.wire import Endpoint, WireClient, token_value, TransportFailure, IdentityFailure, RemoteFailure

PROJECT = "gpt-trace-extractor"
VOLUMES = ("postgres_data", "browser_profile", "runner_state", "benchmark_sources")
CORE = ("postgres", "storage", "teacher-browser", "teacher-browser-tunnel", "kali-workstation-controller", "workstation-gateway")


def run(arguments, *, capture=False, timeout=None):
    # Command arguments are never assembled from a shell string.
    result = subprocess.run([str(x) for x in arguments], cwd=ROOT, check=True,
        text=True, capture_output=capture, timeout=timeout)
    return result.stdout.strip() if capture else ""


def json_command(arguments):
    return json.loads(run(arguments, capture=True, timeout=30))


def path_from_config(value):
    if not isinstance(value, (str, os.PathLike)) or not str(value):
        raise ValueError("an explicit deployment path is required")
    path = Path(value)
    path = path if path.is_absolute() else ROOT / path
    for parent in (path, *path.parents):
        if parent.is_symlink(): raise ValueError("symlink in distributed deployment path")
    return path



# Host identities stay outside versioned TOML. Broker traffic uses Cloudflare Tunnel HTTPS;
# no LAN IP, Cloudflare Access policy, or private CA is required.
DISTRIBUTED_ENV_FIELDS = {('deployment', 'role'): 'DIST_ROLE'}
OPTIONAL_ENV_FIELDS = {'DIST_BROKER_URL', 'DIST_BROKER_TUNNEL_TOKEN', 'DIST_BROKER_ADMIN_TOKEN', 'DIST_BROKER_CONTROLLER_TOKEN'}


def local_deployment_env():
    source = ROOT / '.env'
    if source.is_symlink() or not source.is_file():
        raise ValueError('missing/unsafe local .env; copy .env.example')
    if source.stat().st_mode & 0o077:
        raise ValueError('local .env carries service credentials and must be mode 0600')
    keys = set(DISTRIBUTED_ENV_FIELDS.values()) | OPTIONAL_ENV_FIELDS
    result = {}
    for line in source.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('export '): line = line[7:].lstrip()
        name, sep, value = line.partition('=')
        name = name.strip()
        if not sep or name not in keys: continue
        value = value.strip()
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError('invalid quoted .env field: ' + name)
            value = value[1:-1]
        else:
            value = value.split(' #', 1)[0].rstrip()
        if name in result: raise ValueError('duplicate .env field: ' + name)
        if len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in value):
            raise ValueError('invalid .env field: ' + name)
        if value: result[name] = value
    return result


def broker_origin(value):
    from urllib.parse import urlsplit
    import ipaddress
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
        or parsed.query or parsed.fragment or parsed.path not in ('', '/')
        or parsed.port not in (None, 443)
        or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', parsed.hostname)
        or '.' not in parsed.hostname):
        raise ValueError('DIST_BROKER_URL must be an https://hostname origin')
    try: ipaddress.ip_address(parsed.hostname)
    except ValueError: pass
    else: raise ValueError('broker URL must be a DNS hostname, not an IP')
    return 'https://' + parsed.hostname.lower()


def config(role=None, *, credentials=True):
    source = ROOT / 'config/distributed.toml'
    if source.is_symlink(): raise ValueError('unsafe distributed configuration')
    cfg = tomllib.loads(source.read_text())
    required = {
        'deployment': {'role', 'control_id', 'execution_id'},
        'paths': {'base_image', 'broker_runtime_directory', 'storage_root'},
        'storage': set(VOLUMES),
    }
    if set(cfg) != set(required) or any(set(cfg[section]) != keys for section, keys in required.items()):
        raise ValueError('distributed.toml has missing or unknown fields')
    local = local_deployment_env()
    if cfg['deployment']['role'] != '':
        raise ValueError('tracked config cannot choose a physical host role')
    host_role = local.get('DIST_ROLE')
    if host_role not in {'execution','control'}: raise ValueError('DIST_ROLE must be control or execution')
    cfg['deployment']['role'] = host_role
    if role is not None and host_role != role: raise ValueError('operation belongs to another physical host role')
    deployment = cfg['deployment']
    for name in ('control_id','execution_id'):
        if not re.fullmatch(r'[a-zA-Z0-9-]{1,63}', deployment[name]):
            raise ValueError('invalid deployment identity')
    if deployment['control_id'] == deployment['execution_id']:
        raise ValueError('deployment identities must differ')
    cfg['paths'] = {key: path_from_config(value) for key,value in cfg['paths'].items()}
    if cfg['paths']['base_image'].suffix != '.qcow2': raise ValueError('explicit QCOW2 path required')
    if any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', value)
            for value in cfg['storage'].values()): raise ValueError('invalid Docker volume name')
    if len(set(cfg['storage'].values())) != len(VOLUMES): raise ValueError('duplicate Docker volumes')
    cfg['local'] = local
    if credentials:
        admin = token_value(local.get('DIST_BROKER_ADMIN_TOKEN', ''))
        controller = token_value(local.get('DIST_BROKER_CONTROLLER_TOKEN', ''))
        if secrets.compare_digest(admin, controller):
            raise ValueError('broker scopes must have different tokens')
        if host_role == 'control':
            broker_origin(local.get('DIST_BROKER_URL',''))
        elif not local.get('DIST_BROKER_TUNNEL_TOKEN'):
            raise ValueError('missing DIST_BROKER_TUNNEL_TOKEN on execution host')
    return cfg



def host(role, cfg, *, docker=True, build_tools=False):
    if platform.system() != "Linux" or sys.version_info < (3, 12): raise RuntimeError("Linux/Python >=3.12 required")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=\"?ubuntu\"?$', release, re.M) or not re.search(r'^VERSION_ID=\"?26\.04\"?$', release, re.M):
        raise RuntimeError("deployment requires Ubuntu 26.04")
    if docker:
        commands = [["docker", "info", "--format", "{{.ServerVersion}}"]]
        if build_tools: commands += [["docker", "compose", "version"], ["docker", "buildx", "version"]]
        for command in commands:
            run(command, capture=True, timeout=30)
    if role == "execution":
        if os.geteuid() != 0: raise RuntimeError("execution host broker operations require root")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK): raise RuntimeError("execution host KVM is unavailable")
        run(["virsh", "-c", "qemu:///system", "list", "--all"], capture=True, timeout=30)
        run(["nft", "list", "tables"], capture=True, timeout=30)
        image_directory = cfg["paths"]["base_image"].parent
        if (not image_directory.is_dir() or image_directory.is_symlink()):
            raise RuntimeError("configured Kali image directory must already exist as a dedicated mount")
        target = run(["findmnt", "-n", "-o", "TARGET", "-T", image_directory],
                     capture=True, timeout=10)
        device = run(["findmnt", "-n", "-o", "SOURCE", "-T", image_directory],
                     capture=True, timeout=10)
        filesystem = run(["findmnt", "-n", "-o", "FSTYPE", "-T", image_directory],
                         capture=True, timeout=10)
        options = run(["findmnt", "-n", "-o", "OPTIONS", "-T", image_directory],
                      capture=True, timeout=10)
        # The configured image directory itself is the storage boundary. Requiring
        # it to be the actual mount target prevents a missing data disk from
        # silently falling back to Ubuntu's root filesystem.
        if (Path(target).resolve() != image_directory.resolve() or
                not device.startswith("/dev/") or filesystem not in {"ext4", "xfs"} or
                "rw" not in options.split(",")):
            raise RuntimeError(
                "Kali image directory must be the dedicated writable local ext4/xfs mount target")


def environment(cfg):
    paths, local = cfg['paths'], cfg['local']
    origin = broker_origin(local['DIST_BROKER_URL'])
    values = {
        'COMPOSE_FILE': str(ROOT / 'compose.control.yaml'),
        'DIST_BROKER_ADMIN_TOKEN': token_value(local['DIST_BROKER_ADMIN_TOKEN']),
        'DIST_BROKER_CONTROLLER_TOKEN': token_value(local['DIST_BROKER_CONTROLLER_TOKEN']),
        'DIST_BROKER_URL': origin,
        'WORKSTATION_BROKER_TRANSPORT': 'https',
        'WORKSTATION_BROKER_URL': origin,
    }
    values.update({'DIST_VOLUME_' + key.upper(): name for key,name in cfg['storage'].items()})
    os.environ.update(values)


def broker(cfg, action, payload=None, *, local=False, timeout=None):
    if local:
        endpoint = Endpoint("unix", cfg["paths"]["broker_runtime_directory"] / "broker.sock")
    else:
        endpoint = Endpoint.from_env(Path("/unused-private-broker.sock"))
    client = WireClient(endpoint)
    result = client.request("deployment_probe" if action == "probe" and not local else action,
        payload if payload is not None else {}, token_value(cfg['local']['DIST_BROKER_ADMIN_TOKEN']), timeout=timeout)
    if action == "probe" and not local:
        limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
        expected = hashlib.sha256(json.dumps(limits, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if result.get("project") != PROJECT or result.get("status") != "ok" or result.get("execution_id") != cfg["deployment"]["execution_id"] or result.get("workstation_sha256") != expected:
            raise RuntimeError("execution host identity/workstation configuration differs from control host; preserve attempts and reconcile explicitly")
    return result


def compose(*arguments, capture=False):
    return run(["docker", "compose", "--profile", "runner", "--profile", "app-tunnels", "--profile", "benchmark-fetch", *arguments], capture=capture)


def verify_storage(cfg):
    root = cfg["paths"]["storage_root"]
    if not root.is_dir(): raise RuntimeError("control-plane storage root is missing")
    resolved = {}
    for logical, name in cfg["storage"].items():
        values = json_command(["docker", "volume", "inspect", name])
        if len(values) != 1: raise RuntimeError("ambiguous Docker volume")
        volume = values[0]
        device = volume.get("Options", {}).get("device") if isinstance(volume.get("Options"), dict) else None
        actual = Path(device if device else volume["Mountpoint"]).resolve(strict=True)
        if not actual.is_relative_to(root.resolve(strict=True)):
            raise RuntimeError(f"{logical} storage is outside configured control host storage root; migrate from a verified cold backup")
        if actual == root.resolve(strict=True) or not actual.is_dir():
            raise RuntimeError("volume needs a dedicated directory under the storage root")
        resolved[logical] = actual
    paths = list(resolved.values())
    if any(left == right or left.is_relative_to(right) or right.is_relative_to(left)
           for index, left in enumerate(paths) for right in paths[index+1:]):
        raise RuntimeError("persistent volumes overlap physically")
    return resolved


def init_storage(cfg):
    if os.geteuid() != 0: raise RuntimeError("initializing bind-backed volumes requires root")
    root = cfg["paths"]["storage_root"]
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for logical, name in cfg["storage"].items():
        listed = run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture=True).splitlines()
        if name in listed:
            # Existing volumes are inspected, never overwritten or relabeled.
            continue
        directory = root / logical
        if directory.exists() and any(directory.iterdir()): raise RuntimeError("refusing to adopt nonempty storage without a volume")
        directory.mkdir(mode=0o700, exist_ok=True)
        run(["docker", "volume", "create", "--driver", "local", "--label", "io.gpttrace.project=" + PROJECT,
             "--opt", "type=none", "--opt", "o=bind", "--opt", "device=" + str(directory), name])
    verify_storage(cfg)


def assert_stopped(project=PROJECT):
    running = run(["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=" + project], capture=True)
    if running: raise RuntimeError("cold backup/restore requires every project container stopped")


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""): digest.update(chunk)
    return digest.hexdigest()


def backup(directory):
    if os.geteuid() != 0: raise RuntimeError("cold Docker volume backup requires root")
    directory = path_from_config(directory)
    if directory.exists(): raise RuntimeError("backup destination must be new")
    # Render the original single-host Compose layout explicitly.
    rendered = json_command(["docker", "compose", "-f", str(ROOT / "compose.yaml"), "--profile", "runner", "config", "--format", "json"])
    assert_stopped(rendered["name"])
    directory.mkdir(mode=0o700, parents=True)
    records = {}
    for logical in VOLUMES:
        name = rendered["volumes"][logical]["name"]
        inspected = json_command(["docker", "volume", "inspect", name])[0]
        options = inspected.get("Options") or {}
        source = Path(options.get("device") or inspected["Mountpoint"]).resolve(strict=True)
        if not source.is_dir(): raise RuntimeError("volume mountpoint is not a directory")
        archive = directory / (logical + ".tar")
        with tarfile.open(archive, "w") as output:
            output.add(source, arcname=".", recursive=True)
        records[logical] = {"sha256": file_sha(archive), "size": archive.stat().st_size, "docker_name": name}
    with tarfile.open(directory / "local-secrets.tar", "w") as output:
        for name in (".env", ".secrets", "config/runner.toml"):
            path = ROOT / name
            if path.is_symlink() or not path.exists(): raise RuntimeError("missing/unsafe deployment identity source: " + name)
            output.add(path, arcname=name)
    records["local-secrets"] = {"sha256": file_sha(directory / "local-secrets.tar"),
                                "size": (directory / "local-secrets.tar").stat().st_size}
    for path in directory.iterdir(): path.chmod(0o600)
    (directory / "manifest.json").write_text(json.dumps({"schema": 1, "cold": True, "files": records}, indent=2) + "\n")
    (directory / "manifest.json").chmod(0o600)
    print("Backup complete; manifest SHA256: " + file_sha(directory / "manifest.json"))


def restore(cfg, directory):
    if os.geteuid() != 0: raise RuntimeError("cold restore requires root")
    assert_stopped()
    directory = path_from_config(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("cold") is not True or set(manifest["files"]) != {*VOLUMES, "local-secrets"}:
        raise RuntimeError("unsupported or incomplete cold backup")
    # Hash and validate every archive before writing the first byte to a volume.
    for logical, record in manifest["files"].items():
        path = directory / (logical + ".tar")
        if path.is_symlink() or path.stat().st_size != record["size"] or file_sha(path) != record["sha256"]:
            raise RuntimeError("backup archive integrity mismatch: " + logical)
        with tarfile.open(path) as archive:
            for member in archive:
                name = Path(member.name)
                if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise RuntimeError("unsafe backup member")
                if member.issym() or member.islnk():
                    if Path(member.linkname).is_absolute() or ".." in Path(member.linkname).parts:
                        raise RuntimeError("unsafe backup link")
    init_storage(cfg)
    targets = verify_storage(cfg)
    for logical in VOLUMES:
        target = targets[logical]
        if any(target.iterdir()): raise RuntimeError("restore never overwrites a nonempty volume")
    for logical in VOLUMES:
        with tarfile.open(directory / (logical + ".tar")) as archive:
            archive.extractall(targets[logical], filter="data")
    print("Cold volumes restored. Original archives and local-secrets.tar are retained; no service was started.")



def broker_read_resilient(cfg, action, payload=None, *, outage_seconds=None, quiet=False):
    """Read-only recovery with bounded latency and visible, actual outage time.

    A lost read may be repeated. Mutations (e.g. prepare_templates) are never
    replayed. An unreachable broker is not mistaken for a running worker or
    a successful fetch, even when its Cloudflare tunnel container is healthy.
    """
    controls_path = Path(__file__).resolve().parents[1] / 'config/preparation.toml'
    if controls_path.is_symlink() or not controls_path.is_file():
        raise RuntimeError('missing versioned broker monitoring policy')
    with controls_path.open('rb') as handle:
        controls = tomllib.load(handle).get('acquisition')
    if not isinstance(controls, dict):
        raise RuntimeError('invalid broker monitoring policy')
    request_limit = controls.get('broker_read_timeout_seconds')
    report_interval = controls.get('broker_outage_report_seconds')
    deadline = controls.get('broker_outage_timeout_seconds') if outage_seconds is None else outage_seconds
    if (type(request_limit) is not int or request_limit < 1
            or type(report_interval) is not int or report_interval < 1
            or type(deadline) not in (int, float) or deadline <= 0
            or report_interval >= deadline):
        raise RuntimeError('invalid configured broker monitoring timeouts')
    started = time.monotonic()
    last_report = started
    retries = 0
    last_error = ''
    while True:
        elapsed = time.monotonic() - started
        remaining = deadline - elapsed
        if remaining <= 0:
            raise RuntimeError('broker read link unavailable for %.0f seconds during %s '
                               '(last error: %s); preparation outcome unconfirmed; '
                               'state and workers retained; rerun the explicit fetch '
                               'only after checking broker health' %
                               (elapsed, action, last_error))
        try:
            result = broker(cfg, action, payload, timeout=min(request_limit,remaining))
        except (TransportFailure, RemoteFailure) as exc:
            if isinstance(exc, IdentityFailure):
                raise
            if (isinstance(exc, RemoteFailure) and getattr(exc, 'status', None)
                    not in {502, 503, 504, 520, 521, 522, 523, 524}):
                raise
            last_error = ('HTTP ' + str(exc.status) if isinstance(exc, RemoteFailure)
                          else type(exc).__name__ + ': ' + str(exc))
            elapsed = time.monotonic() - started
            if not quiet and (retries == 0 or elapsed - (last_report-started) >= report_interval):
                print('[broker] connexion interrompue pendant %.0fs | requête %s '
                      '| essai %s | %s | aucune VM relancée' %
                      (elapsed, action, retries+1, last_error), flush=True)
                last_report = time.monotonic()
            retries += 1
            remaining = deadline - (time.monotonic() - started)
            if remaining <= 0:
                continue
            time.sleep(min(remaining, request_limit, 2**min(retries,5)))
        else:
            if retries and not quiet:
                print('[broker] connexion rétablie après %.0fs | %s | %s essais' %
                      (time.monotonic()-started, action, retries), flush=True)
            return result


def retryable_preparation_error(error):
    """Errors which are safe to ask the execution host to retry if its pool is empty."""
    return (
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


def doctor_tests(role):
    """Run every maintained automated test suite on the host that owns it."""
    from host_requirements import verify_host_requirements
    if not verify_host_requirements(
        role=role,
        require_root=role == "execution",
        golden_build=role == "execution",
    ):
        raise RuntimeError(role + " host prerequisites failed")
    if role == "control":
        for service in ("runner", "storage", "workstation-gateway", "kali-workstation-controller"):
            compose("run", "--rm", "--no-deps", "--entrypoint", "python", service,
                    "-m", "pytest", "-q")
        compose("exec", "-T", "teacher-browser", "python3", "-m", "unittest",
                "discover", "-s", "/opt/gpt-trace-browser/tests",
                "-p", "test_*.py", "-v")
        return
    if role == "execution":
        broker_python = ROOT / ".venv-workstation-broker/bin/python"
        distributed_python = ROOT / ".venv-execution-tests/bin/python"
        for python in (broker_python, distributed_python):
            if not python.is_file():
                raise RuntimeError("execution test environment is missing; run make build")
        run([broker_python, "-B", "-m", "pytest", "-q",
             str(ROOT / "apps/workstation-broker/tests")], timeout=1800)
        run([distributed_python, "-B", "-m", "pytest", "-q",
             str(ROOT / "tests/distributed")], timeout=1800)
        return
    raise ValueError("unknown doctor test role")


class _FetchBar:
    """One terminal line using observed broker bytes and completed work only.

    Byte throughput is the aggregate number of actual received bytes over the
    latest window of broker observations, NOT a whole-fetch average or an ETA.
    The window spans two configured worker publication intervals so that the
    worker's throttled snapshots cannot produce spurious zero-speed pulses.
    """
    def __init__(self, stream=None, *, window_seconds=None):
        self.stream = sys.stdout if stream is None else stream
        self.tty = bool(getattr(self.stream, 'isatty', lambda: False)())
        if window_seconds is None:
            # Read versioned progress controls beside the actual module, not the
            # mutable deployment ROOT used for state and test fixtures.
            policy = Path(__file__).resolve().parents[1] / 'config/preparation.toml'
            if policy.is_symlink() or not policy.is_file():
                raise RuntimeError('missing versioned fetch progress controls')
            with policy.open('rb') as handle:
                seconds = tomllib.load(handle)['acquisition']['progress_interval_seconds']
            if type(seconds) is not int or seconds < 1:
                raise RuntimeError('invalid versioned fetch progress interval')
            window_seconds = seconds * 2
        if (type(window_seconds) not in (int, float) or not 0 < window_seconds < float('inf')):
            raise ValueError('invalid fetch rate measurement window')
        self.window_seconds = window_seconds
        self.reset()

    def reset(self):
        self.last = None
        self.previous = None
        self.observed_stage = None
        self.observed_operation = None
        self.stage_started = None
        self.byte_samples = deque()
        self.work_samples = deque()
        self.stage_has_transfer = False

    @staticmethod
    def _rate(samples):
        if len(samples) < 2:
            return 0.0
        elapsed = samples[-1][0] - samples[0][0]
        return ((samples[-1][1] - samples[0][1]) / elapsed
                if elapsed > 0 else 0.0)

    def _observe(self, progress, now):
        stage, operation = progress['stage'], progress['operation_id']
        network, pip = progress['network_bytes'], progress['pip_bytes']
        done = progress['completed']
        if (any(type(value) is not int or value < 0 for value in (network, pip))
                or done is not None and (type(done) is not int or done < 0)):
            raise RuntimeError('invalid fetch transfer or work counters')
        if self.observed_operation is not None and operation != self.observed_operation:
            raise RuntimeError('fetch progress changed operation without an attempt reset')
        if stage != self.observed_stage:
            self.observed_stage = stage
            self.stage_started = now
            self.byte_samples.clear()
            self.work_samples.clear()
            self.stage_has_transfer = False
        self.observed_operation = operation
        received = network + pip
        # Once a stage has displayed download throughput, keep that metric
        # visible even when a burst finishes or pip_active returns to zero.
        self.stage_has_transfer |= received > 0 or progress['pip_active'] > 0
        # A byte-counter reset invalidates the old sampling window rather than
        # manufacturing positive throughput from a discontinuous counter.
        if self.byte_samples and received < self.byte_samples[-1][1]:
            self.byte_samples.clear()
        self.byte_samples.append((now, received))
        if done is not None:
            if self.work_samples and done < self.work_samples[-1][1]:
                raise RuntimeError('fetch completed-work counter went backwards')
            self.work_samples.append((now, done))
        while self.byte_samples and now - self.byte_samples[0][0] > self.window_seconds:
            self.byte_samples.popleft()
        # A per-minute rate is measured over the trailing minute. Using the
        # shorter byte-transfer window made bursty recipe completions swing
        # between zero and extreme extrapolated rates every few seconds.
        while self.work_samples and now - self.work_samples[0][0] > 60:
            self.work_samples.popleft()

    def update(self, phase, progress=None):
        now = time.monotonic()
        if progress is not None:
            if (not isinstance(progress, dict) or progress.get('schema') != 1
                    or not isinstance(progress.get('stage'), str)):
                raise RuntimeError('invalid broker progress record')
            if phase not in ('validating', 'failed', 'interrupted', 'canceled'):
                self._observe(progress, now)
            self.last = progress
        elif self.last is not None and phase not in ('validating', 'failed', 'interrupted', 'canceled'):
            # A missed broker snapshot is still an observation of no new bytes.
            self._observe(self.last, now)
        if phase == 'validating':
            stage, completed, total, unit = 'Validation finale', None, None, ''
        elif phase in ('failed', 'interrupted', 'canceled'):
            stage, completed, total, unit = 'Préparation interrompue', None, None, ''
        elif self.last is not None:
            stage = self.last['stage']
            completed, total = self.last['completed'], self.last['total']
            unit = self.last['unit']
        else:
            stage, completed, total, unit = 'Préparation', None, None, ''
        if type(completed) is int and type(total) is int and total > 0:
            proportion = min(1.0, completed / total)
            label = f'{completed}/{total} {unit} ({100 * proportion:.1f}%)'
            filled = int(24 * proportion)
        elif type(completed) is int and total == 0:
            label = f'{completed}/0 {unit}'
            filled = 24
        else:
            label = 'phase active — total non mesuré'
            filled = 0

        metric = ''
        suffix = ''
        if self.last is not None and phase not in ('validating', 'failed', 'interrupted', 'canceled'):
            transferred = self.last['network_bytes'] + self.last['pip_bytes']
            bytes_per_second = max(0.0, self._rate(self.byte_samples))
            units_per_minute = max(0.0, self._rate(self.work_samples) * 60)
            # These are different quantities, never interchangeable rates.
            # Show both independently when a stage produces work AND downloads.
            if self.stage_has_transfer:
                metric += f' | {bytes_per_second / 1048576:.2f} MiB/s'
            if completed is not None and unit:
                metric += f' | {units_per_minute:.1f} {unit}/min'
            if transferred:
                suffix = f' | {transferred / 1048576:.1f} MiB reçus'
        if not metric and self.stage_started is not None and phase not in ('validating', 'failed', 'interrupted', 'canceled'):
            elapsed = max(0, int(now - self.stage_started))
            metric = f' | {elapsed // 60}m{elapsed % 60:02d}s écoulées'

        # On narrow terminals, shorten duplicated labels and the optional
        # received-volume suffix before sacrificing either rate's units.
        width = 24
        if self.tty:
            columns = shutil.get_terminal_size((100, 24)).columns
            available = max(1, columns - 1)
            def bar_capacity():
                return available - len(f'fetch | {stage} [] {label}{metric}{suffix}')
            if bar_capacity() < 2 and type(completed) is int and type(total) is int and total > 0 and unit:
                # The work-rate metric already identifies the unit.
                label = f'{completed}/{total} ({100 * min(1.0, completed / total):.1f}%)'
            if bar_capacity() < 2:
                suffix = suffix.removesuffix(' reçus')
            if bar_capacity() < 2:
                suffix = ''
            if bar_capacity() < 2 and type(completed) is int and type(total) is int:
                label = f'{completed}/{total}'
            width = min(24, max(2, bar_capacity()))
            if type(total) is int and total > 0 and type(completed) is int:
                filled = min(width, int(width * min(1.0, completed / total)))
            else:
                filled = width if total == 0 and type(completed) is int else 0
        bar = '[' + '#' * filled + '-' * (width - filled) + ']'
        text = f'fetch | {stage} {bar} {label}{metric}{suffix}'
        if self.tty:
            text = text[:max(1, columns - 1)]
            if text != self.previous:
                self.stream.write('\r\x1b[2K' + text)
                self.stream.flush()
        self.previous = text

    def finish(self, success):
        label = 'TERMINÉ' if success else 'ÉCHEC — journal de préparation conservé sur Fossil'
        text = (self.previous + ' | ' if self.previous else 'fetch | ') + label
        if self.tty:
            columns = shutil.get_terminal_size((100, 24)).columns
            if len(text) >= columns:
                text = 'fetch | ' + label
            self.stream.write('\r\x1b[2K' + text + '\n')
        else:
            self.stream.write(text + '\n')
        self.stream.flush()


def _record_fetch_failure(exc):
    """Full local failure record, never print the exception in fetch terminal."""
    import traceback
    directory = ROOT/'state'/'distributed'
    if directory.is_symlink():
        raise RuntimeError('untrusted fetch diagnostics directory')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory/'fetch-failures.log'
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(handle, 'a', encoding='utf-8') as out:
            out.write(''.join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
            out.write('\n')
    except BaseException:
        raise

def preparation_fetch(cfg):
    """Only explicit Lite fetch triggers a job; reads rediscover lost responses."""
    from gpt_trace_transport.local_templates import pool_contract, atomic_json
    view = _FetchBar()
    broker_read_resilient(cfg, "probe", quiet=True)
    identified = broker_read_resilient(cfg, "template_preparation_probe", {"source_contract": pool_contract(ROOT)}, quiet=True)
    operation_id = identified.get("operation_id")
    deployment = {key: cfg["deployment"][key] for key in ("control_id", "execution_id")}
    if (not isinstance(operation_id, str) or re.fullmatch(r"[0-9a-f]{64}", operation_id) is None
            or identified.get("deployment") != deployment or not isinstance(identified.get("compatibility"), dict)):
        raise RuntimeError("execution host preparation identity differs")
    recipe = pool_contract(ROOT)
    compatibility = identified["compatibility"]
    if (set(compatibility) != set(recipe) | {"golden_dependency"}
            or any(compatibility.get(key) != value for key, value in recipe.items())):
        raise RuntimeError("execution host pool contract differs from control host")
    golden_dependency = compatibility["golden_dependency"]
    target = golden_dependency.get("target_environment") if isinstance(golden_dependency, dict) else None
    markers = target.get("markers") if isinstance(target, dict) else None
    if (not isinstance(golden_dependency, dict)
            or set(golden_dependency) != {"schema", "target_environment", "npm_version", "apt_package_manifest_sha256"}
             or re.fullmatch(r"[0-9a-f]{64}", str(golden_dependency.get("apt_package_manifest_sha256", ""))) is None
            or golden_dependency.get("schema") != 1
            or not isinstance(target, dict) or target.get("schema") != 2
            or target.get("source") != "verified-target-interpreter"
            or not isinstance(target.get("tags"), list) or not target["tags"]
            or not isinstance(markers, dict)
            or re.fullmatch(r"\d+\.\d+\.\d+", str(markers.get("python_full_version", ""))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(target.get("interpreter_sha256", ""))) is None
            or re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?",
                            str(golden_dependency.get("npm_version", ""))) is None):
        raise RuntimeError("execution host golden dependency identity is invalid")
    if hashlib.sha256(json.dumps(compatibility, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest() != operation_id:
        raise RuntimeError("execution host preparation content identity differs")
    directory = ROOT / "state/distributed"
    for parent in (directory, *directory.parents):
        if parent.is_symlink(): raise ValueError("unsafe local preparation journal")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_json(directory / ("preparation-" + operation_id + ".json"), identified, 0o600)
    started = False
    last_attempt = None
    try:
        while True:
            status = broker_read_resilient(cfg, "template_preparation_status", {"operation_id": operation_id}, quiet=True)
            if status.get("operation_id") != operation_id or status.get("deployment") != deployment:
                raise RuntimeError("preparation status identity differs")
            phase = status.get("phase")
            attempt = status.get('attempt')
            if attempt != last_attempt:
                view.reset()
                last_attempt = attempt
            # The broker reports atomic worker counters. Its raw process log
            # remains on Fossil and is never forwarded to the Acer terminal.
            view.update(phase, status.get('progress'))
            if phase == "ready":
                result = status.get("result")
                coverage=recipe.get("coverage") or {}
                if (not isinstance(result,dict) or result.get("kind") != "download-only-pool"
                        or result.get("complete") is not True
                        or any(result.get(key)!=coverage.get(key) for key in ("tasks","repos","conda_recipes"))
                        or result.get("runtime_integrated") is not True
                        or result.get("offline_replay") is not True
                        or not isinstance(result.get("generation"), str)):
                    raise RuntimeError("broker reported no fully integrated offline SWE-Gym generation")
                atomic_json(directory / ("preparation-" + operation_id + ".json"), {**identified, "result": result}, 0o600)
                view.finish(True)
                return result
            if phase in {"not_started", "failed", "interrupted", "canceled"}:
                if started:
                    if phase == "not_started":
                        raise RuntimeError(
                            "preparation " + operation_id +
                            " start remains unconfirmed; rerun make superbench-fetch "
                            "ADAPTER=swe-gym-lite to rediscover it; "
                            "no mutation was blindly retried")
                    raise RuntimeError("preparation " + operation_id + " failed: " + str(status.get("error")))
                error = status.get("error")
                # Only an explicit new make superbench-fetch invocation retries
                # a terminal failed job; the broker verifies process/cgroup
                # absence and preserves all old bytes before admitting it.
                retryable_preflight_failure = phase in {"failed", "interrupted"}
                if phase != "not_started" and not retryable_preflight_failure:
                    raise RuntimeError("fetch zombie preserved (" + str(phase) + "): " +
                                       str(error) + "; administrative cleanup required")
                started = True
                # Start exactly once. A lost response triggers read-only
                # reconciliation instead of a duplicate start request.
                try:
                    broker(cfg, "prepare_templates", {"operation_id": operation_id,
                        "compatibility": identified["compatibility"],
                        "retry": retryable_preflight_failure}, timeout=60)
                except (TransportFailure, RemoteFailure) as exc:
                    if isinstance(exc, IdentityFailure):
                        raise
                    if isinstance(exc, RemoteFailure) and getattr(exc, "status", None) not in {
                            502, 503, 504, 520, 521, 522, 523, 524}:
                        raise
            elif phase not in {"starting", "running", "validating"}:
                raise RuntimeError("unknown preparation phase: " + str(phase))
            time.sleep(2)
    except TransportFailure as exc:
        raise RuntimeError("preparation " + operation_id + " has an unconfirmed remote outcome: " + str(exc) +
            "; rerun make superbench-fetch ADAPTER=swe-gym-lite to rediscover it; no mutation was blindly retried") from exc


def confirm_remote_shutdown(cfg, shutdown_id):
    sys.path.insert(0, str(ROOT / "apps/workstation-broker/src"))
    from workstation_broker.shutdown_observer import verify_stopped
    expected = {key: cfg["deployment"][key] for key in ("control_id", "execution_id")}
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            value = broker(cfg, "shutdown_status", {"shutdown_id": shutdown_id}, timeout=5)
        except IdentityFailure: raise
        except RemoteFailure as exc:
            if exc.status not in {502, 503, 504, 520, 521, 522, 523, 524}: raise
        except TransportFailure:
            pass  # A read may be repeated; connection failure is never stopped proof.
        else:
            if value.get("broker_stopped") is True:
                proof = verify_stopped(value, shutdown_id, "global", expected)
                acknowledged = broker(cfg, "shutdown_complete", {"shutdown_id": shutdown_id}, timeout=5)
                verify_stopped(acknowledged, shutdown_id, "global", expected)
                return proof
            if (value.get("shutdown_id") != shutdown_id or value.get("deployment") != expected
                    or value.get("project") != PROJECT or value.get("pending") is not True):
                raise RuntimeError("shutdown status has no verified matching handoff")
        time.sleep(0.2)
    raise RuntimeError("remote broker exit/cleanup confirmation unavailable; global shutdown incomplete")


def execution_environment(cfg):
    paths, local = cfg['paths'], cfg['local']
    os.environ.update({
        'WORKSTATION_CONFIG': str(ROOT / 'config/runner.toml'),
        'WORKSTATION_BROKER_SOCKET': str(paths['broker_runtime_directory'] / 'broker.sock'),
        'WORKSTATION_BROKER_STATE': str(paths['base_image'].parent / 'attempts'),
        'WORKSTATION_TEMPLATE_ROOT': str(paths['base_image'].parent / 'templates'),
        'WORKSTATION_BASE_IMAGE': str(paths['base_image']),
        'WORKSTATION_BROKER_LISTENER': 'unix',
        'WORKSTATION_BROKER_CONTROL_ID': cfg['deployment']['control_id'],
        'WORKSTATION_BROKER_EXECUTION_ID': cfg['deployment']['execution_id'],
        'WORKSTATION_BROKER_ADMIN_TOKEN': token_value(local['DIST_BROKER_ADMIN_TOKEN']),
        'WORKSTATION_BROKER_CONTROLLER_TOKEN': token_value(local['DIST_BROKER_CONTROLLER_TOKEN']),
    })


def execution_tunnel(cfg, action):
    if action not in {'up', 'down', 'ps'}: raise ValueError('invalid execution tunnel action')
    local = cfg['local']
    if action == 'up':
        value = local.get('DIST_BROKER_TUNNEL_TOKEN','')
        if not 30 <= len(value) <= 2048 or not re.fullmatch(r'[A-Za-z0-9._=-]+', value):
            raise ValueError('invalid/missing DIST_BROKER_TUNNEL_TOKEN')
        os.environ['DIST_BROKER_TUNNEL_TOKEN'] = value
    os.environ['DIST_BROKER_RUNTIME_DIR'] = str(cfg['paths']['broker_runtime_directory'])
    # Separate project: control-host Docker teardown never touches this tunnel.
    options = ['up', '-d', '--wait', '--wait-timeout', '120'] if action == 'up' else [action]
    return run(['docker', 'compose', '-f', str(ROOT / 'compose.execution-tunnel.yaml'), *options])


def local_down(cfg):
    print("scope=execution-local; global=false; control host campaign/services are not stopped by this command. Run make down on control host for global shutdown.", flush=True)
    execution_environment(cfg)
    sys.path.insert(0, str(ROOT / "apps/workstation-broker/src"))
    from gpt_trace_transport.local_templates import safe
    from workstation_broker.preparation import same_process
    from workstation_broker.shutdown_observer import verify_stopped
    runtime = cfg["paths"]["broker_runtime_directory"]
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe(runtime, directory=True)
    if runtime.stat().st_mode & 0o077: raise RuntimeError("local broker runtime is not private")
    record_path = runtime / "broker-process.json"
    expected = {key: cfg["deployment"][key] for key in ("control_id", "execution_id")}
    record = json.loads(safe(record_path).read_bytes()) if record_path.exists() else None
    if record is not None and record.get("deployment") != expected:
        raise RuntimeError("local broker identity belongs to another deployment")
    if record is None or not same_process(record["broker_identity"]):
        # The durable record can be absent/stale during a native broker restart.
        # An ACTIVE service must use the authenticated Unix-socket shutdown path,
        # never the offline helper. That helper checks inactive systemd itself.
        status = run(["systemctl", "show", "--property=ActiveState", "--value",
                      "gpt-trace-distributed-broker.service"], capture=True, timeout=30)
        pid = run(["systemctl", "show", "--property=MainPID", "--value",
                   "gpt-trace-distributed-broker.service"], capture=True, timeout=30)
        if status not in {"inactive", "failed"} or pid != "0":
            # Admin token and deployment identity bind this socket to this execution host.
            # A stale recorded PID is not a reason to touch unrelated processes.
            current = broker(cfg, "deployment_probe", local=True, timeout=15)
            if (current.get("status") != "ok" or current.get("project") != PROJECT
                    or current.get("execution_id") != expected["execution_id"]):
                raise RuntimeError("active execution broker did not prove its deployment identity")
        else:
            python = ROOT / ".venv-workstation-broker/bin/python"
            try:
                raw = run([python, "-B", "-m", "workstation_broker.local_shutdown"],
                          capture=True, timeout=900)
            except subprocess.CalledProcessError as exc:
                details = (exc.stderr or "").strip()
                raise RuntimeError("execution-local offline cleanup failed: " +
                                   (details[-8000:] if details else str(exc))) from exc
            result = json.loads(raw)
            if (result.get("scope") != "execution-local" or result.get("global") is not False
                    or result.get("deployment") != expected or result.get("broker_stopped") is not True
                    or result.get("inventory", {}).get("absent") is not True):
                raise RuntimeError("local offline cleanup lacks verified absence")
            print("execution host local shutdown complete; control host global shutdown remains separate; permanent data/images retained.")
            return result
    barrier = broker(cfg, "begin_shutdown", local=True, timeout=90)
    if barrier.get("draining") is not True or barrier.get("project") != PROJECT:
        raise RuntimeError("local mutation barrier unconfirmed")
    broker(cfg, "destroy_all", local=True)
    proof = broker(cfg, "inventory", local=True)
    if proof.get("absent") is not True or proof.get("project") != PROJECT:
        raise RuntimeError("local temporary resources remain")
    shutdown_id = secrets.token_hex(32)
    acknowledgement = broker(cfg, "shutdown", {"shutdown_id": shutdown_id, "scope": "execution-local"}, local=True, timeout=30)
    if acknowledgement.get("shutdown_id") != shutdown_id or acknowledgement.get("shutdown") is not True:
        raise RuntimeError("local broker shutdown handoff unconfirmed")
    path = runtime / ("shutdown-" + shutdown_id + ".json")
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        value = json.loads(safe(path).read_bytes())
        if value.get("status") == "failed": raise RuntimeError("local shutdown confirmation failed: " + str(value.get("error")))
        if value.get("status") == "stopped":
            verify_stopped(value, shutdown_id, "execution-local", expected)
            if same_process(value["broker_identity"]): raise RuntimeError("native broker still exists")
            print("execution host local shutdown confirmed; control host campaign/services remain outside this local scope; permanent data/images retained.")
            return value
        time.sleep(0.2)
    raise RuntimeError("local broker exit confirmation timed out")


def install_unit(cfg):
    if not re.fullmatch(r"[a-zA-Z0-9_./-]+", str(ROOT)):
        raise ValueError("systemd unit requires an unambiguous repository path")
    source = ROOT / "infra/workstation/systemd/gpt-trace-distributed-broker.service.in"
    output = Path("/etc/systemd/system/gpt-trace-distributed-broker.service")
    content = source.read_text().replace("@REPOSITORY@", str(ROOT)).encode()
    for path in (output, *output.parents):
        if path.is_symlink(): raise ValueError("unsafe systemd unit destination")
    if output.exists():
        if output.read_bytes() == content: return
        # Do not replace an unrelated service or a previous checkout identity.
        if (b"WorkingDirectory=" + str(ROOT).encode() + b"\n") not in output.read_bytes():
            raise RuntimeError("existing distributed service belongs to another checkout")
    fd, name = tempfile.mkstemp(prefix=".gpt-trace-broker-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, output)
        run(["systemctl", "daemon-reload"])
    finally:
        Path(name).unlink(missing_ok=True)


def global_down(cfg):
    """control host coordinates cleanup; local producers stop even on credential failure."""
    if cfg["deployment"]["role"] != "control":
        raise RuntimeError("global shutdown must run on control host: make down; no local-only cleanup was performed")
    host("control", cfg)
    project_filter = "label=com.docker.compose.project=" + PROJECT
    before_volumes = set(run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture=True).splitlines())
    running = run(["docker", "ps", "-q", "--filter", project_filter,
                   "--filter", "label=com.docker.compose.service=runner"], capture=True).splitlines()
    if running: run(["docker", "stop", "--time", "30", *running])
    try:
        full = config("control")
        environment(full)
        draining = broker(full, "begin_shutdown")
        if draining.get("draining") is not True or draining.get("project") != PROJECT:
            raise RuntimeError("execution host did not acknowledge the shutdown mutation barrier")
        before = broker(full, "inventory")
        if before.get("project") != PROJECT: raise RuntimeError("remote project identity differs")
        broker(full, "destroy_all")
        proof = broker(full, "inventory")
        if proof.get("absent") is not True or proof.get("project") != PROJECT:
            raise RuntimeError("execution host cleanup has no authenticated absence proof")
        shutdown_id = secrets.token_hex(32)
        reply = broker(full, "shutdown", {"shutdown_id": shutdown_id, "scope": "global"}, timeout=30)
        if (reply.get("shutdown_id") != shutdown_id or reply.get("absent") is not True
                or reply.get("shutdown") is not True):
            raise RuntimeError("execution host broker did not acknowledge the clean shutdown handoff")
        stopped = confirm_remote_shutdown(full, shutdown_id)
        directory = ROOT / "state/distributed"
        for parent in (directory, *directory.parents):
            if parent.is_symlink(): raise ValueError("unsafe cleanup journal")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        from gpt_trace_transport.local_templates import atomic_json
        atomic_json(directory / "last-cleanup.json", {"control_id": cfg["deployment"]["control_id"],
            "execution_id": cfg["deployment"]["execution_id"], "observed_at": time.time(),
            "inventory": proof, "broker_exit_confirmation": stopped}, 0o600)
    finally:
        # Label-scoped Docker teardown does not depend on Compose interpolation,
        # valid remote certificates, a running database, or a secret generator.
        ids = run(["docker", "ps", "-aq", "--filter", project_filter], capture=True).splitlines()
        if ids:
            run(["docker", "stop", "--time", "30", *ids])
            run(["docker", "rm", *ids])  # Deliberately no -v/--volumes.
        networks = run(["docker", "network", "ls", "-q", "--filter", project_filter], capture=True).splitlines()
        if networks: run(["docker", "network", "rm", *networks])
        if run(["docker", "ps", "-aq", "--filter", project_filter], capture=True):
            raise RuntimeError("control host project containers remain after shutdown")
        after_volumes = set(run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture=True).splitlines())
        if before_volumes - after_volumes:
            raise RuntimeError("pre-existing Docker volumes disappeared during shutdown")
    print("Global shutdown confirmed; execution host native broker stopped; temporary execution host resources absent; control host services stopped; data and permanent images retained.")


def control_up(cfg, *, minimal=False):
    verify_storage(cfg)
    run([sys.executable, "scripts/project_state.py", "core"])
    broker(cfg, "probe")
    services = ("kali-workstation-controller", "workstation-gateway") if minimal else CORE
    compose("up", "-d", "--wait", "--wait-timeout", "300", *services)


def control(cfg, action, args):
    if action == "down": return global_down(cfg)
    host("control", cfg, build_tools=action in {"build", "requirements"})
    if action == "init-storage": return init_storage(cfg)
    if action == "restore": return restore(cfg, args.directory)
    if action == "requirements":
        from host_requirements import verify_host_requirements
        if not verify_host_requirements(role="control"): raise RuntimeError("control host prerequisites failed")
        return
    environment(cfg)
    if action == "build":
        # Only empty/new persistent directories may be initialized. Existing
        # data outside the declared storage root is never migrated implicitly.
        init_storage(cfg)
        import build
        build.ensure_builder(ROOT)
        compose("build", "--builder", build.BUILDER_NAME, "storage", "teacher-browser",
                "kali-workstation-controller", "workstation-gateway", "runner", "benchmark-fetch")
        build.verify_manifests(ROOT)
        return
    if action in {"up", "kali_control"}:
        return control_up(cfg, minimal=action == "kali_control")
    if action == "throw_volumes":
        # The historical explicit THROW confirmation and source/cache retention
        # remain in this script. Its shutdown is the same global coordinator.
        return run([sys.executable, "scripts/throw_volumes.py"])
    verify_storage(cfg)
    if action == "reconcile":
        print(json.dumps(broker(cfg, "inventory"), indent=2))
        return
    if action in {"doctor", "acceptance"}:
        control_up(cfg)
        broker(cfg, "probe")
        if action == "acceptance":
            values = ["--adapter", args.adapter] if args.adapter else []
            return compose("run", "--rm", "--no-deps", "--entrypoint", "python", "runner",
                           "/app/tools/distributed_acceptance.py", *values)
        doctor_tests("control")
        node = Path("/dev/dri/renderD128")
        driver = Path("/sys/class/drm/renderD128/device/driver")
        # Intel i915/xe, AMD and Nouveau render nodes are acceptable; the real
        # Chromium renderer is verified by teacher_gpu_doctor.py below.
        if not node.is_char_device() or not driver.exists():
            raise RuntimeError("control host needs a working GPU DRM render node")
        compose("exec", "-T", "teacher-browser", "/usr/local/bin/browser-healthcheck")
        compose("run", "--rm", "--no-deps", "--entrypoint", "python", "runner", "/app/tools/teacher_gpu_doctor.py")
        return compose("run", "--rm", "--no-deps", "runner", "doctor")
    if action == "tunnels":
        control_up(cfg)
        return run([sys.executable, "scripts/tunnels.py"])
    if action in {"auth", "run", "resume", "start_kali", "register_apps"}:
        control_up(cfg)
        run([sys.executable, "scripts/tunnels.py"])
    if action in {"status_kali", "stop_kali"}:
        control_up(cfg, minimal=True)
    if action == "superbench-fetch":
        if not args.adapter: raise ValueError("ADAPTER is required")
        run([sys.executable, "scripts/project_state.py", "core"])
        compose("run", "--rm", "--no-deps", "benchmark-fetch", "--adapter", args.adapter)
        if args.adapter == "swe-gym-lite": return preparation_fetch(cfg)
        return
    mapping = {"auth": "superbench-auth", "run": "superbench-run", "pause": "superbench-pause",
        "resume": "superbench-resume-active", "status": "superbench-active-status",
        "start_kali": "manual-kali-start", "stop_kali": "manual-kali-stop",
        "status_kali": "manual-kali-status", "register_apps": "register-apps",
        "reset-recovery": "superbench-reset-recovery", "export-parquet": "export-parquet"}
    if action not in mapping: raise ValueError("operation does not belong to control host")
    arguments = []
    if action == "run":
        if args.adapter: arguments += ["--adapter", args.adapter]
        if args.limit is not None: arguments += ["--limit", str(args.limit)]
    if action == "reset-recovery":
        if not args.task: raise ValueError("TASK is required")
        arguments = [args.task, "--yes"]
    run([sys.executable, "scripts/project_state.py", "core"])
    if action == "export-parquet":
        (ROOT / "exports").mkdir(exist_ok=True)
        # Export needs PostgreSQL/storage, never a Kali or teacher browser.
        compose("up", "-d", "--wait", "--wait-timeout", "120", "postgres", "storage")
        arguments = ["/data/exports/corpus.parquet"]
    if action in {"run", "resume"}:
        os.environ["GPT_TRACE_RUNNER_BUILD_ID"] = run(["git", "rev-parse", "HEAD"], capture=True)
    compose("run", "--rm", "--no-deps", "-e", "GPT_TRACE_RUNNER_BUILD_ID", "runner", mapping[action], *arguments)


def execution(cfg, action, args):
    allowed = {"requirements", "build", "up", "doctor", "status", "kali_control", "serve", "down"}
    if action not in allowed:
        raise RuntimeError("this operation belongs to control host; execution host never runs control-plane services")
    host("execution", cfg, docker=action in {"requirements", "build"}, build_tools=action in {"requirements", "build"})
    paths = cfg["paths"]
    if action == "down":
        result = local_down(cfg)
        run(['systemctl', 'disable', 'gpt-trace-distributed-broker.service'])
        execution_tunnel(cfg, 'down')
        return result
    if action == "requirements":
        from host_requirements import verify_host_requirements
        if not verify_host_requirements(require_root=True, role="execution", golden_build=True): raise RuntimeError("execution host prerequisites failed")
        return
    if action == "build":
        from host_requirements import verify_host_requirements
        if not verify_host_requirements(require_root=True, role="execution", golden_build=True): raise RuntimeError("execution host prerequisites failed")
        domains = run(["virsh", "-c", "qemu:///system", "list", "--all", "--name"], capture=True).splitlines()
        if any(x.startswith("gpt-trace-ws-") for x in domains):
            raise RuntimeError("preserve existing attempts before installing broker/images")
        import build
        build.build_verified_resolver(ROOT)
        build.build_host_broker(ROOT)
        build.build_workstation_base_image(ROOT)
        build.verify_workstation_image(ROOT)
        install_unit(cfg)
        return
    if action == "serve":
        runtime = paths["broker_runtime_directory"]
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime.chmod(0o700)
        limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
        if limits["provider"] != "libvirt": raise ValueError("libvirt provider required")
        execution_environment(cfg)
        python = ROOT / ".venv-workstation-broker/bin/python"
        os.execv(str(python), [str(python), "-m", "workstation_broker.server"])
    if action in {"up", "kali_control", "doctor"}:
        install_unit(cfg)
        execution_environment(cfg)
        if (paths["base_image"].parent / "broker-drain.json").exists():
            run([ROOT / ".venv-workstation-broker/bin/python", "-B", "-m", "workstation_broker.admission"], timeout=900)
        run(["systemctl", "enable", "--now", "gpt-trace-distributed-broker.service"])
        deadline = time.monotonic() + 900
        while True:
            try:
                broker(cfg, "probe", local=True)
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("execution host broker startup deadline exceeded")
                time.sleep(0.5)
        execution_tunnel(cfg, 'up')
        if action != "doctor": return
    if action in {"status", "doctor"}:
        execution_tunnel(cfg, 'ps')
        print(json.dumps(broker(cfg, "inventory", local=True), indent=2))
        if action == "doctor":
            doctor_tests("execution")
            run([sys.executable, "infra/workstation/image/build.py", "--verify"])
            limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
            if shutil.disk_usage(paths["base_image"].parent).free < limits["overlay_quota_gb"] * 1024 ** 3:
                raise RuntimeError("execution disk cannot reserve one complete configured overlay")


HISTORICAL = ("requirements", "build", "up", "doctor", "tunnels",
    "register_apps", "start_kali", "status_kali", "stop_kali", "auth", "run", "pause", "resume",
    "status", "reset-recovery", "superbench-fetch", "export-parquet", "down", "throw_volumes", "kali_control")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(*HISTORICAL, "serve", "backup", "restore", "init-storage", "reconcile", "acceptance"))
    parser.add_argument("--adapter")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--task")
    parser.add_argument("--directory")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1: parser.error("LIMIT must be positive")
    if args.action == "superbench-fetch" and not args.adapter: parser.error("ADAPTER is required")
    if args.action == "reset-recovery" and not args.task: parser.error("TASK is required")
    if args.action in {"backup", "restore"} and not args.directory: parser.error("--directory is required")
    cfg = config(credentials=args.action not in {"requirements", "backup", "restore", "init-storage", "down"})
    role = cfg["deployment"]["role"]
    if args.action == "backup":
        if role != "control": raise RuntimeError("cold backup belongs to control host")
        host("control", cfg)
        return backup(args.directory)
    return (control if role == "control" else execution)(cfg, args.action, args)


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
        if len(sys.argv) > 1 and sys.argv[1] == 'superbench-fetch':
            _record_fetch_failure(exc)
            _FetchBar().finish(False)
        else:
            print("distributed operation failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)

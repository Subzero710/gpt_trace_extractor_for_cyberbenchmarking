#!/usr/bin/env python3
"""Explicit two-host operations. Applying the source patch never invokes this file."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
from gpt_trace_transport.pki import verify_bundle
from gpt_trace_transport.wire import Endpoint, WireClient, private_address, token

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


def config(role, *, credentials=True):
    source = ROOT / "config/distributed.toml"
    if source.is_symlink(): raise ValueError("unsafe distributed configuration")
    cfg = tomllib.loads(source.read_text())
    required = {
        "deployment": {"role", "control_id", "execution_id", "bundle_manifest_sha256"},
        "network": {"acer_address", "fossil_address", "server_name", "broker_port"},
        "paths": {"tls_directory", "base_image", "broker_runtime_directory", "storage_root"},
        "storage": set(VOLUMES),
    }
    if set(cfg) != set(required) or any(set(cfg[section]) != keys for section, keys in required.items()):
        raise ValueError("distributed.toml has missing or unknown fields")
    if cfg["deployment"]["role"] != role:
        raise ValueError("this checkout has another physical-host role")
    network, deployment = cfg["network"], cfg["deployment"]
    for name in ("acer_address", "fossil_address"):
        network[name] = private_address(network[name])
    if network["acer_address"] == network["fossil_address"]:
        raise ValueError("hosts must have distinct LAN addresses")
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", network["server_name"]):
        raise ValueError("invalid broker DNS identity")
    if type(network["broker_port"]) is not int or not 1024 <= network["broker_port"] <= 65535:
        raise ValueError("invalid private broker port")
    for name in ("control_id", "execution_id"):
        if not re.fullmatch(r"[a-zA-Z0-9-]{1,63}", deployment[name]): raise ValueError("invalid host identity")
    if deployment["control_id"] == deployment["execution_id"]:
        raise ValueError("host identities must differ")
    cfg["paths"] = {key: path_from_config(value) for key, value in cfg["paths"].items()}
    if not cfg["paths"]["base_image"].is_absolute() or cfg["paths"]["base_image"].suffix != ".qcow2":
        raise ValueError("explicit QCOW2 image path required")
    if any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", value) for value in cfg["storage"].values()):
        raise ValueError("invalid explicit Docker volume name")
    if len(set(cfg["storage"].values())) != len(VOLUMES): raise ValueError("persistent volume names must be distinct")
    if credentials:
        expected = {"acer_address": network["acer_address"], "fossil_address": network["fossil_address"],
            "server_name": network["server_name"], "port": network["broker_port"],
            "control_id": deployment["control_id"], "execution_id": deployment["execution_id"]}
        cfg["bundle"] = verify_bundle(cfg["paths"]["tls_directory"], deployment["bundle_manifest_sha256"], role, expected)
    return cfg


def host(role, cfg, *, docker=True):
    if platform.system() != "Linux" or sys.version_info < (3, 12): raise RuntimeError("Linux/Python >=3.12 required")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=\"?ubuntu\"?$', release, re.M) or not re.search(r'^VERSION_ID=\"?26\.04\"?$', release, re.M):
        raise RuntimeError("deployment requires Ubuntu 26.04")
    addresses = {entry["local"] for device in json_command(["ip", "-j", "address", "show"])
                 for entry in device.get("addr_info", []) if entry.get("family") == "inet"}
    if cfg["network"][role + "_address"] not in addresses:
        raise RuntimeError("the configured role LAN address is not assigned to this host")
    if docker:
        for command in (["docker", "info", "--format", "{{.ServerVersion}}"], ["docker", "compose", "version"], ["docker", "buildx", "version"]):
            run(command, capture=True, timeout=30)
    if role == "acer":
        if os.geteuid() != 0: raise RuntimeError("Acer broker operations require root")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK): raise RuntimeError("Acer KVM is unavailable")
        run(["virsh", "-c", "qemu:///system", "list", "--all"], capture=True, timeout=30)
        run(["nft", "list", "tables"], capture=True, timeout=30)
        parent = cfg["paths"]["base_image"].parent
        device = run(["findmnt", "-n", "-o", "SOURCE", "-T", parent], capture=True, timeout=10)
        if not device.startswith("/dev/") or run(["lsblk", "-dn", "-o", "ROTA", device], capture=True, timeout=10) != "0":
            raise RuntimeError("Kali base/templates/overlays must reside on Acer's local SSD")


def environment(cfg):
    paths, network, bundle = cfg["paths"], cfg["network"], cfg["bundle"]
    values = {"COMPOSE_FILE": str(ROOT / "compose.control.yaml"), "DIST_TLS_DIRECTORY": str(paths["tls_directory"]),
        "DIST_BROKER_URL": f'https://{network["server_name"]}:{network["broker_port"]}',
        "DIST_BROKER_ADDRESS": network["acer_address"], "DIST_SERVER_SHA256": bundle["server_sha256"],
        "DIST_CONTROL_ADDRESS": network["fossil_address"],
        "WORKSTATION_BROKER_TRANSPORT": "mtls",
        "WORKSTATION_BROKER_URL": f'https://{network["server_name"]}:{network["broker_port"]}',
        "WORKSTATION_BROKER_ADDRESS": network["acer_address"],
        "WORKSTATION_BROKER_CA_FILE": str(paths["tls_directory"] / "ca.crt"),
        "WORKSTATION_BROKER_CERT_FILE": str(paths["tls_directory"] / "admin.crt"),
        "WORKSTATION_BROKER_KEY_FILE": str(paths["tls_directory"] / "admin.key"),
        "WORKSTATION_BROKER_SERVER_SHA256": bundle["server_sha256"],
        "WORKSTATION_BROKER_ADMIN_TOKEN_FILE": str(paths["tls_directory"] / "workstation_broker_admin_token"),
        "WORKSTATION_BROKER_CONTROLLER_TOKEN_FILE": str(paths["tls_directory"] / "workstation_broker_controller_token")}
    values.update({"DIST_VOLUME_" + key.upper(): name for key, name in cfg["storage"].items()})
    os.environ.update(values)


def broker(cfg, action, payload=None, *, local=False):
    if local:
        endpoint = Endpoint("unix", cfg["paths"]["broker_runtime_directory"] / "broker.sock")
    else:
        endpoint = Endpoint.from_env(Path("/unused-private-broker.sock"))
    result = WireClient(endpoint).request("deployment_probe" if action == "probe" and not local else action,
        payload or {}, token(cfg["paths"]["tls_directory"] / "workstation_broker_admin_token"))
    if action == "probe" and not local:
        limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
        expected = hashlib.sha256(json.dumps(limits, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if result.get("project") != PROJECT or result.get("status") != "ok" or result.get("execution_id") != cfg["deployment"]["execution_id"] or result.get("workstation_sha256") != expected:
            raise RuntimeError("Acer identity/workstation configuration differs from Fossil; preserve attempts and reconcile explicitly")
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
            raise RuntimeError(f"{logical} storage is outside configured Fossil storage root; migrate from a verified cold backup")
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


def fossil(cfg, action, args):
    environment(cfg)
    host("fossil", cfg)
    if action == "init-storage": return init_storage(cfg)
    if action == "restore": return restore(cfg, args.directory)
    if action == "build":
        import build
        build.ensure_builder(ROOT)
        compose("build", "--builder", build.BUILDER_NAME, "storage", "teacher-browser", "kali-workstation-controller", "workstation-gateway", "runner", "benchmark-fetch")
        build.verify_manifests(ROOT)
        return
    verify_storage(cfg)
    if action == "up":
        run([sys.executable, "scripts/project_state.py", "core"])
        broker(cfg, "probe")
        compose("up", "-d", "--wait", "--wait-timeout", "300", *CORE)
        return
    if action == "down":
        # Stop sources of mutations before remote cleanup; retain every journal.
        ids = run(["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=" + PROJECT,
                   "--filter", "label=com.docker.compose.service=runner"], capture=True).splitlines()
        if ids: run(["docker", "stop", "--time", "30", *ids])
        try:
            broker(cfg, "inventory")
            broker(cfg, "destroy_all")
            if broker(cfg, "inventory").get("absent") is not True: raise RuntimeError("Acer cleanup has no verified absence")
        finally:
            compose("down", "--remove-orphans", "--timeout", "30")
        verify_storage(cfg)
        print("Control services stopped; authenticated Acer inventory proves project resources absent; volumes retained.")
        return
    if action == "reconcile":
        print(json.dumps(broker(cfg, "inventory"), indent=2))
        return
    if action == "doctor":
        broker(cfg, "probe")
        driver = Path("/sys/class/drm/renderD128/device/driver")
        if not driver.exists() or driver.resolve().name != "nouveau": raise RuntimeError("Fossil render node is not driven by Nouveau")
        compose("exec", "-T", "teacher-browser", "/usr/local/bin/browser-healthcheck")
        compose("run", "--rm", "--no-deps", "--entrypoint", "python", "runner", "/app/tools/teacher_gpu_doctor.py")
        compose("run", "--rm", "--no-deps", "runner", "doctor")
        return
    if action == "acceptance":
        values = ["--adapter", args.adapter] if args.adapter else []
        compose("run", "--rm", "--no-deps", "--entrypoint", "python", "runner", "/app/tools/distributed_acceptance.py", *values)
        return
    if action == "tunnels":
        broker(cfg, "probe")
        run([sys.executable, "scripts/tunnels.py"])
        return
    mapping = {"auth": "superbench-auth", "run": "superbench-run", "pause": "superbench-pause",
        "resume": "superbench-resume-active", "status": "superbench-active-status", "start-kali": "manual-kali-start",
        "stop-kali": "manual-kali-stop", "status-kali": "manual-kali-status", "register-apps": "register-apps",
        "reset-recovery": "superbench-reset-recovery", "template-doctor": "superbench-template-doctor",
        "export-parquet": "export-parquet", "export-sft": "export-sft"}
    if action in {"auth", "run", "resume", "start-kali", "register-apps"}:
        broker(cfg, "probe")
        run([sys.executable, "scripts/tunnels.py"])
    if action == "fetch":
        if not args.adapter: raise ValueError("--adapter is required")
        return compose("run", "--rm", "--no-deps", "benchmark-fetch", "--adapter", args.adapter)
    arguments = []
    if action in {"run", "template-doctor"}:
        if action == "template-doctor" and not args.adapter: raise ValueError("--adapter is required")
        if args.adapter: arguments += ["--adapter", args.adapter]
        if action == "run" and args.limit: arguments += ["--limit", str(args.limit)]
    if action == "reset-recovery":
        if not args.task: raise ValueError("--task is required")
        arguments = [args.task, "--yes"]
    if action == "export-parquet":
        (ROOT / "exports").mkdir(exist_ok=True)
        arguments = ["/data/exports/corpus.parquet"]
    if action == "export-sft":
        compose("run", "--rm", "--no-deps", "runner", "export-parquet", "/data/exports/corpus.parquet")
        arguments = ["/data/exports/corpus.parquet", "/data/exports/sft.parquet"]
    if action not in mapping: raise ValueError("unknown Fossil operation")
    os.environ["GPT_TRACE_RUNNER_BUILD_ID"] = run(["git", "rev-parse", "HEAD"], capture=True)
    run([sys.executable, "scripts/project_state.py", "core"])
    compose("run", "--rm", "--no-deps", "-e", "GPT_TRACE_RUNNER_BUILD_ID", "runner", mapping[action], *arguments)


def acer(cfg, action, args):
    host("acer", cfg, docker=action == "build")
    paths, network = cfg["paths"], cfg["network"]
    if action == "unit":
        if not re.fullmatch(r"[a-zA-Z0-9_./-]+", str(ROOT)): raise ValueError("systemd unit requires an unambiguous repository path")
        template = (ROOT / "infra/workstation/systemd/gpt-trace-distributed-broker.service.in").read_text()
        output = ROOT / "state/distributed/gpt-trace-distributed-broker.service"
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output.write_text(template.replace("@REPOSITORY@", str(ROOT)))
        print(output)
        return
    if action == "build":
        from host_requirements import verify_host_requirements
        if not verify_host_requirements(require_root=True): raise RuntimeError("Acer runtime prerequisites failed")
        domains = run(["virsh", "-c", "qemu:///system", "list", "--all", "--name"], capture=True).splitlines()
        if any(x.startswith("gpt-trace-ws-") for x in domains): raise RuntimeError("preserve existing attempts before rebuilding the broker/golden")
        import build
        build.build_host_broker(ROOT)
        # Never discard an existing image on a failed verification.
        if paths["base_image"] != Path("/var/lib/libvirt/images/gpt-trace/kali-base.qcow2"):
            raise RuntimeError("the current verified golden installer uses the fixed libvirt SSD root")
        if paths["base_image"].exists():
            build.verify_workstation_image(ROOT)
        else:
            build.build_workstation_base_image(ROOT)
            build.verify_workstation_image(ROOT)
        return
    if action == "serve":
        runtime = paths["broker_runtime_directory"]
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime.chmod(0o700)
        cfg_limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
        if cfg_limits["provider"] != "libvirt": raise ValueError("libvirt provider required")
        os.environ.update({"WORKSTATION_CONFIG": str(ROOT / "config/runner.toml"),
            "WORKSTATION_BROKER_SOCKET": str(runtime / "broker.sock"),
            "WORKSTATION_BROKER_STATE": str(paths["base_image"].parent / "attempts"),
            "WORKSTATION_TEMPLATE_ROOT": str(paths["base_image"].parent / "templates"),
            "WORKSTATION_BASE_IMAGE": str(paths["base_image"]), "WORKSTATION_BROKER_LISTENER": "mtls",
            "WORKSTATION_BROKER_LISTEN_ADDRESS": network["acer_address"],
            "WORKSTATION_BROKER_ALLOWED_PEER": network["fossil_address"],
            "WORKSTATION_BROKER_LISTEN_PORT": str(network["broker_port"]),
            "WORKSTATION_BROKER_CONTROL_ID": cfg["deployment"]["control_id"],
            "WORKSTATION_BROKER_EXECUTION_ID": cfg["deployment"]["execution_id"],
            "WORKSTATION_BROKER_TLS_DIR": str(paths["tls_directory"]),
            "WORKSTATION_CONTROL_PLANE_CIDRS": json.dumps([network["fossil_address"] + "/32"]),
            "WORKSTATION_BROKER_ADMIN_TOKEN_FILE": str(paths["tls_directory"] / "workstation_broker_admin_token"),
            "WORKSTATION_BROKER_CONTROLLER_TOKEN_FILE": str(paths["tls_directory"] / "workstation_broker_controller_token")})
        os.execv(str(ROOT / ".venv-workstation-broker/bin/python"),
                 [str(ROOT / ".venv-workstation-broker/bin/python"), "-m", "workstation_broker.server"])
    if action == "up":
        run(["systemctl", "start", "gpt-trace-distributed-broker.service"])
        deadline = time.monotonic() + 130
        while time.monotonic() < deadline:
            try:
                broker(cfg, "probe", local=True)
                return
            except RuntimeError:
                if run(["systemctl", "is-active", "gpt-trace-distributed-broker.service"], capture=True) != "active":
                    raise RuntimeError("distributed broker service is not active")
                time.sleep(0.5)
        raise RuntimeError("Acer broker startup deadline exceeded")
    if action == "down":
        broker(cfg, "inventory", local=True)
        broker(cfg, "destroy_all", local=True)
        if broker(cfg, "inventory", local=True).get("absent") is not True: raise RuntimeError("local resource audit did not prove absence")
        run(["systemctl", "stop", "gpt-trace-distributed-broker.service"])
        return
    if action in {"status", "doctor"}:
        print(json.dumps(broker(cfg, "inventory", local=True), indent=2))
        if action == "doctor":
            run([sys.executable, "infra/workstation/image/build.py", "--verify"])
            limits = tomllib.loads((ROOT / "config/runner.toml").read_text())["workstation"]
            if shutil.disk_usage(paths["base_image"].parent).free < limits["overlay_quota_gb"] * 1024**3:
                raise RuntimeError("SSD cannot reserve one complete configured overlay")
        return
    if action == "templates":
        python = ROOT / ".venv-workstation-broker/bin/python"
        run([python, "scripts/build_swe_gym_lite_templates.py", *args.template_args])
        return
    raise ValueError("unknown Acer operation")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("fossil", "acer", "backup"))
    parser.add_argument("action", nargs="?")
    parser.add_argument("--adapter")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--task")
    parser.add_argument("--directory")
    args, extra = parser.parse_known_args()
    if args.role == "backup":
        if not args.directory or args.action or extra: parser.error("backup --directory NEW_DIRECTORY")
        return backup(args.directory)
    if not args.action: parser.error("a host operation is required")
    args.template_args = extra
    if extra and not (args.role == "acer" and args.action == "templates"): parser.error("unknown arguments")
    cfg = config(args.role, credentials=not (args.role == "fossil" and args.action in {"init-storage", "restore"}))
    if args.role == "fossil" and args.action in {"init-storage", "restore"}:
        host("fossil", cfg)
        return init_storage(cfg) if args.action == "init-storage" else restore(cfg, args.directory)
    return (fossil if args.role == "fossil" else acer)(cfg, args.action, args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
        print("distributed operation failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Persistent, proof-based Kali golden construction on the execution host."""
from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / "infra/workstation/image"
sys.path.insert(0, str(HERE))
from golden_assets import (CACHE_TAG, CACHE_MOUNT, atomic_bytes, atomic_json,
                           digest, download, mkdir, read_json, safe, sync)
import golden_lock
import guest_build
import host_cache

SOURCE = "https://cdimage.kali.org/kali-2026.2/"
ARCHIVE = "kali-linux-2026.2-qemu-amd64.7z"
ARCHIVE_SHA256 = "c7c35588d05277c482c908bf7a136d348f76ffa68700b04ff53c0b217e6bd071"
APT_SUITE = "kali-last-snapshot"
SOURCE_ARCHITECTURE = "x86_64"
GUEST_PACKAGES = (
    "qemu-guest-agent", "lightdm", "xfce4", "python3", "python3-venv", "python3-pip",
    "git", "build-essential", "rustc", "cargo", "gdb", "curl", "wget", "ca-certificates",
    "iproute2", "iputils-ping", "tcpdump", "nmap", "util-linux", "cloud-guest-utils",
    "nodejs", "npm", "libnss3", "libnspr4", "libgbm1", "libxss1", "libasound2t64",
)
PHASES = ("new", "source_acquired", "base_converted", "offline_started", "offline_complete",
          "guest_started", "guest_complete", "manifests_collected", "provenance_generated",
          "prepared", "installed")
STATE_KEYS = {"schema", "status", "phase", "stage", "fingerprint", "repo_commit", "files", "error"}
BUILD_LOG = None
BUILD_LOCK = None


def versioned_file(path):
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("missing/unsafe versioned golden input: " + str(path))
    return path


def _preparation_build_controls():
    path = versioned_file(ROOT / "config/preparation.toml")
    controls = tomllib.loads(path.read_text())["build"]
    required = {"virtual_disk_gib", "root_min_gib", "golden_provision_timeout_hours", "golden_memory_mb", "golden_vcpus"}
    if not required <= set(controls) or any(type(controls[k]) is not int or controls[k] <= 0 for k in required):
        raise ValueError("golden preparation controls must be positive integers")
    if controls["root_min_gib"] >= controls["virtual_disk_gib"]:
        raise ValueError("root minimum must fit inside the virtual disk")
    return controls


def configured_base_image():
    source = versioned_file(ROOT / "config/distributed.toml")
    path = Path(tomllib.loads(source.read_text())["paths"]["base_image"])
    if not path.is_absolute() or path.suffix != ".qcow2" or ".." in path.parts:
        raise ValueError("base_image must be an absolute canonical QCOW2 path")
    return path


_BUILD_CONTROLS = _preparation_build_controls()
VIRTUAL_DISK_GIB = _BUILD_CONTROLS["virtual_disk_gib"]
ROOT_MIN_GIB = _BUILD_CONTROLS["root_min_gib"]
PROVISION_TIMEOUT_SECONDS = _BUILD_CONTROLS["golden_provision_timeout_hours"] * 3600
DEST = configured_base_image()
CACHE_DIR = DEST.parent / "cache"
CACHE_ARCHIVE = CACHE_DIR / ARCHIVE


def run(*cmd, timeout=7200, **kwargs):
    print("+ " + " ".join(str(x) for x in cmd), flush=True)
    if BUILD_LOG is not None:
        kwargs.setdefault("stdout", BUILD_LOG)
        kwargs.setdefault("stderr", subprocess.STDOUT)
    # Surviving QEMU/guestfs children keep the exclusive lock after parent death.
    if BUILD_LOCK is not None:
        kwargs["pass_fds"] = (BUILD_LOCK,)
    return subprocess.run([str(x) for x in cmd], check=True, timeout=timeout, **kwargs)


def capture(*cmd):
    return subprocess.run([str(x) for x in cmd], check=False, capture_output=True, text=True, timeout=180)


def _hash_component(hasher, label, raw):
    label = label.encode()
    hasher.update(len(label).to_bytes(8, "big") + label)
    hasher.update(len(raw).to_bytes(8, "big") + raw)


def guest_source_bytes(path, raw=None):
    raw = path.read_bytes() if raw is None else raw
    if path == ROOT / "apps/kali-workstation/src/kali_workstation/server.py":
        guard = json.loads(versioned_file(HERE / "host-controller-input.json").read_bytes())
        source = raw.decode()
        for old, new in reversed(guard["replacements"]):
            if source.count(new) != 1:
                raise ValueError("unrecognized host-only controller fingerprint reconstruction")
            source = source.replace(new, old, 1)
        raw = source.encode()
        if hashlib.sha256(raw).hexdigest() != guard["sha256"]:
            raise ValueError("host-only controller fingerprint reconstruction failed")
    return raw


def input_files():
    files = [ROOT / "apps/kali-workstation/pyproject.toml", HERE / "requirements.lock",
             HERE / "python-lock.json", HERE / "golden_lock.py", HERE / "golden_assets.py",
             HERE / "guest_build.py", HERE / "firstboot.sh.in",
             ROOT / "infra/workstation/systemd/gpt-trace-workstation-agent.service",
             ROOT / "infra/workstation/systemd/gpt-trace-golden-build.service"]
    source = ROOT / "apps/kali-workstation/src/kali_workstation"
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in golden source tree: " + str(path))
        if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}:
            files.append(path)
    if not any(path.is_relative_to(source) for path in files):
        raise ValueError("empty guest source tree")
    for path in files:
        if path.is_symlink() or not path.is_file() or any(p.is_symlink() for p in path.parents):
            raise ValueError("missing/unsafe guest input: " + str(path))
    return files


def guest_contract():
    return {"schema": 2, "source": SOURCE + ARCHIVE, "source_sha256": ARCHIVE_SHA256,
            "source_architecture": SOURCE_ARCHITECTURE,
            "virtual_disk_gib": VIRTUAL_DISK_GIB, "root_min_gib": ROOT_MIN_GIB,
            "apt_suite": APT_SUITE, "packages": list(GUEST_PACKAGES)}


def firstboot_script(template=None):
    text = (HERE / "firstboot.sh.in").read_text() if template is None else template
    for token, value in {"@CACHE_MOUNT@": str(CACHE_MOUNT), "@CACHE_TAG@": CACHE_TAG}.items():
        if token not in text or not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
            raise ValueError("invalid firstboot template token/value")
        text = text.replace(token, value)
    if re.search(r"@[A-Z_]+@", text):
        raise ValueError("unexpanded firstboot token")
    return text


def golden_build_input_sha256(payloads=None):
    paths = input_files()
    payloads = {path: path.read_bytes() for path in paths} if payloads is None else payloads
    if set(payloads) != set(paths):
        raise ValueError("frozen input snapshot does not cover the exact guest input set")
    h = hashlib.sha256()
    _hash_component(h, "guest-contract", golden_lock.canonical(guest_contract()))
    _hash_component(h, "firstboot", firstboot_script(payloads[HERE / "firstboot.sh.in"].decode()).encode())
    for path in sorted(paths):
        _hash_component(h, path.relative_to(ROOT).as_posix(), guest_source_bytes(path, payloads[path]))
    # Offline injection changes the guest. Normalize its actual implementation
    # to AST so comments/formatting and unrelated host orchestration stay out.
    tree = ast.parse((HERE / "build.py").read_bytes())
    injection = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "prepare_offline")
    _hash_component(h, "offline-injection", ast.dump(injection, include_attributes=False).encode())
    # Host orchestration, timeouts, role, credentials and commit do not change
    # the installed guest payload and must not invalidate expensive work.
    return h.hexdigest()


def preflight():
    if any(ch in str(path) for path in (ROOT, DEST.parent) for ch in (":", ",", "\n", "\0")):
        raise ValueError("ambiguous libguestfs/QEMU input path")
    _preparation_build_controls()
    for path in (ROOT / "config").glob("*.toml"):
        if path.is_symlink():
            raise ValueError("unsafe versioned TOML input")
        tomllib.loads(path.read_text())
    value = golden_lock.check(ROOT)
    pins = {row["name"] for row in value["packages"]}
    imports = set()
    for name in ("guest_build.py", "golden_assets.py", "golden_lock.py"):
        path = HERE / name
        tree = ast.parse(path.read_bytes(), str(path))
        compile(tree, str(path), "exec")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                imports.add(node.module.split(".")[0])
    internal = {path.stem for path in HERE.glob("*.py")}
    external = imports - sys.stdlib_module_names - internal - {"__future__", "pip"}
    if not external <= pins or not {"packaging", "cloakbrowser"} <= pins:
        raise ValueError("guest helper imports absent from frozen graph: " + str(sorted(external - pins)))
    if not {"python3-venv", "python3-pip", "nodejs", "npm"} <= set(GUEST_PACKAGES):
        raise ValueError("guest bootstrap/Node/npm package contract is incomplete")
    if set(guest_build.MANIFESTS) != {"packages", "python_packages", "target_environment", "system_python", "npm", "node", "browser_runtime"}:
        raise ValueError("host/guest required manifest contract drift")
    unit = (ROOT / "infra/workstation/systemd/gpt-trace-workstation-agent.service").read_text()
    if "EnvironmentFile=/etc/gpt-trace-browser.env" not in unit or "CLOAKBROWSER_VERSION=" in unit:
        raise ValueError("browser version must be derived once from the installed wrapper")
    shell = firstboot_script()
    subprocess.run(["bash", "-n"], input=shell, text=True, check=True)
    if "<<" in shell:
        raise ValueError("nested generated Python/heredocs are forbidden in firstboot")
    if not 0 < ROOT_MIN_GIB < VIRTUAL_DISK_GIB:
        raise ValueError("invalid golden disk controls")
    return golden_build_input_sha256()


def require_execution_role():
    sys.path.insert(0, str(ROOT / "scripts"))
    import distributed
    if distributed.config(credentials=False)["deployment"]["role"] != "execution":
        raise RuntimeError("golden construction is restricted to the configured execution role")


def _safe_parent():
    if not DEST.parent.is_dir():
        raise ValueError("configured dedicated golden storage must already be mounted")
    for path in (DEST.parent, *DEST.parent.parents):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise ValueError("unsafe golden storage root")
    def field(name):
        return subprocess.check_output(["findmnt", "-n", "-o", name, "-T", str(DEST.parent)], text=True).strip()
    if (Path(field("TARGET")) != DEST.parent or not field("SOURCE").startswith("/dev/")
            or field("FSTYPE") not in {"ext4", "xfs"} or "rw" not in field("OPTIONS").split(",")):
        raise ValueError("golden storage is not the configured dedicated writable ext4/xfs mount")


def require_host_build_runtime():
    missing = [name for name in ("curl", "7z", "qemu-img", "qemu-system-x86_64", "virt-customize", "virt-cat", "virt-ls")
               if shutil.which(name) is None]
    if missing:
        raise ValueError("missing golden build tools: " + ", ".join(missing))
    if not Path("/dev/kvm").exists() or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise ValueError("execution host KVM is unavailable")


def repo_commit():
    value = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("repository commit identity is invalid")
    for path in (*input_files(), HERE / "build.py", HERE / "host_cache.py", HERE / "python-metadata.json",
                 HERE / "host-controller-input.json", ROOT / "config/preparation.toml"):
        recorded = subprocess.check_output(["git", "show", value + ":" + path.relative_to(ROOT).as_posix()], cwd=ROOT)
        if recorded != path.read_bytes():
            raise ValueError("commit guest inputs before golden construction: " + str(path))
    return value


def cached_archive():
    # Explicit schema-1 cache permission migration, after path validation.
    if CACHE_DIR.exists() or CACHE_DIR.is_symlink():
        safe(CACHE_DIR, directory=True)
        CACHE_DIR.chmod(0o700)
    else:
        mkdir(CACHE_DIR)
    return download(SOURCE + ARCHIVE, CACHE_ARCHIVE, ARCHIVE_SHA256,
                    pass_fds=() if BUILD_LOCK is None else (BUILD_LOCK,))


def image_info(image):
    safe(image)
    info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", str(image)]))
    data = info.get("format-specific", {}).get("data", {})
    if (info.get("format") != "qcow2" or info.get("backing-filename")
            or info.get("virtual-size") != VIRTUAL_DISK_GIB * 1024**3
            or data.get("corrupt") is True or data.get("dirty-flag") is True):
        raise ValueError("stage is not a clean, independent QCOW2 of the configured size")
    run("qemu-img", "check", image)
    return info


def artifact_paths(base=None):
    base = DEST if base is None else Path(base)
    return (base, base.with_suffix(".provenance.json"), base.parent / "kali-packages.txt", base.parent / "kali-python-packages.txt")


def row(path):
    return {"size": safe(path).stat().st_size, "sha256": digest(path)}


def _stage_name(name, fingerprint=None):
    if not isinstance(name, str) or re.fullmatch(r"\.golden-build-(?:[0-9a-f]{32}|[0-9a-f]{64})", name) is None:
        raise ValueError("invalid golden stage name")
    if len(name.rsplit("-", 1)[-1]) == 64 and fingerprint is not None and name != ".golden-build-" + fingerprint:
        raise ValueError("stage name and fingerprint disagree")
    return name


def validate_state(value):
    if (not isinstance(value, dict) or set(value) != STATE_KEYS or type(value["schema"]) is not int or value["schema"] != 2
            or value["status"] not in {"running", "failed", "prepared", "installed"}
            or value["phase"] not in PHASES or golden_lock.SHA.fullmatch(str(value["fingerprint"])) is None
            or re.fullmatch(r"[0-9a-f]{40}", str(value["repo_commit"])) is None
            or not isinstance(value["files"], dict)
            or (value["error"] is not None and not isinstance(value["error"], str))):
        raise ValueError("invalid golden journal schema/state")
    _stage_name(value["stage"], value["fingerprint"])
    if (value["phase"] in {"prepared", "installed"} and value["status"] not in {value["phase"], "failed"}
            or value["status"] in {"prepared", "installed"} and value["phase"] != value["status"]):
        raise ValueError("contradictory golden journal status/phase")
    for name, item in value["files"].items():
        if (not isinstance(name, str) or Path(name).name != name or name in {".", ".."} or "\\" in name
                or not isinstance(item, dict) or set(item) != {"size", "sha256"}
                or type(item["size"]) is not int or item["size"] < 0
                or golden_lock.SHA.fullmatch(str(item["sha256"])) is None):
            raise ValueError("invalid golden checkpoint inventory")
    populations = {
        "new": set(), "source_acquired": set(), "base_converted": {DEST.name},
        "offline_started": set(), "offline_complete": {DEST.name}, "guest_started": set(),
        "guest_complete": {DEST.name},
        "manifests_collected": {DEST.name, "kali-packages.txt", "kali-python-packages.txt", "guest-manifests.json"},
        "provenance_generated": {DEST.name, DEST.with_suffix(".provenance.json").name,
                                 "kali-packages.txt", "kali-python-packages.txt", "guest-manifests.json"},
        "prepared": {p.name for p in artifact_paths()}, "installed": {p.name for p in artifact_paths()},
    }
    if set(value["files"]) != populations[value["phase"]]:
        raise ValueError("checkpoint inventory does not prove its declared phase")
    return value


def _save(state):
    validate_state(state)
    stage = safe(DEST.parent / state["stage"], directory=True)
    atomic_json(stage / "build-state.json", state)
    atomic_json(DEST.parent / "golden-install.json", state)
    return state


def checkpoint(state, phase, files=None):
    if PHASES.index(phase) < PHASES.index(state["phase"]):
        raise ValueError("golden checkpoint regression is forbidden")
    status = phase if phase in {"prepared", "installed"} else "running"
    return _save({**state, "phase": phase, "status": status,
                  "files": state["files"] if files is None else files, "error": None})


def _validate_checkpoint(state):
    validate_state(state)
    stage = safe(DEST.parent / state["stage"], directory=True)
    for name, expected in state["files"].items():
        if row(stage / name) != expected:
            raise ValueError("checkpoint artifact is missing/corrupt: " + name)
    phase = state["phase"]
    if PHASES.index(phase) >= PHASES.index("base_converted"):
        image_info(stage / DEST.name)
    if phase in {"guest_started", "offline_complete", "guest_complete", "manifests_collected", "provenance_generated", "prepared", "installed"}:
        identity = json.loads(guest_read(stage / DEST.name, str(guest_build.INPUT)))
        if identity != _guest_identity(state):
            raise ValueError("stage guest input identity differs from checkpoint")
    return stage


def guest_read(image, path):
    result = capture("virt-cat", "-a", image, path)
    if result.returncode:
        raise ValueError("required guest artifact unavailable: " + path + "; " + result.stderr.strip())
    return result.stdout.encode()


def guest_listing(image):
    result = capture("virt-ls", "-a", image, "/etc")
    if result.returncode:
        raise ValueError("guest /etc inventory failed: " + result.stderr.strip())
    return set(result.stdout.splitlines())


def _guest_identity(state):
    return {"schema": 2, "build_input_sha256": state["fingerprint"], "repo_commit": state["repo_commit"]}


def guest_complete(image, state):
    names = guest_listing(image)
    if guest_build.FAILED.name in names:
        detail = guest_read(image, str(guest_build.FAILED)).decode().strip()
        if guest_build.COMPLETE.name in names:
            raise ValueError("contradictory guest success/failure markers: " + detail)
        return False
    if guest_build.COMPLETE.name not in names:
        return False
    if guest_read(image, str(guest_build.COMPLETE)).strip() != b"ok":
        raise ValueError("guest completion marker is invalid")
    proof = json.loads(guest_read(image, str(guest_build.PROOF)))
    if (not isinstance(proof, dict) or set(proof) != {*_guest_identity(state), "manifests"}
            or any(proof.get(k) != v for k, v in _guest_identity(state).items())
            or not isinstance(proof.get("manifests"), dict)
            or set(proof["manifests"]) != set(guest_build.MANIFESTS)):
        raise ValueError("guest completion lacks matching current-schema input/manifest proof")
    for key, path in guest_build.MANIFESTS.items():
        raw = guest_read(image, path)
        if not raw or proof["manifests"][key] != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
            raise ValueError("required guest manifest differs from completion proof: " + path)
    return True


def prepare_offline(image, temp, state=None):
    if state is None:
        raise ValueError("offline injection requires a persisted input identity")
    payloads = {path: path.read_bytes() for path in input_files()}
    if golden_build_input_sha256(payloads) != state["fingerprint"]:
        raise ValueError("guest inputs changed since the persisted build identity; refusing injection")
    with tempfile.TemporaryDirectory(prefix=".injection-", dir=temp) as raw:
        work = Path(raw)
        bundle = work / "bundle"
        bundle.mkdir(mode=0o700)
        source_root = ROOT / "apps/kali-workstation/src"
        unit_dir = ROOT / "infra/workstation/systemd"
        for path, content in payloads.items():
            target = None
            if path.is_relative_to(source_root):
                target = bundle / "src" / path.relative_to(source_root)
            elif path == ROOT / "apps/kali-workstation/pyproject.toml":
                target = bundle / "pyproject.toml"
            elif path.parent == HERE and path.suffix in {".py", ".lock", ".json"}:
                target = bundle / path.name
            elif path.parent == unit_dir:
                target = work / path.name
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        atomic_json(bundle / "guest-contract.json", guest_contract())
        script = work / "gpt-trace-firstboot"
        script.write_text(firstboot_script(payloads[HERE / "firstboot.sh.in"].decode()))
        script.chmod(0o700)
        identity = work / guest_build.INPUT.name
        atomic_json(identity, _guest_identity(state))
        # Inject only these private, fingerprint-verified snapshots. Subsequent
        # edits to a development checkout cannot change the bytes being built.
        unit_dir = work
        run("virt-customize", "--no-network", "-a", image,
            "--mkdir", "/opt/gpt-trace", "--copy-in", str(bundle) + ":/opt/gpt-trace",
            "--copy-in", str(script) + ":/usr/local/sbin", "--copy-in", str(identity) + ":/etc",
            "--copy-in", str(unit_dir / "gpt-trace-workstation-agent.service") + ":/etc/systemd/system",
            "--copy-in", str(unit_dir / "gpt-trace-golden-build.service") + ":/etc/systemd/system",
            "--run-command", "systemctl enable gpt-trace-golden-build.service")
        for path in sorted(bundle.rglob("*")):
            if path.is_file() and guest_read(image, "/opt/gpt-trace/bundle/" + path.relative_to(bundle).as_posix()) != path.read_bytes():
                raise ValueError("offline bundle injection byte verification failed")
        for path, name in ((script, "/usr/local/sbin/gpt-trace-firstboot"), (identity, str(guest_build.INPUT)),
                (unit_dir / "gpt-trace-workstation-agent.service", "/etc/systemd/system/gpt-trace-workstation-agent.service"),
                (unit_dir / "gpt-trace-golden-build.service", "/etc/systemd/system/gpt-trace-golden-build.service")):
            if guest_read(image, name) != path.read_bytes():
                raise ValueError("offline firstboot/unit/input injection verification failed")


def provision_in_real_guest(image):
    safe(CACHE_DIR, directory=True)
    if any(ch in str(path) for path in (image, CACHE_DIR) for ch in (",", "\n", "\0")):
        raise ValueError("ambiguous QEMU storage path")
    run("qemu-system-x86_64", "-machine", "accel=kvm", "-cpu", "host",
        "-m", str(_BUILD_CONTROLS["golden_memory_mb"]), "-smp", str(_BUILD_CONTROLS["golden_vcpus"]),
        "-drive", f"file={image},format=qcow2,if=virtio,cache=writeback,discard=unmap",
        "-netdev", "user,id=net0,ipv6=off", "-device", "virtio-net-pci,netdev=net0",
        "-device", "virtio-rng-pci", "-fsdev", f"local,id=goldencache,path={CACHE_DIR},security_model=none",
        "-device", f"virtio-9p-pci,fsdev=goldencache,mount_tag={CACHE_TAG}",
        "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot", timeout=PROVISION_TIMEOUT_SECONDS)


def _convert(archive, stage, state):
    image = stage / DEST.name
    receipt = stage / "conversion.json"
    if receipt.exists() or receipt.is_symlink():
        data = read_json(receipt, private=True)
        part = stage / ".conversion.qcow2.part"
        source = image if image.exists() else part
        if data != {"fingerprint": state["fingerprint"], "image": row(source)}:
            raise ValueError("completed conversion receipt differs; preserved")
        if source != image:
            source.rename(image)
            sync(stage)
        image_info(image)
        return
    if image.exists() or image.is_symlink():
        raise ValueError("unproved converted QCOW2 destination; preserved")
    extracted = stage / "extracted"
    if extracted.exists() or extracted.is_symlink():
        safe(extracted, directory=True)
        for path in extracted.rglob("*"):
            safe(path, directory=path.is_dir())
    else:
        extracted.mkdir(mode=0o700)
    run("7z", "x", archive, "-o" + str(extracted), "-y")
    images = list(extracted.rglob("*.qcow2"))
    if len(images) != 1:
        raise ValueError("official archive must contain exactly one QCOW2")
    safe(images[0])
    part = stage / ".conversion.qcow2.part"
    if part.exists() or part.is_symlink():
        safe(part)
        if part.stat().st_nlink != 1:
            raise ValueError("conversion partial has unexpected hardlinks")
    # Only this explicitly disposable partial can be overwritten after a crash
    # without a conversion receipt. No checkpointed/permanent image is removed.
    run("qemu-img", "convert", "-O", "qcow2", images[0], part)
    run("qemu-img", "resize", "-f", "qcow2", part, str(VIRTUAL_DISK_GIB) + "G")
    image_info(part)
    with part.open("rb") as stream:
        os.fsync(stream.fileno())
    atomic_json(receipt, {"fingerprint": state["fingerprint"], "image": row(part)})
    part.rename(image)
    sync(stage)


def collect_manifests(image, stage, state):
    if not guest_complete(image, state):
        raise ValueError("post-provision collection requires proven guest completion")
    raw = {key: guest_read(image, name) for key, name in guest_build.MANIFESTS.items()}
    atomic_bytes(stage / "kali-packages.txt", raw.pop("packages"), 0o444)
    atomic_bytes(stage / "kali-python-packages.txt", raw.pop("python_packages"), 0o444)
    data = {key: (value.decode().strip() if key == "npm" else json.loads(value)) for key, value in raw.items()}
    atomic_json(stage / "guest-manifests.json", data)
    return data


def validate_provenance_fields(metadata):
    required = {"schema", "source", "source_sha256", "base_sha256", "build_input_sha256", "repo_commit",
                "guest_agent_version", "browser_runtime", "apt_suite", "apt_package_manifest_sha256",
                "python_package_manifest_sha256", "target_environment", "platform_tags", "architecture",
                "system_python", "node", "npm", "python_lock_sha256", "build_utc", "provisioning_network"}
    if not isinstance(metadata, dict) or not required <= set(metadata) or metadata["schema"] != 2:
        raise ValueError("golden provenance schema 2 required; legacy permanent bytes preserved, no implicit migration")
    for key in required:
        if key.endswith("sha256") and golden_lock.SHA.fullmatch(str(metadata[key])) is None:
            raise ValueError("invalid golden provenance hash: " + key)
    if re.fullmatch(r"[0-9a-f]{40}", str(metadata["repo_commit"])) is None:
        raise ValueError("invalid golden repository commit")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(metadata["guest_agent_version"])):
        raise ValueError("invalid guest agent provenance version")
    if datetime.fromisoformat(metadata["build_utc"]).utcoffset() is None:
        raise ValueError("golden timestamp must be timezone-aware")
    target = metadata["target_environment"]
    if (not isinstance(target, dict) or target.get("schema") != 2 or target.get("source") != "verified-target-interpreter"
            or not isinstance(target.get("markers"), dict) or not isinstance(target.get("tags"), list)
            or not target["tags"] or len(target["tags"]) != len(set(target["tags"]))
            or metadata["architecture"] != target.get("architecture") or metadata["platform_tags"] != target["tags"]
            or golden_lock.SHA.fullmatch(str(target.get("interpreter_sha256"))) is None):
        raise ValueError("invalid measured target environment provenance")
    marker_keys = {"implementation_name", "implementation_version", "os_name", "platform_machine",
                   "platform_release", "platform_system", "platform_version", "python_full_version",
                   "python_version", "platform_python_implementation", "sys_platform"}
    markers = target["markers"]
    if (set(markers) != marker_keys or not all(isinstance(v, str) and v for v in markers.values())
            or not re.fullmatch(r"\d+\.\d+\.\d+", markers["python_full_version"])
            or markers["python_version"] != ".".join(markers["python_full_version"].split(".")[:2])
            or any(not isinstance(tag, str) or re.fullmatch(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", tag) is None for tag in target["tags"])
            or target.get("abi") != target["tags"][0].split("-")[1]
            or markers["platform_machine"] != metadata["architecture"]):
        raise ValueError("target markers/ABI/platform tags disagree")
    system = metadata["system_python"]
    if (not isinstance(system, dict) or not re.fullmatch(r"\d+\.\d+\.\d+", str(system.get("full_version")))
            or system["full_version"] != target["markers"].get("python_full_version")
            or system.get("interpreter_sha256") != target["interpreter_sha256"]
            or not isinstance(system.get("executable"), str) or not system["executable"].startswith("/")):
        raise ValueError("invalid actual system Python provenance")
    for key in ("node", "npm"):
        item = metadata[key]
        if not isinstance(item, dict) or not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", str(item.get("version"))):
            raise ValueError("required Node/npm provenance missing: " + key)
    node = metadata["node"]
    if golden_lock.SHA.fullmatch(str(node.get("sha256"))) is None or not str(node.get("executable", "")).startswith("/"):
        raise ValueError("Node executable provenance incomplete")
    browser = metadata["browser_runtime"]
    artifact = browser.get("artifact") if isinstance(browser, dict) else None
    if (not isinstance(artifact, dict) or artifact.get("verification") != "upstream-ed25519-and-sha256"
            or not re.fullmatch(r"\d+(?:\.\d+){3,4}", str(artifact.get("version")))
            or not isinstance(browser.get("files"), dict) or not browser.get("executable_version")
            or golden_lock.SHA.fullmatch(str(browser.get("binary_sha256"))) is None
            or browser["files"].get("chrome", {}).get("sha256") != browser["binary_sha256"]
            or any(golden_lock.SHA.fullmatch(str(artifact.get(k))) is None for k in ("archive_sha256", "manifest_sha256", "signature_sha256"))):
        raise ValueError("browser provenance lacks authenticated artifact/actual binary identity")
    if metadata["provisioning_network"] != "qemu-user-firstboot-with-private-9p-cache":
        raise ValueError("unsupported golden provisioning method")
    locked_browser = next(row["version"] for row in golden_lock.load(HERE / "python-lock.json")["packages"] if row["name"] == "cloakbrowser")
    if artifact.get("wrapper") != locked_browser or metadata["apt_suite"] != APT_SUITE:
        raise ValueError("browser wrapper/APT suite provenance differs from guest inputs")


def provenance(image, stage, state):
    data = read_json(stage / "guest-manifests.json", private=True)
    target = data["target_environment"]
    version = tomllib.loads((ROOT / "apps/kali-workstation/pyproject.toml").read_text())["project"]["version"]
    metadata = {"schema": 2, "source": SOURCE + ARCHIVE, "source_sha256": ARCHIVE_SHA256,
        "base_sha256": state["files"][DEST.name]["sha256"], "build_input_sha256": state["fingerprint"],
        "repo_commit": state["repo_commit"], "guest_agent_version": version,
        "browser_runtime": data["browser_runtime"], "apt_suite": APT_SUITE,
        "apt_package_manifest_sha256": digest(stage / "kali-packages.txt"),
        "python_package_manifest_sha256": digest(stage / "kali-python-packages.txt"),
        "target_environment": target, "platform_tags": target["tags"], "architecture": target["architecture"],
        "system_python": data["system_python"], "node": data["node"], "npm": {"version": data["npm"]},
        "python_lock_sha256": digest(HERE / "requirements.lock"), "build_utc": datetime.now(timezone.utc).isoformat(),
        "provisioning_network": "qemu-user-firstboot-with-private-9p-cache"}
    validate_provenance_fields(metadata)
    atomic_json(image.with_suffix(".provenance.json"), metadata, 0o444)


def verify(base=None):
    base = DEST if base is None else Path(base)
    for path in artifact_paths(base):
        safe(path)
        if path.stat().st_mode & 0o222:
            raise ValueError("golden permanent/prepared bytes must be immutable")
    metadata = read_json(base.with_suffix(".provenance.json"))
    validate_provenance_fields(metadata)
    if (metadata["source"] != SOURCE + ARCHIVE or metadata["source_sha256"] != ARCHIVE_SHA256
            or metadata["architecture"] != SOURCE_ARCHITECTURE
            or metadata["build_input_sha256"] != golden_build_input_sha256()
            or metadata["python_lock_sha256"] != digest(HERE / "requirements.lock")):
        raise ValueError("golden source/lock/input fingerprint incompatible; permanent bytes preserved")
    for path, key in ((base, "base_sha256"), (base.parent / "kali-packages.txt", "apt_package_manifest_sha256"),
                      (base.parent / "kali-python-packages.txt", "python_package_manifest_sha256")):
        if digest(path) != metadata[key]:
            raise ValueError("golden artifact/provenance hash mismatch: " + str(path))
    image_info(base)
    print("Verified immutable golden: " + str(base), flush=True)


def _commit_prepared(state):
    validate_state(state)
    if state["phase"] != "prepared" or state["fingerprint"] != golden_build_input_sha256():
        raise ValueError("prepared golden identity incompatible; preserved")
    stage = _validate_checkpoint(state)
    image = stage / DEST.name
    if set(state["files"]) != {path.name for path in artifact_paths(image)}:
        raise ValueError("prepared golden inventory incomplete")
    verify(image)
    for path in artifact_paths():
        if path.exists() or path.is_symlink():
            safe(path)
            if path.stat().st_mode & 0o222 or row(path) != state["files"][path.name]:
                raise ValueError("golden activation destination conflicts; permanent bytes preserved")
    # Atomic no-clobber links, metadata first and base last. Stage links remain
    # authoritative until and after the installed journal has been fsynced.
    for target in (*artifact_paths()[1:], DEST):
        if not target.exists():
            os.link(stage / target.name, target, follow_symlinks=False)
            sync(target.parent)
    verify()
    return checkpoint(state, "installed")


def _legacy(value, fingerprint):
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("status") not in {"building", "failed", "prepared", "installed"}
            or not {"schema", "status", "stage"} <= set(value)
            or set(value) - {"schema", "status", "stage", "files", "error"}):
        raise ValueError("unrecognized legacy golden journal")
    stage = safe(DEST.parent / _stage_name(value["stage"]), directory=True)
    atomic_json(stage / "legacy-journal.json", value)
    image = stage / DEST.name
    assessment = {"schema": 2, "stage": stage.name, "fingerprint": fingerprint, "recoverable": False,
                  "action": "preserve-legacy-stage-and-build-current-inputs"}
    if image.exists() or image.is_symlink():
        image_info(image)
        names = guest_listing(image)
        assessment["guest_complete"] = guest_build.COMPLETE.name in names and guest_read(image, str(guest_build.COMPLETE)).strip() == b"ok"
        assessment["guest_failed"] = guest_build.FAILED.name in names
        if guest_build.INPUT.name in names and guest_build.PROOF.name in names:
            identity = json.loads(guest_read(image, str(guest_build.INPUT)))
            if identity.get("build_input_sha256") == fingerprint:
                state = {"schema": 2, "status": "running", "phase": "guest_complete", "stage": stage.name,
                         "fingerprint": fingerprint, "repo_commit": identity.get("repo_commit"),
                         "files": {image.name: row(image)}, "error": None}
                validate_state(state)
                if guest_complete(image, state):
                    state["files"] = {image.name: row(image)}
                    atomic_json(stage / "legacy-assessment.json", {**assessment, "recoverable": True,
                                "action": "resume-proven-current-guest-completion"})
                    return _save(state)
            assessment["reason"] = "legacy input proof incompatible with current guest fingerprint"
        else:
            assessment["reason"] = "legacy stage lacks current-schema input/manifest proof; complete=ok cannot authorize recovery"
    else:
        assessment["reason"] = "legacy stage has no image to authenticate"
    atomic_json(stage / "legacy-assessment.json", assessment)
    print(json.dumps(assessment, sort_keys=True), flush=True)
    return None


def _load_state(fingerprint):
    journal = DEST.parent / "golden-install.json"
    previous = None
    if journal.exists() or journal.is_symlink():
        previous = read_json(journal, private=True)
        if not isinstance(previous, dict):
            raise ValueError("golden journal must be an object")
        if previous.get("schema") == 1:
            adopted = _legacy(previous, fingerprint)
            if adopted is not None:
                return adopted
            previous = None
        else:
            validate_state(previous)
            safe(DEST.parent / previous["stage"], directory=True)
    if previous is not None and previous["fingerprint"] == fingerprint:
        path = DEST.parent / previous["stage"] / "build-state.json"
        saved = validate_state(read_json(path, private=True))
        if (saved["stage"], saved["fingerprint"], saved["repo_commit"]) != (
                previous["stage"], fingerprint, previous["repo_commit"]):
            raise ValueError("stage/global journal identity conflict")
        if PHASES.index(saved["phase"]) < PHASES.index(previous["phase"]):
            raise ValueError("stage checkpoint regressed behind global journal")
        return saved
    if previous is not None:
        atomic_json(DEST.parent / previous["stage"] / "superseded-journal.json", previous)
        print("Preserving incompatible stage: " + previous["stage"], flush=True)
    stage = DEST.parent / (".golden-build-" + fingerprint)
    if stage.exists() or stage.is_symlink():
        safe(stage, directory=True)
        path = stage / "build-state.json"
        if path.exists() or path.is_symlink():
            saved = validate_state(read_json(path, private=True))
            if saved["stage"] != stage.name or saved["fingerprint"] != fingerprint:
                raise ValueError("deterministic stage has incompatible input proof")
            return saved
        if any(stage.iterdir()):
            raise ValueError("nonempty deterministic stage has no authenticated checkpoint; preserved")
    else:
        stage.mkdir(mode=0o700)
        sync(stage.parent)
    state = {"schema": 2, "status": "running", "phase": "new", "stage": stage.name,
             "fingerprint": fingerprint, "repo_commit": repo_commit(), "files": {}, "error": None}
    return _save(state)


def build():
    global BUILD_LOG, BUILD_LOCK
    require_execution_role()
    if os.geteuid() != 0:
        raise RuntimeError("golden construction requires execution-host root")
    fingerprint = preflight()
    _safe_parent()
    fd = os.open(DEST.parent / "golden-build.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    state = None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("untrusted golden build lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        BUILD_LOCK = fd
        journal_path = DEST.parent / "golden-install.json"
        if journal_path.is_symlink():
            raise ValueError("symlink in golden installation journal")
        if DEST.exists() or DEST.is_symlink():
            verify()
            if journal_path.exists():
                installed = read_json(journal_path, private=True)
                validate_state(installed)
                if installed["phase"] == "prepared":
                    _commit_prepared(installed)
            return
        state = _load_state(fingerprint)
        stage = _validate_checkpoint(state)
        image = stage / DEST.name
        if state["phase"] == "installed":
            raise ValueError("installed golden absent; refusing silent reinstallation")
        if state["phase"] == "prepared":
            _commit_prepared(state)
            return
        if any(path.exists() or path.is_symlink() for path in artifact_paths()[1:]):
            raise ValueError("permanent metadata has no prepared activation proof; preserved")
        require_host_build_runtime()
        if not CACHE_DIR.exists():
            mkdir(CACHE_DIR)
        safe(CACHE_DIR, directory=True)
        CACHE_DIR.chmod(0o700)
        for path in CACHE_DIR.rglob("*"):
            safe(path, directory=path.is_dir())
        host_cache.verify(CACHE_DIR, golden_lock.load(HERE / "python-lock.json"),
                          system="Linux", architecture=SOURCE_ARCHITECTURE)
        logfd = os.open(stage / "host-build.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(logfd, "ab") as log:
            info = os.fstat(log.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("untrusted golden host log")
            BUILD_LOG = log
            if state["phase"] == "new":
                cached_archive()
                state = checkpoint(state, "source_acquired")
            if state["phase"] == "source_acquired":
                _convert(cached_archive(), stage, state)
                state = checkpoint(state, "base_converted", {image.name: row(image)})
            if state["phase"] == "base_converted":
                state = checkpoint(state, "offline_started", {})
            if state["phase"] == "offline_started":
                prepare_offline(image, stage, state)
                state = checkpoint(state, "offline_complete", {image.name: row(image)})
            if state["phase"] == "offline_complete":
                state = checkpoint(state, "guest_started", {})
            if state["phase"] == "guest_started":
                if not guest_complete(image, state):
                    provision_in_real_guest(image)
                if not guest_complete(image, state):
                    names = guest_listing(image)
                    detail = guest_read(image, str(guest_build.FAILED)).decode() if guest_build.FAILED.name in names else "guest exited without completion proof"
                    raise ValueError("guest provisioning failed: " + detail)
                image_info(image)
                state = checkpoint(state, "guest_complete", {image.name: row(image)})
            if state["phase"] == "guest_complete":
                collect_manifests(image, stage, state)
                files = {**state["files"], **{name: row(stage / name) for name in (
                    "kali-packages.txt", "kali-python-packages.txt", "guest-manifests.json")}}
                state = checkpoint(state, "manifests_collected", files)
            if state["phase"] == "manifests_collected":
                provenance(image, stage, state)
                state = checkpoint(state, "provenance_generated", {
                    **state["files"], image.with_suffix(".provenance.json").name: row(image.with_suffix(".provenance.json"))})
            if state["phase"] == "provenance_generated":
                for path in artifact_paths(image):
                    safe(path).chmod(0o444)
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                verify(image)
                state = checkpoint(state, "prepared", {path.name: state["files"][path.name] for path in artifact_paths(image)})
            _commit_prepared(state)
    except BaseException as exc:
        if state is not None:
            path = DEST.parent / state["stage"] / "build-state.json"
            current = validate_state(read_json(path, private=True))
            phase = current["phase"]
            reusable = True
            validation_error = None
            try:
                _validate_checkpoint(current)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as validation:
                reusable = False
                validation_error = type(validation).__name__ + ": " + str(validation)
            detail = ("phase=" + phase + "; stage=" + current["stage"] + "; fingerprint=" + fingerprint +
                      "; invariant=" + type(exc).__name__ + ": " + str(exc) +
                      "; checkpoint_reusable=" + str(reusable).lower() +
                      "; recoverable=" + str(reusable).lower() + "; journal=" + str(DEST.parent / "golden-install.json") +
                      "; log=" + str(path.parent / "host-build.log") + "; action=preserve-stage-and-checkpoint")
            if validation_error is not None:
                detail += "; checkpoint_invariant=" + validation_error
            atomic_bytes(path.parent / "FAILED.txt", (detail + "\n").encode())
            if phase not in {"prepared", "installed"}:
                _save({**current, "status": "failed", "error": detail})
            raise RuntimeError(detail) from exc
        raise RuntimeError("phase=journal-or-permanent-validation; stage=not-selected; fingerprint=" + fingerprint +
            "; invariant=" + type(exc).__name__ + ": " + str(exc) +
            "; recoverable=false; journal=" + str(DEST.parent / "golden-install.json") +
            "; action=refuse-mutation-and-preserve-existing-bytes") from exc
    finally:
        BUILD_LOG = None
        BUILD_LOCK = None
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--validate", action="store_true", help="host/static validation only; never boots a VM")
    args = parser.parse_args()
    if args.validate:
        preflight()
    elif args.verify:
        verify()
    else:
        build()
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "shared"))
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a verified immutable Kali qcow2, customized with the guest agent."""
from __future__ import annotations

import argparse
import fcntl
import re
import uuid
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = "https://cdimage.kali.org/kali-2026.2/"
ARCHIVE = "kali-linux-2026.2-qemu-amd64.7z"
ARCHIVE_SHA256 = "c7c35588d05277c482c908bf7a136d348f76ffa68700b04ff53c0b217e6bd071"
DEST = Path("/var/lib/libvirt/images/gpt-trace/kali-base.qcow2")
CACHE_DIR = DEST.parent / "cache"
CACHE_ARCHIVE = CACHE_DIR / ARCHIVE
PROVISION_TIMEOUT_SECONDS = 7200
VIRTUAL_DISK_GIB = 512
BUILD_LOG = None

GUEST_PACKAGES = (
    "qemu-guest-agent",
    "lightdm",
    "xfce4",
    "python3",
    "python3-venv",
    "python3-pip",
    "git",
    "build-essential",
    "rustc",
    "cargo",
    "gdb",
    "curl",
    "wget",
    "ca-certificates",
    "iproute2",
    "iputils-ping",
    "tcpdump",
    "nmap",
    "util-linux",
    "cloud-guest-utils",  # growpart for the 512-GiB ext4 root volume
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _hash_component(
    hasher,
    label: str,
    payload: bytes,
) -> None:
    encoded = label.encode("utf-8")
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(payload).to_bytes(8, "big"))
    hasher.update(payload)


def guest_source_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if path == ROOT / "apps/kali-workstation/src/kali_workstation/server.py":
        guard = json.loads((ROOT / "infra/workstation/image/host-controller-input.json").read_text())
        source = raw.decode("utf-8")
        for old, new in reversed(guard["replacements"]):
            if source.count(new) != 1:
                raise RuntimeError("unknown controller revision in guest fingerprint; refuse golden reuse")
            source = source.replace(new, old, 1)
        raw = source.encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != guard["sha256"]:
            raise RuntimeError("host-only controller fingerprint reconstruction failed")
    return raw


def golden_build_input_sha256() -> str:
    """Fingerprint repo/upstream inputs that change guest runtime semantics."""
    hasher = hashlib.sha256()
    _hash_component(hasher, "source", (SOURCE + ARCHIVE).encode("utf-8"))
    _hash_component(hasher, "archive_sha256", ARCHIVE_SHA256.encode("ascii"))
    _hash_component(hasher, "virtual_disk_gib", str(VIRTUAL_DISK_GIB).encode("ascii"))
    _hash_component(hasher, "firstboot_script", firstboot_script().encode("utf-8"))
    _hash_component(
        hasher,
        "prepare_offline",
        inspect.getsource(prepare_offline).encode("utf-8"),
    )
    _hash_component(
        hasher,
        "provision_in_real_guest",
        inspect.getsource(provision_in_real_guest).encode("utf-8"),
    )

    files = (
        ROOT / "apps/kali-workstation/pyproject.toml",
        ROOT / "infra/workstation/image/requirements.lock",
        ROOT / "infra/workstation/systemd/gpt-trace-workstation-agent.service",
    )
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"invalid Kali golden input: {path}")
        _hash_component(
            hasher,
            path.relative_to(ROOT).as_posix(),
            path.read_bytes(),
        )

    source_root = ROOT / "apps/kali-workstation/src/kali_workstation"
    source_entries = sorted(source_root.rglob("*"))
    for path in source_entries:
        if path.is_symlink():
            raise RuntimeError(
                f"Kali workstation guest source contains symlink: {path}"
            )
    source_files = [path for path in source_entries if path.is_file()
                    and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}]
    if not source_files:
        raise RuntimeError("Kali workstation guest source tree is empty")
    for path in source_files:
        _hash_component(
            hasher,
            path.relative_to(ROOT).as_posix(),
            guest_source_bytes(path),
        )
    return hasher.hexdigest()








def run(*cmd: str, timeout: int = 7200, **kwargs) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd), flush=True)
    if BUILD_LOG is not None:
        kwargs.setdefault("stdout", BUILD_LOG)
        kwargs.setdefault("stderr", subprocess.STDOUT)
    return subprocess.run(cmd, check=True, timeout=timeout, **kwargs)


def capture(*cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, text=True, capture_output=True)


def require_host_build_runtime() -> None:
    executables = (
        "curl",
        "7z",
        "qemu-img",
        "qemu-system-x86_64",
        "virt-customize",
        "virt-cat",
    )
    missing = [name for name in executables if shutil.which(name) is None]
    if missing:
        raise RuntimeError(
            "missing Kali image build executable(s): " + ", ".join(missing)
        )

    kvm = Path("/dev/kvm")
    if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
        raise RuntimeError(
            "/dev/kvm is unavailable; enable nested VT-x/AMD-V in VMware "
            "before building the golden Kali image"
        )


def cached_archive() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if CACHE_ARCHIVE.exists():
        if digest(CACHE_ARCHIVE) == ARCHIVE_SHA256:
            print(f"Using cached Kali archive: {CACHE_ARCHIVE}", flush=True)
            return CACHE_ARCHIVE
        raise RuntimeError(f"cached official Kali archive has an invalid SHA-256; preserved: {CACHE_ARCHIVE}")

    partial = CACHE_ARCHIVE.with_name(CACHE_ARCHIVE.name + ".part")
    if partial.exists():
        print(f"Resuming cached Kali download: {partial}", flush=True)

    # Keep .part on transport failure so the next make build can resume it.
    run(
        "curl",
        "--fail",
        "--location",
        "--retry",
        "5",
        "--retry-all-errors",
        "--continue-at",
        "-",
        "--output",
        str(partial),
        SOURCE + ARCHIVE,
    )
    if digest(partial) != ARCHIVE_SHA256:
        partial.unlink(missing_ok=True)
        raise RuntimeError("Kali archive digest mismatch")
    os.replace(partial, CACHE_ARCHIVE)
    return CACHE_ARCHIVE


def firstboot_script() -> str:
    packages = " ".join(GUEST_PACKAGES)
    return f"""#!/bin/bash
set -Eeuo pipefail

LOG=/var/log/gpt-trace-image-build.log
COMPLETE=/etc/gpt-trace-image-build-complete
FAILED=/etc/gpt-trace-image-build-failed
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

shutdown_on_exit() {{
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '%s\\n' "$rc" > "$FAILED"
        echo "golden-image provisioning failed with exit code $rc"
    fi
    sync
    systemctl poweroff --no-block || poweroff -f || true
}}
trap shutdown_on_exit EXIT

rm -f "$COMPLETE" "$FAILED"

# Run networked provisioning in the real Kali guest.  libguestfs is used only
# for offline file injection because its helper appliance can have independent
# DNS failures even when the Ubuntu host has working connectivity.
for _ in $(seq 1 120); do
    if ip route show default | grep -q . \
       && getent ahostsv4 http.kali.org >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
ip route show default | grep -q .
getent ahostsv4 http.kali.org >/dev/null

printf 'deb https://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware\\n' > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/kali.sources

apt-get -o Acquire::Retries=5 update
DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 -y install {packages}

# Grow the actual Kali partition and ext4 filesystem, not just the QCOW2
# container.  This runs only while constructing the new immutable golden.
root_device="$(findmnt -n -o SOURCE /)"
test "$(findmnt -n -o FSTYPE /)" = ext4
parent_device="$(lsblk -n -o PKNAME "$root_device")"
partition_number="$(lsblk -n -o PARTN "$root_device")"
test -n "$parent_device" && test -n "$partition_number"
growpart "/dev/$parent_device" "$partition_number"
resize2fs "$root_device"
test "$(df -B1 --output=size / | tail -n 1)" -ge $((480 * 1024 * 1024 * 1024))

python3 -m venv /opt/gpt-trace/venv
/opt/gpt-trace/venv/bin/pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    -r /opt/gpt-trace/bundle/requirements.lock

CLOAKBROWSER_VERSION=146.0.7680.177.5 \
    /opt/gpt-trace/venv/bin/python -m cloakbrowser install

mkdir -p /opt/cloakbrowser
browser_binary="$(
    CLOAKBROWSER_VERSION=146.0.7680.177.5 \
    /opt/gpt-trace/venv/bin/python -c \
    'from cloakbrowser.download import ensure_binary; print(ensure_binary())'
)"
cp -a "$(dirname "$browser_binary")" /opt/cloakbrowser/chromium
chmod -R a+rX /opt/cloakbrowser
test -x /opt/cloakbrowser/chromium/chrome
! ldd /opt/cloakbrowser/chromium/chrome | grep -q 'not found'

mkdir -p /etc/lightdm/lightdm.conf.d
printf '[Seat:*]\\nautologin-user=kali\\nautologin-user-timeout=0\\n' \
    > /etc/lightdm/lightdm.conf.d/50-gpt-trace.conf

mkdir -p /home/kali/workspace /home/kali/Downloads
chown -R kali:kali /home/kali/workspace /home/kali/Downloads

systemctl enable lightdm qemu-guest-agent gpt-trace-workstation-agent

dpkg-query -W -f='${{Package}} ${{Version}}\\n' > /etc/gpt-trace-packages.txt
/opt/gpt-trace/venv/bin/pip freeze --all > /etc/gpt-trace-python-packages.txt

printf 'ok\\n' > "$COMPLETE"
rm -f "$FAILED"
sync

trap - EXIT
systemctl poweroff --no-block
"""


def prepare_offline(image: Path, temp: Path) -> None:
    bundle = temp / "bundle"
    bundle.mkdir()
    (bundle / "src").mkdir()
    shutil.copytree(
        ROOT / "apps/kali-workstation/src/kali_workstation",
        bundle / "src/kali_workstation",
    )
    shutil.copy(ROOT / "apps/kali-workstation/pyproject.toml", bundle / "pyproject.toml")
    shutil.copy(
        ROOT / "infra/workstation/image/requirements.lock",
        bundle / "requirements.lock",
    )

    firstboot = temp / "gpt-trace-firstboot.sh"
    firstboot.write_text(firstboot_script(), encoding="utf-8")
    firstboot.chmod(0o700)

    unit = ROOT / "infra/workstation/systemd/gpt-trace-workstation-agent.service"

    run(
        "virt-customize",
        "--no-network",
        "-a",
        str(image),
        "--mkdir",
        "/opt/gpt-trace",
        "--copy-in",
        str(bundle) + ":/opt/gpt-trace",
        "--copy-in",
        str(unit) + ":/etc/systemd/system",
        "--firstboot",
        str(firstboot),
    )


def provision_in_real_guest(image: Path) -> None:
    # QEMU user networking gives the real guest its own DHCP/DNS path.  This is
    # deliberately independent of the libguestfs appliance resolver.
    run(
        "qemu-system-x86_64",
        "-machine",
        "accel=kvm",
        "-cpu",
        "host",
        "-m",
        "12288",
        "-smp",
        "4",
        "-drive",
        f"file={image},format=qcow2,if=virtio,cache=writeback,discard=unmap",
        "-netdev",
        "user,id=net0,ipv6=off",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-device",
        "virtio-rng-pci",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-no-reboot",
        timeout=PROVISION_TIMEOUT_SECONDS,
    )

    complete = capture(
        "virt-cat", "-a", str(image), "/etc/gpt-trace-image-build-complete"
    )
    if complete.returncode == 0 and complete.stdout.strip() == "ok":
        return

    failed = capture(
        "virt-cat", "-a", str(image), "/etc/gpt-trace-image-build-failed"
    )
    log = capture(
        "virt-cat", "-a", str(image), "/var/log/gpt-trace-image-build.log"
    )
    exit_detail = failed.stdout.strip() if failed.returncode == 0 else "unknown"
    if log.returncode == 0:
        tail = "\n".join(log.stdout.splitlines()[-100:])
    else:
        tail = "(guest provisioning log unavailable)"
    raise RuntimeError(
        "Kali firstboot provisioning did not complete successfully "
        f"(guest exit={exit_detail}). Last guest log lines:\n{tail}"
    )


def _atomic_json(path, value):
    from gpt_trace_transport.local_templates import atomic_json
    atomic_json(path, value, 0o600)


def _safe_parent():
    DEST.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    for parent in (DEST.parent, *DEST.parent.parents):
        if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022:
            raise RuntimeError("unsafe local golden storage root")


def _commit_prepared(journal):
    from gpt_trace_transport.local_templates import safe, sync_directory
    if (set(journal) != {"schema", "status", "stage", "files"} or journal["schema"] != 1
            or journal["status"] != "prepared" or re.fullmatch(r"\.golden-build-[0-9a-f]{32}", journal["stage"]) is None):
        raise RuntimeError("unrecognized golden installation journal")
    stage = safe(DEST.parent / journal["stage"], directory=True)
    staged_base = stage / DEST.name
    staged_paths = artifact_paths(staged_base)
    if set(journal["files"]) != {p.name for p in staged_paths}:
        raise RuntimeError("incomplete golden installation inventory")
    for path in staged_paths:
        safe(path, immutable=True)
        row = journal["files"][path.name]
        if row != {"size": path.stat().st_size, "sha256": digest(path)}:
            raise RuntimeError("prepared golden artifact changed")
    verify(staged_base)
    run("qemu-img", "check", str(staged_base))
    # Validate every final destination before the first change. A crash can be
    # resumed from this exact journal; an unrelated existing byte is preserved.
    for target in artifact_paths():
        if target.exists() or target.is_symlink():
            safe(target, immutable=True)
            if digest(target) != journal["files"][target.name]["sha256"]:
                raise RuntimeError("golden destination conflicts with prepared bytes; preserved")
    # Independent metadata first, base last is the activation barrier. Keeping
    # immutable stage hardlinks makes interrupted activation recoverable.
    for target in (*artifact_paths()[1:], DEST):
        if target.exists(): continue
        source_path = stage / target.name
        temporary = target.with_name("." + target.name + "." + uuid.uuid4().hex)
        try:
            os.link(source_path, temporary, follow_symlinks=False)
            os.replace(temporary, target)
            sync_directory(target.parent)
        finally:
            temporary.unlink(missing_ok=True)
    verify()
    _atomic_json(DEST.parent / "golden-install.json", {**journal, "status": "installed"})


def build() -> None:
    """Build locally only when absent; existing permanent bytes are never replaced."""
    global BUILD_LOG
    if os.geteuid() != 0: raise RuntimeError("local golden construction requires execution-host root")
    _safe_parent()
    descriptor = os.open(DEST.parent / "golden-build.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_uid != 0 or os.fstat(descriptor).st_mode & 0o077:
            raise RuntimeError("untrusted golden build lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if DEST.exists() or DEST.is_symlink():
            verify()  # Invalid permanent bytes cause an error, never destruction.
            return
        journal_path = DEST.parent / "golden-install.json"
        if journal_path.exists():
            from gpt_trace_transport.local_templates import safe
            safe(journal_path)
            journal = json.loads(journal_path.read_bytes())
            if journal.get("status") == "prepared":
                _commit_prepared(journal)
                return
            if journal.get("status") not in {"failed", "building"}:
                raise RuntimeError("golden is absent with an unexpected installation journal")
        if any(p.exists() or p.is_symlink() for p in artifact_paths()[1:]):
            raise RuntimeError("partial golden without a prepared journal; permanent bytes preserved")
        require_host_build_runtime()
        archive = cached_archive()
        stage = DEST.parent / (".golden-build-" + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        _atomic_json(journal_path, {"schema": 1, "status": "building", "stage": stage.name})
        try:
            with (stage / "host-build.log").open("ab") as log:
                BUILD_LOG = log
                run("7z", "x", str(archive), "-o" + str(stage / "extracted"), "-y")
                images = list((stage / "extracted").rglob("*.qcow2"))
                if len(images) != 1:
                    raise RuntimeError(f"expected one official QEMU image; found {len(images)}")
                image = stage / DEST.name
                run("qemu-img", "convert", "-O", "qcow2", str(images[0]), str(image))
                run("qemu-img", "resize", "-f", "qcow2", str(image), f"{VIRTUAL_DISK_GIB}G")
                prepare_offline(image, stage)
                provision_in_real_guest(image)
                packages = subprocess.check_output(["virt-cat", "-a", str(image), "/etc/gpt-trace-packages.txt"])
                python_packages = subprocess.check_output(["virt-cat", "-a", str(image), "/etc/gpt-trace-python-packages.txt"])
                (stage / "kali-packages.txt").write_bytes(packages)
                (stage / "kali-python-packages.txt").write_bytes(python_packages)
                metadata = {"source": SOURCE + ARCHIVE, "source_sha256": ARCHIVE_SHA256,
                    "base_sha256": digest(image), "build_input_sha256": golden_build_input_sha256(),
                    "repo_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    "guest_agent_version": "3.0.0", "browser_runtime": "CloakBrowser 0.4.8 / 146.0.7680.177.5",
                    "apt_suite": "kali-last-snapshot", "apt_package_manifest_sha256": hashlib.sha256(packages).hexdigest(),
                    "python_package_manifest_sha256": hashlib.sha256(python_packages).hexdigest(),
                    "python_lock_sha256": digest(ROOT / "infra/workstation/image/requirements.lock"),
                    "build_utc": datetime.now(timezone.utc).isoformat(), "provisioning_network": "qemu-user-firstboot"}
                image.with_suffix(".provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
                for path in artifact_paths(image):
                    path.chmod(0o444)
                    with path.open("rb") as handle: os.fsync(handle.fileno())
                verify(image)
                run("qemu-img", "check", str(image))
                journal = {"schema": 1, "status": "prepared", "stage": stage.name,
                    "files": {p.name: {"size": p.stat().st_size, "sha256": digest(p)} for p in artifact_paths(image)}}
                _atomic_json(journal_path, journal)
                _commit_prepared(journal)
        except BaseException as exc:
            (stage / "FAILED.txt").write_text(type(exc).__name__ + ": " + str(exc) + "\n")
            # Do not erase a prepared journal: it may describe metadata already
            # installed and is the only authority for safely completing it.
            current = json.loads(journal_path.read_bytes())
            if current.get("status") == "building":
                _atomic_json(journal_path, {"schema": 1, "status": "failed", "stage": stage.name, "error": str(exc)[:2000]})
            raise
        finally:
            BUILD_LOG = None
    finally:
        os.close(descriptor)


def artifact_paths(base: Path | None = None) -> tuple[Path, Path, Path, Path]:
    base = DEST if base is None else base
    return (
        base,
        base.with_suffix(".provenance.json"),
        base.parent / "kali-packages.txt",
        base.parent / "kali-python-packages.txt",
    )




def verify(base: Path | None = None) -> None:
    base = DEST if base is None else base
    from gpt_trace_transport.local_templates import safe
    for path in artifact_paths(base): safe(path, immutable=True)
    provenance = base.with_suffix(".provenance.json")
    metadata = json.loads(provenance.read_text())
    if metadata["source_sha256"] != ARCHIVE_SHA256 or metadata["source"] != SOURCE + ARCHIVE:
        raise RuntimeError("Kali archive provenance differs from the pinned source")
    current_build_input = golden_build_input_sha256()
    stored_build_input = metadata.get("build_input_sha256")
    if stored_build_input != current_build_input:
        raise RuntimeError("Kali golden build-input fingerprint is missing or incompatible; existing image preserved")
    if metadata["python_lock_sha256"] != digest(
        ROOT / "infra/workstation/image/requirements.lock"
    ):
        raise RuntimeError("Python dependency lock differs from the built image")
    for path, key in (
        (base.parent / "kali-packages.txt", "apt_package_manifest_sha256"),
        (base.parent / "kali-python-packages.txt", "python_package_manifest_sha256"),
    ):
        if hashlib.sha256(path.read_bytes()).hexdigest() != metadata[key]:
            raise RuntimeError(f"{path.name} provenance differs from the built image")
    if metadata["base_sha256"] != digest(base):
        raise RuntimeError("Kali base image mutated")
    info = json.loads(
        subprocess.check_output(["qemu-img", "info", "--output=json", str(base)])
    )
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise RuntimeError("base is not an independent qcow2")
    if info.get("virtual-size") != VIRTUAL_DISK_GIB * 1024**3:
        raise RuntimeError("Kali base does not provide the configured 512-GiB virtual disk")
    physical = base.stat().st_blocks * 512
    print(
        "Kali image:", base,
        "sha256:", metadata["base_sha256"],
        "physical_bytes:", physical,
        flush=True,
    )






def main() -> int:
    parser = argparse.ArgumentParser(description="Build locally or verify the permanent Kali golden on the execution host.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true", help="build locally when absent; otherwise verify")
    mode.add_argument("--verify", action="store_true", help="verify without any image mutation")
    args = parser.parse_args()
    if args.verify: verify()
    else: build()
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "shared"))
    raise SystemExit(main())

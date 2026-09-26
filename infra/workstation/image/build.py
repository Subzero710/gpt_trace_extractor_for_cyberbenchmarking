#!/usr/bin/env python3
"""Build a verified immutable Kali qcow2, customized with the guest agent."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(*cmd: str, timeout: int = 7200, **kwargs) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd), flush=True)
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
        print(f"Discarding invalid cached Kali archive: {CACHE_ARCHIVE}", flush=True)
        CACHE_ARCHIVE.unlink()

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
        "4096",
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


def build() -> None:
    if DEST.exists():
        verify()
        return

    require_host_build_runtime()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    archive = cached_archive()

    with tempfile.TemporaryDirectory(prefix="kali-build-", dir=DEST.parent) as tmp:
        temp = Path(tmp)
        run("7z", "x", str(archive), "-o" + str(temp / "extracted"), "-y")
        images = list((temp / "extracted").rglob("*.qcow2"))
        if len(images) != 1:
            raise RuntimeError(
                f"expected one QEMU qcow2 in archive; found {len(images)}"
            )

        image = temp / "base.qcow2"
        run("qemu-img", "convert", "-O", "qcow2", str(images[0]), str(image))

        prepare_offline(image, temp)
        provision_in_real_guest(image)

        packages = subprocess.check_output(
            ["virt-cat", "-a", str(image), "/etc/gpt-trace-packages.txt"]
        )
        python_packages = subprocess.check_output(
            ["virt-cat", "-a", str(image), "/etc/gpt-trace-python-packages.txt"]
        )
        (DEST.parent / "kali-packages.txt").write_bytes(packages)
        (DEST.parent / "kali-python-packages.txt").write_bytes(python_packages)

        shutil.copy(image, DEST.with_suffix(".tmp"))
        os.replace(DEST.with_suffix(".tmp"), DEST)
        DEST.chmod(0o444)

        metadata = {
            "source": SOURCE + ARCHIVE,
            "source_sha256": ARCHIVE_SHA256,
            "base_sha256": digest(DEST),
            "repo_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "guest_agent_version": "3.0.0",
            "browser_runtime": "CloakBrowser 0.4.8 / 146.0.7680.177.5",
            "apt_suite": "kali-last-snapshot",
            "apt_package_manifest_sha256": hashlib.sha256(packages).hexdigest(),
            "python_package_manifest_sha256": hashlib.sha256(python_packages).hexdigest(),
            "python_lock_sha256": digest(
                ROOT / "infra/workstation/image/requirements.lock"
            ),
            "build_utc": datetime.now(timezone.utc).isoformat(),
            "provisioning_network": "qemu-user-firstboot",
        }
        DEST.with_suffix(".provenance.json").write_text(
            json.dumps(metadata, indent=2) + "\n"
        )

    verify()


def verify() -> None:
    metadata = json.loads(DEST.with_suffix(".provenance.json").read_text())
    if metadata["source_sha256"] != ARCHIVE_SHA256 or metadata["source"] != SOURCE + ARCHIVE:
        raise RuntimeError("Kali archive provenance differs from the pinned source")
    if metadata["python_lock_sha256"] != digest(
        ROOT / "infra/workstation/image/requirements.lock"
    ):
        raise RuntimeError("Python dependency lock differs from the built image")
    for name, key in (
        ("kali-packages.txt", "apt_package_manifest_sha256"),
        ("kali-python-packages.txt", "python_package_manifest_sha256"),
    ):
        if hashlib.sha256((DEST.parent / name).read_bytes()).hexdigest() != metadata[key]:
            raise RuntimeError(f"{name} provenance differs from the built image")
    if metadata["base_sha256"] != digest(DEST):
        raise RuntimeError("Kali base image mutated")
    info = json.loads(
        subprocess.check_output(["qemu-img", "info", "--output=json", str(DEST)])
    )
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise RuntimeError("base is not an independent qcow2")
    print("Kali image:", DEST, "sha256:", metadata["base_sha256"])


if __name__ == "__main__":
    build()

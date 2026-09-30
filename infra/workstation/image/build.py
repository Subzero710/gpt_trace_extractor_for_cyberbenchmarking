#!/usr/bin/env python3
"""Build a verified immutable Kali qcow2, customized with the guest agent."""
from __future__ import annotations

import ast
import hashlib
import inspect
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


def golden_build_input_sha256() -> str:
    """Fingerprint repo/upstream inputs that change guest runtime semantics."""
    hasher = hashlib.sha256()
    _hash_component(hasher, "source", (SOURCE + ARCHIVE).encode("utf-8"))
    _hash_component(hasher, "archive_sha256", ARCHIVE_SHA256.encode("ascii"))
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
    source_files = [path for path in source_entries if path.is_file()]
    if not source_files:
        raise RuntimeError("Kali workstation guest source tree is empty")
    for path in source_files:
        _hash_component(
            hasher,
            path.relative_to(ROOT).as_posix(),
            path.read_bytes(),
        )
    return hasher.hexdigest()


def _builder_semantic_sha256(source: str) -> str:
    """Hash image-building semantics, ignoring fingerprint/verify plumbing."""
    tree = ast.parse(source)
    wanted_assignments = {"SOURCE", "ARCHIVE", "ARCHIVE_SHA256", "GUEST_PACKAGES"}
    wanted_functions = {
        "firstboot_script",
        "prepare_offline",
        "provision_in_real_guest",
    }
    selected: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            for name in sorted(names & wanted_assignments):
                selected[name] = node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in wanted_functions:
                selected[node.name] = node
    missing = (wanted_assignments | wanted_functions) - set(selected)
    if missing:
        raise RuntimeError(
            f"cannot fingerprint Kali builder semantics; missing {sorted(missing)!r}"
        )
    payload = "\n".join(
        name + "=" + ast.dump(selected[name], include_attributes=False)
        for name in sorted(selected)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _legacy_golden_matches_current_inputs(metadata: dict) -> bool:
    """Migrate old provenance only when original guest inputs still match."""
    commit = metadata.get("repo_commit")
    if not isinstance(commit, str) or not commit:
        return False

    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0:
        return False

    input_paths = (
        "apps/kali-workstation/src/kali_workstation",
        "apps/kali-workstation/pyproject.toml",
        "infra/workstation/image/requirements.lock",
        "infra/workstation/systemd/gpt-trace-workstation-agent.service",
    )
    diff = subprocess.run(
        ["git", "diff", "--quiet", commit, "--", *input_paths],
        cwd=ROOT,
    )
    if diff.returncode == 1:
        return False
    if diff.returncode != 0:
        raise RuntimeError("git diff failed while checking legacy Kali provenance")

    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "--", *input_paths],
        cwd=ROOT,
        text=True,
    )
    if untracked.strip():
        return False

    try:
        old_builder = subprocess.check_output(
            ["git", "show", f"{commit}:infra/workstation/image/build.py"],
            cwd=ROOT,
            text=True,
        )
    except subprocess.CalledProcessError:
        return False
    current_builder = Path(__file__).read_text(encoding="utf-8")
    return _builder_semantic_sha256(old_builder) == _builder_semantic_sha256(
        current_builder
    )


def _discard_stale_golden(reason: BaseException | str) -> None:
    print(f"Discarding stale Kali golden image: {reason}", flush=True)
    for path in (
        DEST,
        DEST.with_suffix(".tmp"),
        DEST.with_suffix(".provenance.json"),
        DEST.parent / "kali-packages.txt",
        DEST.parent / "kali-python-packages.txt",
    ):
        path.unlink(missing_ok=True)


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
        try:
            verify()
        except (
            OSError,
            KeyError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as exc:
            _discard_stale_golden(exc)
        else:
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
            "build_input_sha256": golden_build_input_sha256(),
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
    provenance = DEST.with_suffix(".provenance.json")
    metadata = json.loads(provenance.read_text())
    if metadata["source_sha256"] != ARCHIVE_SHA256 or metadata["source"] != SOURCE + ARCHIVE:
        raise RuntimeError("Kali archive provenance differs from the pinned source")
    current_build_input = golden_build_input_sha256()
    stored_build_input = metadata.get("build_input_sha256")
    migrate_legacy = False
    if stored_build_input is None:
        if not _legacy_golden_matches_current_inputs(metadata):
            raise RuntimeError(
                "legacy Kali golden image predates build-input fingerprints and "
                "its original guest inputs differ from the current tree"
            )
        migrate_legacy = True
    elif stored_build_input != current_build_input:
        raise RuntimeError(
            "Kali golden image inputs changed "
            f"(stored={stored_build_input!r}, current={current_build_input!r})"
        )
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
    if migrate_legacy:
        metadata["build_input_sha256"] = current_build_input
        provenance.write_text(json.dumps(metadata, indent=2) + "\n")
        print(
            "Stamped legacy Kali provenance with current build-input fingerprint",
            flush=True,
        )
    print("Kali image:", DEST, "sha256:", metadata["base_sha256"])


if __name__ == "__main__":
    build()

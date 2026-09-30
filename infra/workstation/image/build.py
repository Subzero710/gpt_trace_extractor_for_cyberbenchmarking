#!/usr/bin/env python3
"""Build a verified immutable Kali qcow2, customized with the guest agent."""
from __future__ import annotations

import argparse
import ast
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
GOLDEN_IMAGE_REPOSITORY = "aad7xppz4fd4r8emr/gpt-trace-kali-golden"
GOLDEN_IMAGE_ROOT = Path("/opt/gpt-trace-golden")

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
    """Build the golden image locally. Intended for the publishing machine only."""
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


def artifact_paths(base: Path | None = None) -> tuple[Path, Path, Path, Path]:
    base = DEST if base is None else base
    return (
        base,
        base.with_suffix(".provenance.json"),
        base.parent / "kali-packages.txt",
        base.parent / "kali-python-packages.txt",
    )


def golden_image_ref() -> str:
    # Full semantic input hash makes the Docker tag deterministic for exactly the
    # guest contents expected by this checkout, without a hand-maintained version.
    return f"{GOLDEN_IMAGE_REPOSITORY}:input-{golden_build_input_sha256()}"


def verify(base: Path | None = None) -> None:
    base = DEST if base is None else base
    provenance = base.with_suffix(".provenance.json")
    metadata = json.loads(provenance.read_text())
    if metadata["source_sha256"] != ARCHIVE_SHA256 or metadata["source"] != SOURCE + ARCHIVE:
        raise RuntimeError("Kali archive provenance differs from the pinned source")
    current_build_input = golden_build_input_sha256()
    stored_build_input = metadata.get("build_input_sha256")
    migrate_legacy = False
    if stored_build_input is None:
        # Legacy migration is only meaningful for the installed canonical image.
        if base != DEST or not _legacy_golden_matches_current_inputs(metadata):
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
    if migrate_legacy:
        metadata["build_input_sha256"] = current_build_input
        provenance.write_text(json.dumps(metadata, indent=2) + "\n")
        print(
            "Stamped legacy Kali provenance with current build-input fingerprint",
            flush=True,
        )
    physical = base.stat().st_blocks * 512
    print(
        "Kali image:", base,
        "sha256:", metadata["base_sha256"],
        "physical_bytes:", physical,
        flush=True,
    )


def install_from_image() -> None:
    """Install the prebuilt golden image published on Docker Hub."""
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

    image_ref = golden_image_ref()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    run("docker", "pull", image_ref)
    container_id = ""
    try:
        container_id = subprocess.check_output(
            ["docker", "create", image_ref, "/not-run"], text=True
        ).strip()
        if not container_id:
            raise RuntimeError("docker create returned an empty container id")
        with tempfile.TemporaryDirectory(prefix="kali-golden-pull-", dir=DEST.parent) as raw:
            temp = Path(raw)
            run(
                "docker", "cp",
                f"{container_id}:{GOLDEN_IMAGE_ROOT}/.",
                str(temp),
            )
            staged = temp / DEST.name
            expected = (
                staged,
                temp / "kali-base.provenance.json",
                temp / "kali-packages.txt",
                temp / "kali-python-packages.txt",
            )
            for path in expected:
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError(f"golden image artifact missing or unsafe: {path.name}")
            verify(staged)

            final_paths = artifact_paths()
            for source, target in zip(expected, final_paths, strict=True):
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, target)
            DEST.chmod(0o444)
            verify()
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        # The qcow2 has been copied to libvirt storage. Keeping the Docker image
        # would duplicate several GiB on the benchmark host.
        subprocess.run(
            ["docker", "image", "rm", image_ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def publish_image() -> None:
    """Build locally once, then publish the verified golden as a Docker image."""
    requirements = ROOT / "scripts/host_requirements.py"
    run(sys.executable, str(requirements), "--build", "--golden-build")
    build()
    verify()
    image_ref = golden_image_ref()
    metadata = json.loads(DEST.with_suffix(".provenance.json").read_text())
    exists = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", image_ref],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode == 0:
        raise RuntimeError(
            f"refusing to overwrite existing immutable golden tag: {image_ref}"
        )

    with tempfile.TemporaryDirectory(prefix="kali-golden-docker-") as raw:
        context = Path(raw)
        for source in artifact_paths():
            shutil.copy2(source, context / source.name)
        dockerfile = context / "Dockerfile"
        dockerfile.write_text(
            "FROM scratch\n"
            f"LABEL org.opencontainers.image.title=\"gpt-trace-kali-golden\"\n"
            f"LABEL io.gpttrace.build-input-sha256=\"{metadata['build_input_sha256']}\"\n"
            f"LABEL io.gpttrace.base-sha256=\"{metadata['base_sha256']}\"\n"
            "COPY kali-base.qcow2 /opt/gpt-trace-golden/kali-base.qcow2\n"
            "COPY kali-base.provenance.json /opt/gpt-trace-golden/kali-base.provenance.json\n"
            "COPY kali-packages.txt /opt/gpt-trace-golden/kali-packages.txt\n"
            "COPY kali-python-packages.txt /opt/gpt-trace-golden/kali-python-packages.txt\n",
            encoding="utf-8",
        )
        run(
            "docker", "buildx", "build",
            "--platform", "linux/amd64",
            "--push",
            "--tag", image_ref,
            str(context),
        )
    run("docker", "buildx", "imagetools", "inspect", image_ref)
    print(f"Published Kali golden image: {image_ref}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build, publish, install, or verify the Kali golden workstation image."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true", help="build the qcow2 locally")
    mode.add_argument("--publish", action="store_true", help="build and push the Docker Hub golden image")
    mode.add_argument("--verify", action="store_true", help="verify the installed qcow2")
    mode.add_argument("--install", action="store_true", help="pull and install the prebuilt Docker Hub golden (default)")
    args = parser.parse_args()

    if args.local:
        build()
    elif args.publish:
        publish_image()
    elif args.verify:
        verify()
    else:
        install_from_image()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

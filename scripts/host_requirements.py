#!/usr/bin/env python3
"""Verify host-only packages/capabilities before any hybrid build/runtime work."""
from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements.txt"
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")

# Commands supplied by packages in requirements.txt. Keep this mapping focused on
# the host-native broker/KVM/image path; application commands belong in Docker.
COMMAND_PACKAGES = {
    "qemu-system-x86_64": "qemu-system-x86",
    "qemu-img": "qemu-utils",
    "virsh": "libvirt-clients",
    "virt-customize": "libguestfs-tools",
    "virt-cat": "libguestfs-tools",
    "xorriso": "xorriso",
    "7z": "p7zip-full",
    "nft": "nftables",
    "mkfs.ext4": "e2fsprogs",
    "fallocate": "util-linux",
    "mount": "util-linux",
    "umount": "util-linux",
    "ip": "iproute2",
    "curl": "curl",
    "git": "git",
}


def load_packages(path: Path = REQUIREMENTS) -> tuple[str, ...]:
    if not path.is_file():
        raise RuntimeError(f"missing host requirements manifest: {path}")
    packages: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if not PACKAGE.fullmatch(value):
            raise RuntimeError(f"invalid host package on {path}:{number}: {value!r}")
        if value in packages:
            raise RuntimeError(f"duplicate host package in {path}: {value}")
        packages.append(value)
    if not packages:
        raise RuntimeError(f"host requirements manifest is empty: {path}")
    return tuple(packages)


def _debian_like() -> bool:
    release = Path("/etc/os-release")
    if not release.is_file():
        return False
    values: dict[str, str] = {}
    for raw in release.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"')
    identifiers = {values.get("ID", "").casefold(), *values.get("ID_LIKE", "").casefold().split()}
    return bool({"debian", "ubuntu"} & identifiers)


def _package_installed(name: str) -> bool:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "install ok installed"


def _probe(argv: tuple[str, ...], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    detail = (result.stderr.strip() or result.stdout.strip())[:500]
    return result.returncode == 0, detail


def _probe_venv() -> tuple[bool, str]:
    try:
        with tempfile.TemporaryDirectory(prefix="gpt-trace-venv-probe-") as raw:
            target = Path(raw) / "venv"
            created = subprocess.run(
                [sys.executable, "-m", "venv", str(target)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if created.returncode != 0:
                return False, (created.stderr.strip() or created.stdout.strip())[:1000]
            pip = subprocess.run(
                [str(target / "bin" / "python"), "-m", "pip", "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if pip.returncode != 0:
                return False, (pip.stderr.strip() or pip.stdout.strip())[:1000]
            return True, pip.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def verify_host_requirements(*, require_root: bool = False, verbose: bool = True) -> bool:
    failures: list[str] = []
    missing_packages: list[str] = []

    if platform.system() != "Linux":
        failures.append(f"Linux host required; found {platform.system()}")
    if not _debian_like():
        failures.append("requirements.txt currently targets Ubuntu/Debian hosts")
    if shutil.which("dpkg-query") is None:
        failures.append("dpkg-query is required to verify requirements.txt")

    packages: tuple[str, ...] = ()
    try:
        packages = load_packages()
    except RuntimeError as exc:
        failures.append(str(exc))

    if packages and shutil.which("dpkg-query") is not None:
        missing_packages = [package for package in packages if not _package_installed(package)]

    for command, package in COMMAND_PACKAGES.items():
        if shutil.which(command) is None and package not in missing_packages:
            failures.append(f"{command} is missing even though {package} is installed")

    if sys.version_info < (3, 12):
        failures.append(
            f"Python >=3.12 required for host scripts/broker; found {sys.version.split()[0]}"
        )
    elif "python3-venv" not in missing_packages:
        ok, detail = _probe_venv()
        if not ok:
            failures.append(
                "python3 venv/ensurepip is not functional; reinstall python3-venv"
                + (f" ({detail})" if detail else "")
            )

    docker = shutil.which("docker")
    if docker is None:
        failures.append("Docker Engine CLI is missing")
    else:
        for label, argv in (
            ("Docker daemon", (docker, "info", "--format", "{{.ServerVersion}}")),
            ("Docker Compose", (docker, "compose", "version")),
            ("Docker Buildx", (docker, "buildx", "version")),
        ):
            ok, detail = _probe(argv)
            if not ok:
                failures.append(f"{label} unavailable" + (f": {detail}" if detail else ""))

    if require_root and os.geteuid() != 0:
        failures.append("hybrid build must run as root; use `sudo make build`")

    if missing_packages:
        print("Missing host packages from requirements.txt:", file=sys.stderr)
        for package in missing_packages:
            print(f"  - {package}", file=sys.stderr)
        print("Install them with:", file=sys.stderr)
        print("  sudo apt-get update", file=sys.stderr)
        print("  sudo apt-get install -y " + " ".join(missing_packages), file=sys.stderr)

    if missing_packages or failures:
        if failures:
            print("Host capability failures:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
        return False

    if verbose:
        print(
            f"host requirements: ok ({len(packages)} system packages, "
            "Python venv, Docker Engine/Compose/Buildx)"
        )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify host-only requirements from requirements.txt and Docker capabilities."
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="also require root privileges needed by the host image/broker build path",
    )
    args = parser.parse_args()
    return 0 if verify_host_requirements(require_root=args.build) else 2


if __name__ == "__main__":
    raise SystemExit(main())

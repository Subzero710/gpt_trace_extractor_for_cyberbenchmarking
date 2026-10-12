"""Two-phase APT closure resolution and network-disabled artifact replay."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

PACKAGES = ("build-essential", "cmake", "libpq-dev", "locales", "locales-all", "openjdk-21-jdk",
            "openjdk-21-jre", "pipx", "nodejs", "npm", "libffi-dev", "libtiff-dev", "jq", "cloud-guest-utils")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def installed():
    raw = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${Status}\n"], text=True)
    result = {}
    for line in raw.splitlines():
        name, version, arch, status = line.split("\t", 3)
        if status == "install ok installed":
            result[name] = {"version": version, "architecture": arch}
    return result


def deb_identity(path):
    raw = subprocess.check_output(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], text=True)
    values = {}
    for line in raw.splitlines():
        key, value = line.split(": ", 1)
        values[key.lower()] = value
    if set(values) != {"package", "version", "architecture"}:
        raise RuntimeError("invalid resolved Debian artifact metadata")
    return values


def repository_metadata():
    return {str(path): {"sha256": digest(path), "size": path.stat().st_size}
            for root in (Path("/etc/apt"), Path("/var/lib/apt/lists"))
            for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()}


def verify_artifacts(folder, manifest):
    folder = Path(folder)
    artifacts = manifest.get("artifacts")
    if manifest.get("schema_version") != 1 or not isinstance(artifacts, dict) or not artifacts:
        raise RuntimeError("missing resolved OS package artifacts")
    if set(path.name for path in folder.glob("*.deb")) != set(artifacts):
        raise RuntimeError("missing/extra resolved .deb artifact")
    for name, record in artifacts.items():
        if not re.fullmatch(r"[A-Za-z0-9+._:%~\-]+\.deb", name):
            raise RuntimeError("unsafe resolved .deb filename")
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise RuntimeError("resolved .deb artifact integrity mismatch")
        if deb_identity(path) != {key: record[key] for key in ("package", "version", "architecture")}:
            raise RuntimeError("resolved .deb version/architecture mismatch")


def install(folder, manifest, *, compare_final=True):
    folder = Path(folder)
    verify_artifacts(folder, manifest)
    if installed() != manifest["installed_before"]:
        raise RuntimeError("OS artifact replay does not start from the exact golden package inventory")
    empty = folder / "empty-lists"
    empty.mkdir(exist_ok=True)
    # No lists and no network: APT may resolve only the exact local .debs and
    # already-installed golden packages. Missing closure fails, never downloads.
    command = ["unshare", "--net", "apt-get", "-y", "--no-download", "--no-remove",
               "-o", "Acquire::Retries=0", "-o", "Dir::State::Lists=" + str(empty),
               "-o", "Dir::Cache::Archives=" + str(folder), "install"]
    command += [str(folder / name) for name in sorted(manifest["artifacts"])]
    with (folder / "install.log").open("wb") as log:
        subprocess.run(command, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}, check=True, stdout=log, stderr=subprocess.STDOUT)
    actual = installed()
    if compare_final and actual != manifest["installed_after"]:
        raise RuntimeError("installed OS inventory differs from resolved artifact closure")
    return actual


def resolve(folder):
    """Run only in a disposable trusted resolver overlay, never common.qcow2."""
    folder = Path(folder)
    folder.mkdir(parents=True)
    before = installed()
    with (folder / "resolve.log").open("wb") as log:
        for command in (["apt-get", "update"], ["apt-get", "-y", "--no-remove", "--download-only", "--reinstall",
                         "-o", "Dir::Cache::Archives=" + str(folder), "install", *PACKAGES]):
            subprocess.run(command, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}, check=True, stdout=log, stderr=subprocess.STDOUT)
    artifacts = {path.name: {**deb_identity(path), "sha256": digest(path), "size": path.stat().st_size}
                 for path in sorted(folder.glob("*.deb"))}
    repositories = repository_metadata()
    manifest = {"schema_version": 1, "requested": list(PACKAGES), "installed_before": before,
                "artifacts": artifacts, "repository_metadata": repositories}
    manifest["installed_after"] = install(folder, manifest, compare_final=False)
    if not set(PACKAGES) <= {name.split(":")[0] for name in manifest["installed_after"]}:
        raise RuntimeError("resolved closure lacks a required OS package")
    (folder / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return manifest

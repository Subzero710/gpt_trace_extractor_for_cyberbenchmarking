"""Explicit, replayable golden guest steps; generated shell contains no Python.

Bootstrap uses pip's target-local wheel/tag machinery before installing the
direct runtime dependency packaging. Metadata uses the installed packaging.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

from golden_assets import (BROWSER, CACHE_MOUNT, atomic_bytes, atomic_json,
                           browser_archive, browser_identity, digest,
                           extract_browser, inventory, mkdir, safe, sync)
import golden_lock

BUNDLE = Path("/opt/gpt-trace/bundle")
VENV = Path("/opt/gpt-trace/venv")
INPUT = Path("/etc/gpt-trace-build-input.json")
PROOF = Path("/etc/gpt-trace-guest-proof.json")
COMPLETE = Path("/etc/gpt-trace-image-build-complete")
FAILED = Path("/etc/gpt-trace-image-build-failed")
MANIFESTS = {
    "packages": "/etc/gpt-trace-packages.txt",
    "python_packages": "/etc/gpt-trace-python-packages.txt",
    "target_environment": "/etc/gpt-trace-target-environment.json",
    "system_python": "/etc/gpt-trace-system-python.json",
    "npm": "/etc/gpt-trace-npm-version.txt",
    "node": "/etc/gpt-trace-node.json",
    "browser_runtime": "/etc/gpt-trace-browser-runtime.json",
}


def command(*args):
    subprocess.run([str(x) for x in args], check=True)


def output(*args):
    return subprocess.check_output([str(x) for x in args], text=True).strip()


def input_identity():
    value = json.loads(safe(INPUT).read_bytes())
    if (not isinstance(value, dict) or set(value) != {"schema", "build_input_sha256", "repo_commit"}
            or value["schema"] != 2
            or golden_lock.SHA.fullmatch(str(value["build_input_sha256"])) is None
            or not re.fullmatch(r"[0-9a-f]{40}", str(value["repo_commit"]))):
        raise ValueError("invalid golden input identity")
    return value


def apt():
    identity = input_identity()
    contract = json.loads((BUNDLE / "guest-contract.json").read_bytes())
    stamp = Path("/opt/gpt-trace/apt-checkpoint.json")
    manifest = Path(MANIFESTS["packages"])
    if stamp.exists() or stamp.is_symlink():
        old = json.loads(safe(stamp).read_bytes())
        measured = subprocess.check_output(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
        if (old != {"identity": identity, "manifest_sha256": hashlib.sha256(measured).hexdigest()}
                or not manifest.exists() or manifest.read_bytes() != measured):
            raise ValueError("APT checkpoint differs from the actual installed packages")
        return
    source = "deb https://http.kali.org/kali " + contract["apt_suite"] + " main contrib non-free non-free-firmware\n"
    atomic_bytes(Path("/etc/apt/sources.list"), source.encode(), 0o644)
    sources = Path("/etc/apt/sources.list.d/kali.sources")
    if sources.is_symlink():
        raise ValueError("unsafe original Kali APT source")
    sources.unlink(missing_ok=True)
    command("apt-get", "-o", "Acquire::Retries=5", "update")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    subprocess.run(["apt-get", "-o", "Acquire::Retries=5", "-y", "install", *contract["packages"]],
                   check=True, env=env)
    # Verify every explicit guest dependency before recording success.
    for package in contract["packages"]:
        if output("dpkg-query", "-W", "-f=${Status}", package) != "install ok installed":
            raise ValueError("guest dependency was not installed: " + package)
    raw = subprocess.check_output(["dpkg-query", "-W", "-f=${Package} ${Version}\n"])
    atomic_bytes(manifest, raw, 0o444)
    atomic_json(stamp, {"identity": identity, "manifest_sha256": hashlib.sha256(raw).hexdigest()})


def filesystem():
    contract = json.loads((BUNDLE / "guest-contract.json").read_bytes())
    minimum = contract["root_min_gib"] * 1024**3
    device = output("findmnt", "-n", "-o", "SOURCE", "/")
    if output("findmnt", "-n", "-o", "FSTYPE", "/") != "ext4":
        raise ValueError("golden root filesystem must be ext4")
    def capacity():
        return int(output("df", "-B1", "--output=size", "/").splitlines()[-1])
    if capacity() >= minimum:
        return
    parent = output("lsblk", "-n", "-o", "PKNAME", device)
    number = output("lsblk", "-n", "-o", "PARTN", device)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", parent) or not re.fullmatch(r"[1-9][0-9]*", number):
        raise ValueError("golden root partition identity is invalid")
    disk = "/dev/" + parent
    probe = subprocess.run(["growpart", "--dry-run", disk, number], capture_output=True, text=True)
    if probe.returncode == 0:
        command("growpart", disk, number)
    elif probe.returncode != 1 or not (probe.stdout + probe.stderr).lstrip().startswith("NOCHANGE:"):
        raise RuntimeError("growpart preflight failed: " + probe.stdout + probe.stderr)
    command("resize2fs", device)
    if capacity() < minimum:
        raise ValueError("root filesystem is smaller than its configured minimum")


def wheelhouse(cache, bundle, *, invoke=command):
    # These values are computed by the *guest's* bootstrap interpreter, never
    # pip's host --platform approximation (which would mis-evaluate markers).
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
    from pip._vendor.packaging.version import Version
    lock = golden_lock.load(bundle / "python-lock.json")
    objects = mkdir(mkdir(cache / "python") / "objects")
    incoming = mkdir(cache / "python" / "incoming")
    tags = list(sys_tags())
    ranks = {tag: n for n, tag in enumerate(tags)}
    if not ranks:
        raise ValueError("target interpreter emitted no wheel compatibility tags")
    pins = {row["name"]: row for row in lock["packages"]}
    def validate_wheel(path):
        safe(path)
        name, version, _build, wheel_tags = parse_wheel_filename(path.name)
        row = pins.get(canonicalize_name(name))
        sha = digest(path)
        if row is None or Version(row["version"]) != version or sha not in row["hashes"]:
            raise ValueError("cached wheel is outside the frozen graph: " + path.name)
        return row["name"], sha, wheel_tags
    # Recover complete verified wheels left by a killed pip process. Partial
    # scratch is never promoted merely because its path exists.
    for path in sorted(incoming.iterdir()):
        safe(path, directory=path.is_dir())
        if path.is_file() and path.suffix == ".whl":
            _name, sha, _tags = validate_wheel(path)
            folder = mkdir(objects / sha)
            target = folder / path.name
            if target.exists():
                validate_wheel(target)
                if digest(target) != sha:
                    raise ValueError("wheel CAS collision")
                path.unlink()
            else:
                path.chmod(0o444)
                os.replace(path, target)
            sync(folder)
            sync(incoming)
    candidates = {}
    for folder in sorted(objects.iterdir()):
        safe(folder, directory=True)
        if golden_lock.SHA.fullmatch(folder.name) is None:
            raise ValueError("invalid Python CAS directory identity")
        for path in sorted(folder.iterdir()):
            # Objects from a different reviewed graph remain retained; their
            # content-address is still checked before considering any reuse.
            safe(path)
            if digest(path) != folder.name:
                raise ValueError("persistent wheel CAS corruption: " + str(path))
            name, version, _build, wheel_tags = parse_wheel_filename(path.name)
            row = pins.get(canonicalize_name(name))
            usable = [ranks[t] for t in wheel_tags if t in ranks]
            if row and Version(row["version"]) == version and folder.name in row["hashes"] and usable:
                candidates.setdefault(row["name"], []).append((min(usable), path.name, path))
    selected = {}
    for row in lock["packages"]:
        if row["name"] not in candidates:
            requirement = incoming / "requirement.txt"
            atomic_bytes(requirement, (row["name"] + "==" + row["version"] + " " +
                         " ".join("--hash=sha256:" + sha for sha in row["hashes"]) + "\n").encode())
            invoke(sys.executable, "-m", "pip", "--isolated", "download", "--no-deps",
                   "--only-binary=:all:", "--require-hashes", "--index-url", "https://pypi.org/simple",
                   "--dest", incoming, "-r", requirement)
            wheels = list(incoming.glob("*.whl"))
            if len(wheels) != 1:
                raise ValueError("target wheel acquisition did not produce exactly one complete wheel")
            path = wheels[0]
            name, sha, wheel_tags = validate_wheel(path)
            if name != row["name"] or not set(wheel_tags) & set(ranks):
                raise ValueError("acquired wheel does not match actual target tags")
            folder = mkdir(objects / sha)
            target = folder / path.name
            if target.exists() or target.is_symlink():
                raise ValueError("unexpected wheel CAS destination already exists")
            path.chmod(0o444)
            os.replace(path, target)
            sync(folder)
            sync(incoming)
            candidates[name] = [(0, target.name, target)]
        selected[row["name"]] = sorted(candidates[row["name"]])[0][2]
    return selected


def python_dependencies():
    if not VENV.exists():
        command("python3", "-m", "venv", VENV)
    else:
        safe(VENV, directory=True)
        if not (VENV / "pyvenv.cfg").is_file():
            # venv itself is replayable and does not remove an existing prefix.
            command("python3", "-m", "venv", VENV)
    python = VENV / "bin/python"
    safe(VENV / "pyvenv.cfg")
    safe(python.resolve(strict=True))
    expected = output("python3", "-c", "import sys; print(sys.version)")
    if output(python, "-c", "import sys; print(sys.version)") != expected:
        raise ValueError("existing golden virtualenv has a different system interpreter")
    # Run selection in the venv so it uses the same pip/ABI as installation.
    command(python, BUNDLE / "guest_build.py", "install-python")


def install_python():
    from pip._vendor.packaging.specifiers import SpecifierSet
    value = golden_lock.load(BUNDLE / "python-lock.json")
    if platform.python_version() not in SpecifierSet(value["requires_python"]):
        raise ValueError("actual guest Python is outside the frozen graph's supported range")
    selected = wheelhouse(CACHE_MOUNT, BUNDLE)
    with tempfile.TemporaryDirectory(prefix="gpt-trace-wheelhouse-") as raw:
        house = Path(raw)
        for path in selected.values():
            shutil.copyfile(path, house / path.name)
        command(sys.executable, "-m", "pip", "--isolated", "install", "--no-index",
                "--find-links", house, "--only-binary=:all:", "--require-hashes",
                "-r", BUNDLE / "requirements.lock")
    command(sys.executable, "-m", "pip", "check")
    from packaging.requirements import Requirement
    from packaging.markers import default_environment
    from packaging.specifiers import SpecifierSet as RuntimeSpecifiers
    environment = default_environment()
    pins = {r["name"]: r for r in value["packages"]}
    from packaging.utils import canonicalize_name
    for row in value["packages"]:
        distribution = importlib.metadata.distribution(row["name"])
        if distribution.version != row["version"]:
            raise ValueError("installed Python distribution differs from lock: " + row["name"])
        requires_python = distribution.metadata.get("Requires-Python")
        if requires_python and platform.python_version() not in RuntimeSpecifiers(requires_python):
            raise ValueError("installed wheel does not support actual target Python")
        for text in distribution.requires or []:
            req = Requirement(text)
            if req.marker is not None and not req.marker.evaluate(dict(environment, extra="")):
                continue
            dependency = pins.get(canonicalize_name(req.name))
            if req.url or dependency is None or dependency["version"] not in req.specifier:
                raise ValueError("frozen graph does not close an active target dependency: " + text)


def browser():
    identity = browser_identity()
    locked = golden_lock.load(BUNDLE / "python-lock.json")
    pin = next(row["version"] for row in locked["packages"] if row["name"] == "cloakbrowser")
    if identity["wrapper"] != pin:
        raise ValueError("installed browser wrapper differs from frozen graph")
    archive, evidence = browser_archive(CACHE_MOUNT, identity)
    record = Path(MANIFESTS["browser_runtime"])
    if BROWSER.exists() or BROWSER.is_symlink():
        previous = json.loads(safe(record).read_bytes())
        if previous.get("artifact") != evidence or previous.get("files") != inventory(BROWSER):
            raise ValueError("already-installed Chromium bytes differ from authenticated inventory")
    else:
        parent = BROWSER.parent
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        safe(parent, directory=True)
        with tempfile.TemporaryDirectory(prefix=".extract-", dir=parent) as raw:
            staged = Path(raw) / "chromium"
            extract_browser(archive, staged)
            files = inventory(staged)
            # Record intent before activation. A crash after rename is fully
            # verifiable; a crash before rename can repeat extraction offline.
            atomic_json(record, {"schema": 2, "artifact": evidence, "files": files}, 0o444)
            staged.rename(BROWSER)
            sync(parent)
    safe(BROWSER / "chrome")
    if not os.access(BROWSER / "chrome", os.X_OK):
        raise ValueError("verified Chromium is not executable")
    result = subprocess.run(["ldd", str(BROWSER / "chrome")], capture_output=True, text=True)
    if result.returncode != 0 or "not found" in result.stdout + result.stderr:
        raise ValueError("Chromium has unresolved shared libraries: " + result.stdout + result.stderr)
    binary_version = output(BROWSER / "chrome", "--version")
    if not binary_version:
        raise ValueError("Chromium returned no executable version")
    previous = json.loads(record.read_bytes())
    atomic_json(record, {**previous, "executable_version": binary_version,
                        "binary_sha256": digest(BROWSER / "chrome")}, 0o444)
    atomic_bytes(Path("/etc/gpt-trace-browser.env"), (
        "CLOAKBROWSER_BINARY_PATH=" + str(BROWSER / "chrome") + "\n" +
        "CLOAKBROWSER_VERSION=" + identity["version"] + "\n" +
        "CLOAKBROWSER_AUTO_UPDATE=false\n").encode(), 0o444)


def metadata():
    from packaging.markers import default_environment
    from packaging.tags import sys_tags
    contract = json.loads((BUNDLE / "guest-contract.json").read_bytes())
    if platform.machine() != contract["source_architecture"]:
        raise ValueError("actual guest architecture differs from pinned source architecture")
    full = platform.python_version()
    executable = Path(sys.executable).resolve(strict=True)
    env = {key: str(value) for key, value in default_environment().items()}
    tags = list(dict.fromkeys(str(tag) for tag in sys_tags()))
    if not tags or len(tags[0].split("-")) != 3:
        raise ValueError("actual target has no valid wheel tags")
    target = {"schema": 2, "markers": env, "tags": tags, "implementation": sys.implementation.name,
              "abi": tags[0].split("-")[1], "architecture": platform.machine(),
              "source": "verified-target-interpreter", "interpreter_sha256": digest(executable),
              "python_artifact_sha256": None}
    atomic_json(Path(MANIFESTS["target_environment"]), target, 0o444)
    system = shutil.which("python3")
    if system is None:
        raise ValueError("system Python executable is missing")
    system = Path(system).resolve(strict=True)
    atomic_json(Path(MANIFESTS["system_python"]), {
        "full_version": output(system, "-c", "import platform; print(platform.python_version())"),
        "executable": str(system), "interpreter_sha256": digest(system)}, 0o444)
    for name in ("node", "npm"):
        path = shutil.which(name)
        if path is None:
            raise ValueError("required guest executable is missing: " + name)
        path = Path(path).resolve(strict=True)
        version = output(path, "--version")
        if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise ValueError("required guest executable returned invalid version: " + name)
        if name == "npm":
            atomic_bytes(Path(MANIFESTS[name]), (version + "\n").encode(), 0o444)
        else:
            atomic_json(Path(MANIFESTS[name]), {"version": version,
                "executable": str(path), "sha256": digest(path)}, 0o444)
    raw = subprocess.check_output([sys.executable, "-m", "pip", "freeze", "--all"])
    atomic_bytes(Path(MANIFESTS["python_packages"]), raw, 0o444)
    # An import failure must precede the global success marker.
    command(sys.executable, "-c", "import packaging, cloakbrowser; import kali_workstation.guest.agent")


def complete():
    if COMPLETE.is_symlink():
        raise ValueError("unsafe guest completion marker")
    COMPLETE.unlink(missing_ok=True)
    identity = input_identity()
    manifests = {}
    for key, name in MANIFESTS.items():
        path = safe(Path(name))
        if path.stat().st_size == 0:
            raise ValueError("required guest manifest is empty: " + name)
        manifests[key] = {"size": path.stat().st_size, "sha256": digest(path)}
    atomic_json(PROOF, {**identity, "manifests": manifests}, 0o444)
    FAILED.unlink(missing_ok=True)
    atomic_bytes(COMPLETE, b"ok\n", 0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=("apt", "filesystem", "python", "install-python", "browser", "metadata", "complete"))
    args = parser.parse_args()
    safe(CACHE_MOUNT, directory=True)
    actions = {"apt": apt, "filesystem": filesystem, "python": python_dependencies,
               "install-python": install_python, "browser": browser, "metadata": metadata, "complete": complete}
    actions[args.step]()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
"""Sequential local execution host builder; invoked only by the authenticated preparation job."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/var/lib/libvirt/images/gpt-trace/kali-base.qcow2")
TEMPLATES = BASE.parent / "templates"
GUEST = ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py"
PINS = ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/pins.json"
MINICONDA = "Miniconda3-py311_24.7.1-0-Linux-x86_64.sh"
MINICONDA_SHA256 = "a098a5b1581d8fd078c430b82e27106602223e335efef708a124e723814d120c"
VIRTUAL_GIB = 512
FREE_SPACE_GIB = 64
BUILD_TIMEOUT_HOURS = 96


# Fossil SWE-Gym Lite build guest: 12 GiB RAM, 4 vCPUs, sequential jobs.
# The host has 15 GiB of usable RAM; do not launch a second concurrent VM.
GUEST_MEMORY_MIB = 12288
GUEST_VCPUS = 4
COMMON_COMPLETION = "/opt/swe-gym-lite/common-template-complete.json"
REPO_COMPLETION = "/opt/swe-gym-lite/repository-template-complete.json"
TASK_COMPLETION = "/opt/swe-gym-task/build-complete.json"
RESOLVER_COMPLETION = "/opt/swe-gym-os-resolver-complete.json"


class RecoverableBuildError(RuntimeError):
    """A transient failure with a verified, pinned build checkpoint on disk."""


def _owned_tree(path):
    """Reject links and non-root-owned files before recursively deleting a stage."""
    path = Path(path)
    for item in (path, *path.rglob("*")):
        stat = item.lstat()
        if item.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
            raise RuntimeError("unsafe build cleanup target, preserving: " + str(item))
    return path


def _discard(path):
    path = Path(path)
    if path.suffix == ".qcow2":
        raise RuntimeError("QCOW2 volume deletion is forbidden outside make throw_volumes: " + str(path))
    if path.is_symlink():
        raise RuntimeError("unsafe disposable path: " + str(path))
    if path.is_dir():
        shutil.rmtree(_owned_tree(path))
    elif path.exists():
        from gpt_trace_transport.local_templates import safe
        safe(path)
        path.unlink()


def _transient_failure(exc):
    value = str(exc)
    return re.search(r"IncompleteRead|Connection broken|Connection reset|"
                     r"ReadTimeout|ConnectTimeout|RemoteDisconnected|"
                     r"Temporary failure in name resolution|HTTP (?:429|50[0234])|"
                     r"ChunkedEncodingError|Max retries exceeded|timed out|"
                     r"host free-space safety margin reached|No space left on device|"
                     r"Resource temporarily unavailable",
                     value, re.I) is not None


# Exactly one historical operation can be migrated from the old UUID staging
# layout. This is deliberately NOT a generic cross-recipe reuse mechanism.
LEGACY_CONDA_OPERATION = "118a837a3c3684ab23303fe71e2926df5745862403131eda46e06bfe42a8f34b"
LEGACY_BUILDER_SHA256 = "f1022ba1eaa2c67f8973ccd5440a2b0d7d5dd96967a8feec3b790e8c2a674be8"
LEGACY_GUEST_SHA256 = "0d09722e1b14212ad5588b3d230d1658be8a54f456bf5aeb8c4dcca7b3935e1f"


def _migrate_known_legacy_stage(target_root, staged, identity):
    """Adopt only the proven failed Conda common disk from the reported incident."""
    from gpt_trace_transport.local_templates import safe, canonical
    old_root = BASE.parent / "preparations" / LEGACY_CONDA_OPERATION
    state_path = old_root / "state.json"
    log_path = old_root / "attempt-0001.log"
    if not state_path.exists() or not log_path.exists():
        return False
    state = json.loads(safe(state_path).read_bytes())
    prior = state.get("compatibility", {})
    if (state.get("phase") != "failed" or state.get("operation_id") != LEGACY_CONDA_OPERATION
            or "IncompleteRead" not in str(state.get("error"))
            or hashlib.sha256(canonical(prior)).hexdigest() != LEGACY_CONDA_OPERATION
            or prior.get("builder_sha256") != LEGACY_BUILDER_SHA256
            or prior.get("runtime_sources", {}).get("guest_runtime.py") != LEGACY_GUEST_SHA256):
        return False
    expected = identity["compatibility"]
    if ({k: v for k, v in prior.items() if k not in {"builder_sha256", "runtime_sources"}}
            != {k: v for k, v in expected.items() if k not in {"builder_sha256", "runtime_sources"}}):
        return False
    if ({k: v for k, v in prior["runtime_sources"].items() if k != "guest_runtime.py"}
            != {k: v for k, v in expected["runtime_sources"].items() if k != "guest_runtime.py"}):
        return False
    log = safe(log_path).read_text(errors="replace")
    markers = re.findall(r"build stopped; preserved state:\s+([^\n\r]+)", log)
    if not markers:
        return False
    old = Path(markers[-1].strip())
    if old.parent != target_root or not re.fullmatch(r"\.build-[0-9a-f]{32}", old.name):
        return False
    if not old.exists() or not (old / "common.qcow2").is_file():
        return False
    _purge_apt_partial(old)
    _owned_tree(old)
    common = old / "common.qcow2"
    chain = json.loads(subprocess.check_output(["qemu-img", "info", "--backing-chain", "--output=json", str(common)], timeout=180))
    if (len(chain) != 2 or chain[0].get("format") != "qcow2" or
            Path(chain[0]["filename"]).resolve() != common.resolve() or
            Path(chain[1]["filename"]).resolve() != BASE.resolve()):
        return False
    subprocess.run(["qemu-img", "check", str(common)], check=True, timeout=3600)
    def old_guest(path):
        return subprocess.check_output(["virt-cat", "-a", str(common), path], timeout=180)
    if hashlib.sha256(old_guest("/opt/swe-gym-lite/runtime.py")).hexdigest() != LEGACY_GUEST_SHA256:
        return False
    if old_guest("/etc/gpt-trace-image-build-failed").strip() != b"1":
        return False
    if not old_guest("/opt/miniconda3/bin/conda"):
        return False
    inputs = json.loads(safe(old / "build-inputs/inputs.json").read_bytes())
    if (inputs.get("pins") != expected["pins"] or
            json.loads(old_guest("/opt/swe-gym-lite/build-environments.json")) != inputs.get("environments")):
        return False
    # One atomic move: old failed stage no longer wastes space, and all verified
    # successful Conda environments remain inside the same QCOW2 overlay.
    os.rename(old, staged)
    atomic_json(staged / "build-identity.json", identity)
    marker = staged / ".checkpoints"
    marker.mkdir(mode=0o700, exist_ok=True)
    atomic_json(marker / "legacy-adopted.json", {"operation_id": LEGACY_CONDA_OPERATION,
        "guest_sha256": LEGACY_GUEST_SHA256})
    (staged / "FAILED.txt").unlink(missing_ok=True)
    print("adopted historical failed common disk; verified Conda work retained", flush=True)
    return True


def _purge_apt_partial(stage):
    """Remove ONLY the untrusted APT download scratch from a trusted stage.

    libguestfs copies this guest-created directory with its original _apt UID;
    unlike completed artifacts it is not a trusted build input. Never follow
    symlinks, cross mounts, or relax the ownership rules for anything else.
    """
    stage = Path(stage)
    package_dir = stage / "os" / "swe-gym-os"
    for ancestor in (stage, stage / "os", package_dir):
        if ancestor.is_symlink():
            raise RuntimeError("unsafe APT scratch ancestor: " + str(ancestor))
        if not ancestor.exists():
            return
        info = ancestor.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or ancestor.is_mount()):
            raise RuntimeError("unsafe APT scratch ancestor: " + str(ancestor))
    partial = package_dir / "partial"
    if partial.is_symlink():
        raise RuntimeError("unsafe APT scratch symlink: " + str(partial))
    if partial.exists():
        if not partial.is_dir() or partial.is_mount():
            raise RuntimeError("unsafe APT scratch directory: " + str(partial))
        for item in partial.rglob("*"):
            mode = item.lstat().st_mode
            if (item.is_symlink() or item.is_mount() or
                    not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise RuntimeError("unsafe APT scratch entry: " + str(item))
        # No resolved .deb, manifest, QCOW2 or checkpoint lives in partial.
        shutil.rmtree(partial)

    # APT_AUXFILES_CLEANUP_V1: libguestfs copies this EMPTY runtime directory
    # with the original _apt UID. Remove only this exact path after validating
    # all its ancestors, its owner, and its emptiness. Never relax _owned_tree.
    empty_lists = package_dir / "empty-lists"
    if empty_lists.is_symlink():
        raise RuntimeError("unsafe APT empty-lists symlink: " + str(empty_lists))
    if not empty_lists.exists():
        return
    lists_info = empty_lists.lstat()
    if (not stat.S_ISDIR(lists_info.st_mode) or lists_info.st_uid != 0 or
            lists_info.st_mode & 0o022 or empty_lists.is_mount()):
        raise RuntimeError("unsafe APT empty-lists parent: " + str(empty_lists))
    auxfiles = empty_lists / "auxfiles"
    if auxfiles.is_symlink():
        raise RuntimeError("unsafe APT auxfiles symlink: " + str(auxfiles))
    if not auxfiles.exists():
        return
    import pwd
    apt_uid = pwd.getpwnam("_apt").pw_uid
    info = auxfiles.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, apt_uid) or
            info.st_mode & 0o022 or auxfiles.is_mount()):
        raise RuntimeError("unsafe APT auxfiles directory: " + str(auxfiles))
    if any(auxfiles.iterdir()):
        raise RuntimeError("nonempty APT auxfiles, preserving: " + str(auxfiles))
    auxfiles.rmdir()


def _compatibility_matches(left, right):
    from gpt_trace_transport.local_templates import compatible_template_identity
    try:
        return compatible_template_identity(left, right)
    except (ValueError, TypeError):
        return False


def _stage_score(path):
    """Prefer the stage containing the most already-validated expensive work."""
    common = path / "common.qcow2"
    common_bytes = common.stat().st_blocks * 512 if common.is_file() else 0
    checkpoints = path / ".checkpoints"
    task_count = len(list(checkpoints.glob("task-*.json"))) if checkpoints.is_dir() else 0
    source_count = len(list(checkpoints.glob("source-*.json"))) if checkpoints.is_dir() else 0
    repo_count = len(list((path / "repos").glob("*.qcow2"))) if (path / "repos").is_dir() else 0
    sealed = int((path / "local-validation.json").is_file())
    # Any repo image implies a completed common.  Otherwise preserve the stage
    # with the most common-QCOW2 work, because task/source checkpoints can be
    # imported independently from every other compatible donor below.
    return (sealed, repo_count, common_bytes, task_count, source_count, path.stat().st_mtime_ns)


def _compatible_stage_candidates(target_root, staged, identity):
    candidates = []
    for old in target_root.glob(".build-*"):
        if old == staged or old.is_symlink() or not old.is_dir():
            continue
        record = old / "build-identity.json"
        if not record.is_file() or record.is_symlink():
            continue
        try:
            previous = json.loads(record.read_bytes())
        except (OSError, ValueError):
            continue
        if _compatibility_matches(previous.get("compatibility"), identity["compatibility"]):
            candidates.append(old)
    return candidates


def _adopt_resumable_stage(target_root, staged, identity):
    candidates = _compatible_stage_candidates(target_root, staged, identity)
    if not candidates:
        return False
    # Keep one canonical stage.  Completed source/task artifacts from every
    # other compatible historical stage are imported lazily and validated below.
    old = max(candidates, key=_stage_score)
    _purge_apt_partial(old)
    os.rename(old, staged)
    # A sealed stage's build-identity is part of local-validation.json and must
    # never be rewritten before verification/publication. Mutable partial stages
    # may update this administrative record to the current schema.
    if not (staged / "local-validation.json").exists():
        atomic_json(staged / "build-identity.json", identity)
    print("adopted persistent resumable template stage: " + str(old) + " -> " + str(staged), flush=True)
    if len(candidates) > 1:
        print("compatible historical stages retained as resumable artifact donors", flush=True)
    return True


def guest_resources():
    return GUEST_MEMORY_MIB, GUEST_VCPUS


def guest_failure_diagnostics(image):
    """Read-only recovery of the guest's firstboot failure, including kernel OOM."""
    messages = []
    for path in ("/etc/gpt-trace-image-build-failed", "/var/log/swe-gym-lite-builder.log"):
        try:
            result = subprocess.run(
                ["virt-cat", "-a", str(image), path], capture_output=True,
                timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            messages.append(f"{path}: diagnostic unavailable: {exc}")
            continue
        if result.returncode == 0:
            messages.append(f"{path}:\n" + result.stdout.decode(errors="replace")[-6000:])
    try:
        with tempfile.TemporaryDirectory(prefix="gpt-trace-guest-journal-") as directory:
            extracted = subprocess.run(
                ["virt-copy-out", "-a", str(image), "/var/log/journal", directory],
                capture_output=True, timeout=180, check=False)
            if extracted.returncode == 0:
                journal = subprocess.run(
                    ["journalctl", "--directory", str(Path(directory) / "journal"),
                     "--no-pager", "-o", "short-iso", "-n", "2000"],
                    capture_output=True, timeout=60, check=False)
                if journal.returncode == 0:
                    lines = journal.stdout.decode(errors="replace").splitlines()
                    relevant = [line for line in lines if re.search(
                        r"oom|out of memory|killed process|failed with result|guestfs-firstboot", line, re.I)]
                    if relevant:
                        messages.append("guest system journal:\n" + "\n".join(relevant[-60:]))
    except (OSError, subprocess.TimeoutExpired) as exc:
        messages.append(f"guest journal unavailable: {exc}")
    return "\n".join(messages)[-12000:] or "no readable guest diagnostics"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    with temporary.open("w") as output:
        os.fchmod(output.fileno(), 0o444)
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def free_space(path, margin):
    free = shutil.disk_usage(path).free
    if free < margin:
        raise RuntimeError(f"host free-space safety margin reached: {free} < {margin} bytes")


def command(*args, cwd=None, timeout=3600, log=None, margin=0, monitor=None, **kwargs):
    print("+", " ".join(str(arg) for arg in args), flush=True)
    if monitor:
        free_space(monitor, margin)
    # A log file prevents unbounded QEMU/build output from filling host RAM.
    output = Path(log).open("a+b") if log else tempfile_output()
    try:
        with subprocess.Popen(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, **kwargs) as process:
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("host build command timed out")
                    if monitor:
                        free_space(monitor, margin)
                    time.sleep(1)
            except BaseException:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=15)
                raise
            if process.returncode:
                output.seek(0, os.SEEK_END)
                output.seek(max(0, output.tell()-4000))
                raise RuntimeError(f"host build command failed ({process.returncode}): {output.read().decode(errors='replace')}")
    finally:
        output.close()


def tempfile_output():
    import tempfile
    return tempfile.TemporaryFile()


def capture(*args):
    return subprocess.check_output(args, timeout=3600)


def verify_sources(inputs, mirrors):
    if len(inputs["tasks"]) != 230 or len(inputs["environments"]) != 25:
        raise RuntimeError("Lite task/environment invariants changed")
    repos = {item["repo"] for item in inputs["tasks"].values()}
    if len(repos) != 11:
        raise RuntimeError("Lite repository invariant changed")
    missing = []
    for item in inputs["tasks"].values():
        mirror = mirrors / (item["repo"].replace("/", "_") + ".git")
        status = subprocess.run(["git", "--git-dir", str(mirror), "cat-file", "-e", item["base_commit"] + "^{commit}"], capture_output=True)
        if status.returncode:
            missing.append(item["instance_id"])
    if missing:
        raise RuntimeError("missing exact Lite base commits: " + ", ".join(missing))
    # Verify the implementation-time environment snapshots against actual Git
    # objects, including upstream's ordered path-search 404s.
    for url, snapshot in inputs["snapshots"].items():
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com":
            raise RuntimeError("untrusted environment source URL")
        owner, name, commit, filename = parsed.path.lstrip("/").split("/", 3)
        mirror = mirrors / (owner + "_" + name + ".git")
        result = subprocess.run(["git", "--git-dir", str(mirror), "show", commit + ":" + filename], capture_output=True)
        if snapshot["status_code"] == 404:
            if result.returncode == 0:
                raise RuntimeError("pinned upstream path selection changed")
        elif result.returncode or result.stdout.decode("utf-8") != snapshot["text"]:
            raise RuntimeError("environment content at exact base_commit changed")
    print("source validation: tasks=230 repos=11 env_hashes=25 unmapped=0 missing_base_commits=0", flush=True)


def firstboot(body):
    # Disposable, fixed 8-GiB swap inside the QCOW2 overlay prevents guest OOM
    # while QEMU itself stays at 12288 MiB RAM / 4 vCPUs. A successfully
    # published template has no swap file and has been trimmed.
    return """#!/bin/bash
set -eo pipefail
exec >> /var/log/swe-gym-lite-builder.log 2>&1
rm -f /etc/gpt-trace-image-build-complete /etc/gpt-trace-image-build-failed
# Builder only: no persistent systemd disable or mask.
systemctl stop --no-block gpt-trace-workstation-agent.service display-manager.service 2>/dev/null || true
SWAP_FILE=/root/.gpt-trace-swe-gym-build.swap
finish() {
    rc=$?
    trap - EXIT
    if [ "$rc" -eq 0 ]; then
        if ! swapoff "$SWAP_FILE"; then
            echo 'failed to disable temporary guest swap'
            rc=1
        elif ! rm -f "$SWAP_FILE"; then
            echo 'failed to remove temporary guest swap'
            rc=1
        elif ! fstrim -av; then
            echo 'failed to reclaim temporary guest swap blocks'
            rc=1
        fi
    fi
    if [ "$rc" -eq 0 ]; then
        echo ok > /etc/gpt-trace-image-build-complete
    else
        echo "$rc" > /etc/gpt-trace-image-build-failed
    fi
    sync
    systemctl poweroff --no-block
}
trap finish EXIT
test ! -L "$SWAP_FILE"
# A failed boot leaves this exact private swap file. Reuse it on a verified
# checkpoint reboot without allocating a second 8-GiB file.
if test -e "$SWAP_FILE"; then
    test -f "$SWAP_FILE"
    test "$(stat -c %u:%a "$SWAP_FILE")" = "0:600"
    test "$(stat -c %s "$SWAP_FILE")" = "8589934592"
else
    fallocate -l 8G "$SWAP_FILE"
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE"
fi
swapon "$SWAP_FILE"
echo 'temporary guest build swap enabled: 8 GiB'
""" + body + "\n"


def root_growth():
    # cloud-guest-utils comes from the verified, locally staged .deb closure.
    return r'''
root_device=$(findmnt -n -o SOURCE /)
test "$(findmnt -n -o FSTYPE /)" = ext4
parent=$(lsblk -n -o PKNAME "$root_device")
partition=$(lsblk -n -o PARTN "$root_device")
test -n "$parent" && test -n "$partition"
if growth_output=$(growpart "/dev/$parent" "$partition" 2>&1); then
    printf '%s\n' "$growth_output"
else
    growth_rc=$?
    printf '%s\n' "$growth_output"
    # growpart returns 1 for an already full-size partition (NOCHANGE).
    # Any other error, including exit 1 without NOCHANGE, must still fail.
    if [ "$growth_rc" -ne 1 ] || [[ "$growth_output" != NOCHANGE:* ]]; then
        echo "growpart failed with exit status $growth_rc" >&2
        exit "$growth_rc"
    fi
fi
resize2fs "$root_device"
'''


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generation_identity(resolved):
    """Called only after package resolution, offline replay and disk validation."""
    return hashlib.sha256(json.dumps(resolved, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def physical_bytes(paths):
    seen, total = set(), 0
    for path in paths:
        info = path.stat()
        key = info.st_dev, info.st_ino
        if key not in seen:
            seen.add(key)
            total += info.st_blocks * 512
    return total


def make_immutable(folder):
    for path in folder.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("symlink in immutable host generation")
        path.chmod(0o555 if path.is_dir() else 0o444)
        if path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    for path in [*sorted((p for p in folder.rglob("*") if p.is_dir()), reverse=True), folder]:
        path.chmod(0o555)
        fd = os.open(path, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def install_generation(staged, target_root, manifest, validate):
    """Rename only sealed bytes; validate before a separate atomic activation."""
    generation = manifest["generation"]
    generations = target_root / "generations"
    generations.mkdir(mode=0o755, exist_ok=True)
    final = generations / generation
    if final.exists():
        raise RuntimeError("generation already exists; refusing any content replacement")
    existing_manifest = staged / "manifest.json"
    if existing_manifest.exists():
        if json.loads(existing_manifest.read_bytes()) != manifest:
            raise RuntimeError("sealed manifest differs; preserved")
    else: atomic_json(existing_manifest, manifest)
    make_immutable(staged)
    # Moving a directory between parents requires updating its '..' entry on
    # hosts without DAC override. Contents are already immutable; seal the top
    # directory again immediately after rename, before validation/activation.
    staged.chmod(0o755)
    os.rename(staged, final)
    final.chmod(0o555)
    fd = os.open(final, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(generations, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    from workstation_broker.preparation import record_built_generation
    operation_id = os.environ.get("GPT_TRACE_PREPARATION_ID")
    if operation_id is not None: record_built_generation(operation_id, generation)
    try:
        validate(final, generation)
    except BaseException:
        final.chmod(0o755)
        os.rename(final, staged)
        staged.chmod(0o555)
        for directory in (staged, generations, target_root):
            fd = os.open(directory, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        if operation_id is not None:
            from workstation_broker.preparation import record_rejected_generation
            record_rejected_generation(operation_id, generation)
        raise
    return final


def build(args):
    if os.geteuid() != 0:
        raise RuntimeError("local preparation requires the execution host root execution broker")
    from workstation_broker.preparation import verify_worker_claim
    job = verify_worker_claim(args.operation_id)
    from workstation_broker.preparation_resources import source_container_arguments
    if (args.virtual_gib, args.free_space_gib, args.build_timeout_hours) != (VIRTUAL_GIB, FREE_SPACE_GIB, BUILD_TIMEOUT_HOURS):
        raise RuntimeError("local preparation capacity/deadline differs from the versioned recipe")
    for executable in ("docker", "git", "qemu-img", "virt-customize", "virt-cat", "virt-copy-out", "qemu-system-x86_64", "dpkg-deb"):
        if shutil.which(executable) is None:
            raise RuntimeError("missing host build executable: " + executable)
    golden = load_module("swe_gym_kali_builder", ROOT / "infra/workstation/image/build.py")
    golden.require_host_build_runtime()
    from gpt_trace_transport.local_templates import compatibility, compatible_template_identity
    installed = compatibility(BASE, ROOT)
    if not compatible_template_identity(installed, job["compatibility"]):
        raise RuntimeError("installed Kali/template compatibility changed; persistent template storage preserved")
    tools = load_module("swe_gym_task_sources", GUEST.with_name("task_sources.py"))
    os_tools = load_module("swe_gym_os_packages", GUEST.with_name("os_packages.py"))
    target_root = TEMPLATES / "swe-gym-lite"
    target_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    from gpt_trace_transport.local_templates import safe
    for path in (TEMPLATES, target_root): safe(path, directory=True)
    cache_root = target_root / "build-cache"
    cache_root.mkdir(mode=0o700, exist_ok=True)
    if cache_root.is_symlink() or cache_root.stat().st_uid != 0 or cache_root.stat().st_mode & 0o077:
        raise RuntimeError("untrusted full-mirror host cache")
    with (target_root / "build.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # One deterministic resumable stage per *template identity*, not per
        # checkout/build implementation.  The operation ID is the hash of the
        # stable compatibility record, so code-only changes reuse this path.
        staged = target_root / (".build-resumable-v3-" + args.operation_id)
        identity = {"schema": 3, "compatibility": job["compatibility"]}
        if staged.exists():
            from gpt_trace_transport.local_templates import safe
            safe(staged, directory=True)
            previous = staged / "build-identity.json"
            prior_identity = json.loads(safe(previous, immutable=True).read_text())
            if not _compatibility_matches(prior_identity.get("compatibility"), identity["compatibility"]):
                raise RuntimeError("persistent template stage belongs to another template contract; "
                                   "preserved; only make throw_volumes may remove it")
            sealed_stage = (staged / "local-validation.json").exists()
            if prior_identity != identity and not sealed_stage:
                atomic_json(previous, identity)
            if sealed_stage:
                # An interrupted seal/atomic rename is recoverable without any
                # rebuild. Validate every immutable byte before publication.
                from gpt_trace_transport.local_templates import (verify_manifest,
                    verify_local_validation, activate)
                manifest = verify_manifest(staged, job["compatibility"], source_root=ROOT)
                verify_local_validation(staged, manifest, expected=job["compatibility"])
                generation = manifest["generation"]
                generations = target_root / "generations"
                generations.mkdir(mode=0o755, exist_ok=True)
                final = generations / generation
                if final.exists():
                    raise RuntimeError("sealed generation already exists; refusing replacement")
                os.rename(staged, final)
                from workstation_broker.preparation import record_built_generation
                from workstation_broker.templates import TemplateRegistry
                record_built_generation(args.operation_id, generation)
                def factory(root, base):
                    return TemplateRegistry(root, base, lambda p: json.loads(
                        subprocess.check_output(["qemu-img", "info", "--output=json", str(p)], timeout=60)),
                        source_root=ROOT)
                activate(TEMPLATES, BASE, generation, factory, ROOT)
                return final
            print("resuming verified host preparation " + args.operation_id, flush=True)
        else:
            if not _adopt_resumable_stage(target_root, staged, identity):
                staged.mkdir(mode=0o755)
                atomic_json(staged / "build-identity.json", identity)
        checkpoints = staged / ".checkpoints"
        checkpoints.mkdir(mode=0o700, exist_ok=True)
        from gpt_trace_transport.local_templates import safe
        safe(checkpoints, directory=True)
        historical_stages = _compatible_stage_candidates(target_root, staged, identity)
        scratch_root = target_root / ".scratch"
        scratch_root.mkdir(mode=0o700, exist_ok=True)
        safe(scratch_root, directory=True)

        def read_checkpoint(name):
            path = checkpoints / name
            return json.loads(safe(path, immutable=True).read_text()) if path.exists() else None

        def write_checkpoint(name, data):
            atomic_json(checkpoints / name, data)

        log = staged / "host-build.log"
        margin = args.free_space_gib * 1024**3
        free_space(staged, margin)

        def cmd(*argv, **kw):
            command(*argv, log=log, monitor=staged, margin=margin, **kw)

        def guest_json(image, path):
            return json.loads(capture("virt-cat", "-a", str(image), path))

        def guest_json_optional(image, path):
            result = subprocess.run(["virt-cat", "-a", str(image), path], capture_output=True,
                                    timeout=180, check=False)
            if result.returncode != 0:
                return None
            try:
                return json.loads(result.stdout)
            except (ValueError, UnicodeError):
                return None

        def generic_guest_complete(image):
            proof = subprocess.run(["virt-cat", "-a", str(image), "/etc/gpt-trace-image-build-complete"],
                                   capture_output=True, timeout=180, check=False)
            return proof.returncode == 0 and proof.stdout.strip() == b"ok"

        def completion_matches(image, path, expected):
            # The generic marker is inherited by every QCOW2 overlay, so it is
            # never sufficient on its own.  A stage-specific proof must also be
            # present and exactly match this build step.
            return generic_guest_complete(image) and guest_json_optional(image, path) == expected

        def overlay(image, backing):
            relative = os.path.relpath(backing, image.parent) if backing != BASE else str(BASE)
            cmd("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", relative, image.name,
                str(args.virtual_gib) + "G", cwd=image.parent)

        def reset_scratch_overlay(image, backing):
            """Reuse one fixed scratch volume path; never unlink a QCOW2."""
            if image.is_symlink() or (image.exists() and not image.is_file()):
                raise RuntimeError("unsafe scratch QCOW2 volume: " + str(image))
            image.parent.mkdir(mode=0o700, exist_ok=True)
            if image.exists():
                image.chmod(0o600)
                with image.open("r+b") as handle:
                    handle.truncate(0)
                    handle.flush()
                    os.fsync(handle.fileno())
            overlay(image, backing)

        def provision(image, boot, payload=None, *, network, completion=None):
            boot_file = staged / "firstboot.sh"
            boot_file.write_text(firstboot(boot))
            argv = ["virt-customize", "--no-network", "-a", str(image)]
            if payload is not None:
                argv += ["--copy-in", str(payload) + ":/opt"]
            cmd(*argv, "--firstboot", str(boot_file), timeout=14400)
            memory_mb, vcpus = guest_resources()
            print(f"Execution host preparation VM: RAM={memory_mb} MiB, vCPUs={vcpus}, image={image.name}", flush=True)
            argv = ["qemu-system-x86_64", "-machine", "accel=kvm", "-cpu", "host",
                    "-m", str(memory_mb), "-smp", str(vcpus),
                    "-drive", f"file={image},format=qcow2,if=virtio,cache=writeback,discard=unmap"]
            argv += ["-netdev", "user,id=net0,ipv6=off", "-device", "virtio-net-pci,netdev=net0"] if network else ["-nic", "none"]
            cmd(*argv, "-device", "virtio-rng-pci", "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot",
                timeout=args.build_timeout_hours * 3600)
            # A clean QEMU exit does not imply a successful guest firstboot.
            if not generic_guest_complete(image):
                raise RuntimeError("guest build completion proof is missing; "
                                   "firstboot diagnostics:\n" + guest_failure_diagnostics(image))
            if completion is not None:
                path, expected = completion
                if guest_json_optional(image, path) != expected:
                    raise RuntimeError("guest stage-specific completion proof is missing or differs: " + path)

        def historical_files(relative):
            for old in historical_stages:
                source = old / relative
                if not source.exists():
                    continue
                try:
                    yield safe(source, immutable=True)
                except (OSError, ValueError):
                    continue

        def mirror_for(url, name):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.netloc:
                raise RuntimeError("unsupported trusted public Git source URL")
            path = cache_root / name
            if path.is_symlink() or (path.exists() and path.stat().st_uid != 0):
                raise RuntimeError("untrusted host mirror")
            if path.exists():
                cmd("git", "--git-dir", str(path), "fetch", "--prune", "origin", timeout=14400)
            else:
                cmd("git", "clone", "--mirror", url, str(path), timeout=14400)
            return path

        def submodule_mirror(url, commit):
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.netloc:
                raise RuntimeError("unsupported trusted public Git submodule URL")
            key = "submodule-" + hashlib.sha256(url.encode()).hexdigest() + ".git"
            path = cache_root / key
            # Exact pinned commit already present: no need to re-fetch the entire
            # upstream mirror for each of the 230 task source archives.
            if path.is_dir() and not path.is_symlink() and path.stat().st_uid == 0:
                probe = subprocess.run(
                    ["git", "--git-dir", str(path), "cat-file", "-e", commit + "^{commit}"],
                    capture_output=True, timeout=60, check=False)
                if probe.returncode == 0:
                    return path
            path = mirror_for(url, key)  # Missing object: fetch then validate.
            cmd("git", "--git-dir", str(path), "cat-file", "-e", commit + "^{commit}")
            return path

        def task_boot(item, artifact, *, warm, cache=None):
            # Only this item/source/cache ever enters this scratch disk.
            body = "import runpy,json\nmodule=runpy.run_path('/opt/swe-gym-lite/runtime.py')\n"
            body += "item=json.load(open('/opt/swe-gym-task/item.json'))\n"
            body += "artifact=" + repr({**artifact, "path": "/opt/swe-gym-task/source.tar.gz"}) + "\n"
            if warm:
                body += "module['warm_task'](item,artifact)\n"
                body += "proof=module['export_setup_cache'](item,'/opt/swe-gym-task/setup-cache.tar.gz')\n"
                body += "json.dump(proof,open('/opt/swe-gym-task/cache-proof.json','w'),sort_keys=True)\n"
                completion = {"schema": 1, "kind": "task-warm", "logical_task_id": item["instance_id"],
                              "cache_format": 2}
            else:
                delivered = {**cache, "path": "/opt/swe-gym-task/setup-cache.tar.gz"}
                if cache.get("cache_format") == 2:
                    delivered["wheel_store"] = "/opt/swe-gym-task/wheel-cas"
                body += "cache=" + repr(delivered) + "\n"
                body += "module['install_setup_cache'](item,cache)\n"
                body += "prefix=module['prepare'](item,artifact=artifact,log=module['ROOT']/'logs/offline.log')\n"
                body += "module['evaluation_setup'](item,prefix,item['eval_setup_commands'],module['ROOT']/'logs')\n"
                body += "json.dump({'base_commit':item['base_commit'],'env_hash':item['env_hash'],'offline':True},open('/opt/swe-gym-task/offline-proof.json','w'))\n"
                completion = {"schema": 1, "kind": "task-replay", "logical_task_id": item["instance_id"],
                              "cache_format": cache.get("cache_format", 1), "cache_sha256": cache["sha256"]}
            body += "json.dump(" + repr(completion) + ",open('" + TASK_COMPLETION + "','w'),sort_keys=True)\n"
            return "/usr/bin/python3 - <<'PY_GUEST'\n" + body + "PY_GUEST\n", completion

        try:
            inputs_root = staged / "build-inputs"
            inputs_root.mkdir(exist_ok=True)
            # execution host has no control-plane deployment,
            # credentials, Compose services or persistent campaign volumes.
            # Build only a source-fetch image and bind its private build cache.
            image = "gpt-trace-lite-local-source:" + digest(PINS)[:32]
            if not (inputs_root / "inputs.json").is_file():
                cmd("docker", "build", "--label", "io.gpttrace.local-preparation=source-fetch", "-t", image,
                    "-f", "apps/runner/Dockerfile", ".", cwd=ROOT, timeout=14400)
                source_cache = cache_root / "dataset"
                source_cache.mkdir(mode=0o700, exist_ok=True)
                cmd("docker", "run", "--rm", *source_container_arguments(job), "--network", "bridge", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true", "--entrypoint", "python",
                    "--mount", "type=bind,source=" + str(inputs_root) + ",target=/build-inputs",
                    "--mount", "type=bind,source=" + str(source_cache) + ",target=/source-cache",
                    image, "-m", "gpt_trace_runner.superbench.adapters.swe_gym.source",
                    "--export", "/build-inputs", "--source-root", "/source-cache", cwd=ROOT)
            inputs = json.loads((inputs_root / "inputs.json").read_text())
            pins = json.loads(PINS.read_text())
            if inputs["pins"] != pins or pins["recipe_version"] != 2 or pins["schema_version"] != 2:
                raise RuntimeError("host/fetch container recipe differs; rebuild the runner image")
            repos_set = sorted({item["repo"] for item in inputs["tasks"].values()})
            for repo in repos_set:
                mirror = cache_root / (repo.replace("/", "_") + ".git")
                bases = [row["base_commit"] for row in inputs["tasks"].values() if row["repo"] == repo]
                if mirror.is_dir() and not mirror.is_symlink() and mirror.stat().st_uid == 0 and all(
                        subprocess.run(["git", "--git-dir", str(mirror), "cat-file", "-e", sha + "^{commit}"],
                            capture_output=True, timeout=60).returncode == 0 for sha in bases):
                    continue
                mirror_for("https://github.com/" + repo + ".git", repo.replace("/", "_") + ".git")
            verify_sources(inputs, cache_root)
            source_folder, cache_folder, wheel_cas, audit = (staged / "sources", staged / "setup-caches",
                                                               staged / "wheel-cas", staged / "audit")
            for folder in (source_folder, cache_folder, wheel_cas, audit): folder.mkdir(exist_ok=True)
            artifacts, mapping = {}, {}

            def checked_wheel_files(value):
                if not isinstance(value, dict) or len(value) > 4096:
                    raise RuntimeError("invalid task wheel manifest")
                checked = {}
                for name, record in sorted(value.items()):
                    if (not isinstance(name, str) or not name or name in {".", ".."} or
                            name != Path(name).name or "/" in name or "\\" in name or "\x00" in name):
                        raise RuntimeError("invalid task wheel filename")
                    if (not isinstance(record, dict) or set(record) != {"sha256", "size"} or
                            re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None or
                            type(record.get("size")) is not int or not 0 <= record["size"] <= 2**43):
                        raise RuntimeError("invalid task wheel integrity record")
                    checked[name] = {"sha256": record["sha256"], "size": record["size"]}
                return checked

            def verify_wheel_object(path, sha, size):
                return (path.is_file() and not path.is_symlink() and path.stat().st_size == size and
                        digest(path) == sha)

            def import_wheel_cas(image, logical, proof):
                if proof.get("cache_format") != 2:
                    raise RuntimeError("warm task did not produce content-addressed setup cache")
                wheels = checked_wheel_files(proof.get("wheel_files"))
                unique = {}
                for record in wheels.values():
                    previous = unique.setdefault(record["sha256"], record["size"])
                    if previous != record["size"]:
                        raise RuntimeError("wheel SHA-256 size collision")
                missing = {sha: size for sha, size in unique.items()
                           if not verify_wheel_object(wheel_cas / sha, sha, size)}
                if not missing:
                    return wheels
                with tempfile.TemporaryDirectory(dir=cache_folder, prefix=".wheel-export-") as temporary:
                    cmd("virt-copy-out", "-a", str(image),
                        "/opt/swe-gym-lite/wheelhouse/" + logical, temporary)
                    exported = Path(temporary) / logical
                    if exported.is_symlink() or not exported.is_dir():
                        raise RuntimeError("task wheel export is missing")
                    actual = {path.name for path in exported.iterdir()}
                    if actual != set(wheels):
                        raise RuntimeError("task wheel export population differs from proof")
                    for filename, record in wheels.items():
                        source = exported / filename
                        sha, size = record["sha256"], record["size"]
                        if not verify_wheel_object(source, sha, size):
                            raise RuntimeError("task wheel changed during export")
                        target = wheel_cas / sha
                        if target.exists():
                            if not verify_wheel_object(target, sha, size):
                                raise RuntimeError("persisted wheel CAS object changed")
                            continue
                        source.chmod(0o444)
                        os.link(source, target)
                        with target.open("rb") as stream:
                            os.fsync(stream.fileno())
                    fd = os.open(wheel_cas, os.O_DIRECTORY)
                    try: os.fsync(fd)
                    finally: os.close(fd)
                return wheels

            def stage_task_wheels(incoming, cache_record):
                cache_format = cache_record.get("cache_format", 1)
                if type(cache_format) is not int:
                    raise RuntimeError("unsupported persisted setup-cache format")
                if cache_format != 2:
                    return
                wheels = checked_wheel_files(cache_record.get("wheel_files"))
                folder = incoming / "wheel-cas"
                folder.mkdir()
                unique = {}
                for record in wheels.values():
                    sha, size = record["sha256"], record["size"]
                    previous = unique.setdefault(sha, size)
                    if previous != size:
                        raise RuntimeError("wheel SHA-256 size collision")
                for sha, size in unique.items():
                    source = wheel_cas / sha
                    if not verify_wheel_object(source, sha, size):
                        raise RuntimeError("persisted wheel CAS object changed")
                    os.link(source, folder / sha)
            for logical, item in sorted(inputs["tasks"].items()):
                free_space(staged, margin)
                key = tools.artifact_id("task_source", logical)
                output = source_folder / (key + ".tar.gz")
                record = read_checkpoint("source-" + key + ".json")
                if record is not None:
                    tools.validate_artifact(item, output, record)
                    print("reused verified source: " + logical, flush=True)
                else:
                    if not output.exists():
                        relative_source = Path("sources") / (key + ".tar.gz")
                        for donor in historical_files(relative_source):
                            os.link(donor, output)
                            try:
                                with tempfile.TemporaryDirectory(dir=output.parent, prefix=".recover-source-") as temporary:
                                    checkout = Path(temporary) / "checkout"
                                    integrity = {"sha256": digest(output), "size": output.stat().st_size}
                                    tools.extract(output, checkout, **integrity)
                                    proof = tools.validate_checkout(checkout, item["base_commit"])
                                record = {**integrity, "kind": "task_source", "logical_task_id": item["instance_id"],
                                    "allowed_template_id": item["template_id"],
                                    "source_identity": {name: item[name] for name in ("instance_id", "repo", "base_commit")},
                                    "validation": proof}
                                tools.validate_artifact(item, output, record)
                            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                                output.unlink(missing_ok=True)
                                record = None
                                continue
                            output.chmod(0o444)
                            write_checkpoint("source-" + key + ".json", record)
                            print("reused compatible historical source: " + logical, flush=True)
                            break
                    if record is None and output.exists():
                        if output.is_symlink() or not output.is_file():
                            raise RuntimeError("unsafe orphan task source archive; preserved")
                        with tempfile.TemporaryDirectory(dir=output.parent, prefix=".recover-source-") as temporary:
                            checkout = Path(temporary) / "checkout"
                            integrity = {"sha256": digest(output), "size": output.stat().st_size}
                            tools.extract(output, checkout, **integrity)
                            proof = tools.validate_checkout(checkout, item["base_commit"])
                        record = {**integrity, "kind": "task_source", "logical_task_id": item["instance_id"],
                            "allowed_template_id": item["template_id"],
                            "source_identity": {name: item[name] for name in ("instance_id", "repo", "base_commit")},
                            "validation": proof}
                        tools.validate_artifact(item, output, record)
                        output.chmod(0o444)
                        write_checkpoint("source-" + key + ".json", record)
                        print("recovered orphan verified source: " + logical, flush=True)
                    if record is None:
                        record = tools.build_artifact(item, cache_root / (item["repo"].replace("/", "_") + ".git"), output,
                                                      submodule_mirror=submodule_mirror)
                        output.chmod(0o444)
                        tools.validate_artifact(item, output, record)
                        write_checkpoint("source-" + key + ".json", record)
                artifacts[key] = {**record, "path": output.relative_to(staged).as_posix()}
                mapping[logical] = {"template_id": item["template_id"], "task_source": key,
                                    "setup_cache": tools.artifact_id("setup_cache", logical)}

            # Golden provenance exposes kali-last-snapshot, a mutable alias,
            # not an immutable snapshot ID. Resolve in one persistent resumable
            # resolver volume; never recreate it merely because a host copy-out
            # was interrupted.
            resolver = cache_root / "os-resolver.qcow2"
            os_parent = staged / "os"
            os_folder = os_parent / "swe-gym-os"
            resolver_completion = {"schema": 1, "kind": "os-resolver",
                "source_fingerprint": inputs["source_fingerprint"]}
            if (os_folder / "manifest.json").is_file():
                os_manifest = json.loads((os_folder / "manifest.json").read_text())
                os_tools.verify_artifacts(os_folder, os_manifest)
                print("reused verified OS package closure", flush=True)
            else:
                _purge_apt_partial(staged)
                if not resolver.exists():
                    overlay(resolver, BASE)
                elif resolver.is_symlink() or not resolver.is_file():
                    raise RuntimeError("unsafe persistent OS resolver volume; preserved")
                legacy_resolver_complete = (generic_guest_complete(resolver) and
                    isinstance(guest_json_optional(resolver, "/opt/swe-gym-os/manifest.json"), dict))
                resolver_ready = completion_matches(resolver, RESOLVER_COMPLETION, resolver_completion) or legacy_resolver_complete
                if not resolver_ready:
                    # resolve() is intentionally not idempotent.  Keep the QCOW2
                    # volume itself and clear only its incomplete guest scratch.
                    cmd("virt-customize", "--no-network", "-a", str(resolver),
                        "--run-command", "rm -rf /opt/swe-gym-os /opt/swe-gym-os-helper " + RESOLVER_COMPLETION,
                        timeout=14400)
                    os_payload = staged / "swe-gym-os-helper"
                    if os_payload.exists():
                        shutil.rmtree(os_payload)
                    os_payload.mkdir()
                    shutil.copyfile(GUEST.with_name("os_packages.py"), os_payload / "os_packages.py")
                    resolver_boot = "/usr/bin/python3 - <<'PY_GUEST'\nimport runpy,json\n"
                    resolver_boot += "runpy.run_path('/opt/swe-gym-os-helper/os_packages.py')['resolve']('/opt/swe-gym-os')\n"
                    resolver_boot += "json.dump(" + repr(resolver_completion) + ",open('" + RESOLVER_COMPLETION + "','w'),sort_keys=True)\nPY_GUEST\n"
                    provision(resolver, resolver_boot, os_payload, network=True,
                        completion=(RESOLVER_COMPLETION, resolver_completion))
                    shutil.rmtree(os_payload)
                else:
                    print("reused verified persistent OS resolver volume", flush=True)
                if os_parent.exists():
                    # Host-side copy-out scratch only; the resolver QCOW2 is kept.
                    shutil.rmtree(os_parent)
                os_parent.mkdir()
                cmd("virt-copy-out", "-a", str(resolver), "/opt/swe-gym-os", str(os_parent))
                os_manifest = json.loads((os_folder / "manifest.json").read_text())
                os_tools.verify_artifacts(os_folder, os_manifest)

            # The OS closure is checked; APT's _apt-owned partial download
            # directory is neither a dependency nor a reusable checkpoint.
            _purge_apt_partial(staged)
            payload = staged / "swe-gym-build"
            _discard(payload)
            payload.mkdir()
            for name in ("runtime.py", "task_sources.py", "os_packages.py"):
                shutil.copyfile(GUEST if name == "runtime.py" else GUEST.with_name(name), payload / name)
            (payload / "environments.json").write_text(json.dumps({"environments": inputs["environments"]}, sort_keys=True))
            shutil.copytree(os_folder, payload / "os-artifacts")
            installer = payload / "miniconda.sh"
            cache_installer = cache_root / ("miniconda-" + MINICONDA_SHA256 + ".sh")
            if cache_installer.exists():
                from gpt_trace_transport.local_templates import safe
                safe(cache_installer)
                if digest(cache_installer) != MINICONDA_SHA256:
                    raise RuntimeError("cached Miniconda digest mismatch")
            else:
                for attempt in range(1, 11):
                    partial = cache_installer.with_suffix(".part")
                    _discard(partial)
                    try:
                        with urllib.request.urlopen("https://repo.anaconda.com/miniconda/" + MINICONDA, timeout=180) as response, partial.open("wb") as output:
                            while chunk := response.read(1048576):
                                output.write(chunk)
                                free_space(staged, margin)
                        if digest(partial) != MINICONDA_SHA256:
                            raise RuntimeError("pinned Miniconda installer digest mismatch")
                        partial.chmod(0o444)
                        os.replace(partial, cache_installer)
                        break
                    except (OSError, TimeoutError) as exc:
                        if attempt == 10: raise RecoverableBuildError("Miniconda download interrupted") from exc
                        time.sleep(min(90, 3 * 2 ** min(attempt - 1, 5)))
            shutil.copyfile(cache_installer, installer)
            common = staged / "common.qcow2"
            initial_common = not common.exists()
            if initial_common:
                overlay(common, BASE)
            common_completion = {"schema": 1, "kind": "common",
                "template_abi": job["compatibility"]["template_abi"],
                "source_fingerprint": inputs["source_fingerprint"]}
            marker_line = "json.dump(" + repr(common_completion) + ",open('" + COMMON_COMPLETION + "','w'),sort_keys=True)\n"
            boot = r'''
mkdir -p /opt/swe-gym-lite
cp /opt/swe-gym-build/runtime.py /opt/swe-gym-build/task_sources.py /opt/swe-gym-build/os_packages.py /opt/swe-gym-lite/
cp /opt/swe-gym-build/environments.json /opt/swe-gym-lite/build-environments.json
cp /opt/swe-gym-build/os-artifacts/manifest.json /opt/swe-gym-lite/os-manifest.json
/usr/bin/python3 - <<'PY_GUEST'
import runpy,json
module=runpy.run_path('/opt/swe-gym-lite/os_packages.py')
module['install']('/opt/swe-gym-build/os-artifacts',json.load(open('/opt/swe-gym-lite/os-manifest.json')))
PY_GUEST
''' + root_growth() + r'''
test ! -e /opt/miniconda3
bash /opt/swe-gym-build/miniconda.sh -b -p /opt/miniconda3
rm -rf /opt/swe-gym-build
/usr/bin/python3 - <<'PY_GUEST'
import runpy,json
module=runpy.run_path('/opt/swe-gym-lite/runtime.py')
module['build_common'](json.load(open('/opt/swe-gym-lite/build-environments.json')))
json.dump(module['validate_isolation'](),open('/opt/swe-gym-lite/isolation-validation.json','w'))
''' + marker_line + r'''PY_GUEST
'''
            boot_resume = r'''
/usr/bin/python3 - <<'PY_GUEST'
import runpy,json
module=runpy.run_path('/opt/swe-gym-lite/runtime.py')
module['build_common'](json.load(open('/opt/swe-gym-lite/build-environments.json')))
json.dump(module['validate_isolation'](),open('/opt/swe-gym-lite/isolation-validation.json','w'))
''' + marker_line + r'''PY_GUEST
'''
            clean_isolation = {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}
            legacy_common_complete = False
            if not initial_common and generic_guest_complete(common):
                try:
                    legacy_common_complete = (
                        guest_json(common, "/opt/swe-gym-lite/build-environments.json") ==
                            {"environments": inputs["environments"]}
                        and guest_json(common, "/opt/swe-gym-lite/isolation-validation.json") == clean_isolation
                        and isinstance(guest_json(common, "/opt/swe-gym-lite/environment-cache-provenance.json"), dict)
                        and all(isinstance(guest_json(common, "/opt/swe-gym-lite/environments/" + key + ".json"), dict)
                                for key in inputs["environments"]))
                except (OSError, ValueError, subprocess.SubprocessError):
                    legacy_common_complete = False
            common_ready = completion_matches(common, COMMON_COMPLETION, common_completion) or legacy_common_complete

            def refresh_common_runtime():
                source = subprocess.run(["virt-cat", "-a", str(common), "/opt/swe-gym-lite/runtime.py"],
                    capture_output=True, timeout=180, check=False)
                current = digest(GUEST)
                if source.returncode == 0 and hashlib.sha256(source.stdout).hexdigest() == current:
                    return
                # Runtime implementation changes do not invalidate the 25 frozen
                # Conda environment checkpoints. Replace only the trusted helper
                # bytes and keep the expensive common image contents in place.
                original_mode = stat.S_IMODE(common.stat().st_mode)
                common.chmod(0o600)
                try:
                    cmd("virt-customize", "--no-network", "-a", str(common),
                        "--copy-in", str(GUEST) + ":/opt/swe-gym-lite", timeout=14400)
                    updated = subprocess.check_output(["virt-cat", "-a", str(common),
                        "/opt/swe-gym-lite/runtime.py"], timeout=180)
                    if hashlib.sha256(updated).hexdigest() != current:
                        raise RuntimeError("common runtime update did not verify")
                finally:
                    common.chmod(original_mode)

            if common_ready:
                refresh_common_runtime()
                subprocess.run(["qemu-img", "check", str(common)], check=True, timeout=3600)
                print("reused verified complete common QCOW2", flush=True)
            else:
                # A generic base-image marker is never accepted as common proof.
                # Resume verified Conda checkpoints in-place; otherwise reset only
                # incomplete guest directories, never the QCOW2 volume itself.
                has_conda = (not initial_common and subprocess.run(
                    ["virt-cat", "-a", str(common), "/opt/miniconda3/bin/conda"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180).returncode == 0)
                if has_conda:
                    refresh_common_runtime()
                else:
                    if not initial_common:
                        cmd("virt-customize", "--no-network", "-a", str(common),
                            "--run-command", "rm -rf /opt/miniconda3 /opt/swe-gym-lite /opt/swe-gym-build",
                            timeout=14400)
                    print("resuming incomplete common QCOW2 in place before Miniconda checkpoint", flush=True)
                try:
                    provision(common, boot_resume if has_conda else boot,
                              None if has_conda else payload, network=True,
                              completion=(COMMON_COMPLETION, common_completion))
                except RuntimeError as exc:
                    if _transient_failure(exc):
                        raise RecoverableBuildError("transient guest download; common checkpoint retained: " + str(exc)) from exc
                    raise
            shutil.rmtree(payload)
            common.chmod(0o444)
            environments = {key: guest_json(common, "/opt/swe-gym-lite/environments/" + key + ".json") for key in inputs["environments"]}
            common_cache = guest_json(common, "/opt/swe-gym-lite/environment-cache-provenance.json")
            atomic_json(audit / "environment-inventories.json", environments)
            atomic_json(audit / "environment-downloads.json", common_cache)
            common_validation = guest_json(common, "/opt/swe-gym-lite/isolation-validation.json")
            if common_validation != {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}:
                raise RuntimeError("common image leaked source state")

            # One pair of scratch QCOW2s is reused across all 230 tasks and across
            # retries.  They live outside the staged generation, so a successful
            # publication never needs to delete a volume.  Migrate the historical
            # in-stage scratch pair once if an interrupted old builder left it there.
            for scratch_name in ("task-warm.qcow2", "task-replay.qcow2"):
                legacy = staged / scratch_name
                current_scratch = scratch_root / scratch_name
                if legacy.exists() or legacy.is_symlink():
                    if legacy.is_symlink() or not legacy.is_file():
                        raise RuntimeError("unsafe legacy scratch volume; preserved")
                    if current_scratch.exists() or current_scratch.is_symlink():
                        raise RuntimeError("duplicate scratch QCOW2 volumes exist; preserved; only make throw_volumes may erase them")
                    legacy.chmod(0o600)
                    os.rename(legacy, current_scratch)
                    relative = os.path.relpath(common, current_scratch.parent)
                    cmd("qemu-img", "rebase", "-u", "-f", "qcow2", "-F", "qcow2",
                        "-b", relative, str(current_scratch), timeout=3600)
                    print("migrated persistent task scratch volume: " + scratch_name, flush=True)

            def scratch_uses_common(image):
                if image.is_symlink() or not image.is_file():
                    return False
                try:
                    info = json.loads(capture("qemu-img", "info", "--output=json", str(image)))
                except (OSError, ValueError, subprocess.SubprocessError):
                    return False
                backing_name = info.get("full-backing-filename") or info.get("backing-filename")
                if not backing_name:
                    return False
                backing_path = Path(backing_name) if Path(backing_name).is_absolute() else image.parent / backing_name
                return info.get("format") == "qcow2" and backing_path.resolve() == common.resolve()

            def ensure_cache_wheels(cache_record, stage):
                cache_format = cache_record.get("cache_format", 1)
                if type(cache_format) is not int:
                    raise RuntimeError("unsupported persisted setup-cache format")
                if cache_format == 1:
                    return
                if cache_format != 2:
                    raise RuntimeError("unsupported persisted setup-cache format")
                wheels = checked_wheel_files(cache_record.get("wheel_files"))
                unique = {}
                for record in wheels.values():
                    sha, size = record["sha256"], record["size"]
                    previous = unique.setdefault(sha, size)
                    if previous != size:
                        raise RuntimeError("wheel SHA-256 size collision")
                source_root = stage / "wheel-cas"
                for sha, size in unique.items():
                    source = source_root / sha
                    if not verify_wheel_object(source, sha, size):
                        raise RuntimeError("verified task wheel CAS object changed")
                    if stage == staged:
                        continue
                    target = wheel_cas / sha
                    if target.exists():
                        if not verify_wheel_object(target, sha, size):
                            raise RuntimeError("current wheel CAS conflicts with historical checkpoint; preserved")
                    else:
                        os.link(source, target)

            def recover_historical_task(logical, item, source_record, ckpt_name):
                if (checkpoints / ckpt_name).exists():
                    return False
                key = mapping[logical]["setup_cache"]
                expected_relative = Path("setup-caches") / (key + ".tar.gz")
                for old in historical_stages:
                    old_checkpoint = old / ".checkpoints" / ckpt_name
                    if not old_checkpoint.exists():
                        continue
                    try:
                        done = json.loads(safe(old_checkpoint, immutable=True).read_bytes())
                        cache_record = done["cache_record"]
                        if (done.get("logical_task_id") != logical or
                                cache_record.get("kind") != "setup_cache" or
                                cache_record.get("logical_task_id") != logical or
                                cache_record.get("allowed_template_id") != item["template_id"] or
                                cache_record.get("source_identity") != source_record["source_identity"] or
                                Path(cache_record.get("path", "")) != expected_relative or
                                done.get("offline") != {"base_commit": item["base_commit"],
                                                        "env_hash": item["env_hash"], "offline": True} or
                                not isinstance(done.get("inventories"), dict) or
                                not isinstance(done.get("vcs"), list)):
                            continue
                        old_archive = safe(old / expected_relative, immutable=True)
                        if (old_archive.stat().st_size != cache_record.get("size") or
                                digest(old_archive) != cache_record.get("sha256")):
                            continue
                        ensure_cache_wheels(cache_record, old)
                        old_downloads = safe(old / "audit" / (key + ".downloads.json"), immutable=True)
                        if not isinstance(json.loads(old_downloads.read_bytes()), dict):
                            continue
                    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                        continue
                    archive = staged / expected_relative
                    if archive.exists():
                        if (archive.is_symlink() or not archive.is_file() or
                                archive.stat().st_size != cache_record["size"] or
                                digest(archive) != cache_record["sha256"]):
                            raise RuntimeError("current setup-cache artifact conflicts with a verified historical checkpoint; preserved")
                    else:
                        os.link(old_archive, archive)
                    downloads = audit / (key + ".downloads.json")
                    if downloads.exists():
                        if downloads.is_symlink() or digest(downloads) != digest(old_downloads):
                            raise RuntimeError("current setup-cache provenance conflicts with a verified historical checkpoint; preserved")
                    else:
                        os.link(old_downloads, downloads)
                    write_checkpoint(ckpt_name, done)
                    print("reused verified task from compatible historical stage: " + logical, flush=True)
                    return True
                return False

            offline_proofs, vcs_provenance, task_inventories = {}, {}, {}
            warm = scratch_root / "task-warm.qcow2"
            replay = scratch_root / "task-replay.qcow2"
            incoming = scratch_root / "swe-gym-task"
            for logical, item in sorted(inputs["tasks"].items()):
                free_space(staged, margin)
                source_record = artifacts[mapping[logical]["task_source"]]
                ckpt_name = "task-" + tools.artifact_id("task_source", logical) + ".json"
                recover_historical_task(logical, item, source_record, ckpt_name)
                done = read_checkpoint(ckpt_name)
                if done is not None:
                    cache_record = done["cache_record"]
                    archive = staged / cache_record["path"]
                    if (done.get("logical_task_id") != logical or
                            cache_record["kind"] != "setup_cache" or
                            cache_record["source_identity"] != source_record["source_identity"] or
                            archive.is_symlink() or not archive.is_file() or
                            digest(archive) != cache_record["sha256"] or
                            archive.stat().st_size != cache_record["size"] or
                            done["offline"] != {"base_commit": item["base_commit"],
                                                "env_hash": item["env_hash"], "offline": True}):
                        raise RuntimeError("verified task checkpoint changed; refusing unsafe reuse")
                    ensure_cache_wheels(cache_record, staged)
                    artifacts[mapping[logical]["setup_cache"]] = cache_record
                    vcs_provenance[logical] = done["vcs"]
                    task_inventories[logical] = done["inventories"]
                    offline_proofs[logical] = done["offline"]
                    print("reused verified task: " + logical, flush=True)
                    continue

                _discard(incoming)
                incoming.mkdir(mode=0o700)
                (incoming / "item.json").write_text(json.dumps(item))
                shutil.copyfile(staged / source_record["path"], incoming / "source.tar.gz")

                warm_boot, warm_completion = task_boot(item, source_record, warm=True)
                legacy_warm_ready = False
                if scratch_uses_common(warm) and generic_guest_complete(warm):
                    old_proof = guest_json_optional(warm, "/opt/swe-gym-task/cache-proof.json")
                    legacy_warm_ready = (guest_json_optional(warm, "/opt/swe-gym-task/item.json") == item and
                                         isinstance(old_proof, dict) and old_proof.get("cache_format") == 2)
                warm_ready = (scratch_uses_common(warm) and
                              completion_matches(warm, TASK_COMPLETION, warm_completion)) or legacy_warm_ready
                if warm_ready:
                    print("reused completed task warm scratch: " + logical, flush=True)
                else:
                    reset_scratch_overlay(warm, common)
                    provision(warm, warm_boot, incoming, network=True,
                              completion=(TASK_COMPLETION, warm_completion))
                proof = guest_json(warm, "/opt/swe-gym-task/cache-proof.json")
                wheels = import_wheel_cas(warm, logical, proof)
                key = mapping[logical]["setup_cache"]
                archive = cache_folder / (key + ".tar.gz")
                if not (archive.is_file() and not archive.is_symlink() and
                        archive.stat().st_size == proof.get("size") and digest(archive) == proof.get("sha256")):
                    if archive.exists() or archive.is_symlink():
                        _discard(archive)
                    exported = cache_folder / (".export-" + key)
                    if exported.exists():
                        shutil.rmtree(exported)
                    exported.mkdir()
                    cmd("virt-copy-out", "-a", str(warm), "/opt/swe-gym-task/setup-cache.tar.gz", str(exported))
                    (exported / "setup-cache.tar.gz").rename(archive)
                    exported.rmdir()
                if digest(archive) != proof["sha256"] or archive.stat().st_size != proof["size"]:
                    raise RuntimeError("task setup cache changed during export")
                cache_record = {"kind": "setup_cache", "logical_task_id": logical, "allowed_template_id": item["template_id"],
                                "source_identity": source_record["source_identity"], "sha256": proof["sha256"], "size": proof["size"],
                                "path": archive.relative_to(staged).as_posix(), "cache_format": 2, "wheel_files": wheels}
                artifacts[key] = cache_record
                atomic_json(audit / (key + ".downloads.json"), proof["files"])
                vcs_provenance[logical] = guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".vcs.json")
                task_inventories[logical] = {
                    "repo_setup": guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".setup.json"),
                    "eval_setup": guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".json")}
                archive.chmod(0o444)
                shutil.copyfile(archive, incoming / "setup-cache.tar.gz")
                stage_task_wheels(incoming, cache_record)

                replay_boot, replay_completion = task_boot(item, source_record, warm=False, cache=cache_record)
                expected_offline = {"base_commit": item["base_commit"], "env_hash": item["env_hash"], "offline": True}
                replay_ready = (scratch_uses_common(replay) and
                                completion_matches(replay, TASK_COMPLETION, replay_completion))
                if replay_ready:
                    print("reused completed task replay scratch: " + logical, flush=True)
                else:
                    reset_scratch_overlay(replay, common)
                    provision(replay, replay_boot, incoming, network=False,
                              completion=(TASK_COMPLETION, replay_completion))
                offline_proofs[logical] = guest_json(replay, "/opt/swe-gym-task/offline-proof.json")
                if offline_proofs[logical] != {"base_commit": item["base_commit"], "env_hash": item["env_hash"], "offline": True}:
                    raise RuntimeError("fresh task replay proof differs from exact base/environment")
                write_checkpoint(ckpt_name, {"logical_task_id": logical,
                    "cache_record": cache_record, "vcs": vcs_provenance[logical],
                    "inventories": task_inventories[logical], "offline": offline_proofs[logical]})
                # Scratch disks remain at two fixed paths and are reset in-place for
                # the next task; no QCOW2 volume is ever unlinked here.
                shutil.rmtree(incoming)
            atomic_json(audit / "task-inventories.json", task_inventories)
            atomic_json(audit / "vcs-provenance.json", vcs_provenance)
            atomic_json(audit / "offline-setups.json", offline_proofs)

            repos = staged / "repos"
            repos.mkdir(exist_ok=True)
            templates, isolations = {}, {"common": common_validation}
            base_record = {"path": str(BASE), "sha256": digest(BASE)}
            common_record = {"path": "common.qcow2", "sha256": digest(common)}
            for repo in repos_set:
                image = repos / (repo.replace("/", "_") + ".qcow2")
                repo_completion = {"schema": 1, "kind": "repository", "repo": repo,
                    "template_abi": job["compatibility"]["template_abi"],
                    "source_fingerprint": inputs["source_fingerprint"]}
                ready = False
                if image.exists():
                    if image.is_symlink() or not image.is_file():
                        raise RuntimeError("unsafe persistent repository image; preserved")
                    info = json.loads(capture("qemu-img", "info", "--output=json", str(image)))
                    backing_name = info.get("full-backing-filename") or info.get("backing-filename")
                    backing_path = Path(backing_name) if backing_name and Path(backing_name).is_absolute() else image.parent / str(backing_name)
                    if info.get("format") != "qcow2" or not backing_name or backing_path.resolve() != common.resolve():
                        raise RuntimeError("existing repository volume has another backing; preserved; use make throw_volumes")
                    legacy_repo_complete = False
                    if generic_guest_complete(image):
                        try:
                            legacy_repo_complete = (
                                guest_json(image, "/opt/swe-gym-lite/repo.json") ==
                                    {"repo": repo, "template_id": "swe-gym-lite/" + repo.replace("/", "_")}
                                and guest_json(image, "/opt/swe-gym-lite/isolation-validation.json") == common_validation)
                        except (OSError, ValueError, subprocess.SubprocessError):
                            legacy_repo_complete = False
                    ready = completion_matches(image, REPO_COMPLETION, repo_completion) or legacy_repo_complete
                if ready:
                    subprocess.run(["qemu-img", "check", str(image)], check=True, timeout=3600)
                    print("reused verified repository image " + repo, flush=True)
                else:
                    if not image.exists():
                        overlay(image, common)
                    boot = "/usr/bin/python3 - <<'PY_GUEST'\nimport runpy,json\nmodule=runpy.run_path('/opt/swe-gym-lite/runtime.py')\n"
                    boot += "module['build_repo']({}," + repr(repo) + ")\n"
                    boot += "json.dump(module['validate_isolation'](),open('/opt/swe-gym-lite/isolation-validation.json','w'))\n"
                    boot += "json.dump(" + repr(repo_completion) + ",open('" + REPO_COMPLETION + "','w'),sort_keys=True)\nPY_GUEST\n"
                    provision(image, boot, network=False, completion=(REPO_COMPLETION, repo_completion))
                image.chmod(0o444)
                isolations[repo] = guest_json(image, "/opt/swe-gym-lite/isolation-validation.json")
                if isolations[repo] != common_validation:
                    raise RuntimeError("repository template leaked source or mirror state")
                templates["swe-gym-lite/" + repo.replace("/", "_")] = {"chain": [
                    {"path": image.relative_to(staged).as_posix(), "sha256": digest(image)}, common_record, base_record]}
            sizes = {}
            for image in [common, *sorted(repos.glob("*.qcow2"))]:
                chain = json.loads(capture("qemu-img", "info", "--backing-chain", "--output=json", str(image)))
                expected = [image, BASE] if image == common else [image, common, BASE]
                if len(chain) != len(expected) or any(row.get("format") != "qcow2" or Path(row["filename"]).resolve() != path.resolve()
                                                      for row, path in zip(chain, expected, strict=True)):
                    raise RuntimeError("QCOW2 backing chain failed validation")
                cmd("qemu-img", "check", str(image))
                sizes[image.relative_to(staged).as_posix()] = {"virtual_bytes": chain[0]["virtual-size"], "physical_bytes": image.stat().st_blocks * 512}
            for logical, item in inputs["tasks"].items():
                record = artifacts[mapping[logical]["task_source"]]
                tools.validate_artifact(item, staged / record["path"], record)
            if len(mapping) != 230 or len(templates) != 11 or len(environments) != 25 or len(offline_proofs) != 230:
                raise RuntimeError("final task/template/environment/replay coverage changed")

            referenced_wheels = {}
            wheel_reference_bytes = 0
            for record in artifacts.values():
                if record.get("kind") != "setup_cache" or record.get("cache_format", 1) != 2:
                    continue
                for wheel in checked_wheel_files(record.get("wheel_files")).values():
                    sha, size = wheel["sha256"], wheel["size"]
                    previous = referenced_wheels.setdefault(sha, size)
                    if previous != size:
                        raise RuntimeError("wheel SHA-256 size collision")
                    wheel_reference_bytes += size
            for path in list(wheel_cas.iterdir()):
                if path.is_symlink() or not path.is_file() or re.fullmatch(r"[0-9a-f]{64}", path.name) is None:
                    raise RuntimeError("unexpected wheel CAS entry")
                if path.name not in referenced_wheels:
                    path.unlink()
            wheel_cas_manifest = {}
            for sha, size in sorted(referenced_wheels.items()):
                path = wheel_cas / sha
                if not verify_wheel_object(path, sha, size):
                    raise RuntimeError("final wheel CAS object differs")
                path.chmod(0o444)
                wheel_cas_manifest[sha] = {"path": path.relative_to(staged).as_posix(),
                                           "sha256": sha, "size": size}

            from workstation_broker.templates import SECURITY_CONTRACT, TemplateRegistry
            resolved = {"schema_version": 2, "recipe_version": 2,
                "template_abi": job["compatibility"]["template_abi"], "pins": pins,
                "source_fingerprint": inputs["source_fingerprint"], "security": SECURITY_CONTRACT,
                "golden": {"sha256": base_record["sha256"], "provenance": json.loads(BASE.with_suffix('.provenance.json').read_text())},
                "builder_sources": {path.relative_to(ROOT).as_posix(): digest(path) for path in
                    [Path(__file__), GUEST, GUEST.with_name('task_sources.py'), GUEST.with_name('os_packages.py')]},
                "host_git_version": capture('git','--version').decode().strip(),
                "miniconda": {"installer": MINICONDA, "sha256": MINICONDA_SHA256},
                "capacity": {"virtual_gib": args.virtual_gib, "free_space_gib": args.free_space_gib},
                "resolved_os": os_manifest, "environments": environments,
                "environment_downloads_sha256": digest(audit / 'environment-downloads.json'),
                "task_inventories_sha256": digest(audit / 'task-inventories.json'),
                "vcs_provenance_sha256": digest(audit / 'vcs-provenance.json'),
                "cache_provenance": {path.name: digest(path) for path in sorted(audit.glob('*.downloads.json'))},
                "artifacts": artifacts, "task_artifacts": mapping, "wheel_cas": wheel_cas_manifest,
                "templates": templates, "isolation_validation": isolations,
                "offline_setups_sha256": digest(audit / 'offline-setups.json')}
            # All resolved input bytes AND final QCOW2 hashes are now known. Disk
            # backings are relative, so the final directory name is not an input.
            generation = generation_identity(resolved)
            atomic_json(staged / "resolved-inputs.json", resolved)
            shutil.rmtree(inputs_root)
            (staged / 'firstboot.sh').unlink(missing_ok=True)
            # Keep verified checkpoints; normal commands never erase persistent template progress.
            summary = {"common_physical_bytes": common.stat().st_blocks * 512,
                       "repo_templates_physical_bytes": physical_bytes(repos.glob('*.qcow2')),
                       "task_sources_physical_bytes": physical_bytes(source_folder.glob('*.tar.gz')),
                       "task_sources_logical_bytes": sum(p.stat().st_size for p in source_folder.glob('*.tar.gz')),
                       "setup_caches_physical_bytes": physical_bytes(cache_folder.glob('*.tar.gz')),
                       "setup_caches_logical_bytes": sum(p.stat().st_size for p in cache_folder.glob('*.tar.gz')),
                       "wheel_cas_physical_bytes": physical_bytes(wheel_cas.glob('*')),
                       "wheel_cas_unique_logical_bytes": sum(referenced_wheels.values()),
                       "wheel_references_logical_bytes": wheel_reference_bytes}
            manifest = {"schema_version": 2, "recipe_version": 2, "template_abi": job["compatibility"]["template_abi"],
                "generation": generation, "source_fingerprint": inputs["source_fingerprint"],
                "pins": pins, "security": SECURITY_CONTRACT,
                "resolved_inputs_sha256": digest(staged / 'resolved-inputs.json'),
                "invariants": {"tasks": 230, "repos": 11, "env_hashes": 25, "unmapped_tasks": 0, "missing_base_commits": 0},
                "env_mapping": {key: value['stored_name'] for key, value in inputs['environments'].items()},
                "templates": templates, "artifacts": artifacts, "task_artifacts": mapping,
                "wheel_cas": wheel_cas_manifest, "sizes": sizes,
                "isolation_validation": isolations, "allocation": summary}

            from gpt_trace_transport.local_templates import compatibility, seal_validation, activate
            atomic_json(staged / "manifest.json", manifest)
            seal_validation(staged, compatibility(BASE, ROOT))

            checked_images = {}
            def image_info(path):
                from gpt_trace_transport.local_templates import file_signature
                value = json.loads(capture("qemu-img", "info", "--output=json", str(path)))
                signature = file_signature(path)
                if checked_images.get(path) != signature:
                    command("qemu-img", "check", str(path), timeout=3600)
                    checked_images[path] = signature
                return value

            def registry_factory(root, base):
                return TemplateRegistry(root, base, image_info, source_root=ROOT)

            def validate(final, selected_generation):
                registry = registry_factory(TEMPLATES, BASE)
                registry.validate_generation(selected_generation, complete=True, check_images=True)
                for template_id in templates:
                    record = registry.select(template_id, selected_generation)
                    for logical, row in mapping.items():
                        if row["template_id"] == template_id:
                            registry.task_scope(record, logical)
                if generation_identity(json.loads((final / "resolved-inputs.json").read_text())) != selected_generation:
                    raise RuntimeError("local resolved-input identity mismatch")
            final = install_generation(staged, target_root, manifest, validate)
            # Persist the sealed result BEFORE activation: a worker interruption
            # can finish verification/activation without repeating any VM build.
            from workstation_broker.preparation import record_built_generation
            record_built_generation(args.operation_id, generation)
            activate(TEMPLATES, BASE, generation, registry_factory, ROOT)
            summary['total_immutable_generation_physical_bytes'] = physical_bytes([final, *final.rglob('*')])
            print(json.dumps({"generation": generation, "invariants": manifest['invariants'], "allocation": summary}, indent=2))
            return final
        except BaseException as exc:
            # No normal failure is authorized to erase template volumes/checkpoints.
            # Preserve the single stable stage so a later explicit fetch continues
            # after a code/network/operator fix.  Only make throw_volumes can wipe it.
            print("build stopped; persistent resumable state retained: " + str(staged), file=sys.stderr)
            if isinstance(exc, RecoverableBuildError):
                raise
            raise RecoverableBuildError(str(exc)) from exc


def main():
    raise SystemExit("Use make superbench-fetch ADAPTER=swe-gym-lite on the control host; this local builder is an internal worker recipe")


if __name__ == "__main__":
    main()

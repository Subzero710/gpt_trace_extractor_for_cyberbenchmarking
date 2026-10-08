#!/usr/bin/env python3
"""Sequential host-only Lite builder. Failed generations are never published."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
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


def firstboot(body, *, grow=False):
    growth = r'''
apt-get update
apt-get install -y cloud-guest-utils
root_device=$(findmnt -n -o SOURCE /)
test "$(findmnt -n -o FSTYPE /)" = ext4
parent=$(lsblk -n -o PKNAME "$root_device")
partition=$(lsblk -n -o PARTN "$root_device")
test -n "$parent" && test -n "$partition"
growpart "/dev/$parent" "$partition"
resize2fs "$root_device"
''' if grow else ""
    return """#!/bin/bash
set -eo pipefail
exec >> /var/log/swe-gym-lite-builder.log 2>&1
rm -f /etc/gpt-trace-image-build-complete /etc/gpt-trace-image-build-failed
finish() {
    rc=$?
    if [ "$rc" -ne 0 ]; then echo "$rc" > /etc/gpt-trace-image-build-failed; fi
    sync
    systemctl poweroff --no-block
}
trap finish EXIT
""" + growth + body + """
fstrim -av
echo ok > /etc/gpt-trace-image-build-complete
"""


def build(args):
    if os.geteuid() != 0:
        raise RuntimeError("run sudo make swe-gym-lite-templates")
    for executable in ("docker", "git", "qemu-img", "virt-customize", "virt-cat", "qemu-system-x86_64"):
        if shutil.which(executable) is None:
            raise RuntimeError("missing host build executable: " + executable)
    spec = importlib.util.spec_from_file_location("swe_gym_kali_builder", ROOT / "infra/workstation/image/build.py")
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)
    golden.require_host_build_runtime()
    golden.verify()
    target_root = TEMPLATES / "swe-gym-lite"
    target_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    with (target_root / "build.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        staged = target_root / (".build-" + uuid.uuid4().hex)
        staged.mkdir(mode=0o755)
        log = staged / "host-build.log"
        margin = args.free_space_gib * 1024**3
        free_space(staged, margin)
        try:
            inputs_root = staged / "build-inputs"
            inputs_root.mkdir()
            command("docker", "compose", "run", "--rm", "--no-deps", "--entrypoint", "python", "-v",
                    str(inputs_root) + ":/build-inputs", "benchmark-fetch", "-m",
                    "gpt_trace_runner.superbench.adapters.swe_gym.source", "--export", "/build-inputs",
                    cwd=ROOT, log=log, monitor=staged, margin=margin)
            inputs = json.loads((inputs_root / "inputs.json").read_text())
            pins = json.loads(PINS.read_text())
            if inputs["pins"] != pins:
                raise RuntimeError("host/fetch container source revisions differ; rebuild the runner image")
            generation = hashlib.sha256(json.dumps({"pins": pins, "base_sha256": digest(BASE),
                "builder_sha256": digest(Path(__file__)), "guest_recipe_sha256": digest(GUEST),
                "virtual_gib": args.virtual_gib, "miniconda_sha256": MINICONDA_SHA256}, sort_keys=True).encode()).hexdigest()
            generations = target_root / "generations"
            generations.mkdir(mode=0o755, exist_ok=True)
            final = generations / generation
            if final.exists():
                from workstation_broker.templates import TemplateRegistry
                registry = TemplateRegistry(TEMPLATES, BASE, lambda path: json.loads(capture("qemu-img", "info", "--output=json", str(path))))
                for item in inputs["tasks"].values():
                    registry.select(item["template_id"], generation)
                atomic_json(target_root / "registry.json", {"schema_version": 1, "generation": generation})
                shutil.rmtree(staged)
                print("validated existing immutable generation", generation)
                return
            bundle = staged / "bundle"
            mirrors = bundle / "builder-mirrors"
            mirrors.mkdir(parents=True)
            for repo in sorted({item["repo"] for item in inputs["tasks"].values()}):
                mirror = mirrors / (repo.replace("/", "_") + ".git")
                command("git", "clone", "--mirror", "https://github.com/" + repo + ".git", str(mirror),
                        log=log, monitor=staged, margin=margin, timeout=14400)
            verify_sources(inputs, mirrors)
            installer = bundle / "miniconda.sh"
            with urllib.request.urlopen("https://repo.anaconda.com/miniconda/" + MINICONDA, timeout=120) as response, installer.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    free_space(staged, margin)
            if digest(installer) != MINICONDA_SHA256:
                raise RuntimeError("pinned Miniconda installer digest mismatch")
            shutil.copyfile(GUEST, bundle / "runtime.py")
            shutil.copyfile(inputs_root / "inputs.json", bundle / "inputs.json")
            common = staged / "common.qcow2"
            command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(BASE), str(common),
                    str(args.virtual_gib) + "G", log=log, monitor=staged, margin=margin)
            provision = staged / "common-firstboot.sh"
            provision.write_text(firstboot("""
mkdir -p /opt/swe-gym-lite
cp -a /opt/swe-gym-build/. /opt/swe-gym-lite/
rm -rf /opt/swe-gym-build
test ! -e /opt/miniconda3
bash /opt/swe-gym-lite/miniconda.sh -b -p /opt/miniconda3
rm /opt/swe-gym-lite/miniconda.sh
/usr/bin/python3 - <<'PY_GUEST'
import runpy, json
module = runpy.run_path('/opt/swe-gym-lite/runtime.py')
inputs = json.load(open('/opt/swe-gym-lite/inputs.json'))
module['build_common'](inputs)
PY_GUEST
""", grow=True))
            injection = staged / "swe-gym-build"
            bundle.rename(injection)
            command("virt-customize", "--no-network", "-a", str(common), "--copy-in", str(injection) + ":/opt",
                    "--firstboot", str(provision), log=log, monitor=staged, margin=margin, timeout=14400)
            # Reuse the repository's golden QEMU boot/provision/verification path.
            # Our run wrapper enforces space/timeout and preserves the image/logs.
            golden.run = lambda *argv, timeout=7200, **kw: command(*argv, timeout=timeout, log=log,
                                                                  monitor=staged, margin=margin, **kw)
            golden.PROVISION_TIMEOUT_SECONDS = args.build_timeout_hours * 3600
            golden.provision_in_real_guest(common)
            common.chmod(0o444)
            repos = staged / "repos"
            repos.mkdir()
            templates = {}
            base_record = {"path": str(BASE), "sha256": digest(BASE)}
            common_record = {"path": "common.qcow2", "sha256": digest(common)}
            for repo in sorted({item["repo"] for item in inputs["tasks"].values()}):
                key = repo.replace("/", "_")
                image = repos / (key + ".qcow2")
                command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", "../common.qcow2", image.name,
                        cwd=repos, log=log, monitor=staged, margin=margin)
                incoming = staged / "incoming.git"
                # Hardlinks are safe here: virt-customize reads the host source.
                shutil.copytree(injection / "builder-mirrors" / (key + ".git"), incoming, copy_function=os.link)
                repo_boot = staged / (key + "-firstboot.sh")
                repo_boot.write_text(firstboot("/usr/bin/python3 - <<'PY_GUEST'\nimport runpy,json\n"
                    "module=runpy.run_path('/opt/swe-gym-lite/runtime.py')\n"
                    "module['build_repo'](json.load(open('/opt/swe-gym-lite/inputs.json')), " + repr(repo) + ")\nPY_GUEST\n"))
                command("virt-customize", "--no-network", "-a", str(image), "--copy-in", str(incoming) + ":/opt/swe-gym-lite",
                        "--firstboot", str(repo_boot), log=log, monitor=staged, margin=margin)
                golden.provision_in_real_guest(image)
                shutil.rmtree(incoming)
                image.chmod(0o444)
                templates["swe-gym-lite/" + key] = {"chain": [
                    {"path": "repos/" + image.name, "sha256": digest(image)}, common_record, base_record]}
            manifest = {"schema_version": 1, "generation": generation,
                        "source_fingerprint": inputs["source_fingerprint"], "pins": pins,
                        "invariants": {"tasks": 230, "repos": 11, "env_hashes": 25, "unmapped_tasks": 0, "missing_base_commits": 0},
                        "env_mapping": {key: value["stored_name"] for key, value in inputs["environments"].items()},
                        "templates": templates, "sizes": {str(path.relative_to(staged)): {
                            "virtual_bytes": json.loads(capture("qemu-img", "info", "--output=json", str(path)))["virtual-size"],
                            "physical_bytes": path.stat().st_blocks * 512} for path in [common, *sorted(repos.glob("*.qcow2"))]}}
            for image in [common, *sorted(repos.glob("*.qcow2"))]:
                chain = json.loads(capture("qemu-img", "info", "--backing-chain", "--output=json", str(image)))
                expected = [image, BASE] if image == common else [image, common, BASE]
                if len(chain) != len(expected) or any(row.get("format") != "qcow2" or Path(row["filename"]).resolve() != path.resolve()
                                                      for row, path in zip(chain, expected, strict=True)):
                    raise RuntimeError("QCOW2 backing chain failed validation")
                command("qemu-img", "check", str(image), log=log, monitor=staged, margin=margin)
                with image.open("rb") as image_stream:
                    os.fsync(image_stream.fileno())
            atomic_json(staged / "manifest.json", manifest)
            # Retain compact build logs and provenance, discard duplicated host
            # mirrors/installers before publishing permanent sparse templates.
            shutil.rmtree(injection)
            shutil.rmtree(inputs_root)
            for path in staged.glob("*-firstboot.sh"):
                path.unlink()
            for path in staged.iterdir():
                path.chmod(0o555 if path.is_dir() else 0o444)
            staged.chmod(0o555)
            for directory in (repos, staged):
                fd = os.open(directory, os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
            os.rename(staged, final)
            fd = os.open(generations, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
            from workstation_broker.templates import TemplateRegistry
            registry = TemplateRegistry(TEMPLATES, BASE, lambda path: json.loads(capture("qemu-img", "info", "--output=json", str(path))))
            for template_id in templates:
                registry.select(template_id, generation)
            atomic_json(target_root / "registry.json", {"schema_version": 1, "generation": generation})
            print(json.dumps({"generation": generation, "invariants": manifest["invariants"], "sizes": manifest["sizes"]}, indent=2))
        except BaseException as exc:
            # Never delete a failed guest, replace a good generation, or publish
            # an incomplete registry. Inspection uses virt-cat/virt-customize.
            if staged.exists():
                if staged.stat().st_mode & 0o200:
                    (staged / "FAILED.txt").write_text(type(exc).__name__ + ": " + str(exc) + "\n")
                else:
                    (target_root / (staged.name + ".failed.txt")).write_text(str(exc) + "\n")
            print("build stopped; preserved state:", staged, file=sys.stderr)
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--virtual-gib", type=int, default=512)
    parser.add_argument("--free-space-gib", type=int, default=64)
    parser.add_argument("--build-timeout-hours", type=int, default=96)
    args = parser.parse_args()
    if not 128 <= args.virtual_gib <= 2048 or args.free_space_gib < 32 or not 1 <= args.build_timeout_hours <= 336:
        parser.error("invalid sparse capacity, free-space margin, or build deadline")
    build(args)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "apps/workstation-broker/src"))
    main()

#!/usr/bin/env python3
"""Sequential local Acer builder; invoked only by the authenticated preparation job."""
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
VIRTUAL_GIB = 512
FREE_SPACE_GIB = 64
BUILD_TIMEOUT_HOURS = 96


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
""" + body + "\nfstrim -av\necho ok > /etc/gpt-trace-image-build-complete\n"


def root_growth():
    # cloud-guest-utils comes from the verified, locally staged .deb closure.
    return r'''
root_device=$(findmnt -n -o SOURCE /)
test "$(findmnt -n -o FSTYPE /)" = ext4
parent=$(lsblk -n -o PKNAME "$root_device")
partition=$(lsblk -n -o PARTN "$root_device")
test -n "$parent" && test -n "$partition"
growpart "/dev/$parent" "$partition"
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
        raise RuntimeError("local preparation requires the Acer root execution broker")
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
    golden.verify(BASE)
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
        staged = target_root / (".build-" + uuid.uuid4().hex)
        staged.mkdir(mode=0o755)
        log = staged / "host-build.log"
        margin = args.free_space_gib * 1024**3
        free_space(staged, margin)

        def cmd(*argv, **kw):
            command(*argv, log=log, monitor=staged, margin=margin, **kw)

        def guest_json(image, path):
            return json.loads(capture("virt-cat", "-a", str(image), path))

        def overlay(image, backing):
            relative = os.path.relpath(backing, image.parent) if backing != BASE else str(BASE)
            cmd("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", relative, image.name,
                str(args.virtual_gib) + "G", cwd=image.parent)

        def provision(image, boot, payload=None, *, network):
            boot_file = staged / "firstboot.sh"
            boot_file.write_text(firstboot(boot))
            argv = ["virt-customize", "--no-network", "-a", str(image)]
            if payload is not None:
                argv += ["--copy-in", str(payload) + ":/opt"]
            cmd(*argv, "--firstboot", str(boot_file), timeout=14400)
            argv = ["qemu-system-x86_64", "-machine", "accel=kvm", "-cpu", "host", "-m", "4096", "-smp", "4",
                    "-drive", f"file={image},format=qcow2,if=virtio,cache=writeback,discard=unmap"]
            argv += ["-netdev", "user,id=net0,ipv6=off", "-device", "virtio-net-pci,netdev=net0"] if network else ["-nic", "none"]
            cmd(*argv, "-device", "virtio-rng-pci", "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot",
                timeout=args.build_timeout_hours * 3600)
            if capture("virt-cat", "-a", str(image), "/etc/gpt-trace-image-build-complete").strip() != b"ok":
                raise RuntimeError("guest build completion proof is missing")

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
            key = "submodule-" + hashlib.sha256(url.encode()).hexdigest() + ".git"
            path = mirror_for(url, key)
            cmd("git", "--git-dir", str(path), "cat-file", "-e", commit + "^{commit}")
            return path

        def task_boot(item, artifact, *, warm, cache=None):
            # Only this item/source/cache ever enters this disposable disk.
            body = "import runpy,json\nmodule=runpy.run_path('/opt/swe-gym-lite/runtime.py')\n"
            body += "item=json.load(open('/opt/swe-gym-task/item.json'))\n"
            body += "artifact=" + repr({**artifact, "path": "/opt/swe-gym-task/source.tar.gz"}) + "\n"
            if warm:
                body += "module['warm_task'](item,artifact)\n"
                body += "proof=module['export_setup_cache'](item,'/opt/swe-gym-task/setup-cache.tar.gz')\n"
                body += "json.dump(proof,open('/opt/swe-gym-task/cache-proof.json','w'),sort_keys=True)\n"
            else:
                body += "cache=" + repr({**cache, "path": "/opt/swe-gym-task/setup-cache.tar.gz"}) + "\n"
                body += "module['install_setup_cache'](item,cache)\n"
                body += "prefix=module['prepare'](item,artifact=artifact,log=module['ROOT']/'logs/offline.log')\n"
                body += "module['evaluation_setup'](item,prefix,item['eval_setup_commands'],module['ROOT']/'logs')\n"
                body += "json.dump({'base_commit':item['base_commit'],'env_hash':item['env_hash'],'offline':True},open('/opt/swe-gym-task/offline-proof.json','w'))\n"
            return "/usr/bin/python3 - <<'PY_GUEST'\n" + body + "PY_GUEST\n"

        try:
            inputs_root = staged / "build-inputs"
            inputs_root.mkdir()
            # Acer has no control-plane deployment,
            # credentials, Compose services or persistent campaign volumes.
            # Build only a source-fetch image and bind its private build cache.
            image = "gpt-trace-lite-local-source:" + digest(PINS)[:32]
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
                mirror_for("https://github.com/" + repo + ".git", repo.replace("/", "_") + ".git")
            verify_sources(inputs, cache_root)
            source_folder, cache_folder, audit = staged / "sources", staged / "setup-caches", staged / "audit"
            for folder in (source_folder, cache_folder, audit): folder.mkdir()
            artifacts, mapping = {}, {}
            for logical, item in sorted(inputs["tasks"].items()):
                free_space(staged, margin)
                key = tools.artifact_id("task_source", logical)
                output = source_folder / (key + ".tar.gz")
                record = tools.build_artifact(item, cache_root / (item["repo"].replace("/", "_") + ".git"), output,
                                              submodule_mirror=submodule_mirror)
                artifacts[key] = {**record, "path": output.relative_to(staged).as_posix()}
                output.chmod(0o444)
                mapping[logical] = {"template_id": item["template_id"], "task_source": key,
                                    "setup_cache": tools.artifact_id("setup_cache", logical)}

            # Golden provenance exposes kali-last-snapshot, a mutable alias,
            # not an immutable snapshot ID. Resolve in an expendable VM instead.
            resolver = staged / "os-resolver.qcow2"
            overlay(resolver, BASE)
            os_payload = staged / "swe-gym-os-helper"
            os_payload.mkdir()
            shutil.copyfile(GUEST.with_name("os_packages.py"), os_payload / "os_packages.py")
            provision(resolver, "/usr/bin/python3 - <<'PY_GUEST'\nimport runpy\n"
                "runpy.run_path('/opt/swe-gym-os-helper/os_packages.py')['resolve']('/opt/swe-gym-os')\nPY_GUEST\n", os_payload, network=True)
            os_parent = staged / "os"
            os_parent.mkdir()
            cmd("virt-copy-out", "-a", str(resolver), "/opt/swe-gym-os", str(os_parent))
            os_folder = os_parent / "swe-gym-os"
            os_manifest = json.loads((os_folder / "manifest.json").read_text())
            os_tools.verify_artifacts(os_folder, os_manifest)
            resolver.unlink()  # The local generation contains exact debs, never resolver mutations.
            shutil.rmtree(os_payload)

            payload = staged / "swe-gym-build"
            payload.mkdir()
            for name in ("runtime.py", "task_sources.py", "os_packages.py"):
                shutil.copyfile(GUEST if name == "runtime.py" else GUEST.with_name(name), payload / name)
            (payload / "environments.json").write_text(json.dumps({"environments": inputs["environments"]}, sort_keys=True))
            shutil.copytree(os_folder, payload / "os-artifacts")
            installer = payload / "miniconda.sh"
            with urllib.request.urlopen("https://repo.anaconda.com/miniconda/" + MINICONDA, timeout=120) as response, installer.open("wb") as output:
                while chunk := response.read(1048576):
                    output.write(chunk)
                    free_space(staged, margin)
            if digest(installer) != MINICONDA_SHA256:
                raise RuntimeError("pinned Miniconda installer digest mismatch")
            common = staged / "common.qcow2"
            overlay(common, BASE)
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
PY_GUEST
'''
            provision(common, boot, payload, network=True)
            shutil.rmtree(payload)
            common.chmod(0o444)
            environments = {key: guest_json(common, "/opt/swe-gym-lite/environments/" + key + ".json") for key in inputs["environments"]}
            common_cache = guest_json(common, "/opt/swe-gym-lite/environment-cache-provenance.json")
            atomic_json(audit / "environment-inventories.json", environments)
            atomic_json(audit / "environment-downloads.json", common_cache)
            common_validation = guest_json(common, "/opt/swe-gym-lite/isolation-validation.json")
            if common_validation != {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}:
                raise RuntimeError("common image leaked source state")

            offline_proofs, vcs_provenance, task_inventories = {}, {}, {}
            for logical, item in sorted(inputs["tasks"].items()):
                free_space(staged, margin)
                source_record = artifacts[mapping[logical]["task_source"]]
                incoming = staged / "swe-gym-task"
                incoming.mkdir()
                (incoming / "item.json").write_text(json.dumps(item))
                shutil.copyfile(staged / source_record["path"], incoming / "source.tar.gz")
                warm = staged / "task-warm.qcow2"
                overlay(warm, common)
                provision(warm, task_boot(item, source_record, warm=True), incoming, network=True)
                proof = guest_json(warm, "/opt/swe-gym-task/cache-proof.json")
                key = mapping[logical]["setup_cache"]
                exported = cache_folder / (".export-" + key)
                exported.mkdir()
                cmd("virt-copy-out", "-a", str(warm), "/opt/swe-gym-task/setup-cache.tar.gz", str(exported))
                archive = cache_folder / (key + ".tar.gz")
                (exported / "setup-cache.tar.gz").rename(archive)
                exported.rmdir()
                if digest(archive) != proof["sha256"] or archive.stat().st_size != proof["size"]:
                    raise RuntimeError("task setup cache changed during export")
                cache_record = {"kind": "setup_cache", "logical_task_id": logical, "allowed_template_id": item["template_id"],
                                "source_identity": source_record["source_identity"], "sha256": proof["sha256"], "size": proof["size"],
                                "path": archive.relative_to(staged).as_posix()}
                artifacts[key] = cache_record
                atomic_json(audit / (key + ".downloads.json"), proof["files"])
                vcs_provenance[logical] = guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".vcs.json")
                task_inventories[logical] = {
                    "repo_setup": guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".setup.json"),
                    "eval_setup": guest_json(warm, "/opt/swe-gym-lite/task-provenance/" + logical + ".json")}
                archive.chmod(0o444)
                shutil.copyfile(archive, incoming / "setup-cache.tar.gz")
                replay = staged / "task-replay.qcow2"
                overlay(replay, common)
                provision(replay, task_boot(item, source_record, warm=False, cache=cache_record), incoming, network=False)
                offline_proofs[logical] = guest_json(replay, "/opt/swe-gym-task/offline-proof.json")
                if offline_proofs[logical] != {"base_commit": item["base_commit"], "env_hash": item["env_hash"], "offline": True}:
                    raise RuntimeError("fresh task replay proof differs from exact base/environment")
                # Only after successful fresh replay may expendable disks go away.
                warm.unlink()
                replay.unlink()
                shutil.rmtree(incoming)
            atomic_json(audit / "task-inventories.json", task_inventories)
            atomic_json(audit / "vcs-provenance.json", vcs_provenance)
            atomic_json(audit / "offline-setups.json", offline_proofs)

            repos = staged / "repos"
            repos.mkdir()
            templates, isolations = {}, {"common": common_validation}
            base_record = {"path": str(BASE), "sha256": digest(BASE)}
            common_record = {"path": "common.qcow2", "sha256": digest(common)}
            for repo in repos_set:
                image = repos / (repo.replace("/", "_") + ".qcow2")
                overlay(image, common)
                boot = "/usr/bin/python3 - <<'PY_GUEST'\nimport runpy,json\nmodule=runpy.run_path('/opt/swe-gym-lite/runtime.py')\n"
                boot += "module['build_repo']({}," + repr(repo) + ")\n"
                boot += "json.dump(module['validate_isolation'](),open('/opt/swe-gym-lite/isolation-validation.json','w'))\nPY_GUEST\n"
                provision(image, boot, network=False)
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
            from workstation_broker.templates import SECURITY_CONTRACT, TemplateRegistry
            resolved = {"schema_version": 2, "recipe_version": 2, "pins": pins,
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
                "artifacts": artifacts, "task_artifacts": mapping, "templates": templates,
                "isolation_validation": isolations, "offline_setups_sha256": digest(audit / 'offline-setups.json')}
            # All resolved input bytes AND final QCOW2 hashes are now known. Disk
            # backings are relative, so the final directory name is not an input.
            generation = generation_identity(resolved)
            atomic_json(staged / "resolved-inputs.json", resolved)
            shutil.rmtree(inputs_root)
            (staged / 'firstboot.sh').unlink(missing_ok=True)
            summary = {"common_physical_bytes": common.stat().st_blocks * 512,
                       "repo_templates_physical_bytes": physical_bytes(repos.glob('*.qcow2')),
                       "task_sources_physical_bytes": physical_bytes(source_folder.glob('*.tar.gz')),
                       "task_sources_logical_bytes": sum(p.stat().st_size for p in source_folder.glob('*.tar.gz')),
                       "setup_caches_physical_bytes": physical_bytes(cache_folder.glob('*.tar.gz')),
                       "setup_caches_logical_bytes": sum(p.stat().st_size for p in cache_folder.glob('*.tar.gz'))}
            manifest = {"schema_version": 2, "recipe_version": 2, "generation": generation,
                "source_fingerprint": inputs["source_fingerprint"], "pins": pins, "security": SECURITY_CONTRACT,
                "resolved_inputs_sha256": digest(staged / 'resolved-inputs.json'),
                "invariants": {"tasks": 230, "repos": 11, "env_hashes": 25, "unmapped_tasks": 0, "missing_base_commits": 0},
                "env_mapping": {key: value['stored_name'] for key, value in inputs['environments'].items()},
                "templates": templates, "artifacts": artifacts, "task_artifacts": mapping, "sizes": sizes,
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
            # Preserve failed stages, images, exact debs and logs. Never activate
            # a new registry, reuse an unsafe v1 build, or clean diagnostics here.
            if staged.exists() and staged.stat().st_mode & 0o200:
                (staged / 'FAILED.txt').write_text(type(exc).__name__ + ': ' + str(exc) + '\n')
            else:
                (target_root / (staged.name + '.failed.txt')).write_text(str(exc) + '\n')
            print('build stopped; preserved state:', staged, file=sys.stderr)
            raise


def main():
    raise SystemExit("Use make superbench-fetch ADAPTER=swe-gym-lite on Fossil; this local builder is an internal worker recipe")


if __name__ == "__main__":
    main()

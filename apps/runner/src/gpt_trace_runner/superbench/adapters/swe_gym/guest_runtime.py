"""Standard-library guest recipes, invoked internally through exec_command.

This module adds no MCP tools. Offline setup uses package downloads collected
during the host build and a network namespace, so a missing cache fails closed.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import runpy
import types
from pathlib import Path

ROOT = Path("/opt/swe-gym-lite")
CONDA = Path("/opt/miniconda3/bin/conda")


def run(*args, cwd=None, env=None, input=None):
    return subprocess.run(args, cwd=cwd, env=env, input=input, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


SHARED_WARM_CACHE_ROOT = Path("/mnt/gpt-trace-warm-cache")
BUILDER_WHEEL_STORE = Path("/opt/swe-gym-task/wheel-cas")
TASK_RUNTIME_SCHEMA = 2


def _phase(item, phase, state, elapsed=None):
    """Persist compact task timings and mirror them to the QEMU serial line."""
    record = {"instance_id": item.get("instance_id"), "phase": phase, "state": state,
              "time": time.time()}
    if elapsed is not None:
        record["elapsed_seconds"] = round(float(elapsed), 3)
    line = "GPTTRACE_PHASE " + json.dumps(record, sort_keys=True, separators=(",", ":"))
    try:
        (ROOT / "logs").mkdir(parents=True, exist_ok=True)
        with (ROOT / "logs/task-timings.jsonl").open("a") as output:
            output.write(line + "\n")
    except OSError:
        pass
    try:
        with Path("/dev/ttyS0").open("a") as output:
            output.write(line + "\n")
    except OSError:
        pass


def _timed(item, phase, callback):
    started = time.monotonic()
    _phase(item, phase, "start")
    try:
        result = callback()
    except BaseException:
        _phase(item, phase, "failed", time.monotonic() - started)
        raise
    _phase(item, phase, "done", time.monotonic() - started)
    return result


def _shared_warm_cache():
    value = os.environ.get("GPT_TRACE_SHARED_WARM_CACHE")
    if value != str(SHARED_WARM_CACHE_ROOT):
        return None
    if SHARED_WARM_CACHE_ROOT.is_symlink() or not SHARED_WARM_CACHE_ROOT.is_dir():
        raise RuntimeError("shared warm cache mount is unavailable")
    return SHARED_WARM_CACHE_ROOT


def prime_shared_pip_cache(item):
    """One-time migration of the pre-cache-disk pip cache from a preserved warm scratch."""
    shared = _shared_warm_cache()
    if shared is None:
        return False
    marker = shared / ".legacy-pip-imported-v1"
    if marker.exists():
        if marker.is_symlink() or marker.read_text() != "ok\n":
            raise RuntimeError("shared warm cache migration marker changed")
        return False
    source = ROOT / "caches/pip"
    target = shared / "pip"
    def copy():
        if source.exists():
            if source.is_symlink() or not source.is_dir():
                raise RuntimeError("legacy warm pip cache is unsafe")
            shutil.copytree(source, target, dirs_exist_ok=True, symlinks=True)
        else:
            target.mkdir(parents=True, exist_ok=True)
        marker.write_text("ok\n")
        with marker.open("rb") as handle:
            os.fsync(handle.fileno())
    _timed(item, "shared_pip_cache_import", copy)
    return True


def shell(commands, *, cwd, env=None, offline=False, log=None):
    script = "set -eo pipefail\n" + "\n".join(commands) + "\n"
    argv = ["/bin/bash", "-c", script]
    if offline:
        argv = ["unshare", "--net", "/bin/bash", "-c", "ip link set lo up\n" + script]
    with Path(log).open("w+b") if log else tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            output.seek(0, os.SEEK_END)
            output.seek(max(0, output.tell()-4000))
            raise RuntimeError(f"official setup failed ({result.returncode}): {output.read().decode(errors='replace')}")


def stream_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Build-only environment transformation: pinned official inputs stay byte-for-byte
# unchanged, while Python's final version is constrained before the first solve.
# Reproducibility records BOTH scripts and the solver policy in the guest image.
def locked_environment_script(env_hash, record, lock):
    """Construct an environment only from exact lock transaction archives."""
    if not isinstance(record, dict) or record.get("stored_name") != "swegym_" + env_hash:
        raise RuntimeError("environment identity differs from the pinned contract")
    row = lock.get("environments", {}).get(env_hash)
    if not isinstance(row, dict) or row.get("recipe_sha256") != hashlib.sha256(
            json.dumps(record.get("original_script"), sort_keys=True, separators=(",", ":")).encode()).hexdigest():
        raise RuntimeError("Conda lock recipe identity differs")
    transactions = row.get("transactions")
    if not isinstance(transactions, list) or not transactions:
        raise RuntimeError("Conda lock has no transactions for " + env_hash)
    final = transactions[-1]
    if final.get("python") != python_version_from_recipe(record.get("original_script", [])):
        raise RuntimeError("Conda lock final Python differs from recipe")
    package_files = []
    for package_sha in final.get("packages", []):
        artifact = lock.get("artifacts", {}).get(package_sha)
        if not isinstance(artifact, dict) or artifact.get("sha256") != package_sha:
            raise RuntimeError("Conda lock references an unknown archive")
        filename = str(artifact.get("url", "")).rsplit("/", 1)[-1]
        package_files.append("/opt/swe-gym-lock/" + package_sha + "/" + filename)
    if not package_files:
        raise RuntimeError("Conda lock transaction is empty")
    prefix = "/opt/miniconda3/envs/" + record["stored_name"]
    explicit = "/opt/swe-gym-lock/" + env_hash + ".explicit"
    lines = ["rm -rf " + shlex.quote(prefix), "mkdir -p /opt/swe-gym-lock"]
    lines += ["test -f " + shlex.quote(path) for path in package_files]
    lines += ["printf '%s\\n' '@EXPLICIT' " + " ".join(shlex.quote('file://' + path) for path in package_files) + " > " + shlex.quote(explicit),
              "/opt/miniconda3/bin/conda create --offline --yes --prefix " + shlex.quote(prefix) + " --file " + shlex.quote(explicit)]
    return lines


def python_version_from_recipe(script):
    # Match the Conda package named exactly ``python``; package names such as
    # ``meson-python`` must never be interpreted as interpreter constraints.
    values = re.findall(
        r"(?<![A-Za-z0-9_.-])python\s*=\s*(\d+\.\d+)(?:\.\*)?(?![A-Za-z0-9_.-])",
        "\n".join(script))
    if not values:
        raise RuntimeError("Conda recipe has no Python identity")
    return values[-1]

def build_limits(env=None):
    """Use all four preparation vCPUs while keeping builders bounded."""
    result = dict(os.environ if env is None else env)
    workers = max(1, min(4, os.cpu_count() or 1))
    # Exact lock reconstruction has no live solver policy. These are only
    # transport/resource limits for commands that execute build recipes.
    result.update(CONDA_REMOTE_MAX_RETRIES="10", CONDA_REMOTE_BACKOFF_FACTOR="2",
                  CONDA_REMOTE_CONNECT_TIMEOUT_SECS="30", CONDA_REMOTE_READ_TIMEOUT_SECS="180",
                  PIP_RETRIES="10", PIP_TIMEOUT="180",
                  MAKEFLAGS="-j" + str(workers),
                  CMAKE_BUILD_PARALLEL_LEVEL=str(workers),
                  MAX_JOBS=str(workers), npm_config_jobs=str(workers))
    return result


def env_inventory(prefix):
    """Record installed distributions and conda explicit URLs for provenance."""
    return {"conda_explicit": run(str(CONDA), "list", "--prefix", str(prefix), "--explicit").decode(),
            "pip_freeze": run(str(prefix / "bin/python"), "-m", "pip", "freeze", "--all").decode()}


def stored_env_prefix(item):
    prefix = Path("/opt/miniconda3/envs") / ("swegym_" + item["env_hash"])
    if not prefix.is_dir() or not (prefix / "bin/python").is_file():
        raise RuntimeError("required frozen environment missing; templates must be rebuilt by the operator")
    return prefix


def pristine_stored_env(item):
    prefix = stored_env_prefix(item)
    expected = json.loads((ROOT / "environments" / (item["env_hash"] + ".json")).read_text())
    if env_inventory(prefix) != expected:
        raise RuntimeError("stored environment provenance changed")
    return prefix


def clone_env(item, *, offline):
    stored = pristine_stored_env(item)
    prefix = Path("/opt/miniconda3/envs/testbed")
    if prefix.exists():
        run(str(CONDA), "env", "remove", "--prefix", str(prefix), "-y")
    args = [str(CONDA), "create", "--name", "testbed", "--clone", str(stored), "--yes"]
    if offline:
        args.append("--offline")
    run(*args)
    if not (prefix / "bin/python").is_file():
        raise RuntimeError("Conda did not materialize testbed")
    return prefix


def recovery_env_prefix(item):
    # Recovery is valid only for the real upstream testbed clone.
    return Path("/opt/miniconda3/envs/testbed")


def pip_versions(prefix):
    return {entry["name"].lower().replace("_", "-"): entry["version"]
            for entry in json.loads(run(str(prefix / "bin/python"), "-m", "pip",
                                        "list", "--format=json").decode())}


def repo_name(repo):
    return repo.replace("/", "_")


def source_tools():
    if "_sources" in globals():
        return globals()["_sources"]
    if __package__:
        from . import task_sources
        return task_sources
    return types.SimpleNamespace(**runpy.run_path(str(ROOT / "task_sources.py")))


def clean_checkout(item, artifact, destination):
    destination = Path(destination)
    if destination.is_symlink():
        raise RuntimeError("unsafe checkout destination")
    if destination.exists():
        shutil.rmtree(destination)
    tools = source_tools()
    tools.extract(artifact["path"], destination, sha256=artifact["sha256"], size=artifact["size"])
    tools.validate_checkout(destination, item["base_commit"])


def setup_commands(item, destination, prefix):
    """Adapt official setup semantics to an already-validated pinned checkout."""
    commands=[]
    saw={"clone":False,"chmod":False,"cd":False,"reset":False,"remote":False}
    for line in item["repo_script_list"]:
        try:tokens=shlex.split(line,posix=True)
        except ValueError as exc:raise RuntimeError("unparseable pinned repo setup command") from exc
        # The source artifact already materializes the exact base commit at cwd.
        if (len(tokens)>=5 and tokens[:4]==["git","clone","-o","origin"]
                and tokens[-1]=="/testbed"):
            saw["clone"]=True;continue
        if tokens==["chmod","-R","777","/testbed"]:
            saw["chmod"]=True;continue
        if tokens==["cd","/testbed"]:
            saw["cd"]=True;continue
        if tokens==["git","reset","--hard",item["base_commit"]]:
            saw["reset"]=True;continue
        if tokens==["git","remote","remove","origin"]:
            saw["remote"]=True;continue

        if "apt-get" in tokens:
            # Suppress only the explicit blanket upgrade against the immutable
            # golden. Explicit installs remain in the official command stream.
            for index in range(len(tokens)-7):
                if tokens[index:index+8]==["apt-get","-y","update","&&","apt-get","-y","upgrade","&&"]:
                    del tokens[index+5:index+8]
                    line=shlex.join(tokens)
                    break
        commands.append(line)
    if not all(saw.values()):
        missing=','.join(sorted(key for key,value in saw.items() if not value))
        raise RuntimeError("pinned upstream checkout prelude changed: "+missing)

    # pipx/PDM are permanent build-time tools. Make repeated official install
    # requests idempotent; interpreter compatibility is proven by the golden.
    adapted=[]
    for line in commands:
        if line.startswith("pipx install pdm"):
            system_python=shutil.which("python3")
            if system_python is None:
                raise RuntimeError("golden system Python executable is unavailable")
            line=("test -x /root/.local/bin/pdm || pipx install pdm --python "
                  +shlex.quote(system_python))
        adapted.append(line)
    adapted.append("git remote | xargs -r -n1 git remote remove")
    adapted.append("test \"$(git rev-parse HEAD)\" = " + shlex.quote(item["base_commit"]))
    adapted.append("test \"$CONDA_PREFIX\" = " + shlex.quote(str(prefix)))
    return adapted


def runtime_environment(item, *, offline):
    env = build_limits()
    shared = None if offline else _shared_warm_cache()
    pip_cache = (shared / "pip") if shared is not None else (ROOT / "caches/pip")
    pip_cache.mkdir(parents=True, exist_ok=True)
    env.update(HOME="/root", PIP_CACHE_DIR=str(pip_cache),
               npm_config_cache=str(ROOT / "caches/npm"), PDM_CACHE_DIR=str(ROOT / "caches/pdm"),
               PIPX_HOME=str(ROOT / "caches/pipx"), PIPX_BIN_DIR="/root/.local/bin",
               npm_config_prefix=str(ROOT / "caches/npm-global"))
    env["PATH"] = str(ROOT / "offline-bin") + ":" + str(ROOT / "caches/npm-global/bin") + ":" + env["PATH"]
    if offline:
        env.update(PIP_NO_INDEX="1", PIP_FIND_LINKS=str(ROOT / "wheelhouse" / item["instance_id"]),
                   npm_config_offline="true", PDM_NO_UPDATE_CHECK="1")
    return env


def relocate_checkout(commands, destination):
    # Replace the repository root, never the Conda environment's /testbed suffix.
    pattern = r"(?<![A-Za-z0-9_./-])/testbed(?=/|[^A-Za-z0-9_.-]|$)"
    return [re.sub(pattern, lambda _: str(destination), line) for line in commands]


def prepare(item, *, artifact, offline=True, destination="/testbed", log=None):
    prefix_name = "replay" if offline else "warm"
    _timed(item, prefix_name + "_clean_checkout",
           lambda: clean_checkout(item, artifact, destination))
    if offline:
        if any(line.startswith("pipx install pdm") for line in item["repo_script_list"]) and not Path("/root/.local/bin/pdm").is_file():
            raise RuntimeError("frozen PDM tool is missing; runtime cannot install it")
        configure_vcs_cache(item)
    prefix = _timed(item, prefix_name + "_clone_env",
                    lambda: clone_env(item, offline=offline))
    commands = setup_commands(item, destination, prefix)
    if destination != "/testbed":
        commands = relocate_checkout(commands, destination)
    _timed(item, prefix_name + "_repo_setup",
           lambda: shell(commands, cwd=destination, env=runtime_environment(item, offline=offline),
                         offline=offline, log=log))
    if offline:
        expected = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".setup.json")).read_text())
        if env_inventory(prefix) != expected:
            raise RuntimeError("offline official setup differs from the frozen build-time package inventory")
    verify_os_packages()
    run("git", "-C", str(destination), "reset", "--hard", item["base_commit"])
    return prefix


def candidate_patch(repo, base, output):
    """Capture tracked, deleted, untracked and binary changes without real index writes."""
    repo, output = Path(repo), Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="swegym-index-")
    os.close(fd)
    Path(name).unlink()  # git read-tree creates the temporary index.
    env = {**os.environ, "GIT_INDEX_FILE": name}
    try:
        run("git", "read-tree", base, cwd=repo, env=env)
        run("git", "add", "-A", "--", ".", cwd=repo, env=env)
        patch = run("git", "diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", base, "--", cwd=repo, env=env)
        with output.open("wb") as stream:
            stream.write(patch)
            stream.flush()
            os.fsync(stream.fileno())
        return {"sha256": hashlib.sha256(patch).hexdigest(), "size": len(patch)}
    finally:
        Path(name).unlink(missing_ok=True)
        Path(name + ".lock").unlink(missing_ok=True)


def apply_candidate(candidate, destination, *, sha256=None, size=None):
    candidate = Path(candidate)
    if candidate.is_symlink() or not candidate.is_file() or (size is not None and candidate.stat().st_size != size) or (sha256 is not None and source_tools().digest(candidate) != sha256):
        raise RuntimeError("persisted candidate patch integrity mismatch")
    if Path(candidate).stat().st_size:
        run("git", "apply", "--check", "--binary", str(candidate), cwd=destination)
        run("git", "apply", "--binary", str(candidate), cwd=destination)


def verify_candidate(item, candidate, artifact, destination):
    clean_checkout(item, artifact, destination)
    apply_candidate(candidate, destination)


def evaluation_setup(item, prefix, commands, folder, *, destination="/testbed"):
    _timed(item, "replay_eval_setup",
           lambda: shell(commands, cwd=destination, env=runtime_environment(item, offline=True),
                         offline=True, log=folder / "eval-setup.log"))
    expected = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".json")).read_text())
    if env_inventory(prefix) != expected:
        raise RuntimeError("clean evaluator setup differs from frozen package inventory")
    if run("git", "-C", str(destination), "rev-parse", "HEAD").decode().strip() != item["base_commit"]:
        raise RuntimeError("setup changed the base HEAD")
    run("git", "-C", str(destination), "reset", "--hard", item["base_commit"])
    verify_os_packages()


def prepare_evaluator(item, artifact, setup, folder, *, destination="/testbed"):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    prefix = prepare(item, artifact=artifact, log=folder / "setup.log", destination=destination)
    evaluation_setup(item, prefix, setup, folder, destination=destination)
    return {"base_commit": item["base_commit"], "env_hash": item["env_hash"], "source_sha256": artifact["sha256"]}


def evaluate_clean(item, artifact, candidate, *, candidate_sha256, candidate_size,
                   setup, hidden, test_command, folder, test_prelude=(), destination="/testbed"):
    """Convenience sequence for the instrumented Git regression test."""
    prepare_evaluator(item, artifact, setup, folder, destination=destination)
    return grade_prepared(item, candidate, candidate_sha256=candidate_sha256, candidate_size=candidate_size,
                          hidden=hidden, test_command=test_command, folder=folder,
                          test_prelude=test_prelude, destination=destination)


def grade_prepared(item, candidate, *, candidate_sha256, candidate_size, hidden,
                   test_command, folder, test_prelude=(), destination="/testbed"):
    folder = Path(folder)
    apply_candidate(candidate, destination, sha256=candidate_sha256, size=candidate_size)
    shell(hidden, cwd=destination, env=runtime_environment(item, offline=True), offline=True, log=folder / "hidden.log")
    script = '\n'.join(test_prelude) + '\nsource /opt/miniconda3/bin/activate testbed\nset +e\n' + test_command
    script += ' >' + shlex.quote(str(folder / 'tests.log')) + ' 2>&1\nstatus=$?\n'
    script += 'printf "%s\\n" "$status" >' + shlex.quote(str(folder / 'tests.exit')) + '\nexit 0\n'
    shell([script], cwd=destination, env=runtime_environment(item, offline=True), offline=True, log=folder / "test-launch.log")
    status = int((folder / "tests.exit").read_text())
    if status < 0 or status in (126, 127) or status >= 128:
        raise RuntimeError("native test process failed to execute")
    return {"test_exit_status": status}


def _reset_task_warm_outputs(item):
    instance = item["instance_id"]
    wheelhouse = ROOT / "wheelhouse" / instance
    if wheelhouse.is_symlink():
        raise RuntimeError("untrusted task wheelhouse")
    if wheelhouse.exists():
        shutil.rmtree(wheelhouse)
    for suffix in (".setup.json", ".json", ".vcs.json"):
        path = ROOT / "task-provenance" / (instance + suffix)
        if path.is_symlink():
            raise RuntimeError("untrusted task provenance path")
        path.unlink(missing_ok=True)
    (Path("/opt/swe-gym-task") / "warm-state.json").unlink(missing_ok=True)


def _validate_vcs_provenance(item):
    path = ROOT / "task-provenance" / (item["instance_id"] + ".vcs.json")
    if path.is_symlink() or not path.is_file():
        return False
    try:
        records = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    if not isinstance(records, list):
        return False
    for record in records:
        if (not isinstance(record, dict) or set(record) != {"url", "mirror", "commit"} or
                not isinstance(record["url"], str) or not record["url"].startswith("https://") or
                re.fullmatch(r"[0-9a-f]{40}", str(record["commit"])) is None):
            return False
        mirror = Path(record["mirror"])
        expected_root = ROOT / "caches/git"
        if (not mirror.is_absolute() or not mirror.is_relative_to(expected_root) or
                mirror.is_symlink() or not mirror.is_dir()):
            return False
        try:
            if run("git", "--git-dir", str(mirror), "rev-parse", "HEAD").decode().strip() != record["commit"]:
                return False
        except (OSError, subprocess.SubprocessError):
            return False
    return True


def _compatible_warm_state(path, item):
    """Accept historical schema-2 state with exactly one obsolete extra field.

    Never infer compatibility from the metadata alone: warm_task_ready validates
    installed package inventory, Git commit, VCS provenance and frozen OS state.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    expected = {"schema": TASK_RUNTIME_SCHEMA,
                "instance_id": item["instance_id"], "repo": item["repo"],
                "base_commit": item["base_commit"], "env_hash": item["env_hash"]}
    if data == expected:
        return True
    if data.keys() == expected.keys() | {"runtime_fingerprint"}:
        return {key: data[key] for key in expected} == expected and isinstance(data["runtime_fingerprint"], str)
    return False


def warm_task_ready(item):
    """Deep proof used to salvage a warm scratch that failed after expensive setup."""
    instance = item["instance_id"]
    prefix = recovery_env_prefix(item)
    state_path = Path("/opt/swe-gym-task/warm-state.json")
    setup_record = ROOT / "task-provenance" / (instance + ".setup.json")
    final_record = ROOT / "task-provenance" / (instance + ".json")
    wheelhouse = ROOT / "wheelhouse" / instance
    try:
        if (not prefix.is_dir() or not (prefix / "bin/python").is_file() or
                state_path.is_symlink() or not state_path.is_file() or
                not _compatible_warm_state(state_path, item) or
                setup_record.is_symlink() or final_record.is_symlink() or
                not setup_record.is_file() or not final_record.is_file() or
                wheelhouse.is_symlink() or not wheelhouse.is_dir()):
            return False
        setup_inventory = json.loads(setup_record.read_text())
        final_inventory = json.loads(final_record.read_text())
        if not isinstance(setup_inventory, dict) or not isinstance(final_inventory, dict):
            return False
        if env_inventory(prefix) != final_inventory:
            return False
        if run("git", "-C", "/testbed", "rev-parse", "HEAD").decode().strip() != item["base_commit"]:
            return False
        if not _validate_vcs_provenance(item):
            return False
        pool = ROOT / "caches/wheels"
        if pool.is_symlink() or not pool.is_dir():
            return False
        pool_inodes = set()
        for stored in pool.iterdir():
            if stored.is_symlink() or not stored.is_file():
                return False
            info = stored.stat()
            pool_inodes.add((info.st_dev, info.st_ino, info.st_size))
        for path in wheelhouse.iterdir():
            if path.is_symlink() or not path.is_file():
                return False
            # warm_task() hardlinks every captured distribution into caches/wheels.
            # Inode identity is enough for recovery; export_setup_cache hashes each
            # object afterwards and the offline replay is the final correctness proof.
            info = path.stat()
            if (info.st_dev, info.st_ino, info.st_size) not in pool_inodes:
                return False
        verify_os_packages()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return False
    return True


def _write_warm_state(item):
    path = Path("/opt/swe-gym-task/warm-state.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": TASK_RUNTIME_SCHEMA,
                                "instance_id": item["instance_id"],
                                "repo": item["repo"], "base_commit": item["base_commit"],
                                "env_hash": item["env_hash"]}, sort_keys=True))
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _capture_install_artifacts(item, prefix, requirements_file, wheelhouse):
    """Prefer built wheels so offline replay does not rebuild source distributions."""
    env = runtime_environment(item, offline=False)
    try:
        run(str(prefix / "bin/python"), "-m", "pip", "wheel", "--no-deps",
            "--wheel-dir", str(wheelhouse), "--requirement", str(requirements_file), env=env)
    except subprocess.CalledProcessError:
        for path in wheelhouse.iterdir():
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("unexpected partial wheelhouse entry")
            path.unlink()
        run(str(prefix / "bin/python"), "-m", "pip", "download", "--no-deps",
            "--dest", str(wheelhouse), "--requirement", str(requirements_file), env=env)


def warm_task(item, artifact):
    prime_shared_pip_cache(item)
    _reset_task_warm_outputs(item)
    baseline = pip_versions(pristine_stored_env(item))
    prefix = prepare(item, artifact=artifact, offline=False,
                     log=ROOT / "logs" / (item["instance_id"] + ".warm.log"))
    (ROOT / "task-provenance" / (item["instance_id"] + ".setup.json")).write_text(
        json.dumps(env_inventory(prefix), sort_keys=True))
    _timed(item, "warm_eval_setup",
           lambda: shell(item["eval_setup_commands"], cwd="/testbed", env=runtime_environment(item, offline=False),
                         log=ROOT / "logs/eval-warm.log"))
    wheelhouse = ROOT / "wheelhouse" / item["instance_id"]
    wheelhouse.mkdir(parents=True, exist_ok=True)
    inventory = env_inventory(prefix)
    (ROOT / "task-provenance" / (item["instance_id"] + ".json")).write_text(json.dumps(inventory, sort_keys=True))
    packages = json.loads(run(str(prefix / "bin/python"), "-m", "pip", "list", "--format=json").decode())
    editable = json.loads(run(str(prefix / "bin/python"), "-m", "pip", "list", "--editable", "--format=json").decode())
    excluded = {entry["name"].lower().replace("_", "-") for entry in editable}
    direct = json.loads(run(str(prefix / "bin/python"), "-c", """import importlib.metadata,json
result={}
for dist in importlib.metadata.distributions():
    raw=dist.read_text('direct_url.json')
    if raw:
        result[dist.metadata['Name'].lower().replace('_','-')]=json.loads(raw)
print(json.dumps(result))
""").decode())
    reqs = []
    for entry in packages:
        name = entry["name"].lower().replace("_", "-")
        if name in excluded or baseline.get(name) == entry["version"]:
            continue
        record = direct.get(name, {})
        if "vcs_info" in record:
            vcs = record["vcs_info"]
            if vcs["vcs"] != "git" or not record["url"].startswith("https://"):
                raise RuntimeError("unsupported public VCS wheel source")
            requirement = "git+" + record["url"] + "@" + vcs["commit_id"]
            if record.get("subdirectory"):
                requirement += "#subdirectory=" + record["subdirectory"]
            reqs.append(entry["name"] + " @ " + requirement)
        else:
            reqs.append(entry["name"] + "==" + entry["version"])
    requirements_file = ROOT / "resolved-requirements.txt"
    requirements_file.write_text("\n".join(reqs) + "\n")
    if reqs:
        _timed(item, "warm_capture_wheels",
               lambda: _capture_install_artifacts(
                   item, prefix, requirements_file, wheelhouse))
    requirements_file.unlink()
    _timed(item, "warm_freeze_vcs", lambda: freeze_vcs_dependencies(item, prefix))
    pool = ROOT / "caches/wheels"
    pool.mkdir(parents=True, exist_ok=True)
    for path in wheelhouse.iterdir():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("unexpected wheelhouse entry")
        sha = stream_digest(path)
        stored = pool / sha
        if stored.exists():
            if stream_digest(stored) != sha:
                raise RuntimeError("shared wheel cache changed")
            path.unlink()
            os.link(stored, path)
        else:
            os.link(path, stored)
    _write_warm_state(item)

def freeze_vcs_dependencies(item, prefix):
    script = """import importlib.metadata,json
result=[]
for dist in importlib.metadata.distributions():
    raw=dist.read_text('direct_url.json')
    if raw:
        data=json.loads(raw)
        if 'vcs_info' in data:
            result.append(data)
print(json.dumps(result))
"""
    records = json.loads(run(str(prefix / "bin/python"), "-c", script).decode())
    frozen = []
    folder = ROOT / "caches/git"
    folder.mkdir(exist_ok=True)
    for record in records:
        url, vcs = record["url"], record["vcs_info"]
        commit = vcs["commit_id"]
        if vcs["vcs"] != "git" or not url.startswith("https://") or len(commit) != 40:
            raise RuntimeError("unsupported public VCS dependency contract")
        key = hashlib.sha256((url + "@" + commit).encode()).hexdigest()
        mirror = folder / (key + ".git")
        if not mirror.exists():
            run("git", "init", "--bare", str(mirror))
            run("git", "--git-dir", str(mirror), "fetch", "--depth=1", url, commit)
            run("git", "--git-dir", str(mirror), "update-ref", "refs/heads/frozen", commit)
            run("git", "--git-dir", str(mirror), "symbolic-ref", "HEAD", "refs/heads/frozen")
            requested = vcs.get("requested_revision")
            if requested and requested != commit:
                run("git", "--git-dir", str(mirror), "check-ref-format", "refs/heads/" + requested)
                run("git", "--git-dir", str(mirror), "update-ref", "refs/heads/" + requested, commit)
        frozen.append({"url": url, "mirror": str(mirror), "commit": commit})
    (ROOT / "task-provenance" / (item["instance_id"] + ".vcs.json")).write_text(json.dumps(frozen, sort_keys=True))


def configure_vcs_cache(item):
    records = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".vcs.json")).read_text())
    # Frozen recipes may contain public Git URLs without an explicit revision.
    # Git's standard URL rewrite directs these to their build-time exact commit.
    config = ROOT / "attempt-vcs.gitconfig"
    config.write_text('[protocol "file"]\n\tallow = always\n')
    for record in records:
        mirror = Path(record["mirror"])
        if run("git", "--git-dir", str(mirror), "rev-parse", "HEAD").decode().strip() != record["commit"]:
            raise RuntimeError("frozen VCS dependency changed")
        run("git", "config", "--file", str(config), "--add", "url.file://" + str(mirror) + ".insteadOf", record["url"])
    os.environ["GIT_CONFIG_GLOBAL"] = str(config)



def replay_task_ready(item):
    proof_path = Path("/opt/swe-gym-task/offline-proof.json")
    state_path = Path("/opt/swe-gym-task/replay-state.json")
    prefix = recovery_env_prefix(item)
    try:
        if (proof_path.is_symlink() or not proof_path.is_file() or
                state_path.is_symlink() or not state_path.is_file() or
                json.loads(state_path.read_text()) != {
                    "schema": TASK_RUNTIME_SCHEMA,
                    "instance_id": item["instance_id"]} or
                not prefix.is_dir() or not (prefix / "bin/python").is_file()):
            return False
        if json.loads(proof_path.read_text()) != {
                "base_commit": item["base_commit"], "env_hash": item["env_hash"], "offline": True}:
            return False
        expected = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".json")).read_text())
        if env_inventory(prefix) != expected:
            return False
        if run("git", "-C", "/testbed", "rev-parse", "HEAD").decode().strip() != item["base_commit"]:
            return False
        verify_os_packages()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return False
    return True


def replay_task(item, artifact, cache):
    _timed(item, "replay_install_cache", lambda: install_setup_cache(item, cache))
    prefix = prepare(item, artifact=artifact, log=ROOT / "logs/offline.log")
    evaluation_setup(item, prefix, item["eval_setup_commands"], ROOT / "logs")
    proof = {"base_commit": item["base_commit"], "env_hash": item["env_hash"], "offline": True}
    path = Path("/opt/swe-gym-task/offline-proof.json")
    path.write_text(json.dumps(proof, sort_keys=True))
    state = Path("/opt/swe-gym-task/replay-state.json")
    state.write_text(json.dumps({"schema": TASK_RUNTIME_SCHEMA,
                                 "instance_id": item["instance_id"]}, sort_keys=True))
    for durable in (path, state):
        with durable.open("rb") as handle:
            os.fsync(handle.fileno())

def install_offline_apt_guard():
    """Validate frozen prerequisites; campaigns never upgrade OS packages."""
    folder = ROOT / "offline-bin"
    folder.mkdir(exist_ok=True)
    (folder / "apt-get").write_text('''#!/usr/bin/python3
import subprocess, sys
args = [arg for arg in sys.argv[1:] if arg not in {"-y", "--yes"}]
if args == ["update"]:
    raise SystemExit(0)
if args and args[0] == "install" and len(args) > 1:
    for package in args[1:]:
        status = subprocess.check_output(["dpkg-query", "-W", "-f=${Status}", package], text=True)
        if status.strip() != "install ok installed":
            raise SystemExit("required frozen OS package is absent: " + package)
    raise SystemExit(0)
raise SystemExit("unsupported offline apt-get recipe")
''')
    (folder / "apt-get").chmod(0o755)


def freeze_downloads():
    """Content-addressed wheelhouse provenance, verified before local activation."""
    records = {}
    for path in sorted((ROOT / "wheelhouse").rglob("*")):
        if path.is_file():
            records[str(path.relative_to(ROOT))] = stream_digest(path)
    (ROOT / "download-provenance.json").write_text(json.dumps(records, sort_keys=True))


def build_common(inputs):
    for folder in ("environments", "logs", "task-provenance", "wheelhouse", "caches/pip", "caches/npm", "caches/pdm", "caches/pipx"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)
    install_offline_apt_guard()
    if not CONDA.is_file():
        raise RuntimeError("pinned Miniconda installer did not complete")
    lock_path = ROOT / "conda-lock.json"
    if lock_path.is_symlink() or not lock_path.is_file():
        raise RuntimeError("pinned Conda lock is missing from the common build payload")
    lock = json.loads(lock_path.read_bytes())
    if lock.get("schema") != 1 or lock.get("kind") != "swe-gym-lite-conda-image-lock":
        raise RuntimeError("unsupported pinned Conda lock")
    for env_hash, record in sorted(inputs["environments"].items()):
        commands = locked_environment_script(env_hash, record, lock)
        recipe_proof = {"lock_sha256": stream_digest(lock_path), "transactions": len(lock["environments"][env_hash]["transactions"])}
        prefix = Path("/opt/miniconda3/envs") / record["stored_name"]
        inventory_file = ROOT / "environments" / (env_hash + ".json")
        recipe_file = ROOT / "environments" / (env_hash + ".recipe.json")
        expected_proof = json.dumps(recipe_proof, sort_keys=True)
        # A successful environment is a durable checkpoint inside common.qcow2.
        # Never trust the mere existence of its directory as proof of completion.
        if inventory_file.exists() and recipe_file.exists() and prefix.is_dir():
            if (recipe_file.read_text() == expected_proof and
                    json.loads(inventory_file.read_text()) == env_inventory(prefix)):
                print("SWE-Gym verified environment checkpoint: " + env_hash, flush=True)
                continue
        # Incomplete or unverifiable environments are discarded individually.
        # Valid environments and the verified Conda package download cache survive.
        if prefix.is_symlink() or inventory_file.is_symlink() or recipe_file.is_symlink():
            raise RuntimeError("untrusted Conda checkpoint path")
        if prefix.exists() or inventory_file.exists() or recipe_file.exists():
            raise RuntimeError("existing Conda environment/checkpoint is not verified; preserving "
                               + str(prefix) + "; inspect or migrate explicitly")
        print("SWE-Gym environment " + env_hash + ": exact Conda lock transaction replay", flush=True)
        env = build_limits({**os.environ, "PATH": str(ROOT / "offline-bin") + ":" + os.environ["PATH"]})
        log = ROOT / "logs" / (env_hash + ".build.log")
        for attempt in range(1, 11):
            try:
                shell(commands, cwd=ROOT, env=env, log=log)
                break
            except RuntimeError as exc:
                # Retry only explicitly recognized transient transport failures;
                # do not hide missing packages, bad hashes or solver conflicts.
                transient = re.search(
                    r"IncompleteRead|Connection broken|Connection reset|ReadTimeout|"
                    r"ConnectTimeout|Timed out|ConnectionError|RemoteDisconnected|"
                    r"Temporary failure in name resolution|HTTP (?:429|50[0234])|"
                    r"SSLZeroReturnError|ChunkedEncodingError|Max retries exceeded",
                    str(exc), re.I)
                if not transient or attempt == 10:
                    raise
                print(f"SWE-Gym transient download error for {env_hash}; "
                      f"retry {attempt}/9 after backoff", flush=True)
                if prefix.is_symlink():
                    raise RuntimeError("untrusted partial Conda prefix") from exc
                if prefix.exists():
                    raise RuntimeError("transient Conda failure left an incomplete environment; "
                                       "preserving " + str(prefix) + " for inspection") from exc
                time.sleep(min(90, 3 * 2 ** min(attempt - 1, 5)))
        # Persist proof only after all official commands and the exact installed
        # package inventory succeeded. Atomic rename avoids torn JSON checkpoints.
        data = json.dumps(env_inventory(prefix), sort_keys=True)
        temporary = inventory_file.with_suffix(".json.tmp")
        temporary.write_text(data)
        os.replace(temporary, inventory_file)
        temporary = recipe_file.with_suffix(".json.tmp")
        temporary.write_text(expected_proof)
        os.replace(temporary, recipe_file)
    # Task setup is performed only in disposable builder overlays. The common
    # image has never contained benchmark checkouts or source archives.
    caches = {"conda": file_inventory(Path("/opt/miniconda3/pkgs")),
              "pip": file_inventory(Path("/root/.cache/pip")), "recipe_caches": file_inventory(ROOT / "caches")}
    (ROOT / "environment-cache-provenance.json").write_text(json.dumps(caches, sort_keys=True))
    validate_isolation()
    shell(["chmod -R a+rX " + shlex.quote(str(ROOT)), "chmod -R a+rX /opt/miniconda3"], cwd=ROOT)


def build_repo(inputs, repo):
    (ROOT / "repo.json").write_text(json.dumps({"repo": repo, "template_id": "swe-gym-lite/" + repo_name(repo)}))
    validate_isolation()


def validate_isolation():
    for path in (ROOT / "builder-mirrors", ROOT / "repos", ROOT / "incoming.git", ROOT / "task-sources",
                 Path("/opt/swe-gym-build"), Path("/testbed"), Path("/var/lib/gpt-trace-template-artifacts")):
        if path.exists() or path.is_symlink():
            raise RuntimeError("forbidden source/mirror payload in permanent image: " + str(path))
    if any(ROOT.rglob("*.git")):
        raise RuntimeError("Git object store in permanent common/repo payload")
    if (ROOT / "os-manifest.json").exists():
        verify_os_packages()
    return {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}


def verify_os_packages():
    tools = runpy.run_path(str(ROOT / "os_packages.py"))
    manifest = json.loads((ROOT / "os-manifest.json").read_text())
    if tools["installed"]() != manifest["installed_after"]:
        raise RuntimeError("build/task setup changed the exact frozen OS package inventory")


def file_inventory(folder):
    records = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            records[path.relative_to(folder).as_posix()] = {"link": os.readlink(path)}
        elif path.is_file():
            records[path.relative_to(folder).as_posix()] = {"sha256": stream_digest(path), "size": path.stat().st_size}
    return records


CACHE_LINK_ROOTS = ("/opt/miniconda3", "/opt/swe-gym-lite/caches", "/usr/bin")
TEMPLATE_ARTIFACT_ROOT = Path("/var/lib/gpt-trace-template-artifacts")


def _wheel_files(value):
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



def _link_or_copy(source, destination):
    """Prefer same-filesystem hardlinks, but never fail solely on EXDEV."""
    try:
        os.link(source, destination)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.copyfile(source, destination)


def _cache_copy_ignore(directory, names):
    if Path(directory) == ROOT / "caches":
        return {"pip", "wheels"} & set(names)
    return set()


def _trusted_wheel_store(path):
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        return False
    return path == BUILDER_WHEEL_STORE or path.is_relative_to(TEMPLATE_ARTIFACT_ROOT)


def _materialize_cas_object(source, target, sha, size):
    if target.exists() or target.is_symlink():
        raise RuntimeError("task wheel destination already exists")
    _link_or_copy(source, target)
    if target.is_symlink() or not target.is_file() or target.stat().st_size != size or stream_digest(target) != sha:
        target.unlink(missing_ok=True)
        raise RuntimeError("materialized wheel CAS object differs")


def export_setup_cache(item, output):
    """Export task-only state while reusable download bytes stay shared."""
    def perform():
        verify_os_packages()
        wheelhouse = ROOT / "wheelhouse" / item["instance_id"]
        if wheelhouse.is_symlink() or not wheelhouse.is_dir():
            raise RuntimeError("task wheelhouse is missing")
        wheels = {}
        for path in sorted(wheelhouse.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("unexpected task wheelhouse entry")
            wheels[path.name] = {"sha256": stream_digest(path), "size": path.stat().st_size}
        wheels = _wheel_files(wheels)
        # Keep export staging on ROOT's filesystem. Hardlinks are cheap here;
        # _link_or_copy still handles /root/.local or unusual split mounts.
        with tempfile.TemporaryDirectory(prefix=".swegym-cache-", dir=ROOT) as temporary:
            folder = Path(temporary)
            shutil.copytree(ROOT / "caches", folder / "caches", symlinks=True,
                            copy_function=_link_or_copy, ignore=_cache_copy_ignore)
            shutil.copytree(ROOT / "task-provenance", folder / "task-provenance",
                            symlinks=True, copy_function=_link_or_copy)
            if (folder / "caches/pip").exists() or (folder / "caches/wheels").exists():
                raise RuntimeError("task setup cache contains excluded reusable download bytes")
            (folder / "wheel-files.json").write_text(json.dumps(wheels, sort_keys=True))
            local = Path("/root/.local")
            if local.exists():
                shutil.copytree(local, folder / "root-local", symlinks=True,
                                copy_function=_link_or_copy)
            (folder / "identity.json").write_text(json.dumps(
                {key: item[key] for key in ("instance_id", "repo", "base_commit", "env_hash")}))
            inventory = file_inventory(folder)
            output_path = Path(output)
            if output_path.is_symlink():
                raise RuntimeError("unsafe task setup-cache output")
            partial = output_path.with_name("." + output_path.name + ".partial")
            if partial.is_symlink():
                raise RuntimeError("unsafe task setup-cache partial output")
            partial.unlink(missing_ok=True)
            try:
                integrity = source_tools().pack(folder, partial, allowed_absolute_links=CACHE_LINK_ROOTS)
                os.replace(partial, output_path)
            finally:
                partial.unlink(missing_ok=True)
        return {**integrity, "files": inventory, "cache_format": 2, "wheel_files": wheels}
    return _timed(item, "warm_export_cache", perform)

def install_setup_cache(item, artifact):
    with tempfile.TemporaryDirectory(prefix="swegym-cache-") as temporary:
        folder = Path(temporary) / "payload"
        source_tools().extract(artifact["path"], folder, sha256=artifact["sha256"], size=artifact["size"],
                               allowed_absolute_links=CACHE_LINK_ROOTS)
        expected = {key: item[key] for key in ("instance_id", "repo", "base_commit", "env_hash")}
        if json.loads((folder / "identity.json").read_text()) != expected:
            raise RuntimeError("setup cache belongs to another task/base/environment")
        cache_format = artifact.get("cache_format", 1)
        if type(cache_format) is not int:
            raise RuntimeError("unsupported task setup cache format")
        if cache_format == 1:
            if set(path.name for path in folder.iterdir()) - {"caches", "wheelhouse", "task-provenance", "root-local", "identity.json"}:
                raise RuntimeError("unexpected legacy task setup cache payload")
            for name in ("caches", "wheelhouse", "task-provenance"):
                destination = ROOT / name
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.move(folder / name, destination)
        elif cache_format == 2:
            if set(path.name for path in folder.iterdir()) - {"caches", "task-provenance", "root-local", "identity.json", "wheel-files.json"}:
                raise RuntimeError("unexpected task setup cache payload")
            wheels = _wheel_files(artifact.get("wheel_files"))
            embedded_pool = folder / "caches" / "wheels"
            if embedded_pool.exists() or embedded_pool.is_symlink():
                raise RuntimeError("content-addressed setup cache embeds duplicate wheel bytes")
            if json.loads((folder / "wheel-files.json").read_text()) != wheels:
                raise RuntimeError("task wheel manifest differs from trusted artifact metadata")
            wheel_store = Path(artifact.get("wheel_store", ""))
            if wheels and not _trusted_wheel_store(wheel_store):
                raise RuntimeError("trusted task wheel store is missing")
            for name in ("caches", "task-provenance"):
                destination = ROOT / name
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.move(folder / name, destination)
            wheelhouse = ROOT / "wheelhouse"
            if wheelhouse.is_symlink():
                raise RuntimeError("untrusted task wheelhouse")
            if wheelhouse.exists():
                shutil.rmtree(wheelhouse)
            task_wheels = wheelhouse / item["instance_id"]
            task_wheels.mkdir(parents=True)
            pool = ROOT / "caches" / "wheels"
            if pool.is_symlink():
                raise RuntimeError("untrusted task wheel pool")
            pool.mkdir(parents=True, exist_ok=True)
            verified = {}
            for filename, record in wheels.items():
                sha, size = record["sha256"], record["size"]
                source = wheel_store / sha
                if sha not in verified:
                    if (source.is_symlink() or not source.is_file() or
                            source.stat().st_size != size or stream_digest(source) != sha):
                        raise RuntimeError("trusted wheel CAS object differs")
                    verified[sha] = size
                elif verified[sha] != size:
                    raise RuntimeError("wheel CAS size collision")
                target = task_wheels / filename
                _materialize_cas_object(source, target, sha, size)
                pooled = pool / sha
                if not pooled.exists():
                    _materialize_cas_object(source, pooled, sha, size)
                elif pooled.is_symlink() or not pooled.is_file() or pooled.stat().st_size != size or stream_digest(pooled) != sha:
                    raise RuntimeError("wheel CAS pool changed")
        else:
            raise RuntimeError("unsupported task setup cache format")
        if (folder / "root-local").exists():
            shutil.copytree(folder / "root-local", "/root/.local", dirs_exist_ok=True, symlinks=True)

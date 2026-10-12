"""Standard-library guest recipes, invoked internally through exec_command.

This module adds no MCP tools. Offline setup uses package downloads collected
during the host build and a network namespace, so a missing cache fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import runpy
import types
from pathlib import Path

ROOT = Path("/opt/swe-gym-lite")
CONDA = Path("/opt/miniconda3/bin/conda")


def run(*args, cwd=None, env=None, input=None):
    return subprocess.run(args, cwd=cwd, env=env, input=input, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


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
def optimized_build_script(env_hash, record):
    original = record["stored_script"]
    if not isinstance(original, list) or any(not isinstance(x, str) for x in original):
        raise RuntimeError("invalid pinned SWE-Gym environment recipe")
    name = record["stored_name"]
    if name != "swegym_" + env_hash:
        raise RuntimeError("environment recipe identity changed")
    commands = list(original)
    migration = []
    for i, command in enumerate(commands):
        if "conda install python=" not in command:
            continue
        match = re.fullmatch(
            r"conda activate (swegym_[0-9a-f]{22}) && conda install python=(\d+\.\d+) -y",
            command)
        if match is None or match.group(1) != name:
            raise RuntimeError("unknown post-create Python downgrade; refusing unsafe optimization")
        migration.append((i, match.group(2)))
    if len(migration) > 1:
        raise RuntimeError("multiple post-create Python downgrades")
    python_version = None
    if migration:
        command_i, python_version = migration[0]
        create = [i for i, text in enumerate(commands) if text == "conda env create --file environment.yml"]
        yaml_indices = [i for i, text in enumerate(commands) if text.startswith("cat <<'") and " > environment.yml\n" in text]
        if len(create) != 1 or len(yaml_indices) != 1 or not yaml_indices[0] < create[0] < command_i:
            raise RuntimeError("unexpected upstream YAML/create/downgrade structure")
        yaml_i = yaml_indices[0]
        first, sep, rest = commands[yaml_i].partition("\n")
        header = re.fullmatch(r"cat <<'([A-Za-z0-9_]+)' > environment\.yml", first)
        if not sep or header is None:
            raise RuntimeError("unrecognized upstream environment YAML heredoc")
        delimiter = "\n" + header.group(1)
        body, sep, tail = rest.rpartition(delimiter)
        if not sep or tail.strip():
            raise RuntimeError("unexpected upstream environment YAML termination")
        if len(re.findall(r"^name: ", body, re.M)) != 1 or "name: " + name + "\n" not in body + "\n":
            raise RuntimeError("official stored environment name differs")
        py_specs = re.findall(r"^\s*-\s*python(?=[=<>!~\s])([^\n]*)$", body, re.M)
        if len(py_specs) > 1:
            raise RuntimeError("multiple upstream Python constraints")
        if py_specs:
            # E.g. Bokeh already specifies the target Python=3.10: no YAML edit.
            if re.fullmatch(r"=\s*" + re.escape(python_version) + r"\s*(?:#.*)?", py_specs[0]) is None:
                raise RuntimeError("upstream Python constraint conflicts with final version")
        else:
            if body.count("\ndependencies:\n") != 1:
                raise RuntimeError("unexpected upstream YAML dependencies field")
            body = body.replace("\ndependencies:\n", "\ndependencies:\n  - python=" + python_version + "\n", 1)
        commands[yaml_i] = first + "\n" + body + delimiter + tail
        # The official last command also activates the newly prepared env.
        commands[command_i] = "conda activate " + name
    if any("conda install python=" in text for text in commands):
        raise RuntimeError("late Python version change remains in optimized recipe")
    fingerprint = lambda values: hashlib.sha256(json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return commands, {"official_script_sha256": fingerprint(original),
                      "effective_script_sha256": fingerprint(commands),
                      "single_solve_python": python_version,
                      "solver": "libmamba", "channel_priority": "strict"}


def build_limits(env=None):
    """Bound compile workers, not guest vCPU count or the frozen package set."""
    result = dict(os.environ if env is None else env)
    # The pinned Miniconda already ships libmamba. Strict channel priority
    # avoids exploring conflicting defaults/conda-forge variants.
    result.update(CONDA_SOLVER="libmamba", CONDA_CHANNEL_PRIORITY="strict",
                  MAKEFLAGS="-j2", CMAKE_BUILD_PARALLEL_LEVEL="2",
                  MAX_JOBS="2", npm_config_jobs="2")
    return result


def env_inventory(prefix):
    """Record installed distributions and conda explicit URLs for provenance."""
    return {"conda_explicit": run(str(CONDA), "list", "--prefix", str(prefix), "--explicit").decode(),
            "pip_freeze": run(str(prefix / "bin/python"), "-m", "pip", "freeze", "--all").decode()}


def clone_env(item, *, offline):
    name = "swegym_" + item["env_hash"]
    stored = Path("/opt/miniconda3/envs") / name
    if not stored.is_dir():
        raise RuntimeError("required frozen environment missing; templates must be rebuilt by the operator")
    expected = json.loads((ROOT / "environments" / (item["env_hash"] + ".json")).read_text())
    if env_inventory(stored) != expected:
        raise RuntimeError("stored environment provenance changed")
    prefix = Path("/opt/miniconda3/envs/testbed")
    if prefix.exists():
        run(str(CONDA), "env", "remove", "--prefix", str(prefix), "-y")
    args = [str(CONDA), "create", "--name", "testbed", "--clone", str(stored), "--yes"]
    if offline:
        args.append("--offline")
    run(*args)
    # Conda clone performs prefix relocation; no environment is renamed/moved.
    if not (prefix / "bin/python").is_file():
        raise RuntimeError("Conda did not materialize testbed")
    return prefix


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
    commands = list(item["repo_script_list"])
    # Clone/reset/removal has been replaced by a validated single-commit source.
    if len(commands) < 9 or not commands[0].startswith("git clone -o origin "):
        raise RuntimeError("pinned upstream repo setup contract changed")
    commands = commands[5:]
    # Pandas may fetch only this checkout's single-commit object store, which
    # has no tags or descendants. Never fetch a full benchmark mirror/network.
    commands = [line.replace("https://github.com/" + item["repo"] + ".git", str(destination)) for line in commands]
    commands = [line.replace("apt-get -y update && apt-get -y upgrade &&", "apt-get -y update &&") for line in commands]
    # pipx/PDM are permanent build-time tools. Upstream installs them before
    # every instance; make that prerequisite idempotent once it is frozen.
    adapted = []
    for line in commands:
        if line.startswith("pipx install pdm"):
            frozen_python = Path("/opt/miniconda3/envs") / ("swegym_" + item["env_hash"]) / "bin/python"
            line = "test -x /root/.local/bin/pdm || pipx install pdm --python " + shlex.quote(str(frozen_python))
        adapted.append(line)
    commands = adapted
    commands.append("git remote | xargs -r -n1 git remote remove")
    commands.append("test \"$(git rev-parse HEAD)\" = " + shlex.quote(item["base_commit"]))
    commands.append("test \"$CONDA_PREFIX\" = " + shlex.quote(str(prefix)))
    return commands


def runtime_environment(item, *, offline):
    env = build_limits()
    env.update(HOME="/root", PIP_CACHE_DIR=str(ROOT / "caches/pip"),
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
    clean_checkout(item, artifact, destination)
    if offline:
        if any(line.startswith("pipx install pdm") for line in item["repo_script_list"]) and not Path("/root/.local/bin/pdm").is_file():
            raise RuntimeError("frozen PDM tool is missing; runtime cannot install it")
        configure_vcs_cache(item)
    prefix = clone_env(item, offline=offline)
    commands = setup_commands(item, destination, prefix)
    # Upstream expects /testbed; builder and evaluator use that path too.
    if destination != "/testbed":
        commands = relocate_checkout(commands, destination)
    shell(commands, cwd=destination, env=runtime_environment(item, offline=offline), offline=offline, log=log)
    if offline:
        expected = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".setup.json")).read_text())
        if env_inventory(prefix) != expected:
            raise RuntimeError("offline official setup differs from the frozen build-time package inventory")
    verify_os_packages()
    # Official pre-install recipes can edit tracked requirements/setup files.
    # Preserve installed packages and ignored build products, but restore the
    # exact tracked base that candidate diffs are defined against.
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
    shell(commands, cwd=destination, env=runtime_environment(item, offline=True), offline=True, log=folder / "eval-setup.log")
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


def warm_task(item, artifact):
    prefix = prepare(item, artifact=artifact, offline=False, log=ROOT / "logs" / (item["instance_id"] + ".warm.log"))
    # Upstream evaluation may install additional distributions. Keep distinct
    # inventories so teacher repo setup and clean evaluator setup each verify
    # against their own build-time phase, without requiring identical outputs.
    (ROOT / "task-provenance" / (item["instance_id"] + ".setup.json")).write_text(json.dumps(env_inventory(prefix), sort_keys=True))
    shell(item["eval_setup_commands"], cwd="/testbed", env=runtime_environment(item, offline=False),
          log=ROOT / "logs/eval-warm.log")
    wheelhouse = ROOT / "wheelhouse" / item["instance_id"]
    wheelhouse.mkdir(parents=True, exist_ok=True)
    inventory = env_inventory(prefix)
    (ROOT / "task-provenance" / (item["instance_id"] + ".json")).write_text(json.dumps(inventory, sort_keys=True))
    # The cloned environment already contains the frozen baseline distributions.
    # Download only added/changed packages; conda-only baseline distributions
    # need not exist on PyPI. VCS distributions retain their exact source commit.
    # A clean offline replay below is the local activation criterion.
    requirements = run(str(prefix / "bin/python"), "-m", "pip", "list", "--format=json").decode()
    packages = json.loads(requirements)
    stored = Path("/opt/miniconda3/envs") / ("swegym_" + item["env_hash"])
    baseline = {entry["name"].lower().replace("_", "-"): entry["version"] for entry in json.loads(
        run(str(stored / "bin/python"), "-m", "pip", "list", "--format=json").decode())}
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
        run(str(prefix / "bin/python"), "-m", "pip", "download", "--no-deps", "--dest", str(wheelhouse),
            "--requirement", str(requirements_file), env=runtime_environment(item, offline=False))
    requirements_file.unlink()
    freeze_vcs_dependencies(item, prefix)
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
    for env_hash, record in sorted(inputs["environments"].items()):
        commands, recipe_proof = optimized_build_script(env_hash, record)
        print("SWE-Gym environment " + env_hash + ": python=" +
              str(recipe_proof["single_solve_python"] or "upstream") +
              ", solver=libmamba, channels=strict", flush=True)
        (ROOT / "environments" / (env_hash + ".recipe.json")).write_text(
            json.dumps(recipe_proof, sort_keys=True))
        shell(commands, cwd=ROOT, env=build_limits({**os.environ,
              "PATH": str(ROOT / "offline-bin") + ":" + os.environ["PATH"]}),
              log=ROOT / "logs" / (env_hash + ".build.log"))
        prefix = Path("/opt/miniconda3/envs") / record["stored_name"]
        (ROOT / "environments" / (env_hash + ".json")).write_text(json.dumps(env_inventory(prefix), sort_keys=True))
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


def export_setup_cache(item, output):
    """Only this task's disposable builder has contributed to this cache."""
    verify_os_packages()
    with tempfile.TemporaryDirectory(prefix="swegym-cache-") as temporary:
        folder = Path(temporary)
        for name in ("caches", "wheelhouse", "task-provenance"):
            shutil.copytree(ROOT / name, folder / name, symlinks=True, copy_function=os.link)
        local = Path("/root/.local")
        if local.exists():
            shutil.copytree(local, folder / "root-local", symlinks=True, copy_function=os.link)
        (folder / "identity.json").write_text(json.dumps({key: item[key] for key in ("instance_id", "repo", "base_commit", "env_hash")}))
        inventory = file_inventory(folder)
        integrity = source_tools().pack(folder, output, allowed_absolute_links=CACHE_LINK_ROOTS)
    return {**integrity, "files": inventory}


def install_setup_cache(item, artifact):
    with tempfile.TemporaryDirectory(prefix="swegym-cache-") as temporary:
        folder = Path(temporary) / "payload"
        source_tools().extract(artifact["path"], folder, sha256=artifact["sha256"], size=artifact["size"],
                               allowed_absolute_links=CACHE_LINK_ROOTS)
        expected = {key: item[key] for key in ("instance_id", "repo", "base_commit", "env_hash")}
        if json.loads((folder / "identity.json").read_text()) != expected:
            raise RuntimeError("setup cache belongs to another task/base/environment")
        if set(path.name for path in folder.iterdir()) - {"caches", "wheelhouse", "task-provenance", "root-local", "identity.json"}:
            raise RuntimeError("unexpected task setup cache payload")
        for name in ("caches", "wheelhouse", "task-provenance"):
            destination = ROOT / name
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(folder / name, destination)
        if (folder / "root-local").exists():
            shutil.copytree(folder / "root-local", "/root/.local", dirs_exist_ok=True, symlinks=True)

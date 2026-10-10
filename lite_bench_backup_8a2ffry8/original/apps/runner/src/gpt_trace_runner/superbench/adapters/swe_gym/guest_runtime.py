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
    with Path(log).open("wb") if log else tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            output.seek(0, os.SEEK_END)
            output.seek(max(0, output.tell()-4000))
            raise RuntimeError(f"official setup failed ({result.returncode}): {output.read().decode(errors='replace')}")


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


def clean_checkout(item, mirror, destination):
    destination = Path(destination)
    if destination.is_symlink():
        raise RuntimeError("unsafe checkout destination")
    if destination.exists():
        shutil.rmtree(destination)
    run("git", "clone", "--shared", "--no-checkout", str(mirror), str(destination))
    run("git", "-C", str(destination), "reset", "--hard", item["base_commit"])
    run("git", "-C", str(destination), "remote", "remove", "origin")
    if run("git", "-C", str(destination), "rev-parse", "HEAD").decode().strip() != item["base_commit"]:
        raise RuntimeError("checkout HEAD differs from exact base_commit")


def setup_commands(item, mirror, prefix):
    commands = list(item["repo_script_list"])
    # The original clone/reset/removal is performed above against cached Git.
    if len(commands) < 9 or not commands[0].startswith("git clone -o origin "):
        raise RuntimeError("pinned upstream repo setup contract changed")
    commands = commands[5:]
    # Pandas' tag fetch uses the frozen local mirror, then removes the remote.
    commands = [line.replace("https://github.com/" + item["repo"] + ".git", str(mirror)) for line in commands]
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
    env = os.environ.copy()
    env.update(HOME="/root", PIP_CACHE_DIR=str(ROOT / "caches/pip"),
               npm_config_cache=str(ROOT / "caches/npm"), PDM_CACHE_DIR=str(ROOT / "caches/pdm"),
               PIPX_HOME=str(ROOT / "caches/pipx"), PIPX_BIN_DIR="/root/.local/bin")
    if offline:
        env.update(PIP_NO_INDEX="1", PIP_FIND_LINKS=str(ROOT / "wheelhouse" / item["instance_id"]),
                   npm_config_offline="true", PDM_NO_UPDATE_CHECK="1")
        env["PATH"] = str(ROOT / "offline-bin") + ":" + env["PATH"]
    return env


def relocate_checkout(commands, destination):
    # Replace the repository root, never the Conda environment's /testbed suffix.
    pattern = r"(?<![A-Za-z0-9_./-])/testbed(?=/|[^A-Za-z0-9_.-]|$)"
    return [re.sub(pattern, lambda _: str(destination), line) for line in commands]


def prepare(item, *, mirror=None, offline=True, destination="/testbed", log=None):
    mirror = Path(mirror) if mirror else ROOT / "repos" / (repo_name(item["repo"]) + ".git")
    if not mirror.is_dir():
        raise RuntimeError("cached repository missing")
    if offline:
        if any(line.startswith("pipx install pdm") for line in item["repo_script_list"]) and not Path("/root/.local/bin/pdm").is_file():
            raise RuntimeError("frozen PDM tool is missing; runtime cannot install it")
        configure_vcs_cache(item)
    run("git", "--git-dir", str(mirror), "cat-file", "-e", item["base_commit"] + "^{commit}")
    prefix = clone_env(item, offline=offline)
    clean_checkout(item, mirror, destination)
    commands = setup_commands(item, mirror, prefix)
    # Upstream expects /testbed; builder and evaluator use that path too.
    if destination != "/testbed":
        commands = relocate_checkout(commands, destination)
    shell(commands, cwd=destination, env=runtime_environment(item, offline=offline), offline=offline, log=log)
    if offline:
        expected = json.loads((ROOT / "task-provenance" / (item["instance_id"] + ".json")).read_text())
        if env_inventory(prefix) != expected:
            raise RuntimeError("offline official setup differs from the frozen build-time package inventory")
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


def verify_candidate(item, candidate, mirror, destination):
    clean_checkout(item, mirror, destination)
    if Path(candidate).stat().st_size:
        run("git", "apply", "--check", "--binary", str(candidate), cwd=destination)
        run("git", "apply", "--binary", str(candidate), cwd=destination)


def warm_task(item, mirror):
    prefix = prepare(item, mirror=mirror, offline=False, log=ROOT / "logs" / (item["instance_id"] + ".warm.log"))
    wheelhouse = ROOT / "wheelhouse" / item["instance_id"]
    wheelhouse.mkdir(parents=True, exist_ok=True)
    inventory = env_inventory(prefix)
    (ROOT / "task-provenance" / (item["instance_id"] + ".json")).write_text(json.dumps(inventory, sort_keys=True))
    # The cloned environment already contains the frozen baseline distributions.
    # Download only added/changed packages; conda-only baseline distributions
    # need not exist on PyPI. VCS distributions retain their exact source commit.
    # A clean offline replay below is the publication criterion.
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
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        stored = pool / sha
        if stored.exists():
            if hashlib.sha256(stored.read_bytes()).hexdigest() != sha:
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
if args in (["update"], ["upgrade"]):
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
    """Content-addressed wheelhouse provenance, verified before publication."""
    records = {}
    for path in sorted((ROOT / "wheelhouse").rglob("*")):
        if path.is_file():
            records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    (ROOT / "download-provenance.json").write_text(json.dumps(records, sort_keys=True))


def build_common(inputs):
    for folder in ("environments", "logs", "task-provenance", "repos", "wheelhouse", "caches/pip", "caches/npm", "caches/pdm", "caches/pipx"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)
    shell(["apt-get update", "apt-get -y upgrade", "apt-get install -y build-essential cmake libpq-dev locales locales-all "
           "openjdk-17-jdk openjdk-17-jre pipx nodejs npm libffi-dev libtiff-dev jq"], cwd=ROOT, log=ROOT / "logs/os.log")
    if not CONDA.is_file():
        raise RuntimeError("pinned Miniconda installer did not complete")
    for env_hash, record in sorted(inputs["environments"].items()):
        shell(record["stored_script"], cwd=ROOT, log=ROOT / "logs" / (env_hash + ".build.log"))
        prefix = Path("/opt/miniconda3/envs") / record["stored_name"]
        (ROOT / "environments" / (env_hash + ".json")).write_text(json.dumps(env_inventory(prefix), sort_keys=True))
    temporary_mirrors = ROOT / "builder-mirrors"
    for item in inputs["tasks"].values():
        mirror = temporary_mirrors / (repo_name(item["repo"]) + ".git")
        warm_task(item, mirror)
    install_offline_apt_guard()
    # Mandatory fresh, network-disabled replay for all 230 task setups. No
    # generation is published if pip/npm/PDM/VCS material is still unavailable.
    for item in inputs["tasks"].values():
        mirror = temporary_mirrors / (repo_name(item["repo"]) + ".git")
        prepare(item, mirror=mirror, offline=True, log=ROOT / "logs" / (item["instance_id"] + ".offline.log"))
    run(str(CONDA), "env", "remove", "--name", "testbed", "-y")
    shutil.rmtree("/testbed")
    shutil.rmtree(temporary_mirrors)
    freeze_downloads()
    run("dpkg-query", "-W", "-f=${Package} ${Version}\\n")
    (ROOT / "os-packages.txt").write_bytes(run("dpkg-query", "-W", "-f=${Package} ${Version}\\n"))
    (ROOT / "inputs.json").write_text(json.dumps(inputs, sort_keys=True))
    # Original template stores only reusable environments/caches, no testbed.
    shell(["chmod -R a+rX " + shlex.quote(str(ROOT)), "chmod -R a+rX /opt/miniconda3"], cwd=ROOT)


def build_repo(inputs, repo):
    mirror = ROOT / "repos" / (repo_name(repo) + ".git")
    run("git", "clone", "--mirror", str(ROOT / "incoming.git"), str(mirror))
    shutil.rmtree(ROOT / "incoming.git")
    run("git", "--git-dir", str(mirror), "remote", "remove", "origin")
    for item in inputs["tasks"].values():
        if item["repo"] == repo:
            run("git", "--git-dir", str(mirror), "cat-file", "-e", item["base_commit"] + "^{commit}")

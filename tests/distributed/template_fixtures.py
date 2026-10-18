"""Complete software fixtures using the REAL pinned 230/11/25 source contract.

Disk bytes/QCOW2 metadata and package inventories are explicitly synthetic.
Hashes are calculated from these actual local bytes, never deployment pins.
No guest, Docker service, network listener or benchmark is started here.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
from gpt_trace_transport import local_templates as local
from workstation_broker.templates import TemplateRegistry


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CgroupFilesystemFixture:
    """Explicit virtual sysfs fixture; executes the actual scope implementation.

    Ordinary files cannot emulate kernel cgroup side effects. Only those file
    side effects are replaced; process identity, ownership checks, membership,
    inherited claims and pidfd SIGTERM use the real production code.
    """
    def __init__(self, mount):
        from unittest.mock import patch
        from workstation_broker import preparation_resources as resources
        self.resources, self.mount, self.patches = resources, Path(mount), []
        unit = self.mount / 'system.slice/gpt-trace-distributed-broker.service'
        unit.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.mount / 'cgroup.controllers').write_text('')
        self.original_create = resources.JobScope.create
        self.original_members = resources.JobScope.members
        self.original_close = resources.JobScope.close
        self.original_kill = resources.JobScope.kill
        self.patches += [patch.object(resources, 'MOUNT', self.mount), patch.object(resources, 'UNIT', unit),
            patch.object(resources, '_write', side_effect=self.write),
            patch.object(resources.JobScope, 'create', side_effect=self.create),
            patch.object(resources.JobScope, 'members', side_effect=self.members),
            patch.object(resources.JobScope, 'close', side_effect=self.close)]

    def start(self):
        for item in self.patches: item.start()
        return self

    def stop(self):
        for item in reversed(self.patches): item.stop()

    def create(self, operation_id, attempt):
        value = self.original_create(operation_id, attempt)
        folder = self.resources.UNIT / value['name']
        (folder / 'cgroup.procs').write_text('')
        (folder / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        (folder / 'cgroup.kill').write_text('')
        return value

    def write(self, path, value):
        import uuid
        temporary = path.with_name('.fixture-write-' + uuid.uuid4().hex)
        temporary.write_text(value)
        os.replace(temporary, path)
        if path.name == 'cgroup.procs':
            (path.parent / 'cgroup.events').write_text('populated ' + ('1' if value.strip() else '0') + '\nfrozen 0\n')
        elif path.name == 'cgroup.kill':
            # Test-only kernel effect, limited to explicitly synthetic /proc
            # memberships describing finite children created by these tests.
            import signal
            from workstation_broker import preparation as jobs
            for raw in (path.parent / 'cgroup.procs').read_text().split():
                stamp = jobs.process_identity(int(raw))
                if stamp is None: continue
                try: fd = os.pidfd_open(stamp['pid'])
                except ProcessLookupError: continue
                try:
                    if jobs.same_process(stamp): signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally: os.close(fd)

    def members(self, state):
        from workstation_broker import preparation as jobs
        path = self.resources.JobScope.path(state)
        if path.exists() and not state['scope']['closed']:
            before = (path / 'cgroup.procs').read_text()
            live = [raw for raw in before.split() if jobs.process_identity(int(raw)) is not None]
            if before != ' '.join(live): self.write(path / 'cgroup.procs', ' '.join(live))
        return self.original_members(state)

    def close(self, state):
        path = self.resources.JobScope.path(state)
        if self.members(state): raise RuntimeError('owned preparation descendants remain')
        if path.exists() and not state['scope']['closed']:
            for candidate in path.iterdir():
                if candidate.is_file(): candidate.unlink()
        from unittest.mock import patch
        with patch.object(self.resources.JobScope, 'members', return_value=[]):
            return self.original_close(state)


def fixture(parent, *, activate=True, label="repo"):
    parent = Path(parent)
    root = parent / "templates"
    namespace = root / "swe-gym-lite"
    folder = namespace / (".build-" + hashlib.sha256(label.encode()).hexdigest()[:16])
    for name in ("repos", "sources", "setup-caches", "wheel-cas", "audit", "os/swe-gym-os"):
        (folder / name).mkdir(mode=0o755, parents=True, exist_ok=True)
    base = parent / "kali-base.qcow2"
    if not base.exists():
        base.write_bytes(b"synthetic-test-independent-kali")
        (parent / "kali-packages.txt").write_bytes(b"synthetic-os-inventory\n")
        (parent / "kali-python-packages.txt").write_bytes(b"synthetic-python-inventory\n")
        golden = local.golden_builder(ROOT)
        provenance = {"source": golden.SOURCE + golden.ARCHIVE, "source_sha256": golden.ARCHIVE_SHA256,
            "base_sha256": local.digest(base), "build_input_sha256": golden.golden_build_input_sha256(),
            "python_lock_sha256": local.digest(ROOT / "infra/workstation/image/requirements.lock"),
            "apt_package_manifest_sha256": local.digest(parent / "kali-packages.txt"),
            "python_package_manifest_sha256": local.digest(parent / "kali-python-packages.txt")}
        local.atomic_json(base.with_suffix(".provenance.json"), provenance)
        for path in (base, parent / "kali-packages.txt", parent / "kali-python-packages.txt"): path.chmod(0o444)
    expected = local.compatibility(base, ROOT)
    build_contract = local.source_contract(ROOT)
    contract = json.loads((ROOT / local.RUNTIME / "contract.json").read_bytes())
    tools = load("fixture_task_sources", ROOT / local.RUNTIME / "task_sources.py")
    common = folder / "common.qcow2"
    common.write_bytes(b"synthetic-test-common")
    common.chmod(0o444)
    infos, templates = {base: {"format": "qcow2"}, common: {"format": "qcow2", "backing-filename": str(base)}}, {}
    repos = {t["repo"] for t in contract["tasks"].values()}
    for repo_name in sorted(repos):
        image = folder / "repos" / (repo_name.replace("/", "_") + ".qcow2")
        image.write_bytes(label.encode() if repo_name == "python/mypy" else ("synthetic:" + repo_name + ":" + label).encode())
        image.chmod(0o444)
        templates["swe-gym-lite/" + repo_name.replace("/", "_")] = {"chain": [
            {"path": image.relative_to(folder).as_posix(), "sha256": local.digest(image)},
            {"path": "common.qcow2", "sha256": local.digest(common)},
            {"path": str(base), "sha256": local.digest(base)}]}
        infos[image] = {"format": "qcow2", "backing-filename": "../common.qcow2"}
    artifacts, mapping, proofs, caches = {}, {}, {}, {}
    shared_wheel = folder / "wheel-cas" / hashlib.sha256(b"synthetic-shared-wheel").hexdigest()
    shared_wheel.write_bytes(b"synthetic-shared-wheel")
    shared_wheel.chmod(0o444)
    wheel_sha = shared_wheel.name
    wheel_cas = {wheel_sha: {"path": shared_wheel.relative_to(folder).as_posix(),
                             "sha256": wheel_sha, "size": shared_wheel.stat().st_size}}
    wheel_files = {"synthetic_shared-1-py3-none-any.whl": {"sha256": wheel_sha,
                                                             "size": shared_wheel.stat().st_size}}
    for logical, task in contract["tasks"].items():
        mapping[logical] = {"template_id": task["template_id"]}
        proofs[logical] = {"base_commit": task["base_commit"], "env_hash": task["env_hash"], "offline": True}
        for kind in ("task_source", "setup_cache"):
            key = tools.artifact_id(kind, logical)
            output = folder / ("sources" if kind == "task_source" else "setup-caches") / (key + ".tar.gz")
            output.write_bytes(("synthetic-archive:" + logical + ":" + kind).encode())
            output.chmod(0o444)
            mapping[logical][kind] = key
            artifacts[key] = {"kind": kind, "logical_task_id": logical, "allowed_template_id": task["template_id"],
                "source_identity": {k: task[k] for k in ("instance_id", "repo", "base_commit")},
                "path": output.relative_to(folder).as_posix(), "size": output.stat().st_size, "sha256": local.digest(output)}
            if kind == "setup_cache":
                artifacts[key].update(cache_format=2, wheel_files=wheel_files)
                name = key + ".downloads.json"
                local.atomic_json(folder / "audit" / name, {})
                caches[name] = local.digest(folder / "audit" / name)
    environments = {key: {"conda": [], "pip": []} for key in contract["environments"]}
    inventories = {key: {"repo_setup": {}, "eval_setup": {}} for key in contract["tasks"]}
    for name, value in (("offline-setups.json", proofs), ("environment-inventories.json", environments),
                        ("environment-downloads.json", {}), ("task-inventories.json", inventories),
                        ("vcs-provenance.json", {key: {} for key in contract["tasks"]})):
        local.atomic_json(folder / "audit" / name, value)
    deb = folder / "os/swe-gym-os/synthetic.deb"
    deb.write_bytes(b"synthetic-test-package-bytes")
    deb.chmod(0o444)
    os_manifest = {"schema_version": 1, "artifacts": {deb.name: {"size": deb.stat().st_size,
        "sha256": local.digest(deb), "package": "synthetic-test", "version": "1", "architecture": "all"}},
        "installed_before": {}, "installed_after": {}}
    local.atomic_json(deb.parent / "manifest.json", os_manifest)
    clean = {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}
    resolved = {"schema_version": 2, "recipe_version": 2, "template_abi": expected["template_abi"],
        "pins": expected["pins"], "source_fingerprint": expected["source_fingerprint"], "security": local.SECURITY,
        "templates": templates, "artifacts": artifacts, "task_artifacts": mapping, "wheel_cas": wheel_cas,
        "isolation_validation": {name: clean for name in repos | {"common"}},
        "golden": {"sha256": expected["golden_sha256"], "provenance": expected["golden_provenance"]},
        "builder_sources": {**{(local.RUNTIME / name).as_posix(): sha for name, sha in build_contract["runtime_sources"].items()},
            local.BUILDER.as_posix(): build_contract["builder_sha256"]}, "environments": environments, "resolved_os": os_manifest,
        "cache_provenance": caches, "offline_setups_sha256": local.digest(folder / "audit/offline-setups.json"),
        **{key: local.digest(folder / "audit" / name) for name, key in (
            ("environment-downloads.json", "environment_downloads_sha256"),
            ("task-inventories.json", "task_inventories_sha256"), ("vcs-provenance.json", "vcs_provenance_sha256"))}}
    generation = hashlib.sha256(local.canonical(resolved)).hexdigest()
    local.atomic_json(folder / "resolved-inputs.json", resolved)
    manifest = {**resolved, "generation": generation, "resolved_inputs_sha256": local.digest(folder / "resolved-inputs.json"),
        "invariants": {"tasks": 230, "repos": 11, "env_hashes": 25, "unmapped_tasks": 0, "missing_base_commits": 0},
        "env_mapping": {key: row["stored_name"] for key, row in contract["environments"].items()}}
    local.atomic_json(folder / "manifest.json", manifest)
    local.seal_validation(folder, expected)
    builder = load("fixture_local_builder", ROOT / "scripts/build_local_templates.py")

    def factory(template_root, golden):
        return TemplateRegistry(template_root, golden, lambda path: infos[path], source_root=ROOT)

    original = folder
    final_path = namespace / "generations" / generation
    # Metadata paths in this test double follow the actual atomic directory move.
    infos.update({final_path / path.relative_to(original): value for path, value in list(infos.items()) if path.is_relative_to(original)})
    final = builder.install_generation(folder, namespace, manifest,
        lambda final, selected: factory(root, base).validate_generation(selected, complete=True, check_images=True))
    if activate: local.activate(root, base, generation, factory, ROOT)
    repo = final / "repos/python_mypy.qcow2"
    own = sorted(key for key, row in mapping.items() if row["template_id"] == "swe-gym-lite/python_mypy")
    return SimpleNamespace(root=root, folder=final, base=base, common=final / "common.qcow2", repo=repo,
        manifest=manifest, resolved=resolved, expected=expected, registry_path=namespace / "registry.json",
        registry=factory(root, base), factory=factory, infos=infos, generation=generation, artifacts=artifacts,
        task_artifacts=mapping, task1=own[0], task2=own[1], contract=contract)

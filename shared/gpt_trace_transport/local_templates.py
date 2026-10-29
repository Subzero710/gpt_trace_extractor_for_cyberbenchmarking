# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
"""Root-owned local generations: recipes, complete byte inventory and activation.

No network client and no guest construction lives in this module. Integrity is
checked in full at install/reuse and first selection, then by metadata and the
specific immutable files actually used. Failed and old generations are retained.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath

SHA = re.compile(r"[0-9a-f]{64}\Z")
SECURITY = {"task_scoped_sources": 1, "broker_streaming": 1,
            "isolated_evaluator": 1, "resolved_os_artifacts": 1}
ROOT = Path(__file__).resolve().parents[2]
PINS = Path("apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/pins.json")
RUNTIME = PINS.parent
BUILDER = Path("scripts/build_local_templates.py")
GOLDEN_BUILDER = Path("infra/workstation/image/build.py")
TEMPLATE_ABI = 1
TASK_RUNTIME_SCHEMA = 2
def golden_source_pins(source_root=ROOT):
    builder = golden_builder(source_root)
    return frozenset({(builder.SOURCE + builder.ARCHIVE, builder.ARCHIVE_SHA256)})

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(path):
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file changed or is not regular during SHA-256 verification")
        value = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1048576), b""):
                value.update(chunk)
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("file changed during SHA-256 verification")
        return value.hexdigest()
    finally: os.close(fd)


def relative(name):
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise ValueError("invalid local generation file path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(x in {"", ".", ".."} for x in path.parts) or path.as_posix() != name:
        raise ValueError("local generation path traversal/noncanonical path")
    return path


def wheel_files(value):
    if not isinstance(value, dict) or len(value) > 4096:
        raise ValueError("invalid task wheel manifest")
    checked = {}
    for name, row in sorted(value.items()):
        if (not isinstance(name, str) or not name or name in {".", ".."} or
                PurePosixPath(name).name != name or "/" in name or "\\" in name or "\0" in name):
            raise ValueError("invalid task wheel filename")
        if (not isinstance(row, dict) or set(row) != {"sha256", "size"} or
                SHA.fullmatch(str(row.get("sha256"))) is None or type(row.get("size")) is not int or
                not 0 <= row["size"] <= 2**43):
            raise ValueError("invalid task wheel integrity record")
        checked[name] = {"sha256": row["sha256"], "size": row["size"]}
    return checked


def safe(path, *, immutable=False, directory=False):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in template local generation path")
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("template local generation must be root-owned and protected")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError("local generation directory is missing")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise ValueError("local generation file is not regular")
    if immutable and info.st_mode & 0o222:
        raise ValueError("local generation file became mutable")
    return path


def atomic_json(path, payload, mode=0o444):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("unsafe local generation destination")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(canonical(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def seal(folder):
    for path in sorted(Path(folder).rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_symlink(): raise ValueError("symlink in staged local generation")
        path.chmod(0o555 if path.is_dir() else 0o444)
        if path.is_file():
            with path.open("rb") as handle: os.fsync(handle.fileno())
        else:
            sync_directory(path)
    Path(folder).chmod(0o555)
    sync_directory(folder)


def file_signature(path):
    info = Path(path).lstat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_mtime_ns, info.st_ctime_ns)


def golden_builder(source_root=ROOT):
    path = Path(source_root) / GOLDEN_BUILDER
    spec = importlib.util.spec_from_file_location("gpt_trace_local_golden", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def template_contract(source_root=ROOT):
    """Stable identity of the expensive SWE-Gym template payload.

    Repository implementation hashes deliberately do not belong here.  Bump
    TEMPLATE_ABI only when the bytes required by an already-built template are
    intentionally made incompatible.
    """
    source_root = Path(source_root)
    pins = json.loads((source_root / PINS).read_bytes())
    if pins.get("schema_version") != 2 or pins.get("recipe_version") != 2:
        raise ValueError("unsupported pinned Lite recipe")
    if digest(source_root / RUNTIME / "contract.json") != pins["contract_sha256"]:
        raise ValueError("pinned Lite source contract differs")
    return {"schema_version": 2, "recipe_version": 2, "template_abi": TEMPLATE_ABI,
        "task_runtime_schema": TASK_RUNTIME_SCHEMA,
        "pins": pins, "source_fingerprint": hashlib.sha256(canonical(pins)).hexdigest(),
        "security": SECURITY}


def source_contract(source_root=ROOT):
    """Exact control/execution code contract used only to authorize a build."""
    source_root = Path(source_root)
    stable = template_contract(source_root)
    return {**stable, "builder_sha256": digest(source_root / BUILDER),
        "golden_build_input_sha256": golden_builder(source_root).golden_build_input_sha256(),
        "runtime_sources": {name: digest(source_root / RUNTIME / name)
            for name in ("guest_runtime.py", "task_sources.py", "os_packages.py", "target_environment.py")}}


def contract_coverage(source_root=ROOT):
    contract = json.loads((Path(source_root) / RUNTIME / "contract.json").read_bytes())
    tasks = contract.get("tasks", {}); environments = contract.get("environments", {})
    return {"tasks": len(tasks), "repos": len({row["repo"] for row in tasks.values()}),
            "env_hashes": len(environments), "unmapped_tasks": 0, "missing_base_commits": 0}


def normalized_template_compatibility(value):
    if not isinstance(value, dict):
        raise ValueError("invalid template compatibility record")
    abi = value.get("template_abi", 1 if value.get("recipe_version") == 2 else None)
    # task_runtime_schema intentionally stays out of expensive-stage compatibility:
    # bumping it invalidates task proofs/final generations while preserving reusable
    # common/source work. TEMPLATE_ABI is for actual permanent-template incompatibility.
    keys = ("schema_version", "recipe_version", "pins", "source_fingerprint", "security",
            "architecture", "golden_sha256", "golden_provenance_sha256", "golden_provenance")
    result = {key: value.get(key) for key in keys}
    result["template_abi"] = abi
    if abi is None or any(result[key] is None for key in keys):
        raise ValueError("incomplete template compatibility record")
    return result


def compatible_template_identity(recorded, expected):
    return normalized_template_compatibility(recorded) == normalized_template_compatibility(expected)


def compatibility(base, source_root=ROOT, *, hasher=digest):
    """Bind templates to immutable inputs on disk, not to the current checkout."""
    base, source_root = Path(base), Path(source_root)
    recipe = template_contract(source_root)
    provenance_path = safe(base.with_suffix(".provenance.json"), immutable=True)
    provenance = json.loads(provenance_path.read_bytes())
    required = {"source", "source_sha256", "base_sha256", "build_input_sha256",
                "python_lock_sha256", "apt_package_manifest_sha256",
                "python_package_manifest_sha256", "target_environment", "platform_tags",
                "architecture", "system_python", "npm"}
    if not isinstance(provenance, dict) or not required <= set(provenance):
        raise ValueError("installed Kali golden provenance is incomplete")
    if (provenance.get("source"), provenance.get("source_sha256")) not in golden_source_pins(source_root):
        raise ValueError("installed Kali golden source provenance is not a trusted immutable pin")
    for key in ("source_sha256", "base_sha256", "build_input_sha256", "python_lock_sha256",
                "apt_package_manifest_sha256", "python_package_manifest_sha256"):
        if SHA.fullmatch(str(provenance.get(key))) is None:
            raise ValueError("installed Kali golden provenance contains an invalid SHA-256: " + key)
    for name, key in (("kali-packages.txt", "apt_package_manifest_sha256"),
                      ("kali-python-packages.txt", "python_package_manifest_sha256")):
        if hasher(safe(base.parent / name, immutable=True)) != provenance.get(key):
            raise ValueError("installed Kali package provenance differs: " + name)
    target_path = source_root / RUNTIME / "target_environment.py"
    spec = importlib.util.spec_from_file_location("gpt_trace_target_environment", target_path)
    if spec is None or spec.loader is None:
        raise ValueError("target environment model is unavailable")
    target_module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = target_module
    spec.loader.exec_module(target_module)
    target = target_module.TargetEnvironment.from_dict(provenance["target_environment"])
    if target.source != "verified-target-interpreter" or provenance.get("platform_tags") != list(target.tags):
        raise ValueError("installed Kali target environment provenance differs")
    if provenance.get("architecture") != target.architecture:
        raise ValueError("installed Kali target architecture provenance differs")
    system_python=provenance.get("system_python")
    if (not isinstance(system_python,dict)
            or re.fullmatch(r'\d+\.\d+\.\d+',str(system_python.get("full_version",""))) is None
            or SHA.fullmatch(str(system_python.get("interpreter_sha256",""))) is None
            or not isinstance(system_python.get("executable"),str) or not system_python["executable"].startswith('/')):
        raise ValueError("installed Kali system Python provenance differs")
    if not isinstance(provenance.get("npm", {}).get("version"), str) or not provenance["npm"]["version"]:
        raise ValueError("installed Kali npm provenance is missing")
    sha = hasher(safe(base, immutable=True))
    if provenance.get("base_sha256") != sha:
        raise ValueError("installed Kali golden SHA-256 differs")
    return {**recipe, "architecture": target.architecture, "golden_sha256": sha,
            "golden_provenance_sha256": hasher(provenance_path), "golden_provenance": provenance}


def seal_validation(folder, expected):
    """Bind all actual built bytes to the verified local recipe before sealing."""
    folder = Path(folder)
    manifest = verify_manifest(folder, expected)
    if (folder / "local-validation.json").exists():
        raise ValueError("local validation already exists; refusing replacement")
    files = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink(): raise ValueError("symlink in local build")
        if path.is_dir():
            safe(path, directory=True)
        elif path.is_file():
            safe(path)
            files[path.relative_to(folder).as_posix()] = {"size": path.stat().st_size, "sha256": digest(path)}
        else:
            raise ValueError("special file in local build")
    atomic_json(folder / "local-validation.json", {"schema": 1,
        "generation": manifest["generation"], "compatibility": expected, "files": files})
    seal(folder)
    verify_local_validation(folder, manifest, expected=expected)


def verify_local_validation(folder, manifest, *, expected, hasher=digest, complete=True):
    folder = Path(folder)
    safe(folder, directory=True, immutable=True)
    validation = json.loads(safe(folder / "local-validation.json", immutable=True).read_bytes())
    if (not isinstance(validation, dict) or set(validation) != {"schema", "generation", "compatibility", "files"}
            or validation["schema"] != 1 or validation["generation"] != manifest.get("generation")
            or not compatible_template_identity(validation["compatibility"], expected)):
        raise ValueError("locally validated generation identity/compatibility differs")
    files = validation["files"]
    if not isinstance(files, dict) or not {"manifest.json", "resolved-inputs.json", "common.qcow2", "audit/offline-setups.json"} <= set(files):
        raise ValueError("local generation byte inventory is incomplete")
    if len(files) > 50000: raise ValueError("oversized local generation inventory")
    for name, row in files.items():
        relative(name)
        if name == "local-validation.json" or any(str(p) in files for p in PurePosixPath(name).parents if str(p) != "."):
            raise ValueError("local generation file/directory collision")
        if (not isinstance(row, dict) or set(row) != {"size", "sha256"} or
                type(row["size"]) is not int or not 0 <= row["size"] <= 2**43 or SHA.fullmatch(str(row["sha256"])) is None):
            raise ValueError("invalid local file integrity record")
    if complete:
        actual = set()
        for path in folder.rglob("*"):
            if path.is_symlink(): raise ValueError("symlink in local generation")
            if path.is_dir(): safe(path, directory=True, immutable=True)
            elif path.is_file(): actual.add(path.relative_to(folder).as_posix())
            else: raise ValueError("special file in local generation")
        if actual != set(files) | {"local-validation.json"}:
            raise ValueError("local generation file population differs")
        selected = files
    else:
        selected = {name: files[name] for name in ("manifest.json", "resolved-inputs.json", "audit/offline-setups.json")}
    for key, artifact in manifest.get("artifacts", {}).items():
        name = artifact.get("path")
        relative(name)
        if files.get(name) != {"size": artifact.get("size"), "sha256": artifact.get("sha256")}:
            raise ValueError("task archive differs from the complete byte inventory")
    for sha, row in manifest.get("wheel_cas", {}).items():
        name = row.get("path")
        relative(name)
        if row.get("sha256") != sha or files.get(name) != {"size": row.get("size"), "sha256": sha}:
            raise ValueError("shared wheel CAS differs from the complete byte inventory")
    for template in manifest.get("templates", {}).values():
        for record in template["chain"][:-1]:
            name = str(relative(record.get("path")))
            if files.get(name, {}).get("sha256") != record.get("sha256"):
                raise ValueError("template backing differs from the complete byte inventory")
    for name, row in selected.items():
        path = safe(folder / name, immutable=True)
        if path.stat().st_size != row["size"] or hasher(path) != row["sha256"]:
            raise ValueError("local generation size/SHA-256 mismatch: " + name)
    return validation


def activate(root, base, generation, registry_factory, source_root=ROOT):
    """Only complete, immutable, fully verified generations may be activated."""
    if SHA.fullmatch(str(generation)) is None: raise ValueError("invalid local generation ID")
    root, base = Path(root), Path(base)
    namespace = safe(root / "swe-gym-lite", directory=True)
    folder = namespace / "generations" / generation
    expected = compatibility(base, source_root)
    manifest = verify_manifest(folder, expected, source_root=source_root)
    verify_local_validation(folder, manifest, expected=expected)
    registry = registry_factory(root, base)
    registry.validate_generation(generation, complete=True, check_images=True)
    current = namespace / "registry.json"
    if current.exists():
        safe(current, immutable=True)
        value = json.loads(current.read_bytes())
        if value == {"schema_version": 2, "generation": generation}: return generation
        if value.get("schema_version") != 2 or SHA.fullmatch(str(value.get("generation"))) is None:
            raise ValueError("invalid existing registry; refusing replacement")
    atomic_json(current, {"schema_version": 2, "generation": generation})
    return generation

def verify_manifest(folder, expected, *, source_root=ROOT):
    """Check resolved identities and complete recipe coverage before activation."""
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    resolved_path = folder / "resolved-inputs.json"
    resolved = json.loads(resolved_path.read_bytes())
    generation = hashlib.sha256(canonical(resolved)).hexdigest()
    if manifest.get("generation") != generation or manifest.get("resolved_inputs_sha256") != digest(resolved_path):
        raise ValueError("resolved template generation/input SHA-256 mismatch")
    for key in ("schema_version", "recipe_version", "task_runtime_schema", "pins", "source_fingerprint", "security", "templates", "artifacts", "task_artifacts", "isolation_validation", "dependency_pool"):
        if manifest.get(key) != resolved.get(key): raise ValueError("manifest/resolved input mismatch: " + key)
    if manifest.get("wheel_cas", {}) != resolved.get("wheel_cas", {}):
        raise ValueError("manifest/resolved input mismatch: wheel_cas")
    manifest_abi = manifest.get("template_abi", 1 if manifest.get("recipe_version") == 2 else None)
    resolved_abi = resolved.get("template_abi", 1 if resolved.get("recipe_version") == 2 else None)
    if manifest_abi != resolved_abi or manifest_abi != expected["template_abi"]:
        raise ValueError("template ABI compatibility mismatch")
    for key in ("schema_version", "recipe_version", "task_runtime_schema", "pins", "source_fingerprint", "security"):
        if manifest.get(key) != expected[key]: raise ValueError("template recipe/security compatibility mismatch: " + key)
    if resolved.get("golden", {}).get("sha256") != expected["golden_sha256"]:
        raise ValueError("template uses another Kali golden")
    coverage = contract_coverage(source_root)
    if manifest.get("invariants") != coverage or len(manifest.get("templates", {})) != coverage["repos"] or len(manifest.get("task_artifacts", {})) != coverage["tasks"] or len(manifest.get("env_mapping", {})) != coverage["env_hashes"]:
        raise ValueError("local Lite coverage changed")
    proof = json.loads((folder / "audit/offline-setups.json").read_bytes())
    if digest(folder / "audit/offline-setups.json") != resolved.get("offline_setups_sha256") or set(proof) != set(manifest["task_artifacts"]) or any(not isinstance(x, dict) or x.get("offline") is not True for x in proof.values()):
        raise ValueError("local fresh isolated replay proof differs")
    contract = json.loads((Path(source_root) / RUNTIME / "contract.json").read_bytes())
    if digest(Path(source_root) / RUNTIME / "contract.json") != expected["pins"]["contract_sha256"]:
        raise ValueError("installed native Lite contract differs")
    if set(manifest["task_artifacts"]) != set(contract["tasks"]) or manifest["env_mapping"] != {
            key: row["stored_name"] for key, row in contract["environments"].items()}:
        raise ValueError("local task/environment mapping differs from pinned source")
    clean = {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}
    isolations = manifest["isolation_validation"]
    repos = {row["repo"] for row in contract["tasks"].values()}
    wheel_cas = manifest.get("wheel_cas", {})
    if not isinstance(wheel_cas, dict) or len(wheel_cas) > 50000:
        raise ValueError("invalid shared wheel CAS inventory")
    for sha, row in wheel_cas.items():
        if (SHA.fullmatch(str(sha)) is None or not isinstance(row, dict) or set(row) != {"path", "sha256", "size"} or
                row.get("sha256") != sha or row.get("path") != "wheel-cas/" + sha or
                type(row.get("size")) is not int or not 0 <= row["size"] <= 2**43):
            raise ValueError("invalid shared wheel CAS record")
        path = folder / relative(row["path"])
        if path.is_symlink() or not path.is_file() or path.stat().st_size != row["size"] or digest(path) != sha:
            raise ValueError("shared wheel CAS object integrity differs")
    if not isinstance(isolations, dict) or set(isolations) != repos | {"common"} or any(
            row != clean for row in isolations.values()):
        raise ValueError("permanent template source-isolation proof differs")
    for logical, task in contract["tasks"].items():
        if proof[logical] != {"base_commit": task["base_commit"], "env_hash": task["env_hash"], "offline": True}:
            raise ValueError("local replay used a different task base/environment")
        mapping = manifest["task_artifacts"][logical]
        if mapping.get("template_id") != task["template_id"]:
            raise ValueError("local task/repository template mapping differs")
        for kind in ("task_source", "setup_cache"):
            artifact = manifest["artifacts"].get(mapping.get(kind), {})
            identity = {key: task[key] for key in ("instance_id", "repo", "base_commit")}
            if artifact.get("source_identity") != identity or artifact.get("kind") != kind:
                raise ValueError("local task artifact source provenance differs")
            if kind == "setup_cache":
                cache_format = artifact.get("cache_format", 1)
                if type(cache_format) is not int:
                    raise ValueError("unsupported task setup cache format")
                if cache_format == 1:
                    if "wheel_files" in artifact:
                        raise ValueError("legacy setup cache unexpectedly declares wheel CAS references")
                elif cache_format == 2:
                    for wheel in wheel_files(artifact.get("wheel_files")).values():
                        shared = wheel_cas.get(wheel["sha256"])
                        if shared is None or shared.get("size") != wheel["size"]:
                            raise ValueError("task setup cache references an unknown shared wheel")
                else:
                    raise ValueError("unsupported task setup cache format")
    if set(manifest["templates"]) != {row["template_id"] for row in contract["tasks"].values()}:
        raise ValueError("local template IDs differ from the pinned contract")
    environments = json.loads((folder / "audit/environment-inventories.json").read_bytes())
    if environments != resolved.get("environments") or set(environments) != set(contract["environments"]):
        raise ValueError("local Conda environment inventory differs")
    for name, key in (("environment-downloads.json", "environment_downloads_sha256"),
                      ("task-inventories.json", "task_inventories_sha256"),
                      ("vcs-provenance.json", "vcs_provenance_sha256")):
        if digest(folder / "audit" / name) != resolved.get(key):
            raise ValueError("resolved dependency/provenance audit differs: " + name)
    inventories = json.loads((folder / "audit/task-inventories.json").read_bytes())
    vcs = json.loads((folder / "audit/vcs-provenance.json").read_bytes())
    if set(inventories) != set(contract["tasks"]) or set(vcs) != set(contract["tasks"]):
        raise ValueError("local per-task package/VCS inventory coverage differs")
    caches = resolved.get("cache_provenance")
    if not isinstance(caches, dict) or len(caches) != coverage["tasks"]:
        raise ValueError("local setup-cache download coverage differs")
    for name, sha in caches.items():
        relative(name)
        if "/" in name or digest(folder / "audit" / name) != sha:
            raise ValueError("local setup-cache download audit differs")
    os_folder = folder / "os/swe-gym-os"
    os_manifest = json.loads((os_folder / "manifest.json").read_bytes())
    if os_manifest != resolved.get("resolved_os"):
        raise ValueError("local resolved OS provenance differs")
    for name, row in os_manifest.get("artifacts", {}).items():
        relative(name)
        path = os_folder / name
        if path.is_symlink() or not path.is_file() or digest(path) != row.get("sha256") or path.stat().st_size != row.get("size"):
            raise ValueError("local resolved OS artifact integrity differs")
    expected_artifacts = set()
    spec = importlib.util.spec_from_file_location("gpt_trace_task_artifact_ids", Path(source_root) / RUNTIME / "task_sources.py")
    tools = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tools)
    for logical, task in contract["tasks"].items():
        mapping = manifest["task_artifacts"][logical]
        if set(mapping) != {"template_id", "task_source", "setup_cache"}:
            raise ValueError("local task scope fields differ")
        for kind in ("task_source", "setup_cache"):
            key = tools.artifact_id(kind, logical)
            row = manifest["artifacts"].get(key, {})
            if (mapping[kind] != key or row.get("logical_task_id") != logical or
                    row.get("allowed_template_id") != task["template_id"]):
                raise ValueError("local task artifact identity/scope differs")
            expected_artifacts.add(key)
    if set(manifest["artifacts"]) != expected_artifacts:
        raise ValueError("local artifacts contain missing or cross-task entries")
    if resolved.get("golden", {}).get("provenance") != expected["golden_provenance"]:
        raise ValueError("local golden provenance differs")
    for template_id, row in manifest["templates"].items():
        chain = row.get("chain") if isinstance(row, dict) else None
        if (not isinstance(chain, list) or len(chain) != 3 or chain[1].get("path") != "common.qcow2"
                or chain[2].get("sha256") != expected["golden_sha256"]):
            raise ValueError("local template chain shape differs")
        relative(chain[0].get("path"))
    return manifest


def pool_contract(source_root=ROOT):
    """Content identity for dependency acquisition; independent of KVM/golden/runtime."""
    source_root = Path(source_root)
    pins = json.loads((source_root / PINS).read_bytes())
    if pins.get("schema_version") != 2 or pins.get("recipe_version") != 2:
        raise RuntimeError("unsupported pinned Lite contract")
    contract_path=source_root / RUNTIME / "contract.json"
    if digest(contract_path) != pins["contract_sha256"]:
        raise RuntimeError("SWE-Gym Lite source contract differs")
    try:
        contract=json.loads(contract_path.read_bytes())
        tasks=contract["tasks"];environments=contract["environments"]
        coverage={"tasks":len(tasks),"repos":len({row["repo"] for row in tasks.values()}),
                  "conda_recipes":len(environments)}
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise RuntimeError("invalid SWE-Gym Lite source contract") from exc
    if not all(type(value) is int and value>0 for value in coverage.values()):
        raise RuntimeError("empty SWE-Gym Lite source contract")
    lock = source_root / RUNTIME / "conda-lock.json"
    if lock.is_symlink() or not lock.is_file():
        raise RuntimeError("missing SWE-Gym Lite Conda lock")
    try:
        lock_payload = json.loads(lock.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeError("invalid SWE-Gym Lite Conda lock") from exc
    platform = lock_payload.get("platform")
    if not isinstance(platform, str) or not platform:
        raise RuntimeError("SWE-Gym Lite Conda lock has no target platform identity")
    return {"fetch_kind": "download-only-pool-v3", "pool_schema": 3,
            "pins": pins, "platform": platform, "coverage": coverage,
            "conda_lock_sha256": digest(lock),
            "fetcher_sha256": digest(source_root / "scripts/superbench_pool.py")}

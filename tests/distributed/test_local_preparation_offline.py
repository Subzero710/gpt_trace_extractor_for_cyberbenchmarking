"""Real-file/process software checks. No KVM, live HTTP, Arrow or ChatGPT claim."""
from __future__ import annotations
import ast
import contextlib
import errno
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "shared"), str(ROOT / "apps/workstation-broker/src"),
               str(ROOT / "scripts"), str(ROOT / "tests/distributed")]
sys.dont_write_bytecode = True
from gpt_trace_transport import local_templates as local
from gpt_trace_transport.wire import CONTROLLER_ACTIONS, TransportFailure, IdentityFailure
from workstation_broker import preparation as jobs
from workstation_broker import shutdown_observer as shutdown
from template_fixtures import fixture, load, CgroupFilesystemFixture
from workstation_broker import preparation_resources as resources


def temporary_tree(parent):
    """Restore test-only chmods so fixtures can be removed without root override."""
    for path in sorted(Path(parent).rglob("*"), key=lambda x: len(x.parts)):
        if path.is_dir() and not path.is_symlink(): path.chmod(0o700)


class PersistentBuilderPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load("persistent_builder_policy", ROOT / "scripts/build_local_templates.py")

    def test_qcow2_volumes_are_never_deleted_by_normal_builder_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / "retained.qcow2"
            image.write_bytes(b"persistent-volume")
            with self.assertRaisesRegex(RuntimeError, "outside make throw_volumes"):
                self.builder._discard(image)
            self.assertEqual(image.read_bytes(), b"persistent-volume")

    def test_stage_selection_preserves_common_work_then_imports_other_checkpoints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            common_heavy = root / ".build-heavy-common"
            task_heavy = root / ".build-many-tasks"
            for stage in (common_heavy, task_heavy):
                (stage / ".checkpoints").mkdir(parents=True)
            (common_heavy / "common.qcow2").write_bytes(b"x" * (2 * 1024 * 1024))
            (task_heavy / "common.qcow2").write_bytes(b"x" * (1024 * 1024))
            for index in range(20):
                (task_heavy / ".checkpoints" / f"task-{index}.json").write_text("{}")
            self.assertGreater(self.builder._stage_score(common_heavy), self.builder._stage_score(task_heavy))

    def test_stage_specific_completion_proofs_exist_for_every_persistent_qcow2_kind(self):
        self.assertEqual(self.builder.COMMON_COMPLETION, "/opt/swe-gym-lite/common-template-complete.json")
        self.assertEqual(self.builder.REPO_COMPLETION, "/opt/swe-gym-lite/repository-template-complete.json")
        self.assertEqual(self.builder.TASK_COMPLETION, "/opt/swe-gym-task/build-complete.json")
        self.assertEqual(self.builder.RESOLVER_COMPLETION, "/opt/swe-gym-os-resolver-complete.json")

    def test_task_scratches_skip_trim_and_warm_cache_is_persistent_builder_only(self):
        task_script = self.builder.firstboot("echo fixture", trim=False, shared_warm_cache=True)
        permanent_script = self.builder.firstboot("echo fixture", trim=True, shared_warm_cache=False)
        self.assertNotIn("fstrim -av", task_script)
        self.assertIn("GPTTRACE_SHARED_WARM_CACHE", task_script)
        self.assertIn("/dev/vdb", task_script)
        self.assertIn("fstrim -av", permanent_script)
        self.assertNotIn("GPT_TRACE_SHARED_WARM_CACHE", permanent_script)
        self.assertEqual(self.builder.warm_cache_gib(self.builder.VIRTUAL_GIB), 128)
        source = (ROOT / "scripts/build_local_templates.py").read_text()
        self.assertIn("recovering completed work from interrupted task warm scratch", source)
        self.assertIn("module['warm_task'](item,artifact)", source)
        self.assertIn("module['replay_task'](item,artifact,cache)", source)
        self.assertIn("cache_disk=warm_cache, trim=False", source)
        self.assertIn("refresh_runtime=True", source)

    def test_final_manifest_propagates_template_abi(self):
        tree = ast.parse((ROOT / "scripts/build_local_templates.py").read_bytes())
        candidates = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "manifest" for target in node.targets):
                continue
            keys = {key.value for key in node.value.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)}
            if "generation" in keys and "resolved_inputs_sha256" in keys:
                candidates.append(keys)
        self.assertEqual(len(candidates), 1)
        self.assertIn("template_abi", candidates[0])

    def test_task_checkpoint_reuse_uses_semantic_schema_and_never_falls_back_to_stored_env(self):
        builder_source = (ROOT / "scripts/build_local_templates.py").read_text()
        guest_source = (ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py").read_text()
        self.assertIn("TASK_RUNTIME_SCHEMA = 2", builder_source)
        self.assertIn('"task-v" + str(TASK_RUNTIME_SCHEMA)', builder_source)
        self.assertNotIn("runtime_fingerprint", builder_source)
        self.assertNotIn("task_runtime_fingerprint", guest_source)
        recovery = guest_source.split("def recovery_env_prefix(item):", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('/opt/miniconda3/envs/testbed', recovery)
        self.assertNotIn("stored_env_prefix(item)", recovery)
        self.assertIn("replay-state.json", guest_source)
        contract = local.template_contract(ROOT)
        self.assertEqual(contract["task_runtime_schema"], 2)

    def test_package_capture_prefers_built_wheels_and_uses_all_four_guest_cpus(self):
        source = (ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py").read_text()
        self.assertIn('workers = max(1, min(4, os.cpu_count() or 1))', source)
        self.assertIn('"pip", "wheel", "--no-deps"', source)
        self.assertIn('"pip", "download", "--no-deps"', source)


class WheelCacheFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = load("wheel_cache_guest_runtime", ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py")
        cls.sources = load("wheel_cache_task_sources", ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/task_sources.py")
        cls.runtime._sources = cls.sources

    def item(self):
        return {"instance_id": "fixture-task", "repo": "owner/repo", "base_commit": "a" * 40,
                "env_hash": "b" * 22, "template_id": "swe-gym-lite/owner_repo"}

    def pack(self, folder, archive):
        return self.sources.pack(folder, archive, allowed_absolute_links=self.runtime.CACHE_LINK_ROOTS)

    def test_format2_reconstructs_wheelhouse_from_one_trusted_cas_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = root / "guest"
            trusted = root / "trusted-template-artifacts"
            payload = root / "payload"
            wheel_store = trusted / "setup" / "wheels"
            for path in (guest, payload / "caches", payload / "task-provenance", wheel_store):
                path.mkdir(parents=True, exist_ok=True)
            item = self.item()
            wheel_bytes = b"one immutable shared wheel payload"
            sha = hashlib.sha256(wheel_bytes).hexdigest()
            wheel = wheel_store / sha
            wheel.write_bytes(wheel_bytes)
            manifest = {"shared-1-py3-none-any.whl": {"sha256": sha, "size": len(wheel_bytes)}}
            (payload / "identity.json").write_text(json.dumps({key: item[key]
                for key in ("instance_id", "repo", "base_commit", "env_hash")}))
            (payload / "wheel-files.json").write_text(json.dumps(manifest, sort_keys=True))
            archive = root / "cache.tar.gz"
            integrity = self.pack(payload, archive)
            artifact = {**integrity, "path": str(archive), "cache_format": 2,
                        "wheel_files": manifest, "wheel_store": str(wheel_store)}
            old_root, old_trusted = self.runtime.ROOT, self.runtime.TEMPLATE_ARTIFACT_ROOT
            try:
                self.runtime.ROOT = guest
                self.runtime.TEMPLATE_ARTIFACT_ROOT = trusted
                self.runtime.install_setup_cache(item, artifact)
            finally:
                self.runtime.ROOT = old_root
                self.runtime.TEMPLATE_ARTIFACT_ROOT = old_trusted
            installed = guest / "wheelhouse" / item["instance_id"] / "shared-1-py3-none-any.whl"
            pooled = guest / "caches" / "wheels" / sha
            self.assertEqual(installed.read_bytes(), wheel_bytes)
            self.assertEqual(pooled.read_bytes(), wheel_bytes)
            self.assertEqual(installed.stat().st_ino, wheel.stat().st_ino)
            self.assertEqual(pooled.stat().st_ino, wheel.stat().st_ino)

    def test_link_or_copy_falls_back_only_for_cross_device_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = root / "source", root / "target"
            source.write_bytes(b"cross-device fixture")
            with patch.object(self.runtime.os, "link", side_effect=OSError(errno.EXDEV, "cross-device")):
                self.runtime._link_or_copy(source, target)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            with patch.object(self.runtime.os, "link", side_effect=OSError(errno.EPERM, "denied")):
                with self.assertRaises(PermissionError):
                    self.runtime._link_or_copy(source, root / "denied")

    def test_format2_accepts_only_runtime_tree_or_exact_builder_wheel_store(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime_store = root / "runtime" / "artifact" / "wheels"
            builder_store = root / "builder-wheel-cas"
            foreign = root / "foreign"
            for path in (runtime_store, builder_store, foreign):
                path.mkdir(parents=True)
            old_runtime, old_builder = self.runtime.TEMPLATE_ARTIFACT_ROOT, self.runtime.BUILDER_WHEEL_STORE
            try:
                self.runtime.TEMPLATE_ARTIFACT_ROOT = root / "runtime"
                self.runtime.BUILDER_WHEEL_STORE = builder_store
                self.assertTrue(self.runtime._trusted_wheel_store(runtime_store))
                self.assertTrue(self.runtime._trusted_wheel_store(builder_store))
                self.assertFalse(self.runtime._trusted_wheel_store(foreign))
            finally:
                self.runtime.TEMPLATE_ARTIFACT_ROOT = old_runtime
                self.runtime.BUILDER_WHEEL_STORE = old_builder

    def test_task_cache_explicitly_excludes_reusable_pip_and_wheel_pools(self):
        with tempfile.TemporaryDirectory() as temp:
            old_root = self.runtime.ROOT
            try:
                self.runtime.ROOT = Path(temp)
                ignored = self.runtime._cache_copy_ignore(Path(temp) / "caches",
                                                          ["pip", "wheels", "git", "npm"])
                self.assertEqual(ignored, {"pip", "wheels"})
                self.assertEqual(self.runtime._cache_copy_ignore(Path(temp) / "caches/git",
                                                                 ["pip", "wheels"]), set())
            finally:
                self.runtime.ROOT = old_root

    def test_legacy_format1_cache_remains_installable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest, payload = root / "guest", root / "payload"
            for path in (guest, payload / "caches", payload / "wheelhouse" / "fixture-task",
                         payload / "task-provenance"):
                path.mkdir(parents=True, exist_ok=True)
            item = self.item()
            legacy = payload / "wheelhouse" / item["instance_id"] / "legacy.whl"
            legacy.write_bytes(b"legacy wheel bytes")
            (payload / "identity.json").write_text(json.dumps({key: item[key]
                for key in ("instance_id", "repo", "base_commit", "env_hash")}))
            archive = root / "legacy.tar.gz"
            integrity = self.pack(payload, archive)
            old_root = self.runtime.ROOT
            try:
                self.runtime.ROOT = guest
                self.runtime.install_setup_cache(item, {**integrity, "path": str(archive)})
            finally:
                self.runtime.ROOT = old_root
            self.assertEqual((guest / "wheelhouse" / item["instance_id"] / "legacy.whl").read_bytes(),
                             b"legacy wheel bytes")

    def test_wheel_manifest_rejects_traversal_and_boolean_sizes(self):
        sha = "a" * 64
        for name in (".", "..", "../x.whl", "a/b.whl", "a\\b.whl"):
            with self.assertRaises(RuntimeError):
                self.runtime._wheel_files({name: {"sha256": sha, "size": 1}})
        with self.assertRaises(RuntimeError):
            self.runtime._wheel_files({"x.whl": {"sha256": sha, "size": True}})


class DistributedMountPolicyTests(unittest.TestCase):
    def test_execution_image_storage_requires_exact_mount_target(self):
        source = (ROOT / "scripts/distributed.py").read_text()
        self.assertIn('"TARGET", "-T", image_directory', source)
        self.assertIn("Path(target).resolve() != image_directory.resolve()", source)
        self.assertIn("dedicated writable local ext4/xfs mount target", source)


class LocalGenerationTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0: self.skipTest("real root-ownership fixture required")
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name)
        self.files = fixture(self.parent)

    def tearDown(self):
        if hasattr(self, "temp"):
            temporary_tree(self.parent)
            self.temp.cleanup()

    def snapshot(self):
        return {p.relative_to(self.parent).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode), p.stat().st_mtime_ns)
                for p in self.parent.rglob("*") if p.is_file()}

    def test_complete_real_pinned_contract_and_atomically_activated_local_bytes(self):
        f = self.files
        self.assertEqual(len(f.manifest["task_artifacts"]), 230)
        self.assertEqual(len(f.manifest["templates"]), 11)
        self.assertEqual(len(f.manifest["env_mapping"]), 25)
        self.assertEqual(f.registry.current_generation(complete=True, check_images=True), f.generation)
        for logical, task in f.contract["tasks"].items():
            record = f.registry.select(task["template_id"])
            mapping = f.registry.task_scope(record, logical)
            for kind in ("task_source", "setup_cache"):
                row = f.registry.artifact({**record, "logical_task_id": logical}, mapping[kind])
                self.assertEqual(local.digest(row["host_path"]), row["sha256"])
        self.assertFalse(f.folder.stat().st_mode & 0o222)

    def test_shared_wheel_cas_is_referenced_by_multiple_tasks_without_duplicate_bytes(self):
        f = self.files
        objects = []
        for logical in (f.task1, f.task2):
            task = f.contract["tasks"][logical]
            selected = f.registry.select(task["template_id"])
            mapping = f.registry.task_scope(selected, logical)
            row = f.registry.artifact({**selected, "logical_task_id": logical}, mapping["setup_cache"])
            self.assertEqual(row["cache_format"], 2)
            self.assertEqual(len(row["wheel_objects"]), 1)
            objects.append(row["wheel_objects"][0])
        self.assertEqual(len(f.manifest["wheel_cas"]), 1)
        self.assertEqual(objects[0]["sha256"], objects[1]["sha256"])
        self.assertEqual(objects[0]["host_path"], objects[1]["host_path"])
        self.assertEqual(objects[0]["host_path"].stat().st_ino, objects[1]["host_path"].stat().st_ino)

    def test_permanent_reuse_changes_no_bytes_permissions_or_timestamps(self):
        before = self.snapshot()
        local.activate(self.files.root, self.files.base, self.files.generation, self.files.factory, ROOT)
        local.activate(self.files.root, self.files.base, self.files.generation, self.files.factory, ROOT)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_artifact_cannot_reactivate_and_valid_registry_is_preserved(self):
        f = self.files
        registry_before = f.registry_path.read_bytes()
        key = f.task_artifacts[f.task1]["task_source"]
        path = f.folder / f.artifacts[key]["path"]
        path.chmod(0o644); path.write_bytes(b"corrupted actual bytes"); path.chmod(0o444)
        with self.assertRaises(ValueError): local.activate(f.root, f.base, f.generation, f.factory, ROOT)
        self.assertEqual(f.registry_path.read_bytes(), registry_before)
        self.assertTrue(f.folder.is_dir())

    def test_failed_atomic_install_keeps_previous_generation_and_diagnostics(self):
        f = self.files
        before = self.snapshot()
        builder = load("local_install_failure_test", ROOT / "scripts/build_local_templates.py")
        staged = f.registry_path.parent / ".build-failed"
        staged.mkdir()
        (staged / "diagnostic.qcow2").write_bytes(b"synthetic failed-stage bytes")
        generation = hashlib.sha256(b"failed fixture generation").hexdigest()
        with self.assertRaisesRegex(RuntimeError, "validation fixture"):
            builder.install_generation(staged, f.registry_path.parent, {"generation": generation},
                lambda *_: (_ for _ in ()).throw(RuntimeError("validation fixture failed")))
        self.assertEqual((staged / "diagnostic.qcow2").read_bytes(), b"synthetic failed-stage bytes")
        for name, value in before.items(): self.assertEqual(self.snapshot()[name], value)

    def test_missing_validation_mutable_metadata_bad_mapping_and_foreign_owner_rejected(self):
        f = self.files
        validation = f.folder / "local-validation.json"
        original = validation.read_bytes()
        for attack in ("missing", "mutable", "compatibility", "sha", "unmanifested"):
            f.folder.chmod(0o755)
            if not validation.exists(): validation.write_bytes(original)
            validation.chmod(0o444)
            if attack == "missing": validation.unlink()
            elif attack == "mutable": validation.chmod(0o644)
            elif attack in {"compatibility", "sha"}:
                changed = json.loads(original)
                if attack == "compatibility": changed["compatibility"]["source_fingerprint"] = "0" * 64
                else: changed["files"]["manifest.json"]["sha256"] = "0" * 64
                local.atomic_json(validation, changed)
            else:
                (f.folder / "foreign-file").write_bytes(b"unmanifested")
                (f.folder / "foreign-file").chmod(0o444)
            f.folder.chmod(0o555)
            with self.assertRaises((ValueError, FileNotFoundError)):
                f.factory(f.root, f.base).validate_generation(f.generation, complete=True)
            f.folder.chmod(0o755)
            if attack == "unmanifested": (f.folder / "foreign-file").unlink()
            local.atomic_json(validation, json.loads(original))
            f.folder.chmod(0o555)
        path = f.repo
        original_lstat = Path.lstat
        def foreign_owner(candidate):
            value = original_lstat(candidate)
            if candidate != path: return value
            return SimpleNamespace(st_uid=65534, st_mode=value.st_mode)
        with patch.object(Path, "lstat", side_effect=foreign_owner, autospec=True):
            with self.assertRaises(ValueError): f.registry.select("swe-gym-lite/python_mypy")

    def test_hash_cache_checks_used_files_and_does_not_scan_unrelated_archives_per_tool(self):
        f = self.files
        record = f.registry.select("swe-gym-lite/python_mypy")
        import workstation_broker.templates as templates
        with patch.object(templates, "sha256", wraps=templates.sha256) as hashing:
            for _ in range(5): f.registry.verify_record(record)
        self.assertEqual(hashing.call_count, 0)
        other = next(key for key, value in f.artifacts.items() if value["logical_task_id"] != f.task1)
        path = f.folder / f.artifacts[other]["path"]
        path.chmod(0o644); path.write_bytes(b"unused fixture changed"); path.chmod(0o444)
        f.registry.verify_record(record)  # No unrelated archive read in this tool.
        selected = f.registry.select(f.artifacts[other]["allowed_template_id"])
        with self.assertRaises(ValueError):
            f.registry.artifact({**selected, "logical_task_id": f.artifacts[other]["logical_task_id"]}, other)

    def test_recorded_checkpoint_generation_survives_new_registry_activation(self):
        f = self.files
        selected = f.registry.select("swe-gym-lite/python_mypy")
        second = fixture(self.parent, label="new-repo-bytes")
        self.assertNotEqual(f.generation, second.generation)
        self.assertEqual(f.registry.verify_record(selected), selected)
        self.assertTrue(f.folder.is_dir())
        self.assertEqual(second.registry.current_generation(), second.generation)

    def test_wrong_golden_provenance_is_never_repaired(self):
        f = self.files
        path = f.base.with_suffix(".provenance.json")
        value = json.loads(path.read_bytes()); value["source_sha256"] = "0" * 64
        local.atomic_json(path, value)
        before = self.snapshot()
        with self.assertRaises(ValueError): local.compatibility(f.base, ROOT)
        self.assertEqual(before, self.snapshot())


class DurableJobProcessTests(unittest.TestCase):
    """Real finite children/locks/files; /proc records and KVM are explicit fixtures."""
    def setUp(self):
        if os.geteuid() != 0: self.skipTest("real root-owned process/file fixture required")
        # cgroup filesystem ownership tests require a non-writable ancestor;
        # /tmp itself is world-writable and cannot model that security boundary.
        import pwd
        trusted_temp_parent = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        if (trusted_temp_parent.is_symlink() or trusted_temp_parent.stat().st_uid != 0
                or trusted_temp_parent.stat().st_mode & 0o022):
            self.skipTest("root-private temporary parent required for cgroup fixture")
        self.temp = tempfile.TemporaryDirectory(dir=trusted_temp_parent)
        self.parent = Path(self.temp.name)
        self.files = fixture(self.parent)
        self.deployment = {"control_id": "fixture-control", "execution_id": "fixture-execution"}
        self.manager = jobs.PreparationManager(self.files.base, self.files.root, self.files.registry,
            source_root=ROOT, deployment=self.deployment)
        self.identified = self.manager.probe({"source_contract": local.pool_contract(ROOT)})
        self.operation_id = self.identified["operation_id"]
        self.children = []
        self.original_popen = subprocess.Popen
        self.mode = "success"
        self.proc = self.parent / "proc-fixture"
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("00000000-0000-4000-8000-000000000001")
        self.proc_patch = patch.object(jobs, "PROC", self.proc)
        self.proc_patch.start()
        self.scope_model = CgroupFilesystemFixture(self.parent / 'cgroup-sysfs-fixture').start()
        self.docker_patch = patch.object(jobs, 'source_containers', return_value=[])
        self.docker_patch.start()
        self.resources_docker_patch = patch.object(resources, 'source_containers', return_value=[])
        self.resources_docker_patch.start()
        self.script = self.parent / "finite-build-boundary-fixture.py"
        self.count = self.parent / "construction-boundary-count"
        # Only physical preparation is replaced. The actual worker claim, lock,
        # phases, complete registry validation, activation and ready stamp run.
        body = '''import json,os,sys,time
from pathlib import Path
sys.path[:0] = INPUT_PATHS
from workstation_broker import preparation as jobs
from workstation_broker.templates import TemplateRegistry
jobs.BASE = BASE_PATH
jobs.PROC = PROC_PATH
sys.path.insert(0, FIXTURE_HELPERS)
from template_fixtures import CgroupFilesystemFixture
scope_model = CgroupFilesystemFixture(SCOPE_PATH).start()
jobs.source_containers = lambda deployment: []
pid = os.getpid()
record = jobs.PROC / str(pid)
record.mkdir()
fields = ['S','1',str(os.getpgrp()),str(os.getsid(0))] + ['0'] * 15 + [str(time.monotonic_ns() // 10000000)] + ['0'] * 10
(record / 'stat').write_text(str(pid) + ' (python-fixture) ' + ' '.join(fields))
(record / 'environ').write_bytes(b'\\0'.join((k+'='+v).encode() for k,v in os.environ.items()))
mode = sys.argv[1]
def physical_boundary(manager,state):
    count = COUNT_PATH
    with count.open('ab') as output: output.write(b'one\\n')
    time.sleep(0.3 if mode != 'long' else 30)
    if mode == 'error': raise RuntimeError('explicit synthetic build boundary failure')
    # Software fixture: the physical network/acquisition boundary is replaced,
    # but the actual broker worker/status/reconciliation path runs unmodified.
    pool = manager.base.parent / 'dependency-pool'
    pool.mkdir(exist_ok=True)
    ready = pool / 'ready'
    ready.mkdir()
    coverage = COVERAGE
    record = {'schema': 2, 'operation_id': state['operation_id'],
              'complete': True, **coverage}
    (ready/'inventory.json').write_text(json.dumps(record))
    (ready/'inventory.json').chmod(0o444)
    ready.chmod(0o555)
    result = {'kind': 'download-only-pool', 'complete': True, **coverage,
              'python_versions': LOCKED_PYTHONS,
              'file_count': 0, 'manifest_sha256': 'a' * 64,
              'pool_directory': str(ready), 'runtime_integrated': True,
              'offline_replay': True, 'generation': GENERATION}
    return result
jobs._prepare = physical_boundary
try:
    jobs.worker(sys.argv[2],int(sys.argv[3]))
finally:
    scope_model.stop()
# The parent removes synthetic /proc records only after observing actual exit.
'''
        body = body.replace('INPUT_PATHS', repr([str(ROOT / "shared"), str(ROOT / "apps/workstation-broker/src")]))
        recipe = local.pool_contract(ROOT)
        body = body.replace('COVERAGE', repr(recipe['coverage']))
        lock = json.loads((ROOT / local.RUNTIME / 'conda-lock.json').read_bytes())
        locked_pythons = sorted({'.'.join(str(row['version']).split('.')[:2])
                                 for row in lock['artifacts'].values() if row.get('name') == 'python'})
        body = body.replace('LOCKED_PYTHONS', repr(locked_pythons))
        body = body.replace('BASE_PATH', 'Path(' + repr(str(self.files.base)) + ')')
        body = body.replace('FIXTURE_HELPERS', repr(str(ROOT / 'tests/distributed')))
        body = body.replace('SCOPE_PATH', 'Path(' + repr(str(self.scope_model.mount)) + ')')
        body = body.replace('PROC_PATH', 'Path(' + repr(str(self.proc)) + ')')
        body = body.replace('COUNT_PATH', 'Path(' + repr(str(self.count)) + ')')
        body = body.replace('FOLDER_PATH', 'Path(' + repr(str(self.files.folder)) + ')')
        body = body.replace('GENERATION', repr(self.files.generation))
        self.script.write_text(body)

    def tearDown(self):
        if hasattr(self, "children"):
            for process in self.children:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            self.scope_model.stop()
            self.docker_patch.stop()
            self.resources_docker_patch.stop()
            self.proc_patch.stop()
            temporary_tree(self.parent)
            self.temp.cleanup()

    def spawn(self, arguments, **kwargs):
        self.assertEqual(arguments[1:3], ["-B", str(ROOT / "scripts/prepare_local_templates.py")])
        self.assertEqual(arguments[3], self.operation_id)
        environment = dict(kwargs["env"], WORKSTATION_BROKER_CONTROL_ID=self.deployment["control_id"],
            WORKSTATION_BROKER_EXECUTION_ID=self.deployment["execution_id"])
        process = self.original_popen([sys.executable, "-B", str(self.script), self.mode, arguments[3], arguments[-1]],
            **{**kwargs, "env": environment})
        self.children.append(process)
        return process

    def start(self, retry=False):
        self.refresh_process_fixture()
        with patch.object(jobs.subprocess, "Popen", side_effect=self.spawn):
            return self.manager.start({"operation_id": self.operation_id, "compatibility": self.identified["compatibility"], "retry": retry})

    def refresh_process_fixture(self):
        # The synthetic process table follows the observed real child exit;
        # fixture records never stand in for physical execution host process inspection.
        for process in self.children:
            if process.poll() is not None:
                folder = self.proc / str(process.pid)
                if folder.exists():
                    for path in folder.iterdir(): path.unlink()
                    folder.rmdir()

    def wait_phase(self, phases, manager=None):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            self.refresh_process_fixture()
            value = (manager or self.manager).status({"operation_id": self.operation_id})
            if value["phase"] in phases: return value
            time.sleep(0.03)
        self.fail("fixture job did not reach phase; logs: " + "\n".join(p.read_text() for p in self.manager.root.rglob("*.log")))

    def test_lost_response_and_broker_restart_rediscover_one_actual_worker(self):
        self.start()  # Discard response to represent a disconnected caller.
        self.wait_phase({"running", "validating"})
        restarted = jobs.PreparationManager(self.files.base, self.files.root, self.files.factory(self.files.root, self.files.base),
            source_root=ROOT, deployment=self.deployment)
        with patch.object(jobs.subprocess, "Popen", side_effect=AssertionError("duplicate worker")):
            status = restarted.start({"operation_id": self.operation_id, "compatibility": self.identified["compatibility"], "retry": False})
        self.assertIn(status["phase"], {"running", "validating", "ready"})
        ready = self.wait_phase({"ready"}, restarted)
        self.assertEqual(ready["result"]["kind"], "download-only-pool")
        self.assertEqual(self.count.read_bytes(), b"one\n")
        self.assertEqual(len(self.children), 1)
        self.assertEqual(restarted.status({"operation_id": self.operation_id})["phase"], "ready")

    def test_ready_is_idempotent_and_is_not_rehashed_after_publication(self):
        self.start(); self.wait_phase({"ready"})
        self.assertEqual(self.start()["phase"], "ready")
        self.assertEqual(self.count.read_bytes(), b"one\n")
        # Legacy QCOW2 bytes are unrelated to the immutable dependency pool.
        path = self.files.repo
        path.chmod(0o644); path.write_bytes(b"legacy template changed"); path.chmod(0o444)
        self.assertEqual(self.manager.status({"operation_id": self.operation_id})["phase"], "ready")

    def test_explicit_error_keeps_data_and_prohibits_all_automatic_retries(self):
        before = self.files.registry_path.read_bytes()
        self.mode = "error"
        self.start()
        failed = self.wait_phase({"interrupted"})
        self.assertIn("synthetic build boundary failure", failed["error"])
        for process in self.children: process.wait(timeout=5)
        with self.assertRaisesRegex(RuntimeError, "zombie"):
            self.start()
        self.assertEqual(len(self.children), 1)
        self.assertEqual(self.files.registry_path.read_bytes(), before)
        self.assertTrue(list(self.manager.root.rglob("*.log")))
        self.mode = "success"
        with self.assertRaisesRegex(RuntimeError, "zombie"):
            self.start(retry=True)
        self.assertEqual(len(self.children), 1)

    def test_down_cancels_only_recorded_session_and_keeps_permanent_files(self):
        self.mode = "long"
        before = {p: p.read_bytes() for p in self.files.folder.rglob("*") if p.is_file()}
        self.start(); self.wait_phase({"running"})
        self.assertTrue(self.manager.inventory())
        original_members = resources.JobScope.members
        def observed_members(state):
            self.refresh_process_fixture()
            return original_members(state)
        with patch.object(resources.JobScope, 'members', side_effect=observed_members):
            self.manager.cancel_all()
        self.assertEqual(self.manager.inventory(), [])
        self.assertEqual(self.manager.status({"operation_id": self.operation_id})["phase"], "canceled")
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertTrue(self.count.exists())

    def test_invalid_source_path_operation_or_recipe_rejected_before_spawn(self):
        with patch.object(jobs.subprocess, "Popen", side_effect=AssertionError("spawn forbidden")):
            with self.assertRaises(ValueError): self.manager.probe({"source_contract": {"unknown": True}})
            for attack in ({"operation_id": "../escape", "compatibility": self.identified["compatibility"], "retry": False},
                           {"operation_id": self.operation_id, "compatibility": {}, "retry": False},
                           {"operation_id": self.operation_id, "compatibility": self.identified["compatibility"], "retry": False, "command": "sh"}):
                with self.assertRaises(ValueError): self.manager.start(attack)
        self.assertFalse(self._state_exists())

    def test_down_tracks_a_detached_child_after_its_leader_is_gone(self):
        self.mode = 'long'
        self.start(); self.wait_phase({'running'})
        leader = self.children[0]
        # A separate real private session represents a detached libguestfs
        # descendant. Only kernel membership/process-record IO is a fixture.
        child = self.original_popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'], start_new_session=True)
        self.children.append(child)
        record = self.proc / str(child.pid)
        record.mkdir()
        fields = ['S','1',str(os.getpgid(child.pid)),str(os.getsid(child.pid))] + ['0'] * 15 + ['999999999'] + ['0'] * 10
        (record / 'stat').write_text(str(child.pid) + ' (detached-fixture) ' + ' '.join(fields))
        (record / 'environ').write_bytes(b'GPT_TRACE_PREPARATION_ID=' + self.operation_id.encode())
        state = self.manager._read(self.operation_id)
        folder = resources.JobScope.path(state)
        self.scope_model.write(folder / 'cgroup.procs', f'{leader.pid} {child.pid}')
        leader.terminate(); leader.wait(timeout=5)
        self.refresh_process_fixture()
        status = self.manager.status({'operation_id': self.operation_id})
        self.assertEqual(status['phase'], 'interrupted')
        self.assertIn('descendants', status['error'])
        with self.assertRaisesRegex(RuntimeError, 'zombie'):
            self.start(retry=True)
        original_members = resources.JobScope.members
        def observed(state):
            self.refresh_process_fixture()
            return original_members(state)
        before = self.files.registry_path.read_bytes()
        with patch.object(resources.JobScope, 'members', side_effect=observed): self.manager.cancel_all()
        self.assertIsNotNone(child.poll())
        self.assertEqual(self.manager.inventory(), [])
        self.assertEqual(self.files.registry_path.read_bytes(), before)

    def test_unknown_scope_and_missing_membership_proof_are_never_absence(self):
        extra = resources.UNIT / 'prep-unowned'
        extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, 'no verified durable job'): self.manager.inventory()
        extra.rmdir()
        self.mode = 'long'; self.start(); self.wait_phase({'running'})
        state = self.manager._read(self.operation_id)
        folder = resources.JobScope.path(state)
        (folder / 'cgroup.events').unlink()
        with self.assertRaises(FileNotFoundError): self.manager.inventory()
        (folder / 'cgroup.events').write_text('populated 1\nfrozen 0\n')

    def _state_exists(self): return (self.manager.root / self.operation_id / "state.json").exists()

    def test_unclaimed_dead_spawn_is_interrupted_and_not_blindly_repeated(self):
        def fail_before_claim(arguments, **kwargs):
            process = self.original_popen([sys.executable, "-B", "-c", "raise SystemExit(7)"], **kwargs)
            self.children.append(process)
            return process
        with patch.object(jobs.subprocess, "Popen", side_effect=fail_before_claim):
            with self.assertRaisesRegex(RuntimeError, 'private identity'):
                self.manager.start({'operation_id': self.operation_id, 'compatibility': self.identified['compatibility'], 'retry': False})
        self.children[-1].wait(timeout=5)
        value = self.wait_phase({'failed'})
        self.assertIn('spawn rejected', value['error'])
        with patch.object(jobs.subprocess, "Popen", side_effect=AssertionError("blind retry")):
            with self.assertRaisesRegex(RuntimeError, "zombie"):
                self.start()


class SourceContainerOwnershipTests(unittest.TestCase):
    """Actual discovery/cleanup functions with explicit Docker CLI responses."""
    def setUp(self):
        self.deployment = {'control_id': 'fixture-control', 'execution_id': 'fixture-execution'}
        self.operation_id = hashlib.sha256(b'fixture operation').hexdigest()
        self.container_id = hashlib.sha256(b'fixture container identity').hexdigest()
        self.state = {'operation_id': self.operation_id, 'attempt': 2, 'deployment': self.deployment}
        args = resources.source_container_arguments(self.state)
        self.labels = {args[i+1].split('=',1)[0]: args[i+1].split('=',1)[1]
            for i in range(len(args)) if args[i] == '--label'}
        self.row = {'Id': self.container_id, 'Name': '/' + args[1], 'Config': {'Labels': self.labels}}
        self.active = True
        self.commands = []

    def output(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[1] == 'ps': return (self.container_id + '\n').encode() if self.active else b''
        self.assertEqual(argv, ['docker', 'inspect', self.container_id])
        return json.dumps([self.row]).encode()

    def mutate(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[1] == 'stop': self.active = False  # Explicit --rm side effect fixture.
        return SimpleNamespace(returncode=0)

    def test_exact_labels_name_and_job_allow_only_owned_container_cleanup(self):
        with patch.object(resources.subprocess, 'check_output', side_effect=self.output), patch.object(resources.subprocess, 'run', side_effect=self.mutate):
            resources.remove_source_containers(self.deployment, {self.operation_id})
            self.assertEqual(resources.source_containers(self.deployment), [])
        mutations = [cmd for cmd in self.commands if cmd[1] in {'stop','rm'}]
        self.assertEqual(mutations, [['docker', 'stop', '--time', '15', self.container_id]])
        self.assertFalse(any('-v' in cmd or 'prune' in cmd or 'volume' in cmd for cmd in self.commands))

    def test_foreign_execution_wrong_name_and_unrecorded_job_preserved(self):
        for attack in ('execution', 'name', 'job'):
            row = copy.deepcopy(self.row)
            if attack == 'execution': row['Config']['Labels'][resources.LABEL + 'execution_id'] = 'foreign-execution'
            elif attack == 'name': row['Name'] = '/foreign-container'
            self.row = row
            with patch.object(resources.subprocess, 'check_output', side_effect=self.output), patch.object(resources.subprocess, 'run', side_effect=AssertionError('foreign mutation')):
                with self.assertRaises(RuntimeError):
                    resources.remove_source_containers(self.deployment, set() if attack == 'job' else {self.operation_id})
            self.assertTrue(self.active)
            self.row = {'Id': self.container_id, 'Name': '/gpt-trace-source-' + self.operation_id[:24] + '-2', 'Config': {'Labels': self.labels}}

    def test_unavailable_docker_inventory_never_proves_absence(self):
        with patch.object(resources.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, ['docker','ps'])):
            with self.assertRaises(subprocess.CalledProcessError): resources.source_containers(self.deployment)


class AdministrativeAndShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatch = load("local_dispatch_offline", ROOT / "scripts/distributed.py")

    def test_actual_admin_handler_blocks_all_new_routes_for_controller(self):
        import asyncio, hmac
        path = ROOT / "apps/workstation-broker/src/workstation_broker/server.py"
        parsed = ast.parse(path.read_bytes())
        factory = copy.deepcopy(next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == "create_app"))
        factory.body[-1] = ast.Return(value=ast.Name(id="dispatch", ctx=ast.Load()))
        program = ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")], level=0), factory], type_ignores=[]))
        namespace = {"asyncio": asyncio, "hmac": hmac, "json": json, "MAX_BODY": 32*1024*1024,
            "PROJECT": "gpt-trace-extractor", "CONTROLLER_ACTIONS": CONTROLLER_ACTIONS,
            "JSONResponse": lambda body, status_code=200, **kw: SimpleNamespace(body=body, status_code=status_code)}
        exec(compile(program, str(path), "exec"), namespace)
        actions = {"template_preparation_probe", "prepare_templates", "template_preparation_status", "shutdown", "shutdown_status", "begin_shutdown"}
        self.assertFalse(actions & CONTROLLER_ACTIONS)
        class NeverPrepare:
            def probe(self, payload): raise AssertionError("controller reached administrative preparation")
            start = status = probe
        broker = SimpleNamespace(admin_token="admin-fixture", controller_token="controller-fixture", preparations=NeverPrepare())
        callback = namespace["create_app"](broker)
        class Request:
            def __init__(self, action):
                self.headers = {"authorization": "Bearer controller-fixture"}
                self.path_params = {"action": action}
            async def body(self): raise AssertionError("forbidden body was read")
        async def check():
            for action in actions:
                reply = await callback(Request(action))
                self.assertEqual(reply.status_code, 403)
        asyncio.run(check())

    def test_single_explicit_fetch_polls_and_never_repeats_a_lost_start(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = {"deployment": {"control_id": "fixture-control", "execution_id": "fixture-execution"}}
            recipe = local.pool_contract(ROOT)
            expected = recipe
            operation_id = hashlib.sha256(local.canonical(expected)).hexdigest()
            identified = {"operation_id": operation_id, "compatibility": expected, "deployment": cfg["deployment"]}
            calls = []
            phases = iter(["not_started", "running", "ready"])
            def broker(_, action, payload=None, **kwargs):
                calls.append(action)
                if action == "probe": return {"status": "ok"}
                if action == "template_preparation_probe": return identified
                if action == "prepare_templates": return {"phase": "starting"}
                phase = next(phases)
                return {"operation_id": operation_id, "deployment": cfg["deployment"], "phase": phase,
                    "result": {"kind": "download-only-pool", "complete": True, **recipe["coverage"],
                        "runtime_integrated": True, "offline_replay": True,
                        "generation": "a" * 64}}
            with patch.object(self.dispatch, "ROOT", Path(temp)), patch.object(local, "pool_contract", return_value=recipe), patch.object(self.dispatch, "broker", side_effect=broker), patch.object(self.dispatch.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
                self.dispatch.preparation_fetch(cfg)
            self.assertEqual(calls.count("prepare_templates"), 1)
            self.assertEqual(calls.count("template_preparation_status"), 3)
            calls.clear()
            def lost(_, action, payload=None, **kwargs):
                calls.append(action)
                if action == "probe": return {}
                if action == "template_preparation_probe": return identified
                if action == "template_preparation_status": return {"operation_id": operation_id, "deployment": cfg["deployment"], "phase": "not_started"}
                raise TransportFailure("lost reply after remote start")
            with patch.object(self.dispatch, "ROOT", Path(temp)), patch.object(local, "pool_contract", return_value=recipe), patch.object(self.dispatch, "broker", side_effect=lost), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "rediscover"):
                    self.dispatch.preparation_fetch(cfg)
            self.assertEqual(calls.count("prepare_templates"), 1)

    def test_actual_post_exit_responder_requires_dead_process_admin_and_exact_nonce(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "admin-token"
            credential = secrets.token_urlsafe(32)
            path.write_text(credential); path.chmod(0o600)
            process = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"])
            try:
                proc = Path(temp) / "proc-fixture"
                (proc / "sys/kernel/random").mkdir(parents=True)
                (proc / "sys/kernel/random/boot_id").write_text("00000000-0000-4000-8000-000000000002")
                record = proc / str(process.pid)
                record.mkdir()
                fields = ["S", "1", str(os.getpgid(process.pid)), str(os.getsid(process.pid))] + ["0"] * 15 + ["1000"] + ["0"] * 10
                (record / "stat").write_text(str(process.pid) + " (finite-child-fixture) " + " ".join(fields))
                proc_patch = patch.object(jobs, "PROC", proc)
                proc_patch.start()
                stamp = jobs.process_identity(process.pid)
                shutdown_id = secrets.token_hex(32)
                value = {"project": "gpt-trace-extractor", "scope": "global", "shutdown_id": shutdown_id,
                    "deployment": {"control_id": "fixture-control", "execution_id": "fixture-execution"},
                    "broker_stopped": True, "broker_identity": stamp,
                    "inventory": {"project": "gpt-trace-extractor", "absent": True}}
                with patch.dict(os.environ, {"WORKSTATION_BROKER_ADMIN_TOKEN_FILE": str(path)}):
                    responder = shutdown.Confirmation(value)
                body = json.dumps({"shutdown_id": shutdown_id}).encode()
                self.assertEqual(responder.exchange("POST", "/v1/shutdown_status", body, "Bearer " + credential)[0], 409)
                process.terminate(); process.wait(timeout=5)
                (record / "stat").unlink()
                self.assertFalse(jobs.same_process(stamp))
                self.assertEqual(responder.exchange("POST", "/v1/shutdown_status", body, "Bearer " + credential)[0], 200)
                self.assertEqual(responder.exchange("POST", "/v1/shutdown_status", body, "Bearer wrong")[0], 403)
                self.assertEqual(responder.exchange("POST", "/v1/prepare_templates", body, "Bearer " + credential)[0], 404)
                self.assertEqual(responder.exchange("POST", "/v1/shutdown_status", b'{"shutdown_id":"wrong"}', "Bearer " + credential)[0], 409)
                responder.response_sent("POST", "/v1/shutdown_complete", 200, body, "controller")
                self.assertFalse(responder.completed.is_set())
                responder.response_sent("POST", "/v1/shutdown_complete", 200, body, "admin")
                self.assertTrue(responder.completed.is_set())
            finally:
                if process.poll() is None: process.terminate(); process.wait(timeout=5)
                if "proc_patch" in locals(): proc_patch.stop()

    def test_network_loss_is_not_broker_exit_confirmation(self):
        cfg = {"deployment": {"control_id": "fixture-control", "execution_id": "fixture-execution"}}
        clock = iter([0, 0, 101])
        with patch.object(self.dispatch, "broker", side_effect=TransportFailure("link unavailable")), patch.object(self.dispatch.time, "monotonic", side_effect=lambda: next(clock)), patch.object(self.dispatch.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                self.dispatch.confirm_remote_shutdown(cfg, secrets.token_hex(32))
        with patch.object(self.dispatch, "broker", side_effect=IdentityFailure("server certificate differs")):
            with self.assertRaises(IdentityFailure): self.dispatch.confirm_remote_shutdown(cfg, secrets.token_hex(32))

    def test_global_shutdown_requires_post_exit_proof_before_recording_success(self):
        cfg = {"deployment": {"role": "control", "control_id": "fixture-control", "execution_id": "fixture-execution"}}
        calls = []
        def command(args, **kw):
            if args[:3] == ["docker", "volume", "ls"]: return "persistent_database\npersistent_checkpoints"
            return ""
        def broker(_, action, payload=None, **kw):
            calls.append(action)
            if action == "begin_shutdown": return {"project": "gpt-trace-extractor", "draining": True}
            if action == "inventory": return {"project": "gpt-trace-extractor", "absent": True}
            if action == "shutdown": return {"project": "gpt-trace-extractor", "absent": True,
                "shutdown": True, "shutdown_id": payload["shutdown_id"]}
            return {}
        with tempfile.TemporaryDirectory() as temp, patch.object(self.dispatch, "ROOT", Path(temp)), patch.object(self.dispatch, "host"), patch.object(self.dispatch, "config", return_value=cfg), patch.object(self.dispatch, "environment"), patch.object(self.dispatch, "run", side_effect=command), patch.object(self.dispatch, "broker", side_effect=broker), patch.object(self.dispatch, "confirm_remote_shutdown", side_effect=RuntimeError("native broker still running")):
            with self.assertRaisesRegex(RuntimeError, "still running"):
                self.dispatch.global_down(cfg)
            self.assertFalse((Path(temp) / "state/distributed/last-cleanup.json").exists())
        self.assertEqual(calls, ["begin_shutdown", "inventory", "destroy_all", "inventory", "shutdown"])

    def test_execution_local_scope_is_explicit_before_cleanup(self):
        cfg = {"deployment": {"role": "execution"}, "paths": {}, "network": {}}
        with patch.object(self.dispatch, "execution_environment", side_effect=RuntimeError("fixture stop before deployment access")), contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(RuntimeError): self.dispatch.local_down(cfg)
        self.assertIn("scope=execution-local; global=false", output.getvalue())
        self.assertIn("control host campaign/services are not stopped", output.getvalue())

    def test_scientific_contract_and_hidden_evaluator_routing_are_unchanged(self):
        pins = json.loads((ROOT / local.PINS).read_bytes())
        self.assertEqual(local.digest(ROOT / local.RUNTIME / "contract.json"), pins["contract_sha256"])
        lifecycle = (ROOT / "apps/runner/src/gpt_trace_runner/superbench/execution.py").read_text()
        runtime = (ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym_lite.py").read_text()
        self.assertIn("candidate_checkpointed", lifecycle)
        self.assertIn("conversation_checkpointed", lifecycle)
        self.assertIn("create_evaluator", runtime)
        self.assertIn("test_patch", runtime)
        server = (ROOT / "apps/workstation-broker/src/workstation_broker/server.py").read_text()
        self.assertIn('purpose', server)
        self.assertIn('evaluator', server)
        grading = (ROOT / local.RUNTIME / "upstream/grading.py").read_bytes()
        self.assertEqual(hashlib.sha256(grading).hexdigest(), pins["upstream_files"]["grading.py"])


if __name__ == "__main__": unittest.main()

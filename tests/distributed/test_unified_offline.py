"""Software tests on real files and function bodies; no VM/Parquet/socket claim.

Release/API/QCOW2 metadata below are explicitly synthetic test fixtures. Their
hashes are calculated from actual fixture bytes. They are never deployment pins.
"""
from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "apps/workstation-broker/src"), str(ROOT / "shared"),
               str(ROOT / "apps/runner/src"), str(ROOT / "scripts")]
sys.dont_write_bytecode = True
from gpt_trace_transport import template_release as release
from gpt_trace_runner.superbench.normalize import normalize_messages, tools_from_provenance
from workstation_broker.templates import TemplateRegistry


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def pure_functions(source, names, globals_):
    """Execute the actual selected function ASTs, without importing Arrow/HTTP."""
    tree = ast.parse(source.read_bytes())
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    if {node.name for node in nodes} != set(names): raise AssertionError("source function contract drift")
    namespace = dict(globals_)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class ExportFunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import math
        cls.functions = pure_functions(ROOT / "apps/runner/src/gpt_trace_runner/superbench/exporter.py",
            {"_json", "_evaluation", "_row", "_validate_tool_structure"},
            {"json": json, "math": math, "normalize_messages": normalize_messages,
             "tools_from_provenance": tools_from_provenance})

    def raw(self, status="completed", verdict="pass"):
        return {"task_id": "trajectory:1", "logical_task_id": "source:1", "status": status,
            "messages": [{"author": {"role": "assistant"}, "tool_calls": [
                {"id": "call:1", "name": "exec_command", "arguments": {"command": "true"}}]},
                {"author": {"role": "tool", "name": "exec_command"}, "tool_call_id": "call:1",
                 "content": {"parts": ["exact result\u0000"]}}],
            "app_provenance": [{"app_id": "kali-workstation", "tool_manifest": {"tools": [
                {"name": "exec_command", "description": "Execute", "inputSchema": {"type": "object"}}]}}],
            "runtime_metadata": {"used_tool_calls": [{"app_id": "kali-workstation",
                "canonical_tool_name": "exec_command", "call_id": "call:1"}]},
            "dataset_metadata": {"adapter": "fixture"}, "attempt": 4,
            "evaluation": None if verdict is None else {"verdict": verdict,
                "score": 1.0 if verdict == "pass" else 0.0, "details": {"native": True}, "metadata": {}}}

    def test_all_execution_statuses_and_verdicts_keep_the_capture(self):
        for status in ("completed", "failed", "running", "pending"):
            for verdict in ("pass", "fail", None):
                raw = self.raw(status, verdict)
                row = self.functions["_row"](raw)
                self.assertEqual(row["execution_status"], status)
                self.assertEqual(row["evaluation"]["verdict"] if row["evaluation"] else None, verdict)
                self.assertEqual(json.loads(row["raw_messages_json"]), raw["messages"])
                self.assertEqual(json.loads(row["app_provenance_json"]), raw["app_provenance"])
                self.assertEqual(json.loads(row["metadata_json"])["storage"]["attempt"], 4)
                self.assertTrue(json.loads(row["validation_json"])["complete_tool_pairs"])

    def test_unanswered_call_is_exported_with_real_diagnostics(self):
        raw = self.raw("failed", None)
        raw["messages"].pop()
        row = self.functions["_row"](raw)
        self.assertEqual(row["messages"][0]["tool_calls"][0]["id"], "call:1")
        self.assertEqual(json.loads(row["validation_json"])["issues"], [{"kind": "missing_result", "call_id": "call:1"}])

    def test_orphan_and_duplicate_result_are_kept_without_fabricating_a_call(self):
        raw = self.raw("running", None)
        raw["messages"].append(copy.deepcopy(raw["messages"][-1]))
        row = self.functions["_row"](raw)
        self.assertIn("duplicate_result", {x["kind"] for x in json.loads(row["validation_json"])["issues"]})
        raw["messages"] = raw["messages"][1:]
        row = self.functions["_row"](raw)
        self.assertIn("unmatched_result", {x["kind"] for x in json.loads(row["validation_json"])["issues"]})
        self.assertEqual(json.loads(row["raw_messages_json"]), raw["messages"])

    def test_invalid_identity_payload_and_nonfinite_score_fail_closed(self):
        for key, bad in (("task_id", ""), ("logical_task_id", None), ("messages", None),
                         ("runtime_metadata", []), ("app_provenance", {}), ("dataset_metadata", [])):
            raw = self.raw();raw[key] = bad
            with self.assertRaises(ValueError): self.functions["_row"](raw)
        for bad in (True, float("nan"), float("inf")):
            raw = self.raw();raw["evaluation"]["score"] = bad
            with self.assertRaises(ValueError): self.functions["_row"](raw)

    def test_storage_query_excludes_only_missing_capture_and_has_a_snapshot(self):
        source = (ROOT / "apps/storage/src/gpt_trace_storage/main.py").read_text()
        tree = ast.parse(source)
        node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "export_jsonl")
        actual = ast.get_source_segment(source, node)
        self.assertNotIn('Run.status ==', actual)
        self.assertIn('Run.messages.is_not(None)', actual)
        self.assertIn('func.json_typeof(Run.messages) != "null"', actual)
        self.assertIn('REPEATABLE READ READ ONLY', actual)


class SyntheticDownloads:
    """Fixture API boundary only; production uses the real HTTPS GitHub client."""
    def __init__(self, metadata, blobs):
        self.metadata, self.blobs, self.calls = metadata, blobs, []
    def release(self, tag):
        self.calls.append(("release", tag))
        if self.metadata["tag_name"] != tag: raise RuntimeError("fixture tag mismatch")
        return self.metadata
    def download(self, asset, output):
        self.calls.append(("download", asset["name"]))
        raw = self.blobs[asset["name"]]
        # Same byte-level contract as the live downloader.
        if len(raw) != asset["size"] or hashlib.sha256(raw).hexdigest() != release.asset_digest(asset):
            raise ValueError("fixture transfer size/SHA-256 mismatch")
        output.write(raw)


class PermanentFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.base = self.root / "kali-base.qcow2"
        self.base.write_bytes(b"synthetic file-integrity fixture, not a VM image")
        self.base.chmod(0o444)
        self.base.with_suffix(".provenance.json").write_text(json.dumps({"base_sha256": release.digest(self.base)}))
        self.expected = release.compatibility(self.base)
        contract = json.loads((ROOT / release.RUNTIME / "contract.json").read_bytes())
        self.folder = self.root / "synthetic-build"
        self.folder.mkdir()
        (self.folder / "repos").mkdir()
        (self.folder / "sources").mkdir()
        (self.folder / "audit").mkdir()
        (self.folder / "common.qcow2").write_bytes(b"synthetic common backing bytes")
        templates, artifacts, mapping, proofs = {}, {}, {}, {}
        for logical, task in sorted(contract["tasks"].items()):
            tid = task["template_id"]
            if tid not in templates:
                image = self.folder / "repos" / (tid.split("/")[1] + ".qcow2")
                image.write_bytes(("synthetic repo fixture " + tid).encode())
                templates[tid] = {"chain": [{"path": image.relative_to(self.folder).as_posix(), "sha256": release.digest(image)},
                    {"path": "common.qcow2", "sha256": release.digest(self.folder / "common.qcow2")},
                    {"path": str(self.base), "sha256": release.digest(self.base)}]}
            mapping[logical] = {"template_id": tid}
            proofs[logical] = {"base_commit": task["base_commit"], "env_hash": task["env_hash"], "offline": True}
            for kind in ("task_source", "setup_cache"):
                key = hashlib.sha256((kind + logical).encode()).hexdigest()
                path = self.folder / "sources" / key
                path.write_bytes(("synthetic artifact " + kind + " " + logical).encode())
                mapping[logical][kind] = key
                artifacts[key] = {"kind": kind, "logical_task_id": logical, "allowed_template_id": tid,
                    "source_identity": {key: task[key] for key in ("instance_id", "repo", "base_commit")},
                    "path": path.relative_to(self.folder).as_posix(), "size": path.stat().st_size, "sha256": release.digest(path)}
        release.atomic_json(self.folder / "audit/offline-setups.json", proofs)
        resolved = {key: self.expected[key] for key in ("schema_version", "recipe_version", "pins", "source_fingerprint", "security")}
        clean = {"builder_mirrors": 0, "repo_mirrors": 0, "task_sources": 0, "checkouts": 0}
        resolved.update(templates=templates, artifacts=artifacts, task_artifacts=mapping,
            publication_validation={repo: clean for repo in {"common"} | {t["repo"] for t in contract["tasks"].values()}},
            golden={"sha256": release.digest(self.base)},
            builder_sources={(release.RUNTIME / name).as_posix(): sha for name, sha in self.expected["runtime_sources"].items()},
            offline_setups_sha256=release.digest(self.folder / "audit/offline-setups.json"))
        generation = hashlib.sha256(release.canonical(resolved)).hexdigest()
        release.atomic_json(self.folder / "resolved-inputs.json", resolved)
        manifest = {**resolved, "generation": generation, "resolved_inputs_sha256": release.digest(self.folder / "resolved-inputs.json"),
            "invariants": {"tasks":230,"repos":11,"env_hashes":25,"unmapped_tasks":0,"missing_base_commits":0},
            "env_mapping": {key: row["stored_name"] for key, row in contract["environments"].items()}}
        release.atomic_json(self.folder / "manifest.json", manifest)
        release.seal(self.folder)
        self.destination = self.root / "synthetic-assets"
        self.publication = release.package(self.folder, self.destination, self.expected,
            "2e64fb633814a88939480bbf9d0b9dfdc1c4e041")
        self.blobs = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        assets = [{"id": i+1, "name": name, "size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "state": "uploaded"} for i, (name, raw) in enumerate(sorted(self.blobs.items()))]
        self.metadata = {"id": 1, "tag_name": release.release_tag(self.expected), "draft": False,
            "immutable": True, "assets": assets, "source_commit": self.publication["source_commit"]}
        self.github = SyntheticDownloads(self.metadata, self.blobs)
        self.templates = self.root / "installed-templates"

    def tearDown(self):
        # Writable directories permit removal of only this explicit test tree.
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink(): path.chmod(0o755)
        self.temporary.cleanup()

    def registry(self, root, base):
        def info(path):
            if path == self.base: return {"format": "qcow2"}
            return {"format": "qcow2", "backing-filename": str(self.base) if path.name == "common.qcow2" else "../common.qcow2"}
        return TemplateRegistry(root, base, info)

    def install(self):
        return release.install(self.base, self.templates, self.registry, github=self.github)

    def test_real_compression_hash_install_and_offline_reuse(self):
        generation = self.install()
        self.assertEqual(generation, self.publication["generation"])
        final = self.templates / "swe-gym-lite/generations" / generation
        for name, record in self.publication["files"].items():
            self.assertEqual((final / name).read_bytes(), (self.folder / name).read_bytes())
            self.assertEqual(release.digest(final / name), record["sha256"])
            self.assertFalse((final / name).stat().st_mode & 0o222)
        self.github.calls.clear()
        self.assertEqual(self.install(), generation)
        self.assertEqual(self.github.calls, [])

    def test_mutable_release_or_wrong_tag_cannot_activate_registry(self):
        self.metadata["immutable"] = False
        with self.assertRaises(ValueError): self.install()
        self.assertFalse((self.templates / "swe-gym-lite/registry.json").exists())

    def test_corrupted_download_cannot_activate_or_replace_a_generation(self):
        name = next(name for name in self.blobs if name != "publication.json")
        self.blobs[name] += b"corrupted"
        with self.assertRaises(ValueError): self.install()
        self.assertFalse((self.templates / "swe-gym-lite/registry.json").exists())

    def test_every_installed_artifact_is_rechecked_on_reuse(self):
        generation = self.install()
        registry = self.templates / "swe-gym-lite/registry.json"
        before = registry.read_bytes()
        name = next(name for name in self.publication["files"] if name.startswith("sources/"))
        path = self.templates / "swe-gym-lite/generations" / generation / name
        path.chmod(0o644);path.write_bytes(b"modified");path.chmod(0o444)
        with self.assertRaises(ValueError): self.install()
        self.assertEqual(registry.read_bytes(), before)

    def test_release_source_commit_is_bound_to_the_immutable_git_tag(self):
        assets = release.validate_release(self.metadata, self.metadata["tag_name"])
        with self.assertRaisesRegex(ValueError, "source commit"):
            release.validate_publication(self.publication, self.expected, assets,
                source_commit="6b22d4da8c3bf1e384917124a468d8714a85232e")

    def test_manifest_path_traversal_duplicate_part_and_extra_asset_fail(self):
        assets = release.validate_release(self.metadata, self.metadata["tag_name"])
        original = copy.deepcopy(self.publication)
        row = next(iter(original["files"].values()))
        for bad in ("../outside", "/outside", "a/../../outside"):
            changed = copy.deepcopy(original);changed["files"][bad] = row
            with self.assertRaises(ValueError): release.validate_publication(changed, self.expected, assets)
        changed = copy.deepcopy(original)
        selected = next(iter(changed["files"].values()))
        selected["parts"].append(copy.deepcopy(selected["parts"][0]))
        with self.assertRaises(ValueError): release.validate_publication(changed, self.expected, assets)
        with self.assertRaises(ValueError):
            release.validate_publication(original, self.expected, {**assets, "extra": assets["publication.json"]})

    def test_existing_generation_recovers_activation_without_file_replacement(self):
        generation = self.install()
        registry = self.templates / "swe-gym-lite/registry.json"
        final = registry.parent / "generations" / generation
        before = {p.relative_to(final).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns) for p in final.rglob("*") if p.is_file()}
        registry.unlink()
        self.assertEqual(self.install(), generation)
        after = {p.relative_to(final).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns) for p in final.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


class InterfaceAndShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatch = load("unified_dispatch_test", ROOT / "scripts/distributed.py")

    def test_make_has_exactly_the_retained_historical_targets(self):
        make = (ROOT / "Makefile").read_text()
        targets = set(re.findall(r"^([A-Za-z0-9_-]+):", make, re.M))
        self.assertEqual(targets, set(self.dispatch.HISTORICAL))
        for target in targets:
            self.assertIn("python3 scripts/distributed.py " + target, make)

    def test_acer_refuses_control_operations_before_any_side_effect(self):
        for action in ("run", "resume", "register_apps", "export-parquet", "down"):
            with patch.object(self.dispatch, "host") as host:
                with self.assertRaises(RuntimeError): self.dispatch.acer({"deployment": {"role": "acer"}}, action, None)
                host.assert_not_called()

    def test_fossil_host_plan_checks_docker_without_kvm_or_libvirt(self):
        """Command-planning boundary test, not a physical host prerequisite test."""
        cfg = {"network": {"fossil_address": "192.168.90.20"}}
        addresses = [{"addr_info": [{"family": "inet", "local": "192.168.90.20"}]}]
        with patch.object(self.dispatch.platform, "system", return_value="Linux"), patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="26.04"\n'), patch.object(self.dispatch, "json_command", return_value=addresses), patch.object(self.dispatch, "run", return_value="ok") as command:
            self.dispatch.host("fossil", cfg, build_tools=True)
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            ["docker", "compose", "version"], ["docker", "buildx", "version"]])

    def test_only_absent_publication_leaves_gaia_available(self):
        cfg = {"paths": {"base_image": Path("/unused/kali-base.qcow2")}}
        with patch.object(release, "install", side_effect=release.UnpublishedRelease("fixture absence")), patch("sys.stderr", io.StringIO()) as log:
            self.assertIsNone(self.dispatch.install_templates(cfg))
            self.assertIn("GAIA golden remains usable", log.getvalue())
        for error in (ValueError("mutated artifact"), RuntimeError("network unavailable")):
            with patch.object(release, "install", side_effect=error):
                with self.assertRaises(type(error)): self.dispatch.install_templates(cfg)

    def test_publication_is_the_only_builder_and_has_no_control_compose_dependency(self):
        builder = (ROOT / "scripts/template_publication_build.py").read_text()
        dispatch = (ROOT / "scripts/distributed.py").read_text()
        self.assertIn('getattr(args, "publication", False)', builder)
        self.assertNotIn('"compose"', builder)
        self.assertNotIn("template_publication_build", dispatch)
        self.assertNotIn("publish_template_release", dispatch)

    def test_actual_handler_drains_in_flight_operations_before_blocking_new_mutations(self):
        """Call-level handler/async-lock test; no Starlette/socket/VM assertion."""
        import asyncio
        import hmac
        from types import SimpleNamespace
        from gpt_trace_transport.wire import CONTROLLER_ACTIONS
        path = ROOT / "apps/workstation-broker/src/workstation_broker/server.py"
        parsed = ast.parse(path.read_bytes())
        factory = copy.deepcopy(next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == "create_app"))
        # Keep the actual handler unchanged. Replace only its final HTTP router
        # construction so this dependency-free test can call it directly.
        self.assertIsInstance(factory.body[-1], ast.Return)
        factory.body[-1] = ast.Return(value=ast.Name(id="dispatch", ctx=ast.Load()))
        identity = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == "identity")
        constants = [n for n in parsed.body if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in {"MAX_BODY", "PROJECT", "SAFE_ID", "SHA256"} for t in n.targets)]
        program = ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")], level=0), *constants, identity, factory], type_ignores=[]))
        namespace = {"asyncio": asyncio, "hmac": hmac, "json": json, "re": re,
            "CONTROLLER_ACTIONS": CONTROLLER_ACTIONS,
            "JSONResponse": lambda body, status_code=200, **kwargs: SimpleNamespace(body=body, status_code=status_code)}
        exec(compile(program, str(path), "exec"), namespace)

        async def exercise():
            active, complete = asyncio.Event(), asyncio.Event()
            class Boundary:
                admin_token, controller_token = "a" * 40, "c" * 40
                async def inspect_verified(self, value):
                    active.set(); await complete.wait()
                    return {"identity": value}
                async def create(self, *args):
                    raise AssertionError("new create reached its boundary after shutdown")
            class RequestFixture:
                def __init__(self, action, payload, credential):
                    self.headers = {"authorization": "Bearer " + credential}
                    self.path_params = {"action": action}
                    self.payload = payload
                async def body(self): return json.dumps(self.payload).encode()
            boundary = Boundary()
            callback = namespace["create_app"](boundary)
            value = {"task_id": "fixture", "attempt": 1, "environment_id": "fixture", "fingerprint": "a" * 64}
            forbidden = await callback(RequestFixture("begin_shutdown", {}, boundary.controller_token))
            self.assertEqual(forbidden.status_code, 403)
            old = asyncio.create_task(callback(RequestFixture("inspect_attempt", value, boundary.admin_token)))
            await asyncio.wait_for(active.wait(), 1)
            drain = asyncio.create_task(callback(RequestFixture("begin_shutdown", {}, boundary.admin_token)))
            await asyncio.sleep(0)
            self.assertFalse(drain.done())
            new = asyncio.create_task(callback(RequestFixture("create_attempt", value, boundary.admin_token)))
            complete.set()
            old_result, barrier, blocked = await asyncio.wait_for(asyncio.gather(old, drain, new), 2)
            self.assertEqual(old_result.status_code, 200)
            self.assertTrue(barrier.body["draining"])
            self.assertEqual(blocked.status_code, 409)
        asyncio.run(exercise())

    def test_expired_remote_credentials_still_stop_local_services_and_keep_volumes(self):
        calls, state = [], {"containers": True, "networks": True}
        def command(args, **kwargs):
            calls.append(list(args))
            if args[:3] == ["docker", "volume", "ls"]: return "persistent_db\npersistent_profile"
            if args[:3] == ["docker", "ps", "-aq"]: return "control_container" if state["containers"] else ""
            if args[:3] == ["docker", "ps", "-q"]: return "runner_container"
            if args[:3] == ["docker", "network", "ls"]: return "control_network" if state["networks"] else ""
            if args[:2] == ["docker", "rm"]: state["containers"] = False
            if args[:3] == ["docker", "network", "rm"]: state["networks"] = False
            return ""
        cfg = {"deployment": {"role": "fossil"}}
        with patch.object(self.dispatch, "host"), patch.object(self.dispatch, "config", side_effect=ValueError("expired certificate")), patch.object(self.dispatch, "run", side_effect=command):
            with self.assertRaisesRegex(ValueError, "expired"):
                self.dispatch.global_down(cfg)
        self.assertIn(["docker", "rm", "control_container"], calls)
        self.assertIn(["docker", "network", "rm", "control_network"], calls)
        self.assertFalse(state["containers"])
        self.assertFalse(any(args[:3] in (["docker", "volume", "rm"], ["docker", "image", "rm"]) or "--volumes" in args or "-v" in args for args in calls))

    def test_actual_pinned_gaia_grader_is_unchanged_and_exercises_native_cases(self):
        import string
        functions = pure_functions(ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/gaia.py",
            {"_normalize_number", "_normalize_string", "_is_float", "gaia_question_scorer"},
            {"re": re, "string": string})
        score = functions["gaia_question_scorer"]
        self.assertTrue(score("1,000", "1000"))
        self.assertTrue(score("Paris.", "Paris"))
        self.assertFalse(score("London", "Paris"))


if __name__ == "__main__":
    unittest.main()

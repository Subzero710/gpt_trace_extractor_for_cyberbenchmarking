"""Software tests on real files and function bodies; no VM/Parquet/socket claim.

VM execution boundaries are explicit software fixtures. No KVM/ChatGPT,
HTTP socket or Arrow integration is claimed by these offline tests.
"""
from __future__ import annotations

import ast
import copy
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
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "apps/workstation-broker/src"), str(ROOT / "shared"),
               str(ROOT / "apps/runner/src"), str(ROOT / "scripts")]
sys.dont_write_bytecode = True
from gpt_trace_transport import local_templates as local
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


class InterfaceAndShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatch = load("unified_dispatch_test", ROOT / "scripts/distributed.py")

    def test_doctor_runs_every_maintained_role_test_root(self):
        source = (ROOT / "scripts/distributed.py").read_text()
        doctor = source.split("def doctor_tests(role):", 1)[1].split(
            "def preparation_fetch", 1
        )[0]
        for marker in (
            "runner", "storage", "workstation-gateway",
            "kali-workstation-controller", "/opt/gpt-trace-browser/tests",
            "apps/workstation-broker/tests", "tests/distributed",
        ):
            self.assertIn(marker, doctor)

    def test_make_has_exactly_the_retained_historical_targets(self):
        make = (ROOT / "Makefile").read_text()
        targets = set(re.findall(r"^([A-Za-z0-9_-]+):", make, re.M))
        self.assertEqual(targets, set(self.dispatch.HISTORICAL))
        for target in targets:
            self.assertIn("python3 scripts/distributed.py " + target, make)

    def test_execution_refuses_control_operations_before_any_side_effect(self):
        for action in ("run", "resume", "register_apps", "export-parquet"):
            with patch.object(self.dispatch, "host") as host:
                with self.assertRaises(RuntimeError): self.dispatch.execution({"deployment": {"role": "execution"}}, action, None)
                host.assert_not_called()

    def test_control_host_plan_checks_docker_without_kvm_or_libvirt(self):
        """Command-planning boundary test, not a physical host prerequisite test."""
        cfg = {"network": {"control_address": "192.168.90.20"}}
        addresses = [{"addr_info": [{"family": "inet", "local": "192.168.90.20"}]}]
        with patch.object(self.dispatch.platform, "system", return_value="Linux"), patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="26.04"\n'), patch.object(self.dispatch, "json_command", return_value=addresses), patch.object(self.dispatch, "run", return_value="ok") as command:
            self.dispatch.host("control", cfg, build_tools=True)
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            ["docker", "compose", "version"], ["docker", "buildx", "version"]])

    def test_only_explicit_lite_fetch_triggers_administrative_preparation(self):
        from types import SimpleNamespace
        cfg = {"deployment": {"role": "control"}}
        for adapter in ("gaia", "swe-gym-lite"):
            calls = []
            with patch.object(self.dispatch, "host"), patch.object(self.dispatch, "environment"), patch.object(self.dispatch, "verify_storage"), patch.object(self.dispatch, "run", side_effect=lambda *a, **k: calls.append(("project", a))), patch.object(self.dispatch, "compose", side_effect=lambda *a, **k: calls.append(("fetch", a))), patch.object(self.dispatch, "preparation_fetch", side_effect=lambda *a, **k: calls.append(("prepare", a))):
                self.dispatch.control(cfg, "superbench-fetch", SimpleNamespace(adapter=adapter))
            self.assertEqual(calls[1], ("fetch", ("run", "--rm", "--no-deps", "benchmark-fetch", "--adapter", adapter)))
            self.assertEqual([x[0] for x in calls], ["project", "fetch"] + (["prepare"] if adapter == "swe-gym-lite" else []))

    def test_no_image_build_in_up_run_or_resume(self):
        parsed = ast.parse((ROOT / "scripts/distributed.py").read_bytes())
        execution = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == "execution")
        source = ast.get_source_segment((ROOT / "scripts/distributed.py").read_text(), execution)
        self.assertNotIn("install_templates", source)
        build = next(n for n in execution.body if isinstance(n, ast.If) and ast.unparse(n.test) == "action == 'build'")
        remaining = copy.deepcopy(execution)
        remaining.body.remove(next(n for n in remaining.body if isinstance(n, ast.If) and ast.unparse(n.test) == "action == 'build'"))
        self.assertNotIn("build_workstation_base_image", ast.unparse(remaining))
        self.assertNotIn("build_local_templates", source)
        main = (ROOT / "apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym_lite.py").read_text()
        self.assertNotIn("build_local_templates", main)

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
        cfg = {"deployment": {"role": "control"}}
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

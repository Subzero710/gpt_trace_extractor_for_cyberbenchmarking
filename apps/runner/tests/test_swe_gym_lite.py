from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from gpt_trace_runner.exceptions import AppInfrastructureError, RateLimited, RecoveryIncomplete
from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool, CapturedConversation, task_fingerprint
from gpt_trace_runner.runtime_preflight import preflight_templates
from gpt_trace_runner.superbench.adapters.swe_gym import guest_runtime, source
from gpt_trace_runner.superbench.adapters.swe_gym_lite import SWEGymLiteAdapter, native_grade
from gpt_trace_runner.superbench.lifecycle import classify_incident
from gpt_trace_runner.superbench.models import TaskSpec, TeacherCampaign, task_spec_fingerprint
from gpt_trace_runner.superbench.service import to_benchmark_task
from gpt_trace_runner.superbench.catalog import SuperbenchCatalog
from gpt_trace_runner.superbench.registry import AdapterRegistry
from gpt_trace_runner.workstation_provider import LibvirtWorkstationProvider


def test_official_contract_230_11_25_and_complete_mapping():
    contract = source.contract()
    assert len(contract["tasks"]) == 230
    assert {item["repo"] for item in contract["tasks"].values()} == set(source.COUNTS)
    assert len(contract["environments"]) == 25
    official = source.harness(contract)
    for item in contract["tasks"].values():
        assert all(item.get(key) for key in ("repo", "base_commit", "version", "env_hash", "template_id"))
        assert len(item["base_commit"]) == 40
        assert item["template_id"] == "swe-gym-lite/" + item["repo"].replace("/", "_")
        specs = official.constants.MAP_REPO_VERSION_TO_SPECS[item["repo"].lower()][item["version"]]
        scripts = official.test_spec.make_env_script_list(item, specs, "testbed")
        spec = official.test_spec.TestSpec(item["instance_id"], item["repo"], item["version"], [], [], scripts, "x86_64", [], [])
        assert spec.env_image_key == "sweb.env.x86_64." + item["env_hash"] + ":latest"
        assert hashlib.sha256(str(scripts).encode()).hexdigest()[:22] == item["env_hash"]
        stored = official.test_spec.make_env_script_list(item, specs, "swegym_" + item["env_hash"])
        assert stored == contract["environments"][item["env_hash"]]["stored_script"]
        assert scripts != stored


def test_environment_yml_is_read_at_exact_base_and_changes_hash():
    from gpt_trace_runner.superbench.adapters.swe_gym.harness import load
    requests = []
    def get(url):
        requests.append(url)
        text = "name: old\ndependencies:\n  - numpy=" + ("1.20" if "/" + "a"*40 + "/" in url else "1.21") + "\n"
        return SimpleNamespace(status_code=200, text=text)
    official = load(get)
    hashes = []
    for commit in ("a"*40, "b"*40):
        scripts = official.test_spec.make_env_script_list({"repo": "dask/dask", "base_commit": commit}, {"packages": "environment.yml"}, "testbed")
        hashes.append(hashlib.sha256(str(scripts).encode()).hexdigest()[:22])
        assert "name: testbed" in "\n".join(scripts)
    assert hashes[0] != hashes[1]
    assert len(requests) == 2
    assert all("/" + commit + "/" in url for commit, url in zip(("a"*40, "b"*40), requests, strict=True))


def test_pinned_parquet_live_source():
    root = os.environ.get("GPT_TRACE_SUPERBENCH_SOURCE_ROOT")
    if not root:
        pytest.skip("set GPT_TRACE_SUPERBENCH_SOURCE_ROOT to the pinned fetched sources")
    rows = source.read_rows(Path(root) / "swe-gym-lite")
    assert len(rows) == 230
    source.validate_rows(rows)


def test_adapter_no_gold_no_hidden_metadata_and_smoke_first_11(monkeypatch):
    adapter = SWEGymLiteAdapter()
    rows = {}
    for item in source.contract()["tasks"].values():
        rows[item["instance_id"]] = {**item, "problem_statement": "public issue " + item["instance_id"],
                                    "patch": "GOLD NEVER SENT", "test_patch": "HIDDEN NEVER SENT",
                                    "FAIL_TO_PASS": ["secret-test"], "PASS_TO_PASS": ["secret-test"]}
    monkeypatch.setattr(adapter, "rows", lambda: rows)
    tasks = adapter.discover_tasks()
    assert len(tasks) == 230 and len({task.metadata["repo"] for task in tasks[:11]}) == 11
    catalog = SuperbenchCatalog(AdapterRegistry([adapter])).discover(("swe-gym-lite",))
    assert len({entry.task.metadata["repo"] for entry in catalog[:11]}) == 11
    assert [entry.task.task_id for entry in catalog] == [task.task_id for task in tasks]
    for task in tasks:
        assert task.prompt == rows[task.task_id]["problem_statement"]
        assert task.tools == ("kali-workstation",)
        assert task.initial_workspace is None and task.attachments == ()
        assert not {"patch", "test_patch", "FAIL_TO_PASS", "PASS_TO_PASS", "hints_text"} & set(task.metadata)
        assert "GOLD NEVER SENT" not in repr(task) and "HIDDEN NEVER SENT" not in repr(task)


def test_template_contract_propagation_and_default_fingerprints():
    tool = BenchmarkTool("app", "kali-workstation", "Kali", "local_mcp", "3", "a"*64, {})
    registry = SimpleNamespace(resolve_id=lambda _: SimpleNamespace(app_id=tool.app_id, ui_name=tool.ui_name,
        kind=tool.kind, version=tool.version, manifest_sha256=tool.manifest_sha256, manifest={},
        mcp_endpoint=None, control_endpoint=None, attachment_mode="none"))
    camp = TeacherCampaign("m", {})
    adapter = SWEGymLiteAdapter()
    task = TaskSpec("i", "p", tools=("kali-workstation",), workstation_template="swe-gym-lite/python_mypy")
    bt = to_benchmark_task(task, registry, camp, adapter)
    assert bt.workstation_template == task.workstation_template
    assert task_spec_fingerprint(task) != task_spec_fingerprint(replace(task, workstation_template=None))
    assert task_fingerprint(bt) != task_fingerprint(replace(bt, workstation_template=None))
    assert BenchmarkTask("gaia", "p", ()).workstation_template is None
    for invalid in ("/tmp/evil", "../evil", "swe-gym-lite/../x", "swe-gym-lite/x.qcow2", "swe-gym-lite/x/y"):
        with pytest.raises(ValueError):
            replace(task, workstation_template=invalid)
        with pytest.raises(ValueError):
            replace(bt, workstation_template=invalid)


@pytest.mark.asyncio
async def test_provider_create_selects_template_but_identity_remains_exact(tmp_path):
    token = tmp_path / "token"
    token.write_text("s"*40)
    calls = []
    tool = BenchmarkTool("app", "kali-workstation", "Kali", "local_mcp", "3", "a"*64, {})
    task = BenchmarkTask("t", "p", (), (tool,), workstation_template="swe-gym-lite/python_mypy")
    def handler(request):
        body = json.loads(request.content)
        calls.append((request.url.path, body))
        ident = {key: body[key] for key in ("task_id", "attempt", "environment_id", "fingerprint")}
        return httpx.Response(200, json={"identity": ident, "provider": "libvirt",
            "template_id": task.workstation_template, "backing_path": "/trusted/python_mypy.qcow2",
            "backing_sha256": "b"*64, "template_generation": "c"*64, "template_source_fingerprint": "d"*64})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://broker") as client:
        provider = LibvirtWorkstationProvider(tmp_path/"sock", token, client=client)
        created = await provider.create(task, {"kali-workstation": "env"}, "a"*64, attempt=1, control_token="s"*40)
        assert calls[0][1]["template_id"] == task.workstation_template
        assert created.metadata()["apps"]["kali-workstation"]["template_generation"] == "c"*64
        await provider.discover(task, {"kali-workstation": "env"}, "a"*64, attempt=1, control_token="s"*40)
        assert "template_id" not in calls[1][1]


@pytest.mark.asyncio
async def test_preflight_fails_before_vm_or_teacher():
    class Lifecycle:
        async def preflight_templates(self, tasks):
            raise AppInfrastructureError("template missing")
    with pytest.raises(AppInfrastructureError, match="template missing"):
        await preflight_templates(Lifecycle(), [BenchmarkTask("t", "p", (), workstation_template="swe-gym-lite/python_mypy")])
    assert await preflight_templates(object(), [BenchmarkTask("gaia", "p", ())]) == {"templates": {}}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def test_capture_new_deleted_binary_and_real_index_unchanged(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.test")
    git(repo, "config", "user.name", "test")
    (repo/"old.txt").write_text("old\n")
    (repo/"modified.txt").write_text("before\n")
    (repo/"binary.bin").write_bytes(b"\x00before\x01")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    (repo/"old.txt").unlink()
    (repo/"modified.txt").write_text("after\n")
    (repo/"binary.bin").write_bytes(b"\x00after\xff")
    (repo/"untracked.txt").write_text("new\n")
    git(repo, "add", "modified.txt")
    before = (repo/".git/index").read_bytes()
    patch = tmp_path/"candidate.patch"
    proof = guest_runtime.candidate_patch(repo, base, patch)
    assert (repo/".git/index").read_bytes() == before
    raw = patch.read_bytes()
    assert b"untracked.txt" in raw and b"deleted file mode" in raw and b"GIT binary patch" in raw
    assert proof["sha256"] == hashlib.sha256(raw).hexdigest()
    fresh = tmp_path/"fresh"
    subprocess.check_call(["git", "clone", str(repo), str(fresh)])
    git(fresh, "apply", "--check", "--binary", str(patch))
    git(fresh, "apply", "--binary", str(patch))
    assert (fresh/"untracked.txt").read_text() == "new\n"
    assert not (fresh/"old.txt").exists()
    assert (fresh/"binary.bin").read_bytes() == (repo/"binary.bin").read_bytes()


@pytest.mark.parametrize("verdict", [True, False])
def test_native_grading_uses_official_oracle_semantics(verdict):
    row = {"repo": "getmoto/moto", "FAIL_TO_PASS": ["tests/test_x.py::test_fixed"], "PASS_TO_PASS": ["tests/test_x.py::test_still_works"]}
    log = ("PASSED" if verdict else "FAILED") + " tests/test_x.py::test_fixed\nPASSED tests/test_x.py::test_still_works\n"
    passed, counts = native_grade(row, log)
    assert passed is verdict
    assert counts["FAIL_TO_PASS"]["success"] == int(verdict)
    assert counts["PASS_TO_PASS"]["success"] == 1


def test_empty_native_parser_is_technical_error():
    with pytest.raises(AppInfrastructureError, match="parser"):
        native_grade({"repo": "getmoto/moto", "FAIL_TO_PASS": [], "PASS_TO_PASS": []}, "no test execution")


def test_technical_incidents_require_intervention_rate_limit_preserved():
    assert classify_incident(AppInfrastructureError("qemu")) == ("infrastructure", True)
    assert classify_incident(RecoveryIncomplete("capture")) == ("recovery", True)
    assert classify_incident(RateLimited("server", retry_after_seconds=10)) == ("rate_limited", False)


def test_evaluator_relocation_keeps_exact_conda_prefix():
    destination = "/tmp/swe-gym-evaluator/repo"
    commands = ["cd /testbed", "cat /testbed/setup.py", "test \"$CONDA_PREFIX\" = /opt/miniconda3/envs/testbed"]
    assert guest_runtime.relocate_checkout(commands, destination) == [
        "cd " + destination, "cat " + destination + "/setup.py", commands[2]]


@pytest.mark.asyncio
async def test_template_preflight_does_not_discover_unselected_sources(monkeypatch):
    from gpt_trace_runner.superbench import lifecycle as module
    from gpt_trace_runner.superbench.adapters.base import BenchmarkAdapter
    class Selected(BenchmarkAdapter):
        adapter_id, adapter_version = "selected", "1"
        def discover_tasks(self):
            return [TaskSpec("id", "issue", workstation_template="swe-gym-lite/python_mypy",
                             metadata={"source_fingerprint": "a"*64})]
    class Unselected(Selected):
        adapter_id = "unselected"
        def discover_tasks(self):
            raise AssertionError("unselected gated dataset was discovered")
    adapter = Selected()
    bt = BenchmarkTask("run-id", "issue", (), workstation_template="swe-gym-lite/python_mypy")
    monkeypatch.setattr(module, "campaign", lambda _: object())
    monkeypatch.setattr(module, "to_benchmark_task", lambda *args: bt)
    seen = []
    class Lifecycle:
        async def preflight_templates(self, tasks):
            seen.extend(tasks)
            return {"templates": {bt.workstation_template: {"template_source_fingerprint": "a"*64}}}
        async def close(self): pass
    await module._preflight_selected(object(), object(), AdapterRegistry([adapter, Unselected()]),
        (bt.task_id,), lambda *args: Lifecycle(), ("selected",))
    assert seen == [bt]


@pytest.mark.asyncio
async def test_hidden_patch_is_only_in_native_grading_program(monkeypatch, tmp_path):
    import gpt_trace_runner.superbench.adapters.swe_gym_lite as module
    item = next(item for item in source.contract()["tasks"].values() if item["repo"] == "getmoto/moto")
    row = {**item, "patch": "GOLD_CODE_NEVER_DELIVERED", "test_patch": "HIDDEN_TEST_PATCH_ONLY_FOR_GRADING",
           "FAIL_TO_PASS": ["tests/test_x.py::test_fixed"], "PASS_TO_PASS": ["tests/test_x.py::test_old"]}
    adapter = SWEGymLiteAdapter()
    adapter._rows = {item["instance_id"]: row}
    task = TaskSpec(item["instance_id"], "public issue", tools=("kali-workstation",),
                    workstation_template=item["template_id"])
    programs = []
    async def execute(runtime, program, **kwargs):
        compile(program, "trusted-guest-validation", "exec")
        programs.append(program)
        if "prepare(item, log=ROOT" in program:
            return {"stdout": json.dumps({"base_commit": item["base_commit"], "env_hash": item["env_hash"]})}
        return {"stdout": json.dumps({"test_exit_status": 0})}
    monkeypatch.setattr(module, "execute", execute)
    patch = b"candidate bytes"
    artifact = tmp_path / "candidate.patch"
    artifact.write_bytes(patch)
    candidate = {"local_path": str(artifact), "sha256": hashlib.sha256(patch).hexdigest(), "size": len(patch),
                 "template_id": task.workstation_template, "env_hash": item["env_hash"],
                 "template_generation": "b"*64, "backing_sha256": "c"*64}
    class Provider:
        async def snapshot(self, *args, **kwargs):
            return {"apps": {"kali-workstation": {"template_generation": "b"*64, "backing_sha256": "c"*64}}}
    class Runtime:
        artifact_root = tmp_path
        provider = Provider()
        task, environments, fingerprint, attempt = None, {}, "d"*64, 1
        async def import_bytes(self, data, path):
            assert data == patch
        async def export(self, path, name):
            target = tmp_path / name
            target.write_text("PASSED tests/test_x.py::test_fixed\nPASSED tests/test_x.py::test_old\n")
            return {"local_path": str(target), "artifact_id": "e"*64, "sha256": "e"*64}
    runtime = Runtime()
    prepared = await adapter.prepare(task)
    await adapter.prepare_runtime(task, prepared=prepared, runtime=runtime)
    assert "HIDDEN_TEST_PATCH_ONLY_FOR_GRADING" not in programs[0]
    assert "GOLD_CODE_NEVER_DELIVERED" not in programs[0]
    result = await adapter.evaluate_runtime(task, prepared=prepared, captured=CapturedConversation("conv", []),
                                             candidate=candidate, runtime=runtime)
    assert result.verdict == "pass"
    assert "HIDDEN_TEST_PATCH_ONLY_FOR_GRADING" in programs[1]
    assert all("GOLD_CODE_NEVER_DELIVERED" not in program for program in programs)

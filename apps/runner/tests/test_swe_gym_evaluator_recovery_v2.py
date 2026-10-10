from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from test_runner_recovery import Storage
from test_swe_gym_recovery import NativeLifecycle, Teacher, NoTeacher, make
from gpt_trace_runner.exceptions import AppInfrastructureError
from gpt_trace_runner.journal import JournalStore
from gpt_trace_runner.models import BenchmarkTask, task_fingerprint
from gpt_trace_runner.runner import RuntimeHooks, abandon_recovery
from gpt_trace_runner.superbench.adapters.swe_gym import source, task_sources
from gpt_trace_runner.superbench.adapters.swe_gym_lite import SWEGymLiteAdapter
from gpt_trace_runner.superbench.lifecycle import classify_incident
from gpt_trace_runner.superbench.models import TaskSpec
from gpt_trace_runner.workstation_provider import LibvirtWorkstationProvider


@pytest.fixture
def grading(tmp_path):
    item = next(item for item in source.contract()["tasks"].values() if item["repo"] == "getmoto/moto")
    task = TaskSpec(item["instance_id"], "public", workstation_template=item["template_id"])
    bt = BenchmarkTask("t", "p", (), workstation_template=task.workstation_template, template_task_id=task.task_id)
    row = {**item,"patch":"GOLD_NEVER_DELIVERED","test_patch":"HIDDEN_EVALUATOR_ONLY",
           "FAIL_TO_PASS":["tests/test_x.py::fixed"],"PASS_TO_PASS":["tests/test_x.py::old"]}
    adapter = SWEGymLiteAdapter()
    adapter._rows = {task.task_id:row}
    patch = b"durable candidate\n"
    class BoundStorage(Storage):
        async def set_conversation(self, *args, **kwargs):
            await super().set_conversation(*args, **kwargs)
            self.existing = replace(self.existing, task_fingerprint=task_fingerprint(bt))
        async def fail(self, *args, **kwargs):
            await super().fail(*args, **kwargs)
            self.existing = replace(self.existing, task_fingerprint=task_fingerprint(bt))
    class Provider:
        def __init__(self):
            self.pending, self.created, self.destroyed, self.imported, self.programs, self.actions = None, [], [], [], [], []
            self.verdict, self.broken = "pass", False
        def _identity(self, task, environments, fingerprint, attempt):
            return {"task_id":task.task_id,"attempt":attempt,"environment_id":"env","fingerprint":fingerprint}
        async def snapshot(self, *args, **kwargs):
            return {"apps":{"kali-workstation":{"template_id":item["template_id"],"template_generation":"b"*64,
                    "backing_sha256":"c"*64,"backing_path":"/immutable/repo.qcow2"}}}
        async def create_evaluator(self, task, environments, fingerprint, *, attempt, abandon_stale):
            if self.pending and not abandon_stale: raise AppInfrastructureError("stale evaluator preserved")
            retry = f"{len(self.created)+1:032x}"
            self.created.append((retry, abandon_stale))
            self.pending = retry
            return {"identity":{**self._identity(task,environments,fingerprint,attempt),"purpose":"evaluator","evaluator_retry":retry},
                "domain":"evaluator-"+retry,"overlay":"/isolated/"+retry,"template_id":item["template_id"],
                "template_generation":"b"*64,"backing_sha256":"c"*64,"backing_path":"/immutable/repo.qcow2","network":None}
        async def _request(self, action, payload):
            self.actions.append(action)
            if action == "destroy_evaluator":
                self.destroyed.append(payload["evaluator_retry"])
                self.pending = None
                return {"destroyed":True}
            if action in ("abandon_evaluators","abandon_attempt"):
                self.pending = None
                return {"destroyed":True}
            if action == "evaluator_materialize_template_artifact":
                key = payload["artifact_id"]
                kind = next(k for k in ("task_source","setup_cache") if task_sources.artifact_id(k, task.task_id) == key)
                return {"artifact_id":key,"kind":kind,"logical_task_id":task.task_id,
                    "source_identity":{k:item[k] for k in ("instance_id","repo","base_commit")},
                    "path":"/var/lib/gpt-trace-template-artifacts/"+key+"/payload","sha256":"a"*64,"size":1}
            assert action == "evaluator_rpc"
            program = payload["args"]["stdin"]
            compile(program,"isolated-recovery-test","exec")
            assert "GOLD_NEVER_DELIVERED" not in program
            self.programs.append((payload["evaluator_retry"],program))
            if "proof = prepare_evaluator" in program:
                assert "HIDDEN_EVALUATOR_ONLY" not in program
                return {"exit_code":0,"stdout":json.dumps({"base_commit":item["base_commit"],"env_hash":item["env_hash"],"source_sha256":"a"*64})}
            assert "HIDDEN_EVALUATOR_ONLY" in program
            return {"exit_code":0,"stdout":json.dumps({"test_exit_status":0 if self.verdict == "pass" else 1})}
        async def _import(self, ident, data, path, prefix):
            assert prefix == "evaluator_" and data == patch
            assert "proof = prepare_evaluator" in self.programs[-1][1]
            self.imported.append((ident["evaluator_retry"], data))
        async def _export(self, ident, path, destination, prefix):
            assert prefix == "evaluator_"
            destination.parent.mkdir(parents=True, exist_ok=True)
            text = "NO NATIVE TEST RESULTS" if self.broken else ("PASSED" if self.verdict == "pass" else "FAILED") + " tests/test_x.py::fixed\nPASSED tests/test_x.py::old\n"
            destination.write_text(text)
            return {"local_path":str(destination),"sha256":hashlib.sha256(text.encode()).hexdigest(),"artifact_id":"d"*64}
    provider = Provider()
    class Lifecycle(NativeLifecycle):
        runtime = provider
        async def abandon(self, task, environments, fingerprint, *, attempt):
            self.calls.append("abandon")
            await LibvirtWorkstationProvider.abandon(provider, task, environments, fingerprint, attempt=attempt)
    lifecycle, storage, teacher, journal = Lifecycle(), BoundStorage(), Teacher(), JournalStore(tmp_path/"journal.json")
    async def prepare(runtime): pass
    async def capture(captured, runtime):
        runtime.artifact_root.mkdir(parents=True, exist_ok=True)
        path = runtime.artifact_root / "candidate.patch"
        path.write_bytes(patch)
        return {"local_path":str(path),"sha256":hashlib.sha256(patch).hexdigest(),"size":len(patch),
            "template_id":item["template_id"],"template_generation":"b"*64,"backing_sha256":"c"*64,
            "env_hash":item["env_hash"],"source_sha256":"a"*64,"source_artifact_id":task_sources.artifact_id("task_source",task.task_id)}
    async def evaluate(captured, candidate, runtime):
        return (await adapter.evaluate_runtime(task,prepared=None,captured=captured,candidate=candidate,runtime=runtime)).as_dict()
    return bt, teacher, storage, lifecycle, journal, provider, RuntimeHooks(prepare,capture,evaluate), patch


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["pass","fail"])
async def test_native_verdict_destroys_evaluator_completes_storage_and_cleans_teacher(grading, verdict):
    bt, teacher, storage, lifecycle, journal, provider, hooks, patch = grading
    provider.verdict = verdict
    await make(teacher,storage,lifecycle,journal,hooks).run_task(bt, False)
    assert provider.created == [("1".zfill(32),False)] and provider.destroyed == ["1".zfill(32)]
    assert provider.imported == [("1".zfill(32),patch)]
    assert storage.existing.status == "completed" and storage.existing.evaluation["verdict"] == verdict
    assert lifecycle.calls == ["prepare","reset"] and journal.load() is None


@pytest.mark.asyncio
async def test_technical_error_preserves_exact_checkpoint_and_explicit_resume_uses_fresh_evaluator(grading):
    bt, teacher, storage, lifecycle, journal, provider, hooks, patch = grading
    provider.broken = True
    with pytest.raises(AppInfrastructureError) as caught:
        await make(teacher,storage,lifecycle,journal,hooks).run_task(bt, False)
    assert classify_incident(caught.value) == ("infrastructure",True)
    entry = journal.load()
    assert entry.phase == "candidate_checkpointed" and entry.evaluator["identity"]["purpose"] == "evaluator"
    assert Path(entry.candidate["local_path"]).read_bytes() == patch
    assert provider.destroyed == [] and provider.pending == "1".zfill(32)
    assert storage.existing.status == "running" and lifecycle.calls == ["prepare"]
    async def forbidden(*args): raise AssertionError("candidate was recaptured or teacher prepared")
    provider.broken = False
    await make(NoTeacher(),storage,lifecycle,journal,RuntimeHooks(forbidden,forbidden,hooks.evaluate)).reconcile_journal([bt])
    assert provider.created == [("1".zfill(32),False),("2".zfill(32),True)]
    assert provider.imported == [("1".zfill(32),patch),("2".zfill(32),patch)] and teacher.sends == 1
    assert provider.destroyed == ["2".zfill(32)] and storage.existing.status == "completed"


@pytest.mark.asyncio
async def test_reset_recovery_abandons_both_runtimes_and_retries_same_frozen_task(grading):
    bt, teacher, storage, lifecycle, journal, provider, hooks, _ = grading
    provider.broken = True
    with pytest.raises(AppInfrastructureError):
        await make(teacher,storage,lifecycle,journal,hooks).run_task(bt, False)
    await abandon_recovery(bt,storage=storage,lifecycle=lifecycle,journal=journal)
    assert provider.actions[-2:] == ["abandon_evaluators","abandon_attempt"]
    assert provider.pending is None and journal.load() is None and storage.existing.status == "failed"
    provider.broken = False
    await make(teacher,storage,lifecycle,journal,hooks).run_task(bt, True)
    assert storage.existing.attempt == 2 and storage.existing.task_id == bt.task_id
    assert teacher.sends == 2 and storage.existing.status == "completed"

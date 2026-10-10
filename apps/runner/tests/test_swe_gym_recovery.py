from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import AppInfrastructureError, RecoveryIncomplete
from gpt_trace_runner.journal import JournalStore
from gpt_trace_runner.models import BenchmarkTask, CapturedConversation
from gpt_trace_runner.runner import BenchmarkRunner, RuntimeHooks
from test_runner_recovery import Lifecycle, Storage


TASK = BenchmarkTask("t", "p", ())


class NativeLifecycle(Lifecycle):
    runtime = object()


class Teacher:
    def __init__(self):
        self.sends = 0
        self.deleted = []
    async def prepare_session(self, **kwargs): pass
    async def prepare_task(self, task): return task
    async def submit_task(self, task, *, before_send, on_user_message_id):
        before_send()
        on_user_message_id("user-1")
        self.sends += 1
        return SimpleNamespace(conversation_id="conv", user_message_id="user-1")
    async def wait_for_completion(self, submitted):
        return CapturedConversation(submitted.conversation_id, [{"id": "assistant-1"}], {})
    async def delete_completed_conversation(self, cid):
        self.deleted.append(cid)


class NoTeacher:
    """Only terminal cleanup is permitted after the candidate checkpoint."""
    def __init__(self): self.deleted = []
    def __getattr__(self, name):
        raise AssertionError("teacher interaction resumed after checkpoint: " + name)
    async def delete_completed_conversation(self, cid): self.deleted.append(cid)


def make(teacher, storage, lifecycle, journal, hooks):
    return BenchmarkRunner(chatgpt=teacher, storage=storage, lifecycle=lifecycle,
        journal=journal, runner_id="r", recover_existing=True, console=Console(),
        runtime_hooks={TASK.task_id: hooks})


@pytest.mark.asyncio
async def test_preparing_failure_preserves_same_vm_attempt_and_one_send(tmp_path):
    teacher, storage, lifecycle = Teacher(), Storage(), NativeLifecycle()
    journal = JournalStore(tmp_path/"journal.json")
    prepares = 0
    async def prepare(runtime):
        nonlocal prepares
        prepares += 1
        if prepares == 1:
            raise AppInfrastructureError("offline setup missing package")
    async def capture(captured, runtime): return {"sha256": "a"*64}
    async def evaluate(captured, candidate, runtime): return {"verdict": "fail"}
    hooks = RuntimeHooks(prepare, capture, evaluate)
    runner = make(teacher, storage, lifecycle, journal, hooks)
    with pytest.raises(AppInfrastructureError):
        await runner.run_task(TASK, False)
    assert journal.load().phase == "benchmark_preparing"
    assert lifecycle.calls == ["prepare"]
    assert storage.existing.status == "running" and storage.existing.attempt == 1
    assert teacher.sends == 0 and storage.failed == []
    await make(teacher, storage, lifecycle, journal, hooks).reconcile_journal([TASK])
    assert teacher.sends == 1 and prepares == 2
    assert storage.existing.status == "completed" and storage.existing.attempt == 1
    assert storage.existing.evaluation == {"verdict": "fail"}
    assert lifecycle.calls == ["prepare", "resume", "reset"]
    assert journal.load() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["pass", "fail"])
async def test_native_verdict_completes_and_cleans_up(verdict, tmp_path):
    teacher, storage, lifecycle = Teacher(), Storage(), NativeLifecycle()
    journal = JournalStore(tmp_path/"journal.json")
    async def prepare(runtime): pass
    async def capture(captured, runtime):
        assert journal.load().phase == "conversation_checkpointed"
        assert journal.capture_path.is_file()
        return {"sha256": "b"*64}
    async def evaluate(captured, candidate, runtime):
        assert journal.load().phase == "candidate_checkpointed"
        return {"verdict": verdict}
    await make(teacher, storage, lifecycle, journal, RuntimeHooks(prepare, capture, evaluate)).run_task(TASK, False)
    assert storage.existing.status == "completed"
    assert storage.existing.evaluation == {"verdict": verdict}
    assert lifecycle.calls == ["prepare", "reset"]
    assert journal.load() is None and not journal.capture_path.exists()


@pytest.mark.asyncio
async def test_grading_failure_resumes_exact_candidate_without_model_or_recapture(tmp_path):
    teacher, storage, lifecycle = Teacher(), Storage(), NativeLifecycle()
    journal = JournalStore(tmp_path/"journal.json")
    patch = b"exact binary-compatible candidate bytes\n"
    candidate = {"sha256": hashlib.sha256(patch).hexdigest(), "local_path": str(tmp_path/"candidate.patch")}
    (tmp_path/"candidate.patch").write_bytes(patch)
    evaluated = []
    async def prepare(runtime): pass
    async def capture(captured, runtime): return candidate
    async def broken(captured, checkpoint, runtime):
        evaluated.append(checkpoint)
        raise AppInfrastructureError("grader log parser unavailable after hidden tests")
    with pytest.raises(AppInfrastructureError):
        await make(teacher, storage, lifecycle, journal, RuntimeHooks(prepare, capture, broken)).run_task(TASK, False)
    assert teacher.sends == 1 and storage.failed == []
    assert journal.load().phase == "candidate_checkpointed"
    assert journal.load().candidate == candidate
    assert lifecycle.calls == ["prepare"]
    entry = journal.load()
    assert journal.load_capture(entry).conversation_id == "conv"
    async def forbidden(*args): raise AssertionError("prepare/capture invoked again")
    async def fixed(captured, checkpoint, runtime):
        assert checkpoint == candidate
        assert Path(checkpoint["local_path"]).read_bytes() == patch
        evaluated.append(checkpoint)
        return {"verdict": "pass"}
    cleanup = NoTeacher()
    await make(cleanup, storage, lifecycle, journal, RuntimeHooks(forbidden, forbidden, fixed)).reconcile_journal([TASK])
    assert evaluated == [candidate, candidate]
    assert cleanup.deleted == ["conv"] and teacher.sends == 1
    assert storage.existing.status == "completed"
    assert not journal.capture_path.exists()


@pytest.mark.asyncio
async def test_capture_failure_conversation_barrier_never_resumes_teacher(tmp_path):
    teacher, storage, lifecycle = Teacher(), Storage(), NativeLifecycle()
    journal = JournalStore(tmp_path/"journal.json")
    async def prepare(runtime): pass
    async def broken(captured, runtime): raise AppInfrastructureError("candidate cannot reapply")
    async def evaluate(captured, candidate, runtime): return {"verdict": "fail"}
    with pytest.raises(AppInfrastructureError):
        await make(teacher, storage, lifecycle, journal, RuntimeHooks(prepare, broken, evaluate)).run_task(TASK, False)
    assert journal.load().phase == "conversation_checkpointed"
    async def captured(captured, runtime): return {"sha256": "c"*64}
    await make(NoTeacher(), storage, lifecycle, journal, RuntimeHooks(prepare, captured, evaluate)).reconcile_journal([TASK])
    assert teacher.sends == 1 and storage.existing.status == "completed"


@pytest.mark.asyncio
async def test_mutated_conversation_checkpoint_stops_before_hidden_grading(tmp_path):
    teacher, storage, lifecycle = Teacher(), Storage(), NativeLifecycle()
    journal = JournalStore(tmp_path/"journal.json")
    async def prepare(runtime): pass
    async def capture(captured, runtime): return {"sha256": "d"*64}
    async def evaluate(captured, checkpoint, runtime): raise AppInfrastructureError("grader failure")
    hooks = RuntimeHooks(prepare, capture, evaluate)
    with pytest.raises(AppInfrastructureError):
        await make(teacher, storage, lifecycle, journal, hooks).run_task(TASK, False)
    journal.capture_path.write_text("{}")
    with pytest.raises(RecoveryIncomplete, match="checkpoint invalid"):
        await make(NoTeacher(), storage, lifecycle, journal, hooks).reconcile_journal([TASK])
    assert storage.existing.status == "running"

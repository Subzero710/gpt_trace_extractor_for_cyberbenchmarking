from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import AmbiguousSubmission
from gpt_trace_runner.journal import JournalStore, SubmissionJournal
from gpt_trace_runner.models import BenchmarkTask, CapturedConversation, StoredRun, task_fingerprint
from gpt_trace_runner.runner import BenchmarkRunner, RunOptions


def fp():
    return task_fingerprint(BenchmarkTask("t", "p", ()))


class Storage:
    def __init__(self, existing=None):
        self.existing = existing
        self.failed = []
        self.set_calls = []
        self.completed = []
    async def get(self, task_id): return self.existing
    async def start(self, task_id, runner_id, expected_attempt, task_fingerprint):
        self.existing = StoredRun(task_id, "running", attempt=expected_attempt, runner_id=runner_id, task_fingerprint=task_fingerprint)
        return self.existing
    async def set_conversation(self, task_id, conversation_id, *, attempt, runner_id):
        self.set_calls.append((task_id, conversation_id, attempt, runner_id))
        self.existing = StoredRun(task_id, "running", conversation_id, attempt, runner_id)
        return self.existing
    async def complete(self, task_id, captured, *, attempt, runner_id):
        self.completed.append((task_id, captured.conversation_id, attempt, runner_id))
        self.existing = StoredRun(task_id, "completed", captured.conversation_id, attempt, runner_id)
        return self.existing
    async def fail(self, task_id, error, *, attempt, runner_id):
        self.failed.append((task_id, type(error).__name__, attempt, runner_id))
        self.existing = StoredRun(task_id, "failed", attempt=attempt, runner_id=runner_id)
        return self.existing


class AmbiguousChatGPT:
    async def prepare_session(self, *, fresh_home=False): pass
    async def prepare_task(self, task): return object()
    async def submit_task(self, prepared, *, before_send):
        before_send()
        raise AmbiguousSubmission("unknown after send")


class RecoveryChatGPT:
    async def prepare_session(self, *, fresh_home=False): pass
    async def recover_current_candidate(self, *, task):
        return CapturedConversation("conv", [{"id": "m"}], {})
    async def recover(self, conversation_id, *, task):
        return CapturedConversation(conversation_id, [{"id": "m"}], {})


def runner(chatgpt, storage, journal):
    return BenchmarkRunner(
        chatgpt=chatgpt, storage=storage, runner_id="r", recover_existing=True,
        console=Console(force_terminal=False), journal=journal,
    )


@pytest.mark.asyncio
async def test_ambiguous_after_send_preserves_running_journal(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    storage = Storage()
    r = runner(AmbiguousChatGPT(), storage, store)
    with pytest.raises(AmbiguousSubmission):
        await r.run([BenchmarkTask("t", "p", ())], RunOptions())
    assert storage.failed == []
    assert storage.existing.status == "running"
    assert store.load().phase == "submission_started"


@pytest.mark.asyncio
async def test_starting_journal_is_safe_to_fail_and_clear(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 2, "starting", task_fingerprint=fp()))
    storage = Storage(StoredRun("t", "running", attempt=2, runner_id="old", task_fingerprint=fp()))
    r = runner(RecoveryChatGPT(), storage, store)
    await r.reconcile_journal([BenchmarkTask("t", "p", ())])
    assert storage.existing.status == "failed"
    assert store.load() is None


@pytest.mark.asyncio
async def test_submission_started_recovers_current_conversation_without_resubmit(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 3, "submission_started", task_fingerprint=fp()))
    storage = Storage(StoredRun("t", "running", attempt=3, runner_id="old", task_fingerprint=fp()))
    r = runner(RecoveryChatGPT(), storage, store)
    await r.reconcile_journal([BenchmarkTask("t", "p", ())])
    assert storage.set_calls == [("t", "conv", 3, "old")]
    assert storage.completed == [("t", "conv", 3, "old")]
    assert store.load() is None


@pytest.mark.asyncio
async def test_conversation_known_journal_recovers_by_known_id(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 4, "conversation_known", "known", fp()))
    storage = Storage(StoredRun("t", "running", "known", 4, "old", fp()))
    r = runner(RecoveryChatGPT(), storage, store)
    await r.reconcile_journal([BenchmarkTask("t", "p", ())])
    assert storage.completed[-1][1] == "known"
    assert store.load() is None


@pytest.mark.asyncio
async def test_terminal_failed_row_clears_leftover_journal(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 2, "composer_dirty", task_fingerprint=fp()))
    storage = Storage(
        StoredRun("t", "failed", attempt=2, runner_id="old", task_fingerprint=fp())
    )
    r = runner(RecoveryChatGPT(), storage, store)
    await r.reconcile_journal([BenchmarkTask("t", "p", ())])
    assert store.load() is None

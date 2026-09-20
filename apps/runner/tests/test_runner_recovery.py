from pathlib import Path

import pytest
from rich.console import Console

from gpt_trace_runner.exceptions import AmbiguousSubmission, RecoveryIncomplete, RequiredToolNotUsed
from gpt_trace_runner.journal import JournalStore, SubmissionJournal
from gpt_trace_runner.models import BenchmarkTask, CapturedConversation, StoredRun, task_fingerprint
from gpt_trace_runner.runner import BenchmarkRunner, RunOptions, abandon_recovery


TASK = BenchmarkTask("t", "p", ())


def fp():
    return task_fingerprint(TASK)


class Lifecycle:
    def __init__(self): self.calls = []
    def environment_ids(self, task, *, attempt, fingerprint): return {}
    async def prepare(self, task, environments, fingerprint, *, attempt): self.calls.append("prepare")
    async def assert_resume(self, task, environments, fingerprint, *, attempt): self.calls.append("resume")
    async def runtime_metadata(self, task, environments, fingerprint, *, attempt): return {}
    async def reset(self, task, environments, fingerprint, *, attempt): self.calls.append("reset")


class Storage:
    def __init__(self, existing=None):
        self.existing = existing
        self.failed = []
        self.set_calls = []
        self.completed = []
    async def get(self, task_id): return self.existing
    async def start(self, task_id, runner_id, expected_attempt, task_fingerprint, app_provenance):
        self.existing = StoredRun(
            task_id, "running", attempt=expected_attempt, runner_id=runner_id,
            task_fingerprint=task_fingerprint, app_provenance=app_provenance,
        )
        return self.existing
    async def set_conversation(self, task_id, conversation_id, *, attempt, runner_id):
        self.set_calls.append((task_id, conversation_id, attempt, runner_id))
        self.existing = StoredRun(task_id, "running", conversation_id, attempt, runner_id, fp(), app_provenance=[])
        return self.existing
    async def complete(self, task_id, captured, *, attempt, runner_id):
        self.completed.append((task_id, captured.conversation_id, attempt, runner_id))
        self.existing = StoredRun(task_id, "completed", captured.conversation_id, attempt, runner_id, fp(), app_provenance=[])
        return self.existing
    async def fail(self, task_id, error, *, attempt, runner_id):
        self.failed.append((task_id, type(error).__name__, attempt, runner_id))
        self.existing = StoredRun(task_id, "failed", attempt=attempt, runner_id=runner_id, task_fingerprint=fp(), app_provenance=[])
        return self.existing


class AmbiguousChatGPT:
    async def prepare_session(self, *, fresh_home=False): pass
    async def prepare_task(self, task): return object()
    async def submit_task(self, prepared, *, before_send, on_user_message_id):
        before_send()
        on_user_message_id("submitted-user-message")
        raise AmbiguousSubmission("unknown after send")


class RecoveryChatGPT:
    def __init__(self):
        self.deleted = []
    async def prepare_session(self, *, fresh_home=False): pass
    async def recover_current_candidate(self, *, task, user_message_id):
        assert user_message_id == "submitted-user-message"
        return CapturedConversation("conv", [{"id": "m"}], {})
    async def recover(self, conversation_id, *, task, user_message_id):
        assert user_message_id == "submitted-user-message"
        return CapturedConversation(conversation_id, [{"id": "m"}], {})
    async def delete_completed_conversation(self, conversation_id):
        self.deleted.append(conversation_id)


def runner(chatgpt, storage, journal, lifecycle=None):
    return BenchmarkRunner(
        chatgpt=chatgpt,
        storage=storage,
        lifecycle=lifecycle or Lifecycle(),
        runner_id="r",
        recover_existing=True,
        console=Console(force_terminal=False),
        journal=journal,
    )


@pytest.mark.asyncio
async def test_ambiguous_after_send_preserves_running_journal_and_environment(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    storage = Storage()
    lifecycle = Lifecycle()
    with pytest.raises(AmbiguousSubmission):
        await runner(AmbiguousChatGPT(), storage, store, lifecycle).run([TASK], RunOptions())
    assert storage.failed == []
    assert storage.existing.status == "running"
    assert store.load().phase == "submission_started"
    assert store.load().user_message_id == "submitted-user-message"
    assert lifecycle.calls == ["prepare"]


@pytest.mark.asyncio
async def test_starting_journal_is_cleaned_then_failed(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 2, "starting", task_fingerprint=fp()))
    storage = Storage(StoredRun("t", "running", attempt=2, runner_id="old", task_fingerprint=fp(), app_provenance=[]))
    lifecycle = Lifecycle()
    await runner(RecoveryChatGPT(), storage, store, lifecycle).reconcile_journal([TASK])
    assert storage.existing.status == "failed"
    assert lifecycle.calls == ["reset"]
    assert store.load() is None


@pytest.mark.asyncio
async def test_submission_started_recovers_same_environment_without_resubmit(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal(
        "t", "old", 3, "submission_started", task_fingerprint=fp(),
        user_message_id="submitted-user-message",
    ))
    storage = Storage(StoredRun("t", "running", attempt=3, runner_id="old", task_fingerprint=fp(), app_provenance=[]))
    lifecycle = Lifecycle()
    await runner(RecoveryChatGPT(), storage, store, lifecycle).reconcile_journal([TASK])
    assert storage.set_calls == [("t", "conv", 3, "old")]
    assert storage.completed == [("t", "conv", 3, "old")]
    assert lifecycle.calls == ["resume", "reset"]
    assert store.load() is None


@pytest.mark.asyncio
async def test_completed_row_with_cleanup_journal_is_reset(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal("t", "old", 4, "cleanup_pending", "known", fp()))
    storage = Storage(StoredRun("t", "completed", "known", 4, "old", fp(), app_provenance=[]))
    lifecycle = Lifecycle()
    chatgpt = RecoveryChatGPT()
    await runner(chatgpt, storage, store, lifecycle).reconcile_journal([TASK])
    assert chatgpt.deleted == ["known"]
    assert lifecycle.calls == ["reset"]
    assert store.load() is None


class MissingRequiredOnRecover(RecoveryChatGPT):
    async def recover(self, conversation_id, *, task, user_message_id):
        raise RequiredToolNotUsed("required App was not used")


class MissingRequiredCandidate(RecoveryChatGPT):
    async def recover_current_candidate(self, *, task, user_message_id):
        raise RequiredToolNotUsed("required App was not used")


@pytest.mark.asyncio
async def test_known_conversation_required_tool_failure_terminalizes_and_cleans_environment(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal(
        "t", "old", 3, "conversation_known", "known", fp(),
        user_message_id="submitted-user-message",
    ))
    storage = Storage(StoredRun("t", "running", "known", 3, "old", fp(), app_provenance=[]))
    lifecycle = Lifecycle()
    with pytest.raises(RequiredToolNotUsed):
        await runner(MissingRequiredOnRecover(), storage, store, lifecycle).reconcile_journal([TASK])
    assert storage.existing.status == "failed"
    assert lifecycle.calls == ["resume", "reset"]
    assert store.load() is None


@pytest.mark.asyncio
async def test_unknown_candidate_required_tool_failure_terminalizes_and_cleans_environment(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(SubmissionJournal(
        "t", "old", 3, "submission_started", task_fingerprint=fp(),
        user_message_id="submitted-user-message",
    ))
    storage = Storage(StoredRun("t", "running", attempt=3, runner_id="old", task_fingerprint=fp(), app_provenance=[]))
    lifecycle = Lifecycle()
    with pytest.raises(RequiredToolNotUsed):
        await runner(MissingRequiredCandidate(), storage, store, lifecycle).reconcile_journal([TASK])
    assert storage.existing.status == "failed"
    assert lifecycle.calls == ["resume", "reset"]
    assert store.load() is None

@pytest.mark.asyncio
async def test_abandon_recovery_fails_attempt_resets_apps_and_clears_journal(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    store.write(
        SubmissionJournal(
            "t",
            "old",
            3,
            "conversation_known",
            "deleted-conv",
            fp(),
            {},
            {},
            "submitted-user-message",
        )
    )
    storage = Storage(
        StoredRun(
            "t",
            "running",
            "deleted-conv",
            3,
            "old",
            fp(),
            app_provenance=[],
        )
    )
    lifecycle = Lifecycle()

    await abandon_recovery(
        TASK,
        storage=storage,
        lifecycle=lifecycle,
        journal=store,
    )

    assert storage.failed == [("t", "RecoveryIncomplete", 3, "old")]
    assert storage.existing.status == "failed"
    assert lifecycle.calls == ["reset"]
    assert store.load() is None



@pytest.mark.asyncio
async def test_running_conversation_without_message_identity_proof_is_not_auto_recovered(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    storage = Storage(
        StoredRun(
            "t", "running", "known", 3, "old", fp(), app_provenance=[]
        )
    )
    with pytest.raises(RecoveryIncomplete, match="no submission journal user_message_id proof"):
        await runner(RecoveryChatGPT(), storage, store).run([TASK], RunOptions(resume=True))


def test_submission_journal_persists_user_message_identity(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    entry = SubmissionJournal(
        "t", "r", 1, "submission_started", task_fingerprint=fp(),
        user_message_id="user-123",
    )
    store.write(entry)
    assert store.load() == entry

def test_make_reset_recovery_is_explicit_and_never_starts_dependencies() -> None:
    makefile = (Path(__file__).parents[3] / "Makefile").read_text(encoding="utf-8")
    block = makefile.split("reset-recovery:", 1)[1].split("reset-stale:", 1)[0]
    assert 'test -n "$(TASK)"' in block
    assert "docker compose run --rm --no-deps runner reset-recovery" in block
    assert '"$(TASK)" --yes' in block


def test_runner_deletes_completed_remote_conversation_before_app_reset() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / "runner.py"
    ).read_text(encoding="utf-8")
    run_task = source.split("async def run_task", 1)[1].split("async def run(", 1)[0]

    delete_call = "await self.chatgpt.delete_completed_conversation(submitted.conversation_id)"
    reset_call = "await self.lifecycle.reset(task, environments, fingerprint, attempt=expected_attempt)"
    assert delete_call in run_task
    assert run_task.index(delete_call) < run_task.index(reset_call)
    assert "await self.chatgpt.delete_completed_conversation(existing.conversation_id)" in run_task


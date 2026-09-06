from pathlib import Path

import pytest

from gpt_trace_runner.exceptions import RecoveryIncomplete
from gpt_trace_runner.journal import JournalStore, SubmissionJournal


def test_journal_round_trip_and_clear(tmp_path: Path) -> None:
    store = JournalStore(tmp_path / "j.json")
    item = SubmissionJournal("t", "r", 2, "conversation_known", "c", "a" * 64)
    store.write(item)
    assert store.load() == item
    store.clear()
    assert store.load() is None


def test_corrupt_journal_is_fatal(tmp_path: Path) -> None:
    path = tmp_path / "j.json"
    path.write_text("{")
    with pytest.raises(RecoveryIncomplete):
        JournalStore(path).load()

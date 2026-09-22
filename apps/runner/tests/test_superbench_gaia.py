from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from gpt_trace_runner.models import CapturedConversation
from gpt_trace_runner.superbench.adapters.base import PreparedBenchmarkContext
from gpt_trace_runner.superbench.adapters.gaia import (
    GAIAAdapter,
    GAIA_METADATA_FILE,
    GAIA_REVISION,
    gaia_question_scorer,
)


def _write_metadata(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(
        [
            {
                "task_id": "task-web",
                "Question": "What is the answer?",
                "Level": 1,
                "Final answer": "Paris",
                "file_name": None,
                "file_path": None,
            },
            {
                "task_id": "task-file",
                "Question": "Read the attachment and answer.",
                "Level": 1,
                "Final answer": "42",
                "file_name": "sample.txt",
                "file_path": "2023/validation/sample.txt",
            },
        ]
    )
    pq.write_table(table, path)
    return path


def test_gaia_native_scorer():
    assert gaia_question_scorer("$1,234", "1234")
    assert gaia_question_scorer("Sea Gull", "sea-gull")
    assert gaia_question_scorer("Paris; 2", "paris,2")
    assert not gaia_question_scorer("Paris, 3", "paris,2")


def test_generic_source_root_is_adapter_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("GPT_TRACE_SUPERBENCH_SOURCE_ROOT", str(tmp_path))
    adapter = GAIAAdapter()
    assert adapter.source_root == tmp_path / "gaia"
    assert adapter.revision_root == tmp_path / "gaia" / GAIA_REVISION


def test_discover_exposes_both_apps_without_leaking_labels(tmp_path, monkeypatch):
    monkeypatch.setenv("GPT_TRACE_SUPERBENCH_SOURCE_ROOT", str(tmp_path))
    adapter = GAIAAdapter()
    metadata = adapter.revision_root / GAIA_METADATA_FILE
    _write_metadata(metadata)

    tasks = adapter.discover_tasks()

    assert len(tasks) == 2
    assert all(task.tools == ("browser", "code-workspace") for task in tasks)
    assert all(task.metadata["source_revision"] == GAIA_REVISION for task in tasks)
    assert all("Final answer" not in task.metadata for task in tasks)
    assert all("FINAL ANSWER:" in task.prompt for task in tasks)


def test_fetch_only_downloads_adapter_owned_source_files(tmp_path, monkeypatch):
    monkeypatch.setenv("GPT_TRACE_SUPERBENCH_SOURCE_ROOT", str(tmp_path))
    adapter = GAIAAdapter()
    calls: list[str] = []

    def fake_fetch(filename: str) -> Path:
        calls.append(filename)
        destination = adapter._local_path(filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if filename == GAIA_METADATA_FILE:
            _write_metadata(destination)
        else:
            destination.write_text("42\n", encoding="utf-8")
        return destination

    monkeypatch.setattr(adapter, "_fetch_file", fake_fetch)
    adapter.fetch()

    assert calls == [
        GAIA_METADATA_FILE,
        "2023/validation/sample.txt",
    ]


@pytest.mark.asyncio
async def test_materialize_attachment_and_native_evaluation(tmp_path, monkeypatch):
    monkeypatch.setenv("GPT_TRACE_SUPERBENCH_SOURCE_ROOT", str(tmp_path))
    adapter = GAIAAdapter()

    metadata = adapter.revision_root / GAIA_METADATA_FILE
    _write_metadata(metadata)
    attachment = adapter.revision_root / "2023/validation/sample.txt"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_text("42\n", encoding="utf-8")

    tasks = adapter.discover_tasks()
    task = next(
        item for item in tasks if item.metadata["upstream_task_id"] == "task-file"
    )
    materialized = adapter.materialize_task(task, tmp_path / "staging")

    assert len(materialized.attachments) == 1
    assert materialized.attachments[0].name == "sample.txt"
    assert materialized.attachments[0].read_text(encoding="utf-8") == "42\n"

    captured = CapturedConversation(
        conversation_id="c1",
        messages=[
            {"author": {"role": "assistant"}, "content": {"parts": ["Reasoning"]}},
            {
                "author": {"role": "assistant"},
                "content": {"parts": ["Done.\nFINAL ANSWER: 42"]},
            },
        ],
    )
    result = await adapter.evaluate(
        task,
        prepared=PreparedBenchmarkContext(),
        captured=captured,
    )
    assert result.verdict == "pass"
    assert result.score == 1.0
    assert result.details == {"model_answer": "42"}

import pyarrow.parquet as pq
import pytest

from gpt_trace_runner.superbench.exporter import SCHEMA, write_corpus_stream, _row


def raw_row(task_id, verdict):
    evaluation = None if verdict is None else {
        "verdict": verdict,
        "score": 1.0 if verdict == "pass" else 0.0,
        "details": {},
        "metadata": {},
    }
    return {
        "task_id": f"trajectory:{task_id}",
        "logical_task_id": task_id,
        "status": "completed",
        "evaluation": evaluation,
        "messages": [
            {"author": {"role": "user"}, "content": {"content_type": "text", "parts": ["q"]}},
            {
                "author": {"role": "assistant"},
                "content": {
                    "content_type": "thoughts",
                    "thoughts": [
                        {"summary": "Checking", "content": "Useful reasoning summary."},
                        {"summary": "Checked", "content": ""},
                    ],
                },
                "metadata": {"summary_type": "raw_cot"},
            },
            {
                "author": {"role": "assistant"},
                "channel": "final",
                "end_turn": True,
                "content": {"content_type": "text", "parts": ["a"]},
                "metadata": {"reasoning_title": "Answering"},
            },
        ],
        "app_provenance": [],
        "runtime_metadata": {},
        "dataset_metadata": {},
    }


async def rows():
    for verdict in ("pass", "fail", None):
        yield raw_row(str(verdict), verdict)


@pytest.mark.asyncio
async def test_corpus_keeps_pass_fail_and_unevaluated_rows(tmp_path):
    corpus = tmp_path / "corpus.parquet"
    assert await write_corpus_stream(rows(), corpus, row_group_size=1) == 3
    table = pq.read_table(corpus)
    assert table.schema == SCHEMA
    assert table.num_rows == 3
    first_messages = table.column("messages")[0].as_py()
    assert [message["kind"] for message in first_messages] == [
        "user_prompt",
        "reasoning_summary",
        "assistant_final",
    ]
    assert first_messages[1]["content"] == "Useful reasoning summary."
    assert first_messages[2]["reasoning_title"] == "Answering"


    assert [row["evaluation"]["verdict"] if row["evaluation"] else None for row in table.to_pylist()] == ["pass", "fail", None]
    assert all("raw_messages_json" in row and "validation_json" in row for row in table.to_pylist())


@pytest.mark.asyncio
async def test_corpus_preserves_failed_and_running_captures(tmp_path):
    async def source():
        for status in ("failed", "running", "completed"):
            raw = raw_row(status, None)
            raw["status"] = status
            raw["error_type"] = "CaptureInterrupted" if status == "failed" else None
            yield raw
    output = tmp_path / "all.parquet"
    assert await write_corpus_stream(source(), output) == 3
    data = pq.read_table(output).to_pylist()
    assert [row["execution_status"] for row in data] == ["failed", "running", "completed"]
    assert all(row["evaluation"] is None for row in data)


@pytest.mark.asyncio
async def test_invalid_or_duplicate_capture_preserves_previous_corpus(tmp_path):
    output = tmp_path / "corpus.parquet"
    assert await write_corpus_stream(rows(), output) == 3
    before = output.read_bytes()
    async def bad():
        yield raw_row("same", "pass")
        yield raw_row("same", "fail")
    with pytest.raises(ValueError, match="duplicate"):
        await write_corpus_stream(bad(), output)
    assert output.read_bytes() == before
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.asyncio
async def test_empty_export_has_the_canonical_schema(tmp_path):
    async def empty():
        if False: yield {}
    output = tmp_path / "empty.parquet"
    assert await write_corpus_stream(empty(), output) == 0
    table = pq.read_table(output)
    assert table.num_rows == 0 and table.schema == SCHEMA


def test_partial_tool_trajectory_is_kept_with_diagnostics():
    import json
    raw = raw_row("partial", None)
    raw["status"] = "failed"
    raw["messages"].append({"author": {"role": "assistant"}, "tool_calls": [
        {"id": "pending", "name": "unknown", "arguments": {"command": "true"}}]})
    row = _row(raw)
    assert row["execution_status"] == "failed" and row["evaluation"] is None
    assert row["messages"][-1]["tool_calls"][0]["id"] == "pending"
    assert json.loads(row["raw_messages_json"]) == raw["messages"]
    assert {x["kind"] for x in json.loads(row["validation_json"])["issues"]} >= {"undeclared_tool", "missing_result"}

import pyarrow.parquet as pq
import pytest

from gpt_trace_runner.superbench.exporter import SCHEMA, derive_sft, write_corpus_stream


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
            {"author": {"role": "assistant"}, "content": {"content_type": "text", "parts": ["a"]}},
        ],
        "app_provenance": [],
        "runtime_metadata": {},
        "dataset_metadata": {},
    }


async def rows():
    for verdict in ("pass", "fail", None):
        yield raw_row(str(verdict), verdict)


@pytest.mark.asyncio
async def test_corpus_keeps_all_rows_and_sft_defaults_to_pass(tmp_path):
    corpus = tmp_path / "corpus.parquet"
    assert await write_corpus_stream(rows(), corpus, row_group_size=1) == 3
    table = pq.read_table(corpus)
    assert table.schema == SCHEMA
    assert table.num_rows == 3

    sft = tmp_path / "sft.parquet"
    assert derive_sft(corpus, sft) == 1
    sft_table = pq.read_table(sft)
    assert sft_table.num_rows == 1
    assert sft_table.column("evaluation")[0].as_py()["verdict"] == "pass"


def test_sft_can_explicitly_select_failed_rows(tmp_path):
    # Build synchronously from a tiny valid corpus table for filter behavior.
    import pyarrow as pa
    from gpt_trace_runner.superbench.exporter import _row

    corpus = tmp_path / "corpus.parquet"
    table = pa.Table.from_pylist([_row(raw_row("p", "pass")), _row(raw_row("f", "fail"))], schema=SCHEMA)
    pq.write_table(table, corpus)
    output = tmp_path / "failed.parquet"
    assert derive_sft(corpus, output, verdicts=["fail"]) == 1
    assert pq.read_table(output).column("evaluation")[0].as_py()["verdict"] == "fail"

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from .normalize import normalize_messages, tools_from_provenance


MESSAGE = pa.struct([
    ("role", pa.string()),
    ("content", pa.string()),
    ("name", pa.string()),
    ("tool_call_id", pa.string()),
    ("tool_calls", pa.list_(pa.struct([
        ("id", pa.string()),
        ("name", pa.string()),
        ("arguments", pa.string()),
    ]))),
])

TOOL = pa.struct([
    ("app_id", pa.string()),
    ("name", pa.string()),
    ("description", pa.string()),
    ("input_schema", pa.string()),
    ("output_schema", pa.string()),
])

EVALUATION = pa.struct([
    ("verdict", pa.string()),
    ("score", pa.float64()),
    ("details_json", pa.string()),
    ("metadata_json", pa.string()),
])

SCHEMA = pa.schema([
    ("trajectory_id", pa.string()),
    ("task_id", pa.string()),
    ("messages", pa.list_(MESSAGE)),
    ("tools", pa.list_(TOOL)),
    ("execution_status", pa.string()),
    ("evaluation", EVALUATION),
    ("metadata_json", pa.string()),
])


def _json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _evaluation(raw: dict):
    value = raw.get("evaluation")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("storage row evaluation must be an object or null")
    verdict = value.get("verdict")
    if verdict not in {"pass", "fail"}:
        raise ValueError(f"invalid evaluation verdict: {verdict!r}")
    score = value.get("score")
    if score is not None and (
        not isinstance(score, (int, float)) or isinstance(score, bool)
    ):
        raise ValueError("evaluation score must be numeric or null")
    details = value.get("details", {})
    metadata = value.get("metadata", {})
    if not isinstance(details, dict) or not isinstance(metadata, dict):
        raise ValueError("evaluation details/metadata must be objects")
    return {
        "verdict": verdict,
        "score": float(score) if score is not None else None,
        "details_json": _json(details),
        "metadata_json": _json(metadata),
    }


def _row(raw: dict) -> dict:
    runtime = raw.get("runtime_metadata") or {}
    apps = raw.get("app_provenance") or []
    logical_task_id = raw.get("logical_task_id")
    if not isinstance(logical_task_id, str) or not logical_task_id:
        raise ValueError("storage row is missing logical_task_id")
    dataset_metadata = raw.get("dataset_metadata")
    if not isinstance(dataset_metadata, dict):
        raise ValueError("storage row dataset_metadata must be an object")

    messages = normalize_messages(
        raw.get("messages") or [],
        used_tool_calls=runtime.get("used_tool_calls") or [],
        app_provenance=apps,
    )
    tools = tools_from_provenance(apps)

    metadata = dict(dataset_metadata)
    metadata["runtime"] = runtime
    metadata["captured_at"] = raw.get("captured_at")

    return {
        "trajectory_id": str(raw.get("task_id") or ""),
        "task_id": logical_task_id,
        "messages": messages,
        "tools": tools,
        "execution_status": str(raw.get("status") or ""),
        "evaluation": _evaluation(raw),
        "metadata_json": _json(metadata),
    }


async def write_corpus_stream(
    rows: AsyncIterator[dict],
    output: Path,
    *,
    row_group_size: int = 512,
) -> int:
    """Write the single canonical ML corpus from storage rows."""
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    writer = None
    batch: list[dict] = []
    count = 0
    try:
        async for raw in rows:
            batch.append(_row(raw))
            if len(batch) >= row_group_size:
                table = pa.Table.from_pylist(batch, schema=SCHEMA)
                writer = writer or pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
                writer.write_table(table)
                count += len(batch)
                batch.clear()
        if batch:
            table = pa.Table.from_pylist(batch, schema=SCHEMA)
            writer = writer or pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
            writer.write_table(table)
            count += len(batch)
        if writer is None:
            writer = pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
        writer.close()
        writer = None
        tmp.replace(output)
        return count
    finally:
        if writer is not None:
            writer.close()
        if tmp.exists():
            tmp.unlink()


def _selected(row: dict, verdicts: set[str]) -> bool:
    if not verdicts:
        return True
    evaluation = row.get("evaluation")
    verdict = evaluation.get("verdict") if isinstance(evaluation, dict) else None
    key = verdict if verdict in {"pass", "fail"} else "unevaluated"
    return key in verdicts


def _validate_tool_structure(row: dict) -> None:
    trajectory = row.get("trajectory_id")
    declared = [tool.get("name") for tool in row.get("tools") or []]
    if any(not isinstance(name, str) or not name for name in declared):
        raise ValueError(f"{trajectory}: declared tool has an empty name")
    if len(set(declared)) != len(declared):
        raise ValueError(f"{trajectory}: duplicate declared tool names")
    declared_set = set(declared)

    calls: dict[str, tuple[str, int]] = {}
    consumed: set[str] = set()
    for index, message in enumerate(row.get("messages") or []):
        for call in message.get("tool_calls") or []:
            call_id = str(call.get("id") or "")
            name = str(call.get("name") or "")
            if not call_id:
                raise ValueError(f"{trajectory}: tool call without id at message {index}")
            if call_id in calls:
                raise ValueError(f"{trajectory}: duplicate tool call id {call_id!r}")
            if name not in declared_set:
                raise ValueError(
                    f"{trajectory}: tool call {call_id!r} references undeclared tool {name!r}"
                )
            calls[call_id] = (name, index)

        if message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not call_id:
                raise ValueError(
                    f"{trajectory}: tool result without tool_call_id at message {index}"
                )
            if call_id not in calls:
                raise ValueError(
                    f"{trajectory}: tool result references unknown/non-prior call {call_id!r}"
                )
            if call_id in consumed:
                raise ValueError(f"{trajectory}: duplicate result for tool call {call_id!r}")
            expected_name, call_index = calls[call_id]
            if call_index >= index:
                raise ValueError(f"{trajectory}: tool result precedes its call {call_id!r}")
            result_name = message.get("name")
            if result_name and result_name != expected_name:
                raise ValueError(
                    f"{trajectory}: tool result name {result_name!r} does not match "
                    f"call {expected_name!r}"
                )
            consumed.add(call_id)

    missing = set(calls) - consumed
    if missing:
        raise ValueError(f"{trajectory}: tool calls without results: {sorted(missing)!r}")


def derive_sft(
    corpus: Path,
    output: Path,
    *,
    verdicts: Iterable[str] = (),
    row_group_size: int = 512,
) -> int:
    """Derive a training view from corpus.parquet; never read storage directly."""
    selected_verdicts = {str(value) for value in verdicts}
    invalid = selected_verdicts - {"pass", "fail", "unevaluated"}
    if invalid:
        raise ValueError(f"unknown verdict filter(s): {sorted(invalid)!r}")

    source = pq.ParquetFile(corpus)
    if source.schema_arrow != SCHEMA:
        raise ValueError("input Parquet is not a Superbench corpus schema")

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    writer = None
    batch: list[dict] = []
    count = 0
    try:
        for record_batch in source.iter_batches(batch_size=row_group_size):
            for row in pa.Table.from_batches([record_batch], schema=SCHEMA).to_pylist():
                if not _selected(row, selected_verdicts):
                    continue
                _validate_tool_structure(row)
                batch.append(row)
                if len(batch) >= row_group_size:
                    table = pa.Table.from_pylist(batch, schema=SCHEMA)
                    writer = writer or pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
                    writer.write_table(table)
                    count += len(batch)
                    batch.clear()
        if batch:
            table = pa.Table.from_pylist(batch, schema=SCHEMA)
            writer = writer or pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
            writer.write_table(table)
            count += len(batch)
        if writer is None:
            writer = pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
        writer.close()
        writer = None
        tmp.replace(output)
        return count
    finally:
        if writer is not None:
            writer.close()
        if tmp.exists():
            tmp.unlink()

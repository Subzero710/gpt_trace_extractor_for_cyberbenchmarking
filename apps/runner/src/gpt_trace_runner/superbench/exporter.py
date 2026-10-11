from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from .normalize import normalize_messages, tools_from_provenance


MESSAGE = pa.struct([
    ("role", pa.string()),
    ("kind", pa.string()),
    ("content", pa.string()),
    ("reasoning_title", pa.string()),
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
    ("raw_messages_json", pa.string()),
    ("app_provenance_json", pa.string()),
    ("validation_json", pa.string()),
])


def _json(value) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
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
        not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score)
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
    if not isinstance(raw, dict):
        raise ValueError("storage row must be an object")
    for key in ("task_id", "logical_task_id", "status"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise ValueError("storage row is missing " + key)
    messages_raw = raw.get("messages")
    runtime = raw.get("runtime_metadata")
    apps = raw.get("app_provenance")
    dataset = raw.get("dataset_metadata")
    if not isinstance(messages_raw, list) or any(not isinstance(x, dict) for x in messages_raw):
        raise ValueError("storage row messages must be an array of objects")
    if not isinstance(runtime, dict) or not isinstance(apps, list) or any(not isinstance(x, dict) for x in apps):
        raise ValueError("storage row runtime/App provenance has the wrong type")
    if not isinstance(dataset, dict):
        raise ValueError("storage row dataset_metadata must be an object")
    used = runtime.get("used_tool_calls", [])
    if not isinstance(used, list) or any(not isinstance(x, dict) for x in used):
        raise ValueError("storage row used_tool_calls must be an array of objects")
    messages = normalize_messages(messages_raw, used_tool_calls=used, app_provenance=apps)
    tools = tools_from_provenance(apps)
    metadata = dict(dataset)
    metadata["runtime"] = runtime
    metadata["captured_at"] = raw.get("captured_at")
    metadata["storage"] = {key: raw.get(key) for key in (
        "conversation_id", "attempt", "runner_id", "task_fingerprint", "error_type",
        "error_message", "started_at", "created_at", "updated_at")}
    row = {"trajectory_id": raw["task_id"], "task_id": raw["logical_task_id"],
        "messages": messages, "tools": tools, "execution_status": raw["status"],
        "evaluation": _evaluation(raw), "metadata_json": _json(metadata),
        # Normalization never destroys the captured source or its provenance.
        "raw_messages_json": _json(messages_raw), "app_provenance_json": _json(apps)}
    row["validation_json"] = _json(_validate_tool_structure(row))
    return row


async def write_corpus_stream(rows: AsyncIterator[dict], output: Path, *, row_group_size: int = 512) -> int:
    """Atomic, unfiltered export; an invalid row aborts instead of being skipped."""
    if type(row_group_size) is not int or row_group_size < 1:
        raise ValueError("row_group_size must be positive")
    output = Path(output).absolute()
    for parent in (output, *output.parents):
        if parent.is_symlink():
            raise ValueError("symlink in export destination")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + output.name + ".", suffix=".tmp", dir=output.parent)
    os.close(fd)
    tmp, writer, batch, count, seen = Path(name), None, [], 0, set()
    try:
        writer = pq.ParquetWriter(tmp, SCHEMA, compression="zstd")
        async for raw in rows:
            row = _row(raw)
            if row["trajectory_id"] in seen:
                raise ValueError("duplicate trajectory_id: " + row["trajectory_id"])
            seen.add(row["trajectory_id"])
            batch.append(row)
            if len(batch) >= row_group_size:
                writer.write_table(pa.Table.from_pylist(batch, schema=SCHEMA))
                count += len(batch)
                batch.clear()
        if batch:
            writer.write_table(pa.Table.from_pylist(batch, schema=SCHEMA))
            count += len(batch)
        writer.close()
        writer = None
        actual = pq.ParquetFile(tmp)
        if actual.schema_arrow != SCHEMA or actual.metadata.num_rows != count:
            raise ValueError("written corpus schema/row count mismatch")
        del actual
        with tmp.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(tmp, output)
        fd = os.open(output.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        return count
    finally:
        if writer is not None:
            writer.close()
        tmp.unlink(missing_ok=True)




def _validate_tool_structure(row: dict) -> dict:
    """Report partial/ambiguous tool traces without discarding their trajectory."""
    declared = [tool.get("name") for tool in row.get("tools", [])]
    issues = []
    if any(not isinstance(name, str) or not name for name in declared):
        issues.append({"kind": "empty_declared_tool"})
    if len(set(declared)) != len(declared):
        issues.append({"kind": "duplicate_declared_tool"})
    calls, consumed = {}, set()
    for index, message in enumerate(row.get("messages", [])):
        for call in message.get("tool_calls", []):
            cid, name = call.get("id"), call.get("name")
            if not cid or cid in calls:
                issues.append({"kind": "missing_or_duplicate_call_id", "call_id": cid, "message": index})
                continue
            if name not in declared:
                issues.append({"kind": "undeclared_tool", "call_id": cid, "name": name})
            calls[cid] = (name, index)
        if message.get("role") == "tool":
            cid = message.get("tool_call_id")
            if not cid or cid not in calls or calls[cid][1] >= index:
                issues.append({"kind": "unmatched_result", "call_id": cid, "message": index})
            elif cid in consumed:
                issues.append({"kind": "duplicate_result", "call_id": cid, "message": index})
            else:
                if message.get("name") and message["name"] != calls[cid][0]:
                    issues.append({"kind": "result_name_mismatch", "call_id": cid, "message": index})
                consumed.add(cid)
    for cid in sorted(set(calls) - consumed):
        issues.append({"kind": "missing_result", "call_id": cid})
    return {"complete_tool_pairs": not issues, "issues": issues}



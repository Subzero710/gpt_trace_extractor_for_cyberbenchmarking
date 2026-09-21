from __future__ import annotations
import json
from pathlib import Path
from collections.abc import AsyncIterator
import pyarrow as pa
import pyarrow.parquet as pq
from .normalize import normalize_messages, sanitize, tools_from_provenance

MESSAGE = pa.struct([
    ("role",pa.string()),("content",pa.string()),("name",pa.string()),
    ("tool_call_id",pa.string()),
    ("tool_calls",pa.list_(pa.struct([
        ("id",pa.string()),("name",pa.string()),("arguments",pa.string())
    ]))),
    ("content_type",pa.string()),("metadata_json",pa.string())
])
TOOL = pa.struct([
    ("app_id",pa.string()),("name",pa.string()),("description",pa.string()),
    ("input_schema",pa.string()),("output_schema",pa.string())
])
SCHEMA = pa.schema([
    ("trajectory_id",pa.string()),("canonical_task_id",pa.string()),
    ("campaign_id",pa.string()),
    ("source",pa.struct([
        ("benchmark",pa.string()),("version",pa.string()),("task_id",pa.string()),
        ("repository",pa.string()),("commit",pa.string()),("license",pa.string())
    ])),
    ("teacher",pa.struct([
        ("expected_model",pa.string()),("observed_model",pa.string())
    ])),
    ("run_status",pa.string()),("success",pa.bool_()),("reward",pa.float64()),
    ("native_result",pa.map_(pa.string(),pa.string())),
    ("messages",pa.list_(MESSAGE)),("tools",pa.list_(TOOL)),
    ("app_provenance",pa.list_(pa.struct([
        ("app_id",pa.string()),("ui_name",pa.string()),("version",pa.string()),
        ("manifest_sha256",pa.string())
    ]))),
    ("runtime_provenance",pa.map_(pa.string(),pa.string())),
    ("task_metadata",pa.map_(pa.string(),pa.string())),
    ("sanitization_redactions",pa.int32()),
])


def _map(value):
    return [
        (str(key), json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        for key, item in sorted((value or {}).items())
    ]


def _row(raw):
    clean, redactions = sanitize(raw)
    runtime = clean.get("runtime_metadata") or {}
    apps = clean.get("app_provenance") or []
    messages = normalize_messages(
        clean.get("messages") or [],
        used_tool_calls=runtime.get("used_tool_calls") or [],
        app_provenance=apps,
    )
    tools = tools_from_provenance(apps)
    return {
        "trajectory_id": str(clean.get("task_id")),
        "canonical_task_id": clean.get("canonical_task_id"),
        "campaign_id": clean.get("campaign_id"),
        "source": {
            "benchmark": clean.get("source_benchmark"),
            "version": clean.get("source_benchmark_version"),
            "task_id": clean.get("source_task_id"),
            "repository": clean.get("upstream_repository"),
            "commit": clean.get("upstream_commit"),
            "license": clean.get("source_license"),
        },
        "teacher": {
            "expected_model": (clean.get("teacher_metadata") or {}).get("expected_model"),
            "observed_model": runtime.get("model_slug"),
        },
        "run_status": clean.get("run_status") or (
            "completed" if clean.get("status") == "completed" else "infra_failed"
        ),
        "success": clean.get("success"),
        "reward": clean.get("reward"),
        "native_result": _map(clean.get("native_result")),
        "messages": messages,
        "tools": tools,
        "app_provenance": [
            {
                "app_id": str(app.get("app_id", "")),
                "ui_name": str(app.get("ui_name", "")),
                "version": str(app.get("version", "")),
                "manifest_sha256": str(app.get("tool_manifest_sha256", "")),
            }
            for app in apps
        ],
        "runtime_provenance": _map(runtime),
        "task_metadata": _map(clean.get("source_metadata")),
        "sanitization_redactions": redactions,
    }


def _validate_sft_row(row: dict) -> None:
    trajectory = row.get("trajectory_id")
    if row.get("run_status") != "completed" or row.get("success") is not True:
        raise ValueError(f"{trajectory}: SFT row must be completed with success=true")

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
                raise ValueError(f"{trajectory}: tool result without tool_call_id at message {index}")
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
        raise ValueError(
            f"{trajectory}: tool calls without results: {sorted(missing)!r}"
        )


async def write_parquet_stream(
    rows: AsyncIterator[dict],
    output: Path,
    *,
    sft: bool = False,
    row_group_size: int = 512,
):
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    writer = None
    batch = []
    count = 0
    try:
        async for raw in rows:
            if sft and not (
                raw.get("status") == "completed" and raw.get("success") is True
            ):
                continue
            row = _row(raw)
            if sft:
                _validate_sft_row(row)
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

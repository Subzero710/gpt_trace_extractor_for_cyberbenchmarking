from __future__ import annotations
import json
from pathlib import Path
from collections.abc import AsyncIterator
import pyarrow as pa
import pyarrow.parquet as pq
from .normalize import normalize_messages, sanitize, tools_from_provenance
MESSAGE = pa.struct([("role",pa.string()),("content",pa.string()),("name",pa.string()),("tool_call_id",pa.string()),("tool_calls",pa.list_(pa.struct([("id",pa.string()),("name",pa.string()),("arguments",pa.string())]))),("content_type",pa.string()),("metadata_json",pa.string())])
TOOL = pa.struct([("app_id",pa.string()),("name",pa.string()),("description",pa.string()),("input_schema",pa.string()),("output_schema",pa.string())])
SCHEMA = pa.schema([("trajectory_id",pa.string()),("canonical_task_id",pa.string()),("campaign_id",pa.string()),("source",pa.struct([("benchmark",pa.string()),("version",pa.string()),("task_id",pa.string()),("repository",pa.string()),("commit",pa.string()),("license",pa.string())])),("teacher",pa.struct([("expected_model",pa.string()),("observed_model",pa.string())])),("run_status",pa.string()),("success",pa.bool_()),("reward",pa.float64()),("native_result",pa.map_(pa.string(),pa.string())),("messages",pa.list_(MESSAGE)),("tools",pa.list_(TOOL)),("app_provenance",pa.list_(pa.struct([("app_id",pa.string()),("ui_name",pa.string()),("version",pa.string()),("manifest_sha256",pa.string())]))),("runtime_provenance",pa.map_(pa.string(),pa.string())),("task_metadata",pa.map_(pa.string(),pa.string())),("sanitization_redactions",pa.int32())])
def _map(d): return [(str(k),json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))) for k,v in sorted((d or {}).items())]
def _row(r):
    clean,n=sanitize(r); msgs=normalize_messages(clean.get("messages") or []); tools=tools_from_provenance(clean.get("app_provenance") or [])
    return {"trajectory_id":str(clean.get("task_id")),"canonical_task_id":clean.get("canonical_task_id"),"campaign_id":clean.get("campaign_id"),"source":{"benchmark":clean.get("source_benchmark"),"version":clean.get("source_benchmark_version"),"task_id":clean.get("source_task_id"),"repository":clean.get("upstream_repository"),"commit":clean.get("upstream_commit"),"license":clean.get("source_license")},"teacher":{"expected_model":(clean.get("teacher_metadata") or {}).get("expected_model"),"observed_model":(clean.get("runtime_metadata") or {}).get("model_slug")},"run_status":clean.get("run_status") or ("completed" if clean.get("status")=="completed" else "infra_failed"),"success":clean.get("success"),"reward":clean.get("reward"),"native_result":_map(clean.get("native_result")),"messages":msgs,"tools":tools,"app_provenance":[{"app_id":str(a.get("app_id","")),"ui_name":str(a.get("ui_name","")),"version":str(a.get("version","")),"manifest_sha256":str(a.get("tool_manifest_sha256",""))} for a in clean.get("app_provenance") or []],"runtime_provenance":_map(clean.get("runtime_metadata")),"task_metadata":_map(clean.get("source_metadata")),"sanitization_redactions":n}
async def write_parquet_stream(rows: AsyncIterator[dict], output: Path, *, sft=False, row_group_size=512):
    output.parent.mkdir(parents=True,exist_ok=True); tmp=output.with_suffix(output.suffix+".tmp"); writer=None; batch=[]; count=0
    try:
        async for r in rows:
            if sft and not (r.get("status")=="completed" and r.get("success") is True): continue
            batch.append(_row(r))
            if len(batch)>=row_group_size:
                table=pa.Table.from_pylist(batch,schema=SCHEMA); writer=writer or pq.ParquetWriter(tmp,SCHEMA,compression="zstd"); writer.write_table(table); count+=len(batch); batch.clear()
        if batch:
            table=pa.Table.from_pylist(batch,schema=SCHEMA); writer=writer or pq.ParquetWriter(tmp,SCHEMA,compression="zstd"); writer.write_table(table); count+=len(batch)
        if writer is None: writer=pq.ParquetWriter(tmp,SCHEMA,compression="zstd")
        writer.close(); writer=None; tmp.replace(output); return count
    finally:
        if writer is not None: writer.close()
        if tmp.exists(): tmp.unlink()

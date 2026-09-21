import pyarrow.parquet as pq
import pytest
from gpt_trace_runner.superbench.exporter import write_parquet_stream,SCHEMA
def row(success): return {"task_id":"x","canonical_task_id":"c","campaign_id":"d","status":"completed","run_status":"completed","success":success,"reward":1.0 if success else 0.0,"native_result":{"stage":success},"messages":[{"author":{"role":"user"},"content":{"content_type":"text","parts":["q"]}},{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["a"]}}],"app_provenance":[{"app_id":"code","tool_manifest":{"tools":[{"name":"exec","inputSchema":{"type":"object"},"outputSchema":{"type":"object"}}]}}],"runtime_metadata":{},"source_metadata":{}}
async def rows():
 for x in (row(True),row(False)): yield x
@pytest.mark.asyncio
async def test_parquet_stream_nested_and_sft(tmp_path):
 p=tmp_path/"c.parquet"; assert await write_parquet_stream(rows(),p,row_group_size=1)==2; t=pq.read_table(p); assert t.schema==SCHEMA; assert t.num_rows==2; assert t.column("messages")[0].as_py()[0]["role"]=="user"; assert isinstance(t.column("tools")[0].as_py()[0]["input_schema"],str)
 s=tmp_path/"s.parquet"; assert await write_parquet_stream(rows(),s,sft=True,row_group_size=1)==1; assert pq.read_table(s).num_rows==1

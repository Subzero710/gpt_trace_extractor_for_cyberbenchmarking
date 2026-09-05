import json
from pathlib import Path
import pytest
from gpt_trace_runner.benchmark import load_benchmark
from gpt_trace_runner.exceptions import BenchmarkError

def test_load_benchmark(tmp_path: Path) -> None:
    artifact = tmp_path / "repo.zip"; artifact.write_bytes(b"zip")
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id":"t1","prompt":"inspect","attachments":["repo.zip"]}) + "\n")
    tasks = load_benchmark(manifest)
    assert tasks[0].attachments == (artifact.resolve(),)

def test_duplicate_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    row = json.dumps({"task_id":"dup","prompt":"x","attachments":[]})
    manifest.write_text(row + "\n" + row + "\n")
    with pytest.raises(BenchmarkError): load_benchmark(manifest)

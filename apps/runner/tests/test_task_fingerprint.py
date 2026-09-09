from dataclasses import replace
from pathlib import Path

from gpt_trace_runner.benchmark import load_benchmark
from gpt_trace_runner.models import BenchmarkTask, task_fingerprint
from registry_helpers import make_registry


def test_task_fingerprint_changes_with_exact_prompt_and_attachment(tmp_path: Path) -> None:
    a = BenchmarkTask("t", "x", ())
    b = BenchmarkTask("t", " x", ())
    assert task_fingerprint(a) != task_fingerprint(b)
    path = tmp_path / "a.txt"
    path.write_text("one")
    first = task_fingerprint(BenchmarkTask("t", "x", (path,)))
    path.write_text("two")
    assert first != task_fingerprint(BenchmarkTask("t", "x", (path,)))


def test_fingerprint_uses_canonical_contract_not_mutable_ui_name(tmp_path: Path) -> None:
    registry = make_registry(tmp_path, github_ui="First UI name")
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text('{"task_id":"t","prompt":"x","tools":[{"id":"github","required":true}]}\n')
    task = load_benchmark(manifest, registry=registry)[0]
    renamed = replace(task, tools=(replace(task.tools[0], ui_name="Second UI name"),))
    assert task_fingerprint(task) == task_fingerprint(renamed)
    changed_hash = replace(task, tools=(replace(task.tools[0], manifest_sha256="f" * 64),))
    assert task_fingerprint(task) != task_fingerprint(changed_hash)
    changed_version = replace(task, tools=(replace(task.tools[0], version="9.0.0"),))
    assert task_fingerprint(task) != task_fingerprint(changed_version)

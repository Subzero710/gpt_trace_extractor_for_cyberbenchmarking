from pathlib import Path

from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool, task_fingerprint


def test_task_fingerprint_changes_with_exact_prompt(tmp_path: Path) -> None:
    a = BenchmarkTask("t", "x", ())
    b = BenchmarkTask("t", " x", ())
    assert task_fingerprint(a) != task_fingerprint(b)


def test_task_fingerprint_changes_with_attachment_content(tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("one")
    first = task_fingerprint(BenchmarkTask("t", "x", (p,)))
    p.write_text("two")
    second = task_fingerprint(BenchmarkTask("t", "x", (p,)))
    assert first != second


def test_task_fingerprint_changes_with_tool_contract() -> None:
    a = BenchmarkTask("t", "x", (), (BenchmarkTool("app", "GitHub", False),))
    b = BenchmarkTask("t", "x", (), (BenchmarkTool("app", "GitHub", True),))
    assert task_fingerprint(a) != task_fingerprint(b)

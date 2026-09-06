from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpt_trace_runner.benchmark import load_benchmark
from gpt_trace_runner.exceptions import BenchmarkError


def test_load_relative_attachment_from_tasks_root(
    tmp_path: Path,
) -> None:
    tasks_root = tmp_path / "tasks"
    tasks_root.mkdir()
    artifact = tasks_root / "case" / "repo.zip"
    artifact.parent.mkdir()
    artifact.write_bytes(b"zip")

    manifest = tmp_path / "benchmarks" / "benchmark.jsonl"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "attachments": ["case/repo.zip"],
                "tools": [],
            }
        )
        + "\n"
    )

    task = load_benchmark(
        manifest,
        tasks_root=tasks_root,
    )[0]
    assert task.attachments == (artifact.resolve(),)


def test_tasks_prefix_is_accepted(tmp_path: Path) -> None:
    tasks_root = tmp_path / "tasks"
    tasks_root.mkdir()
    artifact = tasks_root / "case" / "repo.zip"
    artifact.parent.mkdir()
    artifact.write_bytes(b"zip")

    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "attachments": ["tasks/case/repo.zip"],
            }
        )
        + "\n"
    )

    task = load_benchmark(
        manifest,
        tasks_root=tasks_root,
    )[0]
    assert task.attachments == (artifact.resolve(),)


def test_attachment_escape_is_rejected(tmp_path: Path) -> None:
    tasks_root = tmp_path / "tasks"
    tasks_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")

    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "attachments": ["../outside.txt"],
            }
        )
        + "\n"
    )

    with pytest.raises(BenchmarkError, match="escapes TASKS_ROOT"):
        load_benchmark(
            manifest,
            tasks_root=tasks_root,
        )


def test_tools_support_string_and_object(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "attachments": [],
                "tools": [
                    "Github (mosaic)",
                    {
                        "type": "app",
                        "name": "Zotero",
                        "required": True,
                    },
                ],
            }
        )
        + "\n"
    )

    task = load_benchmark(manifest)[0]
    assert task.tools[0].name == "Github (mosaic)"
    assert task.tools[0].required is False
    assert task.tools[1].name == "Zotero"
    assert task.tools[1].required is True


def test_unsupported_tool_type_is_rejected(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "attachments": [],
                "tools": [
                    {"type": "function", "name": "shell"},
                ],
            }
        )
        + "\n"
    )

    with pytest.raises(BenchmarkError, match="unsupported tool type"):
        load_benchmark(manifest)


def test_required_must_be_boolean(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "task_id": "t1",
                "prompt": "inspect",
                "tools": [
                    {
                        "type": "app",
                        "name": "GitHub",
                        "required": "yes",
                    }
                ],
            }
        )
        + "\n"
    )

    with pytest.raises(BenchmarkError, match="must be a boolean"):
        load_benchmark(manifest)


def test_duplicate_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    row = json.dumps(
        {
            "task_id": "dup",
            "prompt": "x",
            "attachments": [],
        }
    )
    manifest.write_text(row + "\n" + row + "\n")

    with pytest.raises(BenchmarkError):
        load_benchmark(manifest)


def test_prompt_is_preserved_exactly(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": "t1", "prompt": "  exact prompt  ", "attachments": []}) + "\n")
    assert load_benchmark(manifest)[0].prompt == "  exact prompt  "


def test_invalid_task_id_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": "../bad", "prompt": "x", "attachments": []}) + "\n")
    with pytest.raises(BenchmarkError, match="unsupported characters"):
        load_benchmark(manifest)


def test_empty_manifest_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text("\n")
    with pytest.raises(BenchmarkError, match="empty"):
        load_benchmark(manifest)


def test_null_task_id_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": None, "prompt": "x", "attachments": []}) + "\n")
    with pytest.raises(BenchmarkError, match="task_id must be a string"):
        load_benchmark(manifest)


def test_whitespace_only_prompt_is_rejected_without_stripping_valid_prompts(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": "t", "prompt": "   ", "attachments": []}) + "\n")
    with pytest.raises(BenchmarkError, match="missing prompt"):
        load_benchmark(manifest)


def test_duplicate_tools_are_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": "t", "prompt": "x", "tools": ["GitHub", "github"]}) + "\n")
    with pytest.raises(BenchmarkError, match="duplicate tool"):
        load_benchmark(manifest)


def test_reserved_dot_task_id_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text(json.dumps({"task_id": "..", "prompt": "x"}) + "\n")
    with pytest.raises(BenchmarkError, match="reserved task_id"):
        load_benchmark(manifest)

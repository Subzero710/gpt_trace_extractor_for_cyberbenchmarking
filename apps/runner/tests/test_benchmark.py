from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpt_trace_runner.benchmark import load_benchmark
from gpt_trace_runner.exceptions import AppRegistryError, BenchmarkError
from registry_helpers import make_registry


def write_manifest(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value) + "\n")
    return path


def test_load_relative_attachment_and_preserve_prompt(tmp_path: Path) -> None:
    tasks_root = tmp_path / "tasks"
    artifact = tasks_root / "case" / "repo.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"zip")
    manifest = write_manifest(tmp_path / "benchmark.jsonl", {
        "task_id": "t1", "prompt": "  inspect exactly  ",
        "attachments": ["case/repo.zip"], "tools": [],
    })
    task = load_benchmark(manifest, tasks_root=tasks_root)[0]
    assert task.prompt == "  inspect exactly  "
    assert task.attachments == (artifact.resolve(),)


def test_logical_ids_and_legacy_configured_name_resolve(tmp_path: Path) -> None:
    registry = make_registry(tmp_path, github_ui="Current GitHub")
    manifest = write_manifest(tmp_path / "benchmark.jsonl", {
        "task_id": "t1", "prompt": "inspect", "attachments": [],
        "tools": [
            {"type": "app", "id": "github", "required": True},
            "Browser",
        ],
    })
    task = load_benchmark(manifest, registry=registry)[0]
    assert [(tool.app_id, tool.ui_name, tool.required) for tool in task.tools] == [
        ("github", "Current GitHub", True),
        ("browser", "Browser", False),
    ]


def test_unknown_app_is_rejected_early(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path / "benchmark.jsonl", {"task_id": "t", "prompt": "x", "tools": ["Unknown"]})
    with pytest.raises(AppRegistryError, match="unknown"):
        load_benchmark(manifest, registry=make_registry(tmp_path))


def test_attachment_escape_and_duplicate_basenames_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "tasks"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("x")
    manifest = write_manifest(tmp_path / "bad.jsonl", {"task_id": "t", "prompt": "x", "attachments": ["../outside"]})
    with pytest.raises(BenchmarkError, match="escapes"):
        load_benchmark(manifest, tasks_root=root)
    for folder in ("a", "b"):
        path = root / folder / "same.txt"
        path.parent.mkdir()
        path.write_text(folder)
    manifest = write_manifest(tmp_path / "dup.jsonl", {"task_id": "t", "prompt": "x", "attachments": ["a/same.txt", "b/same.txt"]})
    with pytest.raises(BenchmarkError, match="basenames"):
        load_benchmark(manifest, tasks_root=root)


@pytest.mark.parametrize("value, match", [
    ({"task_id": None, "prompt": "x"}, "task_id must be"),
    ({"task_id": "../bad", "prompt": "x"}, "unsupported characters"),
    ({"task_id": "t", "prompt": "   "}, "missing prompt"),
    ({"task_id": "t", "prompt": "x", "tools": [{"type": "function", "name": "x"}]}, "unsupported tool type"),
    ({"task_id": "t", "prompt": "x", "tools": [{"id": "browser", "required": "yes"}]}, "must be a boolean"),
])
def test_invalid_manifest_values(tmp_path: Path, value: dict, match: str) -> None:
    manifest = write_manifest(tmp_path / "benchmark.jsonl", value)
    with pytest.raises(BenchmarkError, match=match):
        load_benchmark(manifest, registry=make_registry(tmp_path))


def test_duplicate_task_and_logical_app_are_rejected(tmp_path: Path) -> None:
    row = {"task_id": "dup", "prompt": "x", "tools": ["browser", "Browser"]}
    manifest = write_manifest(tmp_path / "apps.jsonl", row)
    with pytest.raises(BenchmarkError, match="duplicate logical App"):
        load_benchmark(manifest, registry=make_registry(tmp_path))
    manifest.write_text(json.dumps({"task_id": "dup", "prompt": "x"}) + "\n" + json.dumps({"task_id": "dup", "prompt": "y"}) + "\n")
    with pytest.raises(BenchmarkError, match="duplicate task_id"):
        load_benchmark(manifest)


def test_empty_manifest_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "benchmark.jsonl"
    manifest.write_text("\n")
    with pytest.raises(BenchmarkError, match="empty"):
        load_benchmark(manifest)

from __future__ import annotations

import hashlib
import os
import re
import shutil
import string
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pyarrow.parquet as pq

from ...models import CapturedConversation
from ..models import EvaluationResult, TaskSpec
from .base import BenchmarkAdapter, PreparedBenchmarkContext


GAIA_REPO_ID = "gaia-benchmark/GAIA"
GAIA_REVISION = "682dd723ee1e1697e00360edccf2366dc8418dd9"
GAIA_YEAR = "2023"
GAIA_SPLIT = "validation"
GAIA_LEVEL = 1
GAIA_METADATA_FILE = f"{GAIA_YEAR}/{GAIA_SPLIT}/metadata.level{GAIA_LEVEL}.parquet"
GAIA_SOURCE_URL = "https://huggingface.co/datasets/gaia-benchmark/GAIA"
GAIA_PAPER = "https://arxiv.org/abs/2311.12983"

ANSWER_INSTRUCTION = (
    "Give the final answer as briefly as possible. End your response with exactly "
    "'FINAL ANSWER: <answer>'."
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_number(value: str) -> float:
    for char in ("$", "%", ","):
        value = value.replace(char, "")
    try:
        return float(value)
    except ValueError:
        return float("inf")


def _normalize_string(value: str, *, remove_punctuation: bool = True) -> str:
    no_spaces = re.sub(r"\s", "", value)
    if remove_punctuation:
        return no_spaces.lower().translate(str.maketrans("", "", string.punctuation))
    return no_spaces.lower()


def _is_float(value: str) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def gaia_question_scorer(model_answer: str | None, ground_truth: str) -> bool:
    """GAIA quasi-exact-match normalization/evaluation."""
    if model_answer is None:
        model_answer = "None"

    if _is_float(ground_truth):
        return _normalize_number(model_answer) == float(ground_truth)

    if any(char in ground_truth for char in (",", ";")):
        gt_elements = re.split(r"[,;]", ground_truth)
        answer_elements = re.split(r"[,;]", model_answer)
        if len(gt_elements) != len(answer_elements):
            return False
        for answer_element, gt_element in zip(answer_elements, gt_elements, strict=True):
            if _is_float(gt_element):
                if _normalize_number(answer_element) != float(gt_element):
                    return False
            elif _normalize_string(
                answer_element, remove_punctuation=False
            ) != _normalize_string(gt_element, remove_punctuation=False):
                return False
        return True

    return _normalize_string(model_answer) == _normalize_string(ground_truth)


def _message_role(message: dict[str, Any]) -> str:
    author = message.get("author")
    if isinstance(author, dict) and isinstance(author.get("role"), str):
        return author["role"]
    return str(message.get("role") or "")


def _content_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(part for item in value if (part := _content_text(item)))
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        if "parts" in value:
            return _content_text(value.get("parts"))
        if isinstance(value.get("content"), str):
            return value["content"]
        return ""
    return str(value)


def _model_answer(captured: CapturedConversation) -> str:
    final_text = ""
    for message in reversed(captured.messages):
        if isinstance(message, dict) and _message_role(message) == "assistant":
            final_text = _content_text(message.get("content")).strip()
            if final_text:
                break
    if not final_text:
        return ""

    parts = re.split(r"FINAL\s+ANSWER\s*:\s*", final_text, flags=re.IGNORECASE)
    return parts[-1].strip() if len(parts) > 1 else final_text


class GAIAAdapter(BenchmarkAdapter):
    """Pinned GAIA 2023 Level-1 validation adapter."""

    adapter_id = "gaia"
    adapter_version = "4"

    def __init__(self) -> None:
        self._answers: dict[str, str] = {}
        self._materialized_roots: dict[str, Path] = {}

    @property
    def revision_root(self) -> Path:
        return self.source_root / GAIA_REVISION

    def _local_path(self, filename: str) -> Path:
        candidate = self.revision_root / filename
        resolved_root = self.revision_root.resolve()
        resolved = candidate.resolve()
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise ValueError(f"invalid GAIA source path: {filename!r}")
        return candidate

    @staticmethod
    def _source_token() -> str:
        token = os.environ.get("BENCHMARK_SOURCE_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "This source is gated. Set BENCHMARK_SOURCE_TOKEN for the fetch "
                "process after obtaining upstream access."
            )
        return token

    @staticmethod
    def _remote_url(filename: str) -> str:
        encoded_path = "/".join(quote(part, safe="") for part in filename.split("/"))
        return (
            f"https://huggingface.co/datasets/{GAIA_REPO_ID}/resolve/"
            f"{GAIA_REVISION}/{encoded_path}"
        )

    def _fetch_file(self, filename: str) -> Path:
        destination = self._local_path(filename)
        if destination.is_file():
            return destination

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".part")
        headers = {"Authorization": f"Bearer {self._source_token()}"}

        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            with client.stream("GET", self._remote_url(filename), headers=headers) as response:
                response.raise_for_status()
                with temporary.open("wb") as handle:
                    for chunk in response.iter_bytes():
                        handle.write(chunk)

        temporary.replace(destination)
        return destination

    def _require_file(self, filename: str) -> Path:
        path = self._local_path(filename)
        if not path.is_file():
            raise RuntimeError(
                f"benchmark source file is missing: {filename}. "
                "Run the generic superbench fetch command for adapter 'gaia'."
            )
        return path

    def fetch(self) -> None:
        metadata = self._fetch_file(GAIA_METADATA_FILE)
        rows = pq.read_table(metadata).to_pylist()
        for row in rows:
            value = row.get("file_path")
            if value is None:
                continue
            file_path = str(value).strip()
            if file_path:
                self._fetch_file(file_path)

    def discover_tasks(self) -> list[TaskSpec]:
        rows = pq.read_table(self._require_file(GAIA_METADATA_FILE)).to_pylist()
        tasks: list[TaskSpec] = []
        answers: dict[str, str] = {}

        for row in rows:
            upstream_id = str(row["task_id"]).strip()
            question = str(row["Question"]).strip()
            ground_truth = row.get("Final answer")
            level = int(row["Level"])
            file_path_value = row.get("file_path")
            file_path = (
                str(file_path_value).strip()
                if file_path_value is not None and str(file_path_value).strip()
                else None
            )
            source_file_sha256 = (
                _sha256_file(self._require_file(file_path)) if file_path else None
            )

            if not upstream_id or not question:
                raise ValueError("GAIA row has an empty task_id or Question")
            if level != GAIA_LEVEL:
                raise ValueError(
                    f"GAIA metadata file contains level {level}, expected {GAIA_LEVEL}"
                )
            if ground_truth is None:
                raise ValueError(f"GAIA validation task {upstream_id!r} has no ground truth")

            logical_id = f"gaia:{GAIA_YEAR}:{GAIA_SPLIT}:level{level}:{upstream_id}"
            if logical_id in answers:
                raise ValueError(f"duplicate GAIA task id {logical_id!r}")

            answers[logical_id] = str(ground_truth)
            if file_path:
                required_tools = ("code-workspace",)
                tool_instruction = (
                    "Use Code Workspace to inspect the benchmark file under "
                    "/workspace/attachments/ before answering."
                )
            else:
                required_tools = ("browser",)
                tool_instruction = "Use Browser to research and verify the answer before responding."
            tasks.append(
                TaskSpec(
                    task_id=logical_id,
                    prompt=f"{question}\n\n{tool_instruction}\n{ANSWER_INSTRUCTION}",
                    tools=("browser", "code-workspace"),
                    required_tools=required_tools,
                    metadata={
                        "benchmark": "GAIA",
                        "year": GAIA_YEAR,
                        "split": GAIA_SPLIT,
                        "level": level,
                        "upstream_task_id": upstream_id,
                        "source_repo": GAIA_REPO_ID,
                        "source_revision": GAIA_REVISION,
                        "source_url": GAIA_SOURCE_URL,
                        "paper": GAIA_PAPER,
                        "license": "not_declared",
                        "access": "gated",
                        "file_path": file_path,
                        "source_file_sha256": source_file_sha256,
                    },
                )
            )

        required_apps = {
            app_id
            for task in tasks
            for app_id in task.required_tools
        }
        expected_apps = {"browser", "code-workspace"}
        if required_apps != expected_apps:
            raise RuntimeError(
                "pinned GAIA smoke split no longer exercises both required MCP Apps: "
                f"found {sorted(required_apps)!r}"
            )

        self._answers = answers
        return tasks

    def materialize_task(self, task: TaskSpec, staging_root: Path) -> TaskSpec:
        file_path = task.metadata.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            return task

        source = self._require_file(file_path)
        destination_dir = (
            staging_root
            / self.adapter_id
            / hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:20]
        )
        workspace = destination_dir / "workspace"
        attachment_dir = workspace / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)
        destination = attachment_dir / Path(file_path).name
        shutil.copy2(source, destination)
        self._materialized_roots[task.task_id] = destination_dir

        return TaskSpec(
            task_id=task.task_id,
            prompt=task.prompt,
            tools=task.tools,
            required_tools=task.required_tools,
            attachments=(),
            initial_workspace=workspace,
            metadata=dict(task.metadata),
        )

    async def cleanup(
        self,
        task: TaskSpec,
        *,
        prepared: PreparedBenchmarkContext | None,
    ) -> None:
        root = self._materialized_roots.pop(task.task_id, None)
        if root is not None and root.exists():
            shutil.rmtree(root)

    async def evaluate(
        self,
        task: TaskSpec,
        *,
        prepared: PreparedBenchmarkContext,
        captured: CapturedConversation,
    ) -> EvaluationResult:
        try:
            ground_truth = self._answers[task.task_id]
        except KeyError as exc:
            raise RuntimeError(
                f"GAIA ground truth unavailable for {task.task_id!r}; "
                "discover_tasks() must run before evaluate()"
            ) from exc

        model_answer = _model_answer(captured)
        passed = gaia_question_scorer(model_answer, ground_truth)
        return EvaluationResult(
            verdict="pass" if passed else "fail",
            score=1.0 if passed else 0.0,
            details={"model_answer": model_answer},
            metadata={
                "scorer": "gaia_question_scorer",
                "source_revision": GAIA_REVISION,
            },
        )

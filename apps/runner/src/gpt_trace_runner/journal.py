from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from .exceptions import RecoveryIncomplete

JournalPhase = Literal[
    "starting",
    "apps_prepared",
    "benchmark_preparing",
    "benchmark_ready",
    "composer_dirty",
    "submission_started",
    "conversation_known",
    "conversation_checkpointed",
    "candidate_checkpointed",
    "cleanup_pending",
]


@dataclass(frozen=True, slots=True)
class SubmissionJournal:
    task_id: str
    runner_id: str
    attempt: int
    phase: JournalPhase
    conversation_id: str | None = None
    task_fingerprint: str | None = None
    app_environments: dict[str, str] = field(default_factory=dict)
    resolved_app_names: dict[str, str] = field(default_factory=dict)
    user_message_id: str | None = None
    # Wall-clock epoch before which recovery must not call ChatGPT again after a
    # server Retry-After. Optional for backward compatibility with old journals.
    retry_not_before: float | None = None
    capture_sha256: str | None = None
    candidate: dict | None = None


class JournalStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> SubmissionJournal | None:
        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return SubmissionJournal(**payload)
        except Exception as exc:
            raise RecoveryIncomplete(f"submission journal is unreadable: {self.path}: {exc}") from exc

    def write(self, journal: SubmissionJournal) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        data = json.dumps(asdict(journal), sort_keys=True, separators=(",", ":"))
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        self._sync_parent()

    def _sync_parent(self) -> None:
        fd = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def clear(self) -> None:
        if not self.path.exists():
            return
        self.path.unlink()
        self._sync_parent()

    @property
    def capture_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".capture.json")

    def write_capture(self, captured, entry: SubmissionJournal) -> str:
        import hashlib
        payload = {"task_id": entry.task_id, "attempt": entry.attempt,
                   "runner_id": entry.runner_id, "fingerprint": entry.task_fingerprint,
                   "conversation_id": captured.conversation_id, "messages": captured.messages,
                   "runtime_metadata": captured.runtime_metadata}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.capture_path.with_suffix(".tmp")
        with temporary.open("wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.capture_path)
        self._sync_parent()
        return hashlib.sha256(raw).hexdigest()

    def load_capture(self, entry: SubmissionJournal):
        import hashlib
        from .models import CapturedConversation
        try:
            raw = self.capture_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != entry.capture_sha256:
                raise ValueError("capture digest mismatch")
            data = json.loads(raw)
            if any(data[key] != value for key, value in {
                "task_id": entry.task_id, "attempt": entry.attempt, "runner_id": entry.runner_id,
                "fingerprint": entry.task_fingerprint, "conversation_id": entry.conversation_id,
            }.items()):
                raise ValueError("capture attempt identity mismatch")
            return CapturedConversation(data["conversation_id"], data["messages"], data["runtime_metadata"])
        except Exception as exc:
            raise RecoveryIncomplete(f"durable conversation checkpoint invalid: {exc}") from exc

    def clear_capture(self) -> None:
        self.capture_path.unlink(missing_ok=True)
        if self.path.parent.exists():
            self._sync_parent()

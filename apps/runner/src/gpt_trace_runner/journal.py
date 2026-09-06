from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from .exceptions import RecoveryIncomplete


JournalPhase = Literal[
    "starting",
    "composer_dirty",
    "submission_started",
    "conversation_known",
]


@dataclass(frozen=True, slots=True)
class SubmissionJournal:
    task_id: str
    runner_id: str
    attempt: int
    phase: JournalPhase
    conversation_id: str | None = None
    task_fingerprint: str | None = None


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
            raise RecoveryIncomplete(
                f"submission journal is unreadable: {self.path}: {exc}"
            ) from exc

    def write(self, journal: SubmissionJournal) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        data = json.dumps(asdict(journal), sort_keys=True, separators=(",", ":"))
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        dir_fd = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def clear(self) -> None:
        if not self.path.exists():
            return
        self.path.unlink()
        dir_fd = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

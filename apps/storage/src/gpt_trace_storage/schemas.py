from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StartRunRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    runner_id: str = Field(min_length=1, max_length=255)
    expected_attempt: int = Field(ge=1)
    task_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("task_id")
    @classmethod
    def _not_reserved_path_segment(cls, value: str) -> str:
        if value in {".", ".."}:
            raise ValueError("reserved task_id")
        return value


class MutationBase(BaseModel):
    attempt: int = Field(ge=1)
    runner_id: str = Field(min_length=1, max_length=255)


class ConversationRequest(MutationBase):
    conversation_id: str = Field(min_length=1, max_length=255)


class CompleteRunRequest(MutationBase):
    conversation_id: str = Field(min_length=1, max_length=255)
    messages: list[dict[str, Any]] = Field(min_length=2)
    runtime_metadata: dict[str, Any] = Field(default_factory=dict)


class FailRunRequest(MutationBase):
    error_type: str = Field(min_length=1, max_length=255)
    error_message: str = Field(max_length=8000)


class RunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    task_id: str
    status: str
    runner_id: str | None = None
    attempt: int
    task_fingerprint: str | None = None
    conversation_id: str | None = None
    runtime_metadata: dict[str, Any] | None = None
    error_type: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class StatsResponse(BaseModel):
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    total: int = 0

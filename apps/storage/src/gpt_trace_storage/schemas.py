from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StartRunRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=255)
    runner_id: str = Field(min_length=1, max_length=255)


class ConversationRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=255)


class CompleteRunRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=255)
    messages: list[dict[str, Any]]
    runtime_metadata: dict[str, Any] = Field(default_factory=dict)


class FailRunRequest(BaseModel):
    error_type: str = Field(min_length=1, max_length=255)
    error_message: str = Field(max_length=8000)


class RunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_id: str
    status: str
    runner_id: str | None = None
    attempt: int
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

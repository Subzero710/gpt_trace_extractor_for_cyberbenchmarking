from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    task_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="pending")
    runner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    task_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conversation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    messages: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    runtime_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    app_provenance: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    canonical_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_benchmark: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_benchmark_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    upstream_repository: Mapped[str | None] = mapped_column(Text, nullable=True)
    upstream_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_license: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    teacher_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    adapter_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    adapter_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evaluator_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    run_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reward: Mapped[float | None] = mapped_column(Float, nullable=True)
    native_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

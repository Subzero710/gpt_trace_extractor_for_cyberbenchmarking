from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    task_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        index=True,
        default="pending",
    )
    runner_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    task_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    attempt: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    conversation_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    messages: Mapped[list | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    runtime_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    error_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

"""initial storage schema

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", sa.String(length=255), nullable=False),
        sa.Column("logical_task_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("runner_id", sa.String(length=255), nullable=True),
        sa.Column("task_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("conversation_id", sa.String(length=255), nullable=True),
        sa.Column("messages", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("runtime_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("app_provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "dataset_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("evaluation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed')",
            name="ck_runs_status",
        ),
        sa.CheckConstraint(
            "attempt >= 0",
            name="ck_runs_attempt_nonnegative",
        ),
    )

    op.create_index("ix_runs_task_id", "runs", ["task_id"], unique=True)
    op.create_index("ix_runs_logical_task_id", "runs", ["logical_task_id"], unique=False)
    op.create_index("ix_runs_status", "runs", ["status"], unique=False)
    op.create_index("ix_runs_conversation_id", "runs", ["conversation_id"], unique=False)
    op.create_index(
        "uq_runs_conversation_id_not_null",
        "runs",
        ["conversation_id"],
        unique=True,
        postgresql_where=sa.text("conversation_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_runs_conversation_id_not_null", table_name="runs")
    op.drop_index("ix_runs_conversation_id", table_name="runs")
    op.drop_index("ix_runs_status", table_name="runs")
    op.drop_index("ix_runs_logical_task_id", table_name="runs")
    op.drop_index("ix_runs_task_id", table_name="runs")
    op.drop_table("runs")

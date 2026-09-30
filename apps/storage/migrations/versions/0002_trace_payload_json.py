"""use PostgreSQL JSON for externally sourced trace payloads

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


_TRACE_JSON_COLUMNS = (
    "messages",
    "runtime_metadata",
    "dataset_metadata",
    "evaluation",
)


def upgrade() -> None:
    op.alter_column("runs", "dataset_metadata", server_default=None)

    for column in _TRACE_JSON_COLUMNS:
        op.alter_column(
            "runs",
            column,
            existing_type=postgresql.JSONB(astext_type=sa.Text()),
            type_=postgresql.JSON(astext_type=sa.Text()),
            postgresql_using=f"{column}::json",
        )

    op.alter_column(
        "runs",
        "dataset_metadata",
        server_default=sa.text("'{}'::json"),
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column("runs", "dataset_metadata", server_default=None)

    for column in _TRACE_JSON_COLUMNS:
        op.alter_column(
            "runs",
            column,
            existing_type=postgresql.JSON(astext_type=sa.Text()),
            type_=postgresql.JSONB(astext_type=sa.Text()),
            postgresql_using=f"{column}::jsonb",
        )

    op.alter_column(
        "runs",
        "dataset_metadata",
        server_default=sa.text("'{}'::jsonb"),
        nullable=False,
    )

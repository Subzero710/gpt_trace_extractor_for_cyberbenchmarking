"""guard run integrity

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    duplicate = bind.execute(
        sa.text(
            "SELECT conversation_id FROM runs "
            "WHERE conversation_id IS NOT NULL "
            "GROUP BY conversation_id HAVING count(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicate is not None:
        raise RuntimeError(
            "cannot install run-integrity guards: duplicate conversation_id exists"
        )
    invalid_status = bind.execute(
        sa.text(
            "SELECT status FROM runs "
            "WHERE status NOT IN ('pending','running','completed','failed') LIMIT 1"
        )
    ).first()
    if invalid_status is not None:
        raise RuntimeError(
            "cannot install run-integrity guards: invalid run status exists"
        )
    negative_attempt = bind.execute(
        sa.text("SELECT attempt FROM runs WHERE attempt < 0 LIMIT 1")
    ).first()
    if negative_attempt is not None:
        raise RuntimeError(
            "cannot install run-integrity guards: negative attempt exists"
        )

    op.add_column("runs", sa.Column("task_fingerprint", sa.String(length=64), nullable=True))
    op.create_index(
        "uq_runs_conversation_id_not_null",
        "runs",
        ["conversation_id"],
        unique=True,
        postgresql_where=sa.text("conversation_id IS NOT NULL"),
    )
    op.create_check_constraint(
        "ck_runs_status", "runs",
        "status IN ('pending','running','completed','failed')",
    )
    op.create_check_constraint("ck_runs_attempt_nonnegative", "runs", "attempt >= 0")


def downgrade() -> None:
    op.drop_constraint("ck_runs_attempt_nonnegative", "runs", type_="check")
    op.drop_constraint("ck_runs_status", "runs", type_="check")
    op.drop_index("uq_runs_conversation_id_not_null", table_name="runs")
    op.drop_column("runs", "task_fingerprint")

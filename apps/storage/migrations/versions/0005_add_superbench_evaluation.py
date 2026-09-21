"""add Superbench provenance and native evaluation
Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision='0005'; down_revision='0004'; branch_labels=None; depends_on=None
def upgrade():
    for name,typ in [('canonical_task_id',sa.String(255)),('campaign_id',sa.String(64)),('source_benchmark',sa.String(128)),('source_benchmark_version',sa.String(128)),('source_task_id',sa.String(255)),('upstream_repository',sa.Text()),('upstream_commit',sa.String(128)),('source_license',sa.String(128)),('adapter_id',sa.String(128)),('adapter_version',sa.String(64)),('run_status',sa.String(32))]: op.add_column('runs',sa.Column(name,typ,nullable=True))
    for name in ('source_metadata','teacher_metadata','evaluator_metadata','native_result'): op.add_column('runs',sa.Column(name,postgresql.JSONB(astext_type=sa.Text()),nullable=True))
    op.add_column('runs',sa.Column('success',sa.Boolean(),nullable=True)); op.add_column('runs',sa.Column('reward',sa.Float(),nullable=True))
    op.create_index('ix_runs_canonical_campaign','runs',['canonical_task_id','campaign_id'],unique=False)
    op.create_check_constraint('ck_runs_superbench_run_status','runs',"run_status IS NULL OR run_status IN ('completed','infra_failed','unsupported')")
def downgrade():
    op.drop_constraint('ck_runs_superbench_run_status','runs',type_='check'); op.drop_index('ix_runs_canonical_campaign',table_name='runs')
    for n in ('reward','success','native_result','evaluator_metadata','teacher_metadata','source_metadata','run_status','adapter_version','adapter_id','source_license','upstream_commit','upstream_repository','source_task_id','source_benchmark_version','source_benchmark','campaign_id','canonical_task_id'): op.drop_column('runs',n)

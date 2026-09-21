from pathlib import Path
from gpt_trace_storage.models import Run

def test_superbench_migration_is_append_only_and_typed():
    p=Path(__file__).parents[1]/'migrations/versions/0005_add_superbench_evaluation.py'; text=p.read_text(); assert "down_revision='0004'" in text; assert "canonical_task_id" in text; assert "success" in text; assert "native_result" in text; assert "run_status" in text

def test_superbench_columns_are_nullable_for_legacy_runs():
    r=Run(task_id='legacy',status='completed',attempt=1); assert r.canonical_task_id is None; assert r.success is None

from pathlib import Path

from gpt_trace_storage.models import Run


def test_squashed_initial_schema_contains_current_superbench_fields():
    path = Path(__file__).parents[1] / "migrations/versions/0001_initial.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0001"' in text
    assert 'sa.Column("logical_task_id"' in text
    assert '"dataset_metadata"' in text
    assert 'sa.Column("evaluation"' in text


def test_current_run_model_exposes_superbench_fields():
    assert hasattr(Run, "logical_task_id")
    assert hasattr(Run, "dataset_metadata")
    assert hasattr(Run, "evaluation")

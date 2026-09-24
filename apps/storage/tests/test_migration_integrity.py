from pathlib import Path


def initial_migration_text() -> str:
    migration = Path(__file__).parents[1] / "migrations" / "versions" / "0001_initial.py"
    return migration.read_text(encoding="utf-8")


def test_squashed_schema_has_unique_non_null_conversation_index() -> None:
    text = initial_migration_text()
    assert '"uq_runs_conversation_id_not_null"' in text
    assert 'unique=True' in text
    assert 'conversation_id IS NOT NULL' in text


def test_squashed_schema_keeps_run_integrity_constraints() -> None:
    text = initial_migration_text()
    assert "status IN ('pending','running','completed','failed')" in text
    assert 'attempt >= 0' in text
    assert '"ck_runs_status"' in text
    assert '"ck_runs_attempt_nonnegative"' in text


def test_squashed_schema_contains_app_provenance() -> None:
    assert '"app_provenance"' in initial_migration_text()

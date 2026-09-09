from pathlib import Path


def test_conversation_id_unique_index_migration_exists() -> None:
    migration = Path(__file__).parents[1] / "migrations" / "versions" / "0003_guard_run_integrity.py"
    text = migration.read_text()
    assert "unique=True" in text
    assert "conversation_id IS NOT NULL" in text


def test_migration_preflights_existing_integrity() -> None:
    migration = Path(__file__).parents[1] / "migrations" / "versions" / "0003_guard_run_integrity.py"
    text = migration.read_text()
    assert "HAVING count(*) > 1" in text
    assert "invalid run status exists" in text
    assert "negative attempt exists" in text


def test_app_provenance_migration_follows_integrity_guards() -> None:
    migration = Path(__file__).parents[1] / "migrations" / "versions" / "0004_add_app_provenance.py"
    text = migration.read_text()
    assert 'down_revision = "0003"' in text
    assert '"app_provenance"' in text

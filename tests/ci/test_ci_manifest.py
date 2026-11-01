"""Behavioral tests of CI; no pinned repository state, counts or config values."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / ".github/scripts/ci_manifest.py"
SPEC = importlib.util.spec_from_file_location("ci_manifest_under_test", SOURCE)
assert SPEC is not None and SPEC.loader is not None
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


def create_project(root, name, *, has_tests):
    directory = root / "apps" / name
    directory.mkdir(parents=True)
    (directory / "pyproject.toml").write_text(
        '[project]\nname = "a-component"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    if has_tests:
        tests = directory / "tests"
        tests.mkdir()
        (tests / "test_behavior.py").write_text("def test_working(): assert True\n", encoding="utf-8")
    return directory


def test_matrix_discovers_new_components_without_manual_list(tmp_path):
    (tmp_path / "apps").mkdir()
    create_project(tmp_path, "with-tests", has_tests=True)
    create_project(tmp_path, "no-tests", has_tests=False)
    initial = CI.components(tmp_path)
    assert initial == ["apps/with-tests"]
    create_project(tmp_path, "later-added", has_tests=True)
    updated = CI.components(tmp_path)
    assert set(updated) - set(initial) == {"apps/later-added"}
    assert "apps/no-tests" not in updated
    (tmp_path / "apps" / "later-added" / "Dockerfile").write_text("FROM scratch\n")
    assert CI.components(tmp_path, docker_only=True) == ["apps/later-added"]


def test_matrix_rejects_missing_tests_instead_of_claiming_coverage(tmp_path):
    (tmp_path / "apps").mkdir()
    create_project(tmp_path, "no-tests", has_tests=False)
    with pytest.raises(ValueError, match="no matching testable"):
        CI.components(tmp_path)


def test_validation_accepts_changed_configuration_values(tmp_path):
    path = Path("config/settings.toml")
    target = tmp_path / path
    target.parent.mkdir()
    for content in ('[settings]\nworkers = 3\n', '[settings]\nworkers = 19\nnew_option = true\n'):
        target.write_text(content, encoding="utf-8")
        assert CI.validate_file(tmp_path, path)


def test_validation_rejects_invalid_python_and_config_syntax(tmp_path):
    path = Path("scripts/feature.py")
    target = tmp_path / path
    target.parent.mkdir()
    target.write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(SyntaxError):
        CI.validate_file(tmp_path, path)
    config = Path("config/settings.json")
    target = tmp_path / config
    target.parent.mkdir(exist_ok=True)
    target.write_text('{"incomplete":', encoding="utf-8")
    with pytest.raises(ValueError):
        CI.validate_file(tmp_path, config)


def test_gate_requires_all_jobs_and_rejects_skips():
    CI.gate({"first": {"result": "success"}, "second": {"result": "success"}})
    with pytest.raises(ValueError, match="skipped"):
        CI.gate({"first": {"result": "success"}, "second": {"result": "skipped"}})
    with pytest.raises(ValueError, match="failure"):
        CI.gate({"first": {"result": "failure"}})
    with pytest.raises(ValueError, match="missing"):
        CI.gate({})


def test_missing_package_metadata_is_a_failure_not_a_silent_skip(tmp_path):
    tests = tmp_path / "apps" / "new-service" / "tests"
    tests.mkdir(parents=True)
    (tests / "test_new_feature.py").write_text("def test_feature(): assert True\n")
    with pytest.raises(ValueError, match="no trusted Python metadata"):
        CI.components(tmp_path)

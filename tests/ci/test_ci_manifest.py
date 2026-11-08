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


def test_golden_validation_and_storage_fixture_remain_mandatory():
    import yaml
    workflow=yaml.safe_load((SOURCE.parents[1]/'workflows/ci.yml').read_text())
    jobs=workflow['jobs']
    assert 'golden' in jobs['gate']['needs']
    commands='\n'.join(step.get('run','') for step in jobs['golden']['steps'])
    assert "apps/kali-workstation[test]" in commands
    assert 'tests/distributed/test_golden_resume.py' in commands
    assert 'sudo "$(command -v python)" -m pytest' in commands
    docker_command='\n'.join(step.get('run','') for step in jobs['docker']['steps'])
    assert 'ci_manifest.py docker-context' in docker_command
    assert 'docker build --file "${COMPONENT}/Dockerfile" "${CONTEXT}"' in docker_command
    service_test=next(step for step in jobs['services']['steps'] if step.get('name')=='Execute discovered service tests')
    assert service_test['env']['POSTGRES_PASSWORD']



def test_rust_compilation_unit_tests_and_runtime_binary_are_ci_gated():
    import yaml
    workflow = yaml.safe_load((SOURCE.parents[1] / 'workflows/ci.yml').read_text())
    jobs = workflow['jobs']
    assert 'rust' in jobs['gate']['needs']
    assert 'rust' in jobs['distributed']['needs']
    rust_commands = '\n'.join(step.get('run', '') for step in jobs['rust']['steps'])
    assert 'cargo test --offline --locked --manifest-path rust/verified-resolver/Cargo.toml' in rust_commands
    assert 'cargo build --offline --locked --release --manifest-path rust/verified-resolver/Cargo.toml' in rust_commands
    integration_commands = '\n'.join(step.get('run', '') for step in jobs['distributed']['steps'])
    assert 'cargo build --offline --locked --release --manifest-path rust/verified-resolver/Cargo.toml' in integration_commands
    # The binary path is derived from Cargo.toml, not duplicated in CI tests.
    assert 'from scripts.build import _verified_resolver_contract' in integration_commands
    assert '.fetch_runtime_executables(Path.cwd())' in integration_commands
    assert 'sudo chown root:root "$BINARY"' in integration_commands
    assert 'from scripts.build import seal_verified_resolver_build' in integration_commands
    assert 'sudo test -x "$BINARY"' in integration_commands
    build_source = (SOURCE.parents[2] / 'scripts/build.py').read_text()
    assert 'binary.chmod(0o555)' in build_source
    assert 'contract.verify_fetch_runtime_build_identity(root)' in build_source
    native_source = (SOURCE.parents[2] / 'rust/verified-resolver/src/main.rs').read_text()
    assert '#[cfg(test)]' in native_source
    assert '#[test]' in native_source


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


def write_docker_component(root, name, dockerfile, files):
    directory = root / "apps" / name
    directory.mkdir(parents=True)
    (directory / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    for relative in files:
        path = root / relative
        if relative.startswith("apps/" + name + "/"):
            path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.write_text("fixture\n", encoding="utf-8")
    return directory


def test_docker_context_is_derived_from_copy_sources_not_service_names(tmp_path):
    (tmp_path / "apps").mkdir()
    root_component = tmp_path / "apps" / "root-context"
    root_component.mkdir()
    (root_component / "Dockerfile").write_text(
        "FROM scratch\nCOPY apps/root-context/src /app/src\nCOPY shared /app/shared\n",
        encoding="utf-8",
    )
    (root_component / "src").mkdir()
    (tmp_path / "shared").mkdir()

    local_component = tmp_path / "apps" / "local-context"
    local_component.mkdir()
    (local_component / "Dockerfile").write_text(
        "FROM scratch\nCOPY src /app/src\nCOPY pyproject.toml /app/pyproject.toml\n",
        encoding="utf-8",
    )
    (local_component / "src").mkdir()
    (local_component / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='1'\n")

    assert CI.docker_context(tmp_path, "apps/root-context") == "."
    assert CI.docker_context(tmp_path, "apps/local-context") == "apps/local-context"


def test_tracked_dockerfiles_all_have_one_derived_context():
    root = SOURCE.parents[2]
    components = CI.components(root, docker_only=True)
    assert components
    for component in components:
        context = CI.docker_context(root, component)
        assert context in {".", component}


def test_docker_context_handles_flags_json_form_and_stage_copies(tmp_path):
    (tmp_path / "apps").mkdir()
    component = tmp_path / "apps" / "flagged"
    component.mkdir()
    (component / "Dockerfile").write_text(
        'FROM scratch AS source\n'
        'COPY --from=source /built /built\n'
        'COPY --chmod=0644 ["src", "/app/src"]\n',
        encoding="utf-8",
    )
    (component / "src").mkdir()
    assert CI.docker_context(tmp_path, "apps/flagged") == "apps/flagged"


def test_docker_context_refuses_ambiguous_or_missing_sources(tmp_path):
    (tmp_path / "apps").mkdir()
    ambiguous = tmp_path / "apps" / "ambiguous"
    ambiguous.mkdir()
    (ambiguous / "Dockerfile").write_text("FROM scratch\nCOPY shared.txt /shared.txt\n")
    (ambiguous / "shared.txt").write_text("component\n")
    (tmp_path / "shared.txt").write_text("root\n")
    with pytest.raises(ValueError, match="not uniquely derivable"):
        CI.docker_context(tmp_path, "apps/ambiguous")

    missing = tmp_path / "apps" / "missing"
    missing.mkdir()
    (missing / "Dockerfile").write_text("FROM scratch\nCOPY absent /absent\n")
    with pytest.raises(ValueError, match="not uniquely derivable"):
        CI.docker_context(tmp_path, "apps/missing")

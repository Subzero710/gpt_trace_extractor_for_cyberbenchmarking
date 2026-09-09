import json
from pathlib import Path

import pytest

from gpt_trace_runner.exceptions import AppRegistryError
from gpt_trace_runner.registry import AppRegistry, manifest_sha256
from registry_helpers import make_registry


def test_stable_ids_resolve_to_configured_ui_names(tmp_path: Path) -> None:
    registry = make_registry(tmp_path, github_ui="Renamed GitHub")
    logical = registry.resolve_id("github")
    legacy = registry.resolve_name("Renamed GitHub")
    assert logical.app_id == legacy.app_id == "github"
    assert logical.ui_name == "Renamed GitHub"
    assert logical.version == "2.1.0"
    assert logical.manifest_sha256 == manifest_sha256(logical.manifest)


def test_external_connector_requires_explicit_ui_name_and_manifest(tmp_path: Path) -> None:
    path = tmp_path / "apps.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "apps": [{
            "id": "github", "kind": "external_connector",
            "display_name_env": "APP_GITHUB_UI_NAME",
            "manifest_path_env": "APP_GITHUB_MANIFEST_PATH",
        }],
    }))
    registry = AppRegistry.load(path, environment={})
    with pytest.raises(AppRegistryError, match="required"):
        registry.resolve_id("github")


def test_manifest_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    definition = registry._by_id["browser"]
    definition_path = Path(definition.raw["manifest_path_default"])
    payload = json.loads(definition_path.read_text())
    payload["tools"][0]["description"] += " drift"
    definition_path.write_text(json.dumps(payload))
    with pytest.raises(AppRegistryError, match="hash mismatch"):
        registry.resolve_id("browser")


def test_duplicate_ids_and_aliases_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "apps.json"
    entry = {"id": "browser", "kind": "external_connector", "display_name_default": "Browser", "manifest_path_default": "x", "aliases": []}
    path.write_text(json.dumps({"schema_version": 1, "apps": [entry, entry]}))
    with pytest.raises(AppRegistryError, match="duplicate"):
        AppRegistry.load(path, environment={})


def test_registry_rejects_unknown_fields_instead_of_ignoring_typos(tmp_path: Path) -> None:
    path = tmp_path / "apps.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "apps": [{
            "id": "browser",
            "kind": "external_connector",
            "display_name_default": "Browser",
            "manifest_path_default": "manifest.json",
            "display_nam_typo": "ignored",
        }],
    }))
    with pytest.raises(AppRegistryError, match="unknown App registry fields"):
        AppRegistry.load(path, environment={})


def test_registry_rejects_unknown_root_fields(tmp_path: Path) -> None:
    path = tmp_path / "apps.json"
    path.write_text(json.dumps({"schema_version": 1, "apps": [], "ignored": True}))
    with pytest.raises(AppRegistryError, match="schema_version 1"):
        AppRegistry.load(path, environment={})


def test_registry_rejects_non_string_environment_values(tmp_path: Path) -> None:
    registry = make_registry(tmp_path)
    with pytest.raises(AppRegistryError, match="must be a string"):
        AppRegistry.load(
            tmp_path / "apps.json",
            environment={"TEST_GITHUB_NAME": 42},  # type: ignore[dict-item]
        ).resolve_id("github")

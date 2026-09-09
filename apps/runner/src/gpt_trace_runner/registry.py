from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .exceptions import AppRegistryError

APP_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
REGISTRY_FIELDS = {
    "id",
    "kind",
    "aliases",
    "attachment_mode",
    "display_name_env",
    "display_name_default",
    "version",
    "mcp_endpoint_env",
    "mcp_endpoint_default",
    "control_endpoint_env",
    "control_endpoint_default",
    "manifest_path_env",
    "manifest_path_default",
    "manifest_sha256",
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


def validate_manifest(value: Any, *, expected_app_id: str, expected_version: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AppRegistryError("tool manifest must be a JSON object")
    if set(value) != {"app_id", "version", "tools"}:
        raise AppRegistryError("tool manifest must contain exactly app_id, version, and tools")
    if value["app_id"] != expected_app_id:
        raise AppRegistryError(f"tool manifest app_id does not match {expected_app_id!r}")
    version = value["version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise AppRegistryError(f"invalid semantic version for app {expected_app_id!r}")
    if expected_version is not None and version != expected_version:
        raise AppRegistryError(f"manifest version for {expected_app_id!r} differs from registry")
    tools = value["tools"]
    if not isinstance(tools, list):
        raise AppRegistryError("tool manifest tools must be a list")
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {"name", "description", "inputSchema"}:
            raise AppRegistryError("each canonical tool must contain exactly name, description, and inputSchema")
        name = tool["name"]
        if not isinstance(name, str) or not TOOL_NAME_RE.fullmatch(name):
            raise AppRegistryError(f"invalid canonical tool name: {name!r}")
        if name in seen:
            raise AppRegistryError(f"duplicate tool name {name!r} in app {expected_app_id!r}")
        seen.add(name)
        if not isinstance(tool["description"], str) or not tool["description"].strip():
            raise AppRegistryError(f"tool {name!r} must have a description")
        schema = tool["inputSchema"]
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise AppRegistryError(f"tool {name!r} inputSchema must be an object schema")
    return deepcopy(value)


@dataclass(frozen=True, slots=True)
class ResolvedApp:
    app_id: str
    ui_name: str
    kind: str
    version: str
    manifest_sha256: str
    manifest: dict[str, Any]
    mcp_endpoint: str | None
    control_endpoint: str | None
    attachment_mode: str

    def provenance(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "ui_name": self.ui_name,
            "kind": self.kind,
            "version": self.version,
            "tool_manifest_sha256": self.manifest_sha256,
            "tool_manifest": deepcopy(self.manifest),
        }


@dataclass(frozen=True, slots=True)
class AppDefinition:
    raw: dict[str, Any]
    registry_dir: Path
    environment: Mapping[str, str]

    @property
    def app_id(self) -> str:
        return self.raw["id"]

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(self.raw.get("aliases", []))

    def _configured(self, field: str, *, required: bool) -> str | None:
        env_name = self.raw.get(f"{field}_env")
        if env_name is not None:
            if not isinstance(env_name, str) or not env_name:
                raise AppRegistryError(f"invalid {field}_env for app {self.app_id!r}")
            if env_name in self.environment:
                configured = self.environment[env_name]
                if not isinstance(configured, str):
                    raise AppRegistryError(f"{env_name} must be a string for app {self.app_id!r}")
                value = configured.strip()
                if value:
                    return value
                if required:
                    raise AppRegistryError(f"{env_name} is required for app {self.app_id!r}")
                return None
        default = self.raw.get(f"{field}_default")
        if default is not None:
            if not isinstance(default, str) or not default.strip():
                raise AppRegistryError(f"invalid {field}_default for app {self.app_id!r}")
            return default.strip()
        if required:
            label = env_name or field
            raise AppRegistryError(f"{label} is required for app {self.app_id!r}")
        return None

    def display_name(self, *, required: bool = True) -> str | None:
        return self._configured("display_name", required=required)

    def _manifest_path(self) -> Path:
        configured = self._configured("manifest_path", required=True)
        assert configured is not None
        path = Path(configured)
        return path if path.is_absolute() else (self.registry_dir / path).resolve()

    def resolve(self) -> ResolvedApp:
        ui_name = self.display_name(required=True)
        assert ui_name is not None
        path = self._manifest_path()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AppRegistryError(f"cannot load tool manifest for app {self.app_id!r}: {path}") from exc
        expected_version = self.raw.get("version")
        if expected_version is not None and not isinstance(expected_version, str):
            raise AppRegistryError(f"invalid version for app {self.app_id!r}")
        manifest = validate_manifest(payload, expected_app_id=self.app_id, expected_version=expected_version)
        digest = manifest_sha256(manifest)
        expected_digest = self.raw.get("manifest_sha256")
        if expected_digest is not None and digest != expected_digest:
            raise AppRegistryError(f"tool manifest hash mismatch for app {self.app_id!r}")
        kind = self.raw["kind"]
        mcp = self._configured("mcp_endpoint", required=kind == "local_mcp")
        control = self._configured("control_endpoint", required=kind == "local_mcp")
        attachment_mode = self.raw.get("attachment_mode", "none")
        return ResolvedApp(
            app_id=self.app_id,
            ui_name=ui_name,
            kind=kind,
            version=manifest["version"],
            manifest_sha256=digest,
            manifest=manifest,
            mcp_endpoint=mcp,
            control_endpoint=control,
            attachment_mode=attachment_mode,
        )


class AppRegistry:
    def __init__(self, definitions: tuple[AppDefinition, ...]) -> None:
        self.definitions = definitions
        self._by_id = {definition.app_id: definition for definition in definitions}

    @classmethod
    def load(cls, path: Path, *, environment: Mapping[str, str] | None = None) -> "AppRegistry":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AppRegistryError(f"cannot read App registry: {path}") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "apps"}
            or payload.get("schema_version") != 1
            or not isinstance(payload.get("apps"), list)
        ):
            raise AppRegistryError("App registry must use schema_version 1 and contain apps[]")
        env = environment if environment is not None else os.environ
        definitions: list[AppDefinition] = []
        identifiers: dict[str, str] = {}
        for raw in payload["apps"]:
            if not isinstance(raw, dict):
                raise AppRegistryError("App registry entries must be objects")
            unknown_fields = set(raw) - REGISTRY_FIELDS
            if unknown_fields:
                raise AppRegistryError(f"unknown App registry fields: {sorted(unknown_fields)}")
            app_id = raw.get("id")
            kind = raw.get("kind")
            if not isinstance(app_id, str) or not APP_ID_RE.fullmatch(app_id):
                raise AppRegistryError(f"invalid App id: {app_id!r}")
            if kind not in {"local_mcp", "external_connector"}:
                raise AppRegistryError(f"invalid App kind for {app_id!r}")
            if kind == "local_mcp":
                version = raw.get("version")
                digest = raw.get("manifest_sha256")
                if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
                    raise AppRegistryError(f"local App {app_id!r} requires a semantic version")
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise AppRegistryError(f"local App {app_id!r} requires a manifest SHA-256")
            aliases = raw.get("aliases", [])
            if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias.strip() for alias in aliases):
                raise AppRegistryError(f"invalid aliases for {app_id!r}")
            if raw.get("attachment_mode", "none") not in {"none", "copy"}:
                raise AppRegistryError(f"invalid attachment_mode for {app_id!r}")
            if kind == "external_connector" and raw.get("attachment_mode", "none") != "none":
                raise AppRegistryError(f"external App {app_id!r} cannot receive local attachments")
            for identifier in [app_id, *aliases]:
                folded = identifier.casefold()
                if folded in identifiers:
                    raise AppRegistryError(f"duplicate App id/alias {identifier!r}")
                identifiers[folded] = app_id
            definitions.append(AppDefinition(deepcopy(raw), path.parent.resolve(), env))
        return cls(tuple(definitions))

    def resolve_id(self, app_id: str) -> ResolvedApp:
        definition = self._by_id.get(app_id.casefold())
        if definition is None:
            for candidate in self.definitions:
                if app_id.casefold() in {alias.casefold() for alias in candidate.aliases}:
                    definition = candidate
                    break
        if definition is None:
            raise AppRegistryError(f"unknown logical App id {app_id!r}")
        return definition.resolve()

    def resolve_name(self, name: str) -> ResolvedApp:
        folded = name.casefold()
        logical = [
            definition
            for definition in self.definitions
            if folded == definition.app_id.casefold()
            or folded in {alias.casefold() for alias in definition.aliases}
        ]
        if not logical:
            for definition in self.definitions:
                display = definition.display_name(required=False)
                if display is not None and display.casefold() == folded:
                    logical.append(definition)
        if len(logical) != 1:
            if not logical:
                raise AppRegistryError(f"unknown App name or id {name!r}")
            raise AppRegistryError(f"ambiguous App name {name!r}")
        return logical[0].resolve()

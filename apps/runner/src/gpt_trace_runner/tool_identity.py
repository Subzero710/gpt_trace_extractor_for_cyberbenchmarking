from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Iterable

from .exceptions import AppRegistryError


def stable_tool_name(app_id: str, tool_name: str) -> str:
    """Return the provider-independent global name for one App tool."""
    prefix = re.sub(r"[^A-Za-z0-9_]", "_", app_id).strip("_")
    tool = re.sub(r"[^A-Za-z0-9_]", "_", tool_name).strip("_")
    if not prefix or not tool:
        raise AppRegistryError(f"cannot represent tool identity {app_id!r}/{tool_name!r}")

    value = f"{prefix}__{tool}"
    if len(value) > 128:
        digest = hashlib.sha256(f"{app_id}\0{tool_name}".encode("utf-8")).hexdigest()[:16]
        available = 128 - len(prefix) - len(digest) - 3
        if available < 1:
            prefix = prefix[:40]
            available = 128 - len(prefix) - len(digest) - 3
        value = f"{prefix}__{tool[:available]}_{digest}"

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
        raise AppRegistryError(f"invalid stable tool name for {app_id!r}/{tool_name!r}")
    return value


def flatten_app_provenance(apps: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Flatten App manifests into globally named, provider-neutral function schemas."""
    tools: list[dict[str, Any]] = []
    identity_map: list[dict[str, str]] = []
    function_names: set[str] = set()

    for app in apps:
        app_id = app.get("app_id")
        manifest = app.get("tool_manifest")
        digest = app.get("tool_manifest_sha256")
        if not isinstance(app_id, str):
            raise AppRegistryError("App provenance has no app_id")
        if not isinstance(manifest, dict) or not isinstance(manifest.get("tools"), list):
            raise AppRegistryError("App provenance has no canonical tool manifest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AppRegistryError(f"App provenance has an invalid manifest hash for {app_id}")

        for tool in manifest["tools"]:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                raise AppRegistryError("canonical tool has no name")
            if not isinstance(tool.get("description"), str):
                raise AppRegistryError("canonical tool has no description")
            if not isinstance(tool.get("inputSchema"), dict):
                raise AppRegistryError("canonical tool has no input schema")

            canonical_name = tool["name"]
            function_name = stable_tool_name(app_id, canonical_name)
            if function_name in function_names:
                raise AppRegistryError(f"stable function name collision: {function_name}")
            function_names.add(function_name)

            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": function_name,
                        "description": tool["description"],
                        "parameters": deepcopy(tool["inputSchema"]),
                    },
                }
            )
            identity_map.append(
                {
                    "app_id": app_id,
                    "tool_name": canonical_name,
                    "function_name": function_name,
                    "tool_manifest_sha256": digest,
                }
            )

    return {"tools": tools, "tool_identity": identity_map}

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Iterable

from .exceptions import AppRegistryError


def _namespace(app_id: str, tool_name: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9_]", "_", app_id)
    value = f"{prefix}__{tool_name}"
    if len(value) > 128:
        digest = hashlib.sha256(f"{app_id}\0{tool_name}".encode("utf-8")).hexdigest()[:16]
        available = 128 - len(prefix) - len(digest) - 3
        if available < 1:
            prefix = prefix[:40]
            available = 128 - len(prefix) - len(digest) - 3
        value = f"{prefix}__{tool_name[:available]}_{digest}"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
        raise AppRegistryError(f"collision namespace cannot represent {app_id}/{tool_name}")
    return value


def flatten_app_provenance(apps: Iterable[dict[str, Any]]) -> dict[str, Any]:
    app_list = list(apps)
    occurrences: dict[str, int] = {}
    for app in app_list:
        manifest = app.get("tool_manifest")
        if not isinstance(manifest, dict) or not isinstance(manifest.get("tools"), list):
            raise AppRegistryError("App provenance has no canonical tool manifest")
        for tool in manifest["tools"]:
            name = tool.get("name") if isinstance(tool, dict) else None
            if not isinstance(name, str):
                raise AppRegistryError("canonical tool has no name")
            occurrences[name] = occurrences.get(name, 0) + 1

    records: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    namespaced: set[str] = set()
    for app in app_list:
        app_id = app.get("app_id")
        if not isinstance(app_id, str):
            raise AppRegistryError("App provenance has no app_id")
        for tool in app["tool_manifest"]["tools"]:
            namespaced.add(_namespace(app_id, tool["name"]))
            records.append((app, tool, app_id))

    tools: list[dict[str, Any]] = []
    identity_map: list[dict[str, str]] = []
    function_names: set[str] = set()
    for app, tool, app_id in records:
        digest = app["tool_manifest_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AppRegistryError(f"App provenance has an invalid manifest hash for {app_id}")
        canonical_name = tool["name"]
        bare_is_safe = occurrences[canonical_name] == 1 and canonical_name not in namespaced
        function_name = canonical_name if bare_is_safe else _namespace(app_id, canonical_name)
        if function_name in function_names:
            raise AppRegistryError(f"Qwen function name collision: {function_name}")
        function_names.add(function_name)
        tools.append({
            "type": "function",
            "function": {
                "name": function_name,
                "description": tool["description"],
                "parameters": deepcopy(tool["inputSchema"]),
            },
        })
        identity_map.append({
            "app_id": app_id,
            "tool_name": canonical_name,
            "function_name": function_name,
            "tool_manifest_sha256": digest,
        })
    return {"tools": tools, "tool_identity": identity_map}

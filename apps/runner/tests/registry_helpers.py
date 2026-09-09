from __future__ import annotations

import hashlib
import json
from pathlib import Path

from gpt_trace_runner.registry import AppRegistry, canonical_json_bytes


def tool_manifest(app_id: str, *, version: str = "1.0.0", name: str = "read_item") -> dict:
    return {
        "app_id": app_id,
        "version": version,
        "tools": [{
            "name": name,
            "description": f"Read one item through {app_id}.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }],
    }


def make_registry(tmp_path: Path, *, github_ui: str = "GitHub Connector") -> AppRegistry:
    manifests = tmp_path / "manifests"
    manifests.mkdir(exist_ok=True)
    apps = []
    for app_id, display, kind, version in [
        ("code-workspace", "Code Workspace", "local_mcp", "1.0.0"),
        ("browser", "Browser", "local_mcp", "1.0.0"),
        ("github", github_ui, "external_connector", "2.1.0"),
    ]:
        manifest = tool_manifest(app_id, version=version)
        path = manifests / f"{app_id}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        entry = {
            "id": app_id,
            "kind": kind,
            "display_name_env": f"TEST_{app_id.upper().replace('-', '_')}_NAME",
            "manifest_path_default": str(path),
            "attachment_mode": "copy" if app_id == "code-workspace" else "none",
            "aliases": [],
        }
        if kind == "local_mcp":
            entry.update({
                "display_name_default": display,
                "version": version,
                "mcp_endpoint_default": f"http://{app_id}:8000/mcp",
                "control_endpoint_default": f"http://app-{app_id}:8000",
                "manifest_sha256": hashlib.sha256(canonical_json_bytes(manifest)).hexdigest(),
            })
        apps.append(entry)
    registry_path = tmp_path / "apps.json"
    registry_path.write_text(json.dumps({"schema_version": 1, "apps": apps}), encoding="utf-8")
    return AppRegistry.load(
        registry_path,
        environment={"TEST_GITHUB_NAME": github_ui},
    )

import hashlib
import json
from pathlib import Path

from code_workspace.contracts import TOOLS, canonical_bytes, manifest


def test_committed_manifest_matches_server_contract() -> None:
    path = Path(__file__).parents[1] / "tool-manifest.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert canonical_bytes(stored) == canonical_bytes(manifest())
    assert [tool["name"] for tool in TOOLS] == [
        "exec_command",
        "read_file",
        "write_file",
        "apply_patch",
        "list_directory",
        "search_files",
    ]
    assert len(hashlib.sha256(canonical_bytes(stored)).hexdigest()) == 64


def test_schema_change_changes_manifest_hash() -> None:
    original = manifest()
    changed = manifest()
    changed["tools"][0]["description"] += " changed"
    assert hashlib.sha256(canonical_bytes(original)).digest() != hashlib.sha256(canonical_bytes(changed)).digest()

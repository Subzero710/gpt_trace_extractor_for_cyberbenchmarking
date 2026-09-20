import hashlib
import json
from pathlib import Path

from browser_mcp.contracts import TOOLS, canonical_bytes, manifest


def test_manifest_is_exact_and_ordered() -> None:
    stored = json.loads((Path(__file__).parents[1] / "tool-manifest.json").read_text(encoding="utf-8"))
    assert canonical_bytes(stored) == canonical_bytes(manifest())
    names = [tool["name"] for tool in TOOLS]
    assert names[0] == "search"
    assert len(names) > 10
    assert stored["schema_version"] == 2
    assert len(hashlib.sha256(canonical_bytes(stored)).hexdigest()) == 64

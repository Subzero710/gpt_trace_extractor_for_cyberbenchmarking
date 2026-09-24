
from pathlib import Path


def test_gateway_forces_backend_authorization():
    source = (
        Path(__file__).parents[1] / "src" / "mcp_gateway" / "server.py"
    ).read_text(encoding="utf-8")
    assert 'headers["authorization"] = f"Bearer {active.backend_token}"' in source

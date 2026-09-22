
from pathlib import Path
def test_gateway_forces_backend_authorization():
 source=Path("src/mcp_gateway/server.py").read_text()
 assert 'headers["authorization"] = f"Bearer {active.backend_token}"' in source

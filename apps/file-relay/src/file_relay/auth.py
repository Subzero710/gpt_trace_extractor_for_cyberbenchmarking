from __future__ import annotations
import hmac
import os
from .models import Identity

class AuthError(RuntimeError): pass

def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value

TASK_ID = _required("FILE_RELAY_TASK_ID")
ATTEMPT = int(_required("FILE_RELAY_ATTEMPT"))
TOKENS = {
    _required("FILE_RELAY_WORKSPACE_TOKEN"): Identity(TASK_ID, ATTEMPT, "code-workspace"),
    _required("FILE_RELAY_BROWSER_TOKEN"): Identity(TASK_ID, ATTEMPT, "browser"),
}

def authenticate(header: str | None) -> Identity:
    if not header or not header.startswith("Bearer "):
        raise AuthError("missing relay credential")
    supplied = header[7:]
    for token, identity in TOKENS.items():
        if hmac.compare_digest(supplied, token):
            return identity
    raise AuthError("invalid relay credential")

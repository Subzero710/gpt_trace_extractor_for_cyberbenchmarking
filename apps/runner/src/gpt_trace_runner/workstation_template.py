"""IDs are contracts; host filesystem paths are never task inputs."""
from __future__ import annotations

import re

TEMPLATE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


def validate_template_id(value: str | None) -> str | None:
    if value is not None and (not isinstance(value, str) or TEMPLATE_ID.fullmatch(value) is None):
        raise ValueError("invalid immutable workstation template ID")
    return value

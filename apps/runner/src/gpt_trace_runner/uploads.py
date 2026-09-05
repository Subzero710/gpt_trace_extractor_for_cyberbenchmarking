"""Helpers for preparing local benchmark artifacts for Playwright uploads.

The runner and browser live in separate containers. Passing local path strings to
``set_input_files`` would therefore couple the browser container to the runner's
filesystem. These helpers materialize Playwright-compatible payloads in the
runner and send the file bytes across the CDP connection instead.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import TypedDict


class UploadPayload(TypedDict):
    name: str
    mimeType: str
    buffer: bytes


def build_file_payloads(attachments: tuple[Path, ...]) -> list[UploadPayload]:
    """Build Playwright file payloads from benchmark attachment paths."""
    payloads: list[UploadPayload] = []

    for attachment in attachments:
        path = attachment.expanduser().resolve()

        if not path.is_file():
            raise FileNotFoundError(path)

        mime_type, _ = mimetypes.guess_type(path.name)

        payloads.append(
            {
                "name": path.name,
                "mimeType": mime_type or "application/octet-stream",
                "buffer": path.read_bytes(),
            }
        )

    return payloads

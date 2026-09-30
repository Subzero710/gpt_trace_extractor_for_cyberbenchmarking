#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path

URL = "https://127.0.0.1:6901/"


def _credentials() -> tuple[str, str]:
    username = os.environ.get("BROWSER_KASM_USERNAME", "kasm_user").strip()
    password_file = Path(
        os.environ.get(
            "BROWSER_KASM_PASSWORD_FILE",
            "/run/secrets/teacher_browser_password",
        )
    )
    if not username:
        raise RuntimeError("BROWSER_KASM_USERNAME is empty")
    password = password_file.read_text(encoding="utf-8").strip()
    if not 12 <= len(password) <= 128:
        raise RuntimeError("teacher browser Kasm password must be 12..128 characters")
    return username, password


def _request(*, authenticated: bool) -> int:
    headers: dict[str, str] = {}
    if authenticated:
        username, password = _credentials()
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(URL, headers=headers)
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, timeout=3, context=context) as response:
            response.read(1)
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-authwall", action="store_true")
    args = parser.parse_args()

    if args.require_authwall:
        anonymous = _request(authenticated=False)
        if anonymous != 401:
            raise SystemExit(
                f"KasmVNC authwall invariant failed: anonymous HTTP {anonymous}, expected 401"
            )

    authenticated = _request(authenticated=True)
    if authenticated != 200:
        raise SystemExit(
            f"KasmVNC authenticated endpoint returned HTTP {authenticated}, expected 200"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

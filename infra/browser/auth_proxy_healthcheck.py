#!/usr/bin/env python3
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

BASE = "https://127.0.0.1:6901"
CTX = ssl._create_unverified_context()


def get(path: str) -> tuple[int, dict[str, str]]:
    request = urllib.request.Request(BASE + path)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPRedirectHandler())
    try:
        with opener.open(request, timeout=3) as response:
            return response.status, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items())


def main() -> int:
    health, _ = get("/_auth/healthz")
    if health != 200:
        raise SystemExit(f"auth proxy health returned {health}, expected 200")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), NoRedirect())
    try:
        opener.open(urllib.request.Request(BASE + "/"), timeout=3)
        status = 200
        headers = {}
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items())
    if status not in {302, 303}:
        raise SystemExit(f"anonymous auth proxy root returned {status}, expected redirect")
    if any(key.lower() == "www-authenticate" for key in headers):
        raise SystemExit("public auth proxy leaked WWW-Authenticate and can trigger native Basic Auth UI")
    location = next((v for k, v in headers.items() if k.lower() == "location"), "")
    if not location.startswith("/_auth/login"):
        raise SystemExit(f"anonymous auth proxy redirect is wrong: {location!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

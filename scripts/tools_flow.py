#!/usr/bin/env python3
from __future__ import annotations

import sys


def main() -> int:
    print(
        "scripts/tools_flow.py is obsolete. Use `make tunnels` for the OpenAI "
        "Secure MCP Tunnel, `make register_apps` for App registration, and "
        "`make start_kali` / `make stop_kali` for a manual ephemeral VM.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

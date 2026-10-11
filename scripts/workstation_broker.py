#!/usr/bin/env python3
"""Compatibility entry point for role-aware start and global shutdown."""
from __future__ import annotations
import sys


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "stop"}:
        raise SystemExit("usage: workstation_broker.py start|stop")
    import distributed
    distributed.main(["up" if sys.argv[1] == "start" else "down"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

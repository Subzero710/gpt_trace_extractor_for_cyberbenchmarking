#!/usr/bin/env python3
"""Internal finite worker. Only the native admin broker supplies its build slot."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "shared"), str(ROOT / "apps/workstation-broker/src")]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation_id")
    parser.add_argument("--slot-fd", type=int, required=True)
    args = parser.parse_args()
    from workstation_broker.preparation import worker
    worker(args.operation_id, args.slot_fd)

#!/usr/bin/env python3
from __future__ import annotations

import re
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
env = root / ".env"
example = root / ".env.example"
example_lines = example.read_text(encoding="utf-8").splitlines()
if not env.exists():
    env.write_text("\n".join(example_lines) + "\n", encoding="utf-8")

lines = env.read_text(encoding="utf-8").splitlines()
existing_keys = {
    match.group(1)
    for line in lines
    if (match := re.match(r"^([A-Z][A-Z0-9_]*)=", line))
}
missing = []
for line in example_lines:
    match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
    if match and match.group(1) not in existing_keys:
        missing.append(line)
if missing:
    lines.extend(["", "# Added by scripts/init_env.py"] + missing)

found = False
out = []
for line in lines:
    if line.startswith("BROWSER_FINGERPRINT_SEED="):
        found = True
        value = line.split("=", 1)[1].strip()
        if not value:
            value = str(secrets.randbelow(2_000_000_000) + 1)
        elif not value.isdigit() or int(value) <= 0:
            raise SystemExit("BROWSER_FINGERPRINT_SEED must be a positive integer")
        line = f"BROWSER_FINGERPRINT_SEED={value}"
    out.append(line)
if not found:
    out.append(f"BROWSER_FINGERPRINT_SEED={secrets.randbelow(2_000_000_000) + 1}")
env.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
print("initialized .env; existing values preserved and fingerprint seed kept stable")

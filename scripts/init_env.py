#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import secrets
import stat
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
EXAMPLE_PATH = ROOT / ".env.example"
SECRETS_DIR = ROOT / ".secrets"
CONTROL_TOKEN = SECRETS_DIR / "app_control_token"


def atomic_text(path: Path, content: str, mode: int) -> None:
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_secret() -> None:
    if SECRETS_DIR.exists() and (SECRETS_DIR.is_symlink() or not SECRETS_DIR.is_dir()):
        raise SystemExit(f"refusing unsafe secrets directory: {SECRETS_DIR}")
    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    if CONTROL_TOKEN.exists() or CONTROL_TOKEN.is_symlink():
        info = CONTROL_TOKEN.lstat()
        if not stat.S_ISREG(info.st_mode) or CONTROL_TOKEN.is_symlink():
            raise SystemExit(f"refusing unsafe control token path: {CONTROL_TOKEN}")
        token = CONTROL_TOKEN.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise SystemExit("existing App control token is too short")
        os.chmod(CONTROL_TOKEN, 0o600)
        return
    atomic_text(CONTROL_TOKEN, secrets.token_urlsafe(48) + "\n", 0o600)


def positive_seed(lines: list[str], key: str) -> list[str]:
    found = False
    output: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            found = True
            value = line.split("=", 1)[1].strip()
            if not value:
                value = str(secrets.randbelow(2_000_000_000) + 1)
            elif not value.isdigit() or int(value) <= 0:
                raise SystemExit(f"{key} must be a positive integer")
            line = f"{key}={value}"
        output.append(line)
    if not found:
        output.append(f"{key}={secrets.randbelow(2_000_000_000) + 1}")
    return output


def main() -> None:
    if ENV_PATH.is_symlink():
        raise SystemExit(f"refusing symlinked environment file: {ENV_PATH}")
    example_lines = EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else list(example_lines)
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
        lines.extend(["", "# Added by scripts/init_env.py", *missing])
    lines = positive_seed(lines, "BROWSER_FINGERPRINT_SEED")
    lines = positive_seed(lines, "APP_BROWSER_FINGERPRINT_SEED")
    atomic_text(ENV_PATH, "\n".join(lines).rstrip() + "\n", 0o600)
    ensure_secret()
    print("initialized .env and App control secret; existing values and both browser identities were preserved")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
SECRETS_DIR = ROOT / ".secrets"
TEACHER_BROWSER_PASSWORD = SECRETS_DIR / "teacher_browser_password"

KNOWN_SECRET_KEYS = {
    "POSTGRES_PASSWORD",
    "CONTROL_PLANE_API_KEY",
    "APP_KALI_WORKSTATION_TUNNEL_ID",
    "TEACHER_BROWSER_PASSWORD",
    "TEACHER_BROWSER_TUNNEL_TOKEN",
    "APP_CONTROL_TOKEN",
}
KNOWN_LOCAL_CONFIG_KEYS = {
    "TEACHER_BROWSER_PUBLIC_URL",
    "DIST_ROLE",
    "DIST_BROKER_URL",
}
SECRET_NAME = re.compile(
    r"(?:^|_)(?:PASSWORD|SECRET|TOKEN|API_KEY|LICENSE_KEY|PRIVATE_KEY)$"
)
TUNNEL_ID = re.compile(r"^tunnel_[a-z0-9]{32}$")


def parse_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise SystemExit("missing .env; copy .env.example and fill the secrets")
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise SystemExit(f"invalid .env line: {raw!r}")
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            raise SystemExit(f"duplicate .env key: {key}")
        values[key] = value.strip().strip("'\"")
    return values


def is_secret_key(key: str) -> bool:
    return key in KNOWN_SECRET_KEYS or bool(SECRET_NAME.search(key))


def validate_env(values: dict[str, str]) -> None:
    invalid = sorted(
        key
        for key in values
        if not is_secret_key(key) and key not in KNOWN_LOCAL_CONFIG_KEYS
    )
    if invalid:
        raise SystemExit(
            ".env contains unsupported non-secret configuration keys: "
            + ", ".join(invalid)
            + ". Move versioned configuration to config/ or explicitly allow "
            "deployment-local keys in scripts/project_state.py."
        )
    if not values.get("POSTGRES_PASSWORD"):
        raise SystemExit("POSTGRES_PASSWORD is required in .env")
    if not values.get("TEACHER_BROWSER_TUNNEL_TOKEN"):
        raise SystemExit("TEACHER_BROWSER_TUNNEL_TOKEN is required in .env")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,512}", values.get("APP_CONTROL_TOKEN", "")):
        raise SystemExit("APP_CONTROL_TOKEN must be provided in .env (32..512 allowed characters)")

    public_url = values.get("TEACHER_BROWSER_PUBLIC_URL", "").strip()
    parsed = urlparse(public_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit(
            "TEACHER_BROWSER_PUBLIC_URL must be an HTTPS origin URL such as "
            "https://kasm.example.com"
        )


def atomic_secret(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def materialize_teacher_browser_password(values: dict[str, str]) -> None:
    password = values.get("TEACHER_BROWSER_PASSWORD", "")
    if not 12 <= len(password) <= 128:
        raise SystemExit("TEACHER_BROWSER_PASSWORD must be 12..128 characters in .env")
    if "\n" in password or "\r" in password:
        raise SystemExit("TEACHER_BROWSER_PASSWORD must be a single line")
    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    atomic_secret(TEACHER_BROWSER_PASSWORD, password + "\n")
    # Docker Compose bind-mounts file secrets. Keep the directory private while
    # allowing the remapped non-root browser uid to read this one secret.
    os.chmod(TEACHER_BROWSER_PASSWORD, 0o444)

def validate_tunnels(values: dict[str, str]) -> None:
    tunnel_keys = ("APP_KALI_WORKSTATION_TUNNEL_ID",)
    for key in tunnel_keys:
        value = values.get(key, "")
        if not TUNNEL_ID.fullmatch(value):
            raise SystemExit(f"invalid/missing {key} in .env")



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("core", "doctor", "tunnels"))
    args = parser.parse_args()

    values = parse_env(ENV_PATH)
    validate_env(values)
    if ENV_PATH.is_symlink() or ENV_PATH.stat().st_mode & 0o077:
        raise SystemExit(".env must be a regular owner-private file (chmod 600 .env manually)")
    materialize_teacher_browser_password(values)

    if args.mode in ("doctor", "tunnels"):
        validate_tunnels(values)

    if args.mode == "tunnels":
        if not values.get("CONTROL_PLANE_API_KEY"):
            raise SystemExit("CONTROL_PLANE_API_KEY is required in .env for make tunnels")

    print(f"project state: {args.mode} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

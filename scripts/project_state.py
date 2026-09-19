#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
SECRETS_DIR = ROOT / ".secrets"
CONTROL_TOKEN = SECRETS_DIR / "app_control_token"
TUNNELS_PATH = ROOT / "state" / "tunnels.json"

KNOWN_SECRET_KEYS = {
    "POSTGRES_PASSWORD",
    "CLOAKBROWSER_LICENSE_KEY",
    "CONTROL_PLANE_API_KEY",
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


def validate_secret_only_env(values: dict[str, str]) -> None:
    invalid = sorted(key for key in values if not is_secret_key(key))
    if invalid:
        raise SystemExit(
            ".env contains non-secret configuration keys: "
            + ", ".join(invalid)
            + ". Move configuration to config/ or state/."
        )
    if not values.get("POSTGRES_PASSWORD"):
        raise SystemExit("POSTGRES_PASSWORD is required in .env")


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


def ensure_control_token() -> None:
    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    if CONTROL_TOKEN.exists():
        info = CONTROL_TOKEN.lstat()
        if CONTROL_TOKEN.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"refusing unsafe control token path: {CONTROL_TOKEN}")
        if len(CONTROL_TOKEN.read_text(encoding="utf-8").strip()) < 32:
            raise SystemExit("existing App control token is too short")
        os.chmod(CONTROL_TOKEN, 0o600)
        return
    atomic_secret(CONTROL_TOKEN, secrets.token_urlsafe(48) + "\n")


def validate_tunnels() -> None:
    try:
        payload = json.loads(TUNNELS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(
            "missing state/tunnels.json; rerun the architecture migration "
            "or restore the two existing tunnel IDs"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("tunnels"), dict)
    ):
        raise SystemExit("state/tunnels.json is malformed")
    tunnels = payload["tunnels"]
    for app_id in ("code-workspace", "browser"):
        value = tunnels.get(app_id)
        if not isinstance(value, str) or not TUNNEL_ID.fullmatch(value):
            raise SystemExit(f"invalid/missing tunnel id for {app_id}")

    workspace_tunnel = tunnels["code-workspace"]
    browser_tunnel = tunnels["browser"]
    if workspace_tunnel == browser_tunnel:
        raise SystemExit(
            "invalid tunnel state: code-workspace and browser must use "
            "different tunnel IDs"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("core", "doctor", "tools"))
    args = parser.parse_args()

    values = parse_env(ENV_PATH)
    validate_secret_only_env(values)
    os.chmod(ENV_PATH, 0o600)
    ensure_control_token()

    if args.mode in ("doctor", "tools"):
        validate_tunnels()

    if args.mode == "tools":
        if not values.get("CONTROL_PLANE_API_KEY"):
            raise SystemExit("CONTROL_PLANE_API_KEY is required in .env for make tools")

    print(f"project state: {args.mode} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

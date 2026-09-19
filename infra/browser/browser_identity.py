#!/usr/bin/env python3
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path


def parse_marker(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        if "=" not in raw:
            raise SystemExit("browser identity marker contains a malformed line")
        key, value = raw.split("=", 1)
        if key in values:
            raise SystemExit(f"duplicate browser identity key: {key}")
        values[key] = value

    allowed = {"fingerprint", "timezone", "locale", "geoip"}
    unknown = set(values) - allowed
    if unknown:
        raise SystemExit(f"unknown browser identity keys: {sorted(unknown)}")

    seed = values.get("fingerprint", "")
    if not seed.isdigit() or int(seed) <= 0:
        raise SystemExit("browser fingerprint must be a positive integer")

    timezone = values.get("timezone", "")
    locale = values.get("locale", "")
    geoip = values.get("geoip", "false").casefold()
    if timezone and (
        len(timezone) > 128
        or any(
            ch not in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+/-"
            for ch in timezone
        )
    ):
        raise SystemExit("invalid browser timezone")
    if locale and (
        len(locale) > 64
        or any(
            ch not in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
            for ch in locale
        )
    ):
        raise SystemExit("invalid browser locale")
    if geoip not in {"true", "false"}:
        raise SystemExit("browser geoip must be true or false")

    return {
        "fingerprint": seed,
        "timezone": timezone,
        "locale": locale,
        "geoip": geoip,
    }


def canonical(values: dict[str, str]) -> str:
    return (
        f"fingerprint={values['fingerprint']}\n"
        f"timezone={values['timezone']}\n"
        f"locale={values['locale']}\n"
        f"geoip={values['geoip']}\n"
    )


def atomic_write(path: Path, content: str) -> None:
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


def ensure(profile: Path) -> dict[str, str]:
    profile.mkdir(parents=True, exist_ok=True)
    marker = profile / ".gpt-trace-identity"
    if marker.exists():
        values = parse_marker(marker)
        wanted = canonical(values)
        if marker.read_text(encoding="utf-8") != wanted:
            atomic_write(marker, wanted)
        return values

    existing = [entry for entry in profile.iterdir() if entry.name != marker.name]
    if existing:
        raise SystemExit(
            "existing browser profile has no identity marker; refusing to invent "
            "a new fingerprint for an existing authenticated profile"
        )

    values = {
        "fingerprint": str(secrets.randbelow(2_000_000_000) + 1),
        "timezone": "",
        "locale": "",
        "geoip": "false",
    }
    atomic_write(marker, canonical(values))
    return values


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"ensure", "values"}:
        print("usage: browser-identity {ensure|values} PROFILE_DIR", file=sys.stderr)
        return 2
    profile = Path(sys.argv[2])
    values = ensure(profile) if sys.argv[1] == "ensure" else parse_marker(
        profile / ".gpt-trace-identity"
    )
    if sys.argv[1] == "values":
        print(values["fingerprint"])
        print(values["timezone"])
        print(values["locale"])
        print(values["geoip"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

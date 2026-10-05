#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
TUNNELS = (("mcp-tunnel-workstation", "kali-workstation"),)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            raise RuntimeError(f"invalid .env line: {raw!r}")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def compose_env() -> dict[str, str]:
    subprocess.run(
        ["python3", "scripts/project_state.py", "tunnels"],
        cwd=ROOT,
        check=True,
        text=True,
    )
    env = dict(os.environ)
    env.update(parse_env(ROOT / ".env"))
    return env


def run(
    args: list[str],
    *,
    env: dict[str, str],
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        check=check,
        capture_output=capture,
    )


def active_runner_containers(env: dict[str, str]) -> list[str]:
    proc = run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project=gpt-trace-extractor",
            "--filter",
            "label=com.docker.compose.service=runner",
            "--format",
            "{{.ID}} {{.Command}}",
        ],
        env=env,
        capture=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def tunnel_has_recent_session(
    service: str,
    server_name: str,
    *,
    env: dict[str, str],
) -> bool:
    proc = run(
        COMPOSE
        + [
            "--profile",
            "app-tunnels",
            "logs",
            "--since=90s",
            service,
        ],
        env=env,
        check=False,
        capture=True,
    )
    logs = proc.stdout + proc.stderr
    return (
        "mcp session initialized" in logs
        and f"server_name={server_name}" in logs
    )


def wait_for_tunnel(
    service: str,
    server_name: str,
    *,
    env: dict[str, str],
    timeout: float = 30.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tunnel_has_recent_session(service, server_name, env=env):
            return True
        time.sleep(1.0)
    return False


def ensure_tunnels_ready(env: dict[str, str]) -> None:
    run(
        COMPOSE
        + [
            "--profile",
            "app-tunnels",
            "up",
            "-d",
            "--force-recreate",
            "mcp-tunnel-workstation",
        ],
        env=env,
    )

    for service, server_name in TUNNELS:
        if wait_for_tunnel(service, server_name, env=env):
            print(f"{service}: MCP session ready", flush=True)
            continue

        print(f"{service}: no MCP session yet; restarting once", flush=True)
        run(
            COMPOSE + ["--profile", "app-tunnels", "restart", service],
            env=env,
        )
        if not wait_for_tunnel(service, server_name, env=env):
            run(
                COMPOSE
                + [
                    "--profile",
                    "app-tunnels",
                    "logs",
                    "--tail=100",
                    service,
                ],
                env=env,
                check=False,
            )
            raise RuntimeError(f"{service} failed to initialize MCP")


def main() -> int:
    env = compose_env()
    active = active_runner_containers(env)
    if active:
        details = "\n  ".join(active)
        raise RuntimeError(
            "a runner process is active; refusing to recycle the MCP tunnel:\n  "
            + details
        )
    ensure_tunnels_ready(env)
    print("Secure MCP tunnels: ready", flush=True)
    print("No Kali VM was created.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"tunnel setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
TUNNELS = ("mcp-tunnel-workstation",)
HEALTH_URL = "http://127.0.0.1:8080"
TUNNEL_READY_TIMEOUT_SECONDS = 60.0


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


def tunnel_health_report(
    service: str,
    *,
    env: dict[str, str],
) -> tuple[dict | None, str | None]:
    # The tunnel-client health command intentionally exits non-zero when
    # /readyz is red. That is expected while no Kali backend is attached:
    # /readyz includes the one-time MCP startup probe. For tunnel bootstrap we
    # care about process liveness plus a successful OpenAI control-plane poll.
    proc = run(
        COMPOSE
        + [
            "--profile",
            "app-tunnels",
            "exec",
            "-T",
            service,
            "/usr/bin/tunnel-client",
            "health",
            "--url",
            HEALTH_URL,
            "--require-control-plane-poll",
            "--json",
        ],
        env=env,
        check=False,
        capture=True,
    )

    raw = proc.stdout.strip()
    if not raw:
        detail = proc.stderr.strip() or f"health command exited {proc.returncode}"
        return None, detail

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        detail = proc.stderr.strip()
        suffix = f"; stderr={detail}" if detail else ""
        return None, f"invalid tunnel health JSON: {exc}{suffix}"

    if not isinstance(payload, dict):
        return None, "tunnel health JSON is not an object"
    return payload, None


def tunnel_control_plane_ready(report: dict | None) -> bool:
    if not isinstance(report, dict):
        return False

    healthz = report.get("healthz")
    poll = report.get("control_plane_poll")
    return (
        isinstance(healthz, dict)
        and healthz.get("ok") is True
        and isinstance(poll, dict)
        and poll.get("ok") is True
    )


def wait_for_tunnel(
    service: str,
    *,
    env: dict[str, str],
    timeout: float = TUNNEL_READY_TIMEOUT_SECONDS,
) -> tuple[bool, dict | None, str | None]:
    deadline = time.monotonic() + timeout
    last_report: dict | None = None
    last_error: str | None = None

    while time.monotonic() < deadline:
        report, error = tunnel_health_report(service, env=env)
        if report is not None:
            last_report = report
        if error is not None:
            last_error = error

        if tunnel_control_plane_ready(report):
            return True, report, None

        time.sleep(1.0)

    return False, last_report, last_error


def print_health_diagnostic(
    service: str,
    report: dict | None,
    error: str | None,
) -> None:
    print(f"{service}: tunnel health diagnostic:", file=sys.stderr)
    if report is not None:
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    elif error:
        print(error, file=sys.stderr)
    else:
        print("no tunnel health report was available", file=sys.stderr)


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

    for service in TUNNELS:
        ready, report, error = wait_for_tunnel(service, env=env)
        if ready:
            print(
                f"{service}: OpenAI control-plane poll ready "
                "(MCP backend may be idle)",
                flush=True,
            )
            continue

        print(
            f"{service}: no successful OpenAI control-plane poll yet; "
            "restarting once",
            flush=True,
        )
        run(
            COMPOSE + ["--profile", "app-tunnels", "restart", service],
            env=env,
        )

        ready, report, error = wait_for_tunnel(service, env=env)
        if ready:
            print(
                f"{service}: OpenAI control-plane poll ready "
                "(MCP backend may be idle)",
                flush=True,
            )
            continue

        print_health_diagnostic(service, report, error)
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
        raise RuntimeError(
            f"{service} failed to establish a successful OpenAI control-plane poll"
        )


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
    print("Secure MCP tunnels: control plane ready", flush=True)
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

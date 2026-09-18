#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
REGISTRATION_READY = "registration backends: ready"
TUNNELS = (
    ("mcp-tunnel-workspace", "code-workspace"),
    ("mcp-tunnel-browser", "browser"),
)


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        values[key] = value
    return values


def compose_env() -> dict[str, str]:
    env = dict(os.environ)
    dotenv = load_dotenv(ROOT / ".env")
    # Existing process variables win, matching Compose precedence.
    for key, value in dotenv.items():
        env.setdefault(key, value)
    return env


def validate_env(env: dict[str, str]) -> None:
    problems: list[str] = []

    key = env.get("CONTROL_PLANE_API_KEY", "")
    if not (key.startswith("sk-") and len(key) > 20):
        problems.append("CONTROL_PLANE_API_KEY is missing/invalid")

    tunnel_re = re.compile(r"^tunnel_[a-z0-9]{32}$")
    for name in ("APP_CODE_WORKSPACE_TUNNEL_ID", "APP_BROWSER_TUNNEL_ID"):
        if not tunnel_re.fullmatch(env.get(name, "")):
            problems.append(f"{name} is missing/invalid")

    if problems:
        raise RuntimeError("; ".join(problems))


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


def wait_for_registration(
    proc: subprocess.Popen[str],
    timeout: float = 180.0,
) -> None:
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line:
            print(line, end="", flush=True)
            if REGISTRATION_READY in line:
                return
        elif proc.poll() is not None:
            raise RuntimeError(
                f"register-apps exited before readiness with code {proc.returncode}"
            )
        else:
            time.sleep(0.1)
    raise RuntimeError("timed out waiting for registration backends")


def tunnel_has_session(
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
    text = proc.stdout + proc.stderr
    return (
        "mcp session initialized" in text
        and f"server_name={server_name}" in text
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
        if tunnel_has_session(service, server_name, env=env):
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
            "mcp-tunnel-workspace",
            "mcp-tunnel-browser",
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


def finish_registration(
    proc: subprocess.Popen[str],
) -> None:
    if proc.poll() is not None:
        return
    if proc.stdin is None:
        raise RuntimeError("register-apps stdin is unavailable")

    proc.stdin.write("\n")
    proc.stdin.flush()

    if proc.stdout is not None:
        for line in proc.stdout:
            print(line, end="", flush=True)

    rc = proc.wait(timeout=60)
    if rc != 0:
        raise RuntimeError(f"register-apps cleanup exited with code {rc}")


def main() -> int:
    env = compose_env()
    validate_env(env)

    active = active_runner_containers(env)
    if active:
        details = "\n  ".join(active)
        raise RuntimeError(
            "a runner process is already active and may own runner.lock. "
            "Finish that command first:\n  " + details
        )

    reg_cmd = COMPOSE + [
        "run",
        "--rm",
        "runner",
        "register-apps",
        "/data/benchmarks/benchmark.jsonl",
        "--task-id",
        "smoke_isolation_001",
    ]
    print("+ " + " ".join(reg_cmd), flush=True)
    proc = subprocess.Popen(
        reg_cmd,
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    completed = False
    try:
        wait_for_registration(proc)
        ensure_tunnels_ready(env)

        code_name = env.get("APP_CODE_WORKSPACE_UI_NAME", "Code Workspace")
        browser_name = env.get("APP_BROWSER_UI_NAME", "Cloak Browser")

        print()
        print("MCP backends + Secure MCP Tunnels: ready")
        print(f"Verify the ChatGPT Apps with @: @{code_name} and @{browser_name}")
        input(
            "Press Enter only after both Apps resolve and their tools are visible... "
        )

        finish_registration(proc)
        completed = True
        print("temporary registration backends cleaned up")
        print("tunnels remain running")
        return 0
    finally:
        if not completed and proc.poll() is None:
            try:
                finish_registration(proc)
            except Exception:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    proc.kill()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"tools flow failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

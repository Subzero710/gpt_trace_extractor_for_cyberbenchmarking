#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose"]
REGISTRATION_READY = "registration backends: ready"
TUNNELS_PATH = ROOT / "state" / "tunnels.json"
REGISTRY_PATH = ROOT / "apps" / "registry" / "apps.json"
TUNNEL_ID = re.compile(r"^tunnel_[a-z0-9]{32}$")

TUNNELS = (
    ("mcp-tunnel-workspace", "code-workspace"),
    ("mcp-tunnel-browser", "browser"),
)


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


def tunnel_state() -> dict[str, str]:
    payload = json.loads(TUNNELS_PATH.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("tunnels"), dict)
    ):
        raise RuntimeError("state/tunnels.json is malformed")
    tunnels = payload["tunnels"]
    result: dict[str, str] = {}
    for app_id in ("code-workspace", "browser"):
        value = tunnels.get(app_id)
        if not isinstance(value, str) or not TUNNEL_ID.fullmatch(value):
            raise RuntimeError(f"invalid/missing tunnel id for {app_id}")
        result[app_id] = value

    if result["code-workspace"] == result["browser"]:
        raise RuntimeError(
            "invalid tunnel state: code-workspace and browser must use "
            "different tunnel IDs"
        )

    return result


def app_names() -> dict[str, str]:
    payload = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    names: dict[str, str] = {}
    for row in payload.get("apps", []):
        if not isinstance(row, dict):
            continue
        app_id = row.get("id")
        name = row.get("display_name_default")
        if isinstance(app_id, str) and isinstance(name, str) and name.strip():
            names[app_id] = name.strip()
    return names


def compose_env() -> dict[str, str]:
    subprocess.run(
        ["python3", "scripts/project_state.py", "tools"],
        cwd=ROOT,
        check=True,
        text=True,
    )
    env = dict(os.environ)
    for key, value in parse_env(ROOT / ".env").items():
        env[key] = value
    tunnels = tunnel_state()
    env["APP_CODE_WORKSPACE_TUNNEL_ID"] = tunnels["code-workspace"]
    env["APP_BROWSER_TUNNEL_ID"] = tunnels["browser"]
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


def finish_registration(proc: subprocess.Popen[str]) -> None:
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

        names = app_names()
        code_name = names.get("code-workspace", "Code Workspace")
        browser_name = names.get("browser", "Cloak Browser")

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

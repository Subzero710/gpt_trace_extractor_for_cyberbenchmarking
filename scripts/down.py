#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DownError(RuntimeError):
    pass


def _show(cmd: list[str]) -> None:
    print("+ " + shlex.join(cmd), flush=True)


def _run(
    cmd: list[str],
    *,
    capture: bool = False,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    _show(cmd)
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode != 0:
        if capture:
            if result.stdout:
                sys.stderr.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
        raise DownError(
            f"command failed with exit code {result.returncode}: {shlex.join(cmd)}"
        )
    return result


def _lines(cmd: list[str], *, check: bool = True) -> list[str]:
    result = _run(cmd, capture=True, check=check)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _compose_config() -> dict:
    # Pure config rendering: does not create/start/pull Docker resources.
    result = _run(
        [
            "docker",
            "compose",
            "--profile",
            "runner",
            "--profile",
            "app-tunnels",
            "config",
            "--format",
            "json",
        ],
        capture=True,
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DownError("docker compose config returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise DownError("docker compose config did not return an object")
    name = value.get("name")
    if not isinstance(name, str) or not name:
        raise DownError("Compose project name is missing")
    return value


def _configured_volumes(config: dict) -> dict[str, str]:
    raw = config.get("volumes", {})
    if not isinstance(raw, dict):
        raise DownError("Compose volumes configuration is invalid")
    result: dict[str, str] = {}
    for logical, definition in raw.items():
        if not isinstance(logical, str) or not logical:
            raise DownError("Compose volume has an invalid logical name")
        if not isinstance(definition, dict):
            raise DownError(f"invalid Compose volume definition: {logical!r}")
        actual = definition.get("name")
        if not isinstance(actual, str) or not actual:
            raise DownError(f"Compose volume {logical!r} has no resolved Docker name")
        result[logical] = actual
    return result


def _volume_exists(name: str) -> bool:
    return (
        _run(
            ["docker", "volume", "inspect", name],
            capture=True,
            check=False,
        ).returncode
        == 0
    )


def _volume_mountpoint(name: str) -> Path | None:
    result = _run(
        ["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", name],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    if not text:
        return None
    return Path(text)


def _container_ids(*filters: str, running_only: bool = False) -> set[str]:
    cmd = ["docker", "ps" if running_only else "ps", "-q" if running_only else "-aq"]
    for item in filters:
        cmd += ["--filter", item]
    return set(_lines(cmd))


def _remove_containers(ids: set[str]) -> None:
    if ids:
        _run(["docker", "rm", "-f", *sorted(ids)])


def _postgres_running_container(project: str) -> str | None:
    ids = sorted(
        _container_ids(
            f"label=com.docker.compose.project={project}",
            "label=com.docker.compose.service=postgres",
            running_only=True,
        )
    )
    if len(ids) > 1:
        raise DownError(
            "multiple running postgres containers found for this Compose project"
        )
    return ids[0] if ids else None


def _interrupt_running_rows_if_possible(postgres_container: str | None) -> None:
    if postgres_container is None:
        print(
            "postgres is not running; DB finalization skipped (down will not start it)",
            flush=True,
        )
        return

    # First determine whether the schema exists. This covers a postgres-only
    # container on a fresh/unmigrated installation without turning down into
    # a migration/start command.
    probe = _run(
        [
            "docker",
            "exec",
            "-i",
            postgres_container,
            "sh",
            "-lc",
            (
                'psql -qAt -v ON_ERROR_STOP=1 '
                '-U "$POSTGRES_USER" -d "$POSTGRES_DB" '
                "-c \"SELECT to_regclass('public.runs') IS NOT NULL\""
            ),
        ],
        capture=True,
        check=False,
    )
    if probe.returncode != 0:
        print(
            "postgres is running but DB schema could not be inspected; "
            "skipping DB mutation and continuing shutdown",
            file=sys.stderr,
            flush=True,
        )
        return
    if probe.stdout.strip() != "t":
        print(
            "postgres is running but runs table does not exist; "
            "DB finalization skipped",
            flush=True,
        )
        return

    sql = """
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('gpt_trace_single_runner'));
WITH interrupted AS (
    UPDATE runs
       SET status = 'failed',
           error_type = 'RunnerShutdown',
           error_message = 'interrupted by make down',
           updated_at = now()
     WHERE status = 'running'
 RETURNING task_id, attempt, runner_id
)
SELECT task_id || E'\\t' || attempt::text || E'\\t' || COALESCE(runner_id, '')
  FROM interrupted;
COMMIT;
"""
    result = _run(
        [
            "docker",
            "exec",
            "-i",
            postgres_container,
            "sh",
            "-lc",
            'psql -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        capture=True,
        input_text=sql,
    )
    rows = [
        line
        for line in result.stdout.splitlines()
        if line.strip() and "\t" in line
    ]
    if not rows:
        print("no running DB task to interrupt", flush=True)
        return
    for row in rows:
        parts = row.split("\t", 2)
        task_id = parts[0]
        attempt = parts[1] if len(parts) > 1 else ""
        runner_id = parts[2] if len(parts) > 2 else ""
        print(
            f"interrupted DB run: task={task_id} "
            f"attempt={attempt} runner={runner_id}",
            flush=True,
        )


def _clear_runner_state_without_container(
    configured_volumes: dict[str, str],
) -> None:
    volume = configured_volumes.get("runner_state")
    if volume is None:
        print("runner_state is not configured; nothing to purge", flush=True)
        return
    if not _volume_exists(volume):
        print("runner_state volume does not exist; nothing to purge", flush=True)
        return

    mountpoint = _volume_mountpoint(volume)
    if mountpoint is None:
        raise DownError(
            f"cannot resolve mountpoint for runner_state volume {volume}"
        )

    try:
        root = mountpoint.resolve(strict=True)
    except OSError as exc:
        raise DownError(
            f"cannot resolve runner_state mountpoint {mountpoint}: {exc}"
        ) from exc

    if not root.is_dir():
        raise DownError(
            f"runner_state mountpoint is not a directory: {root}"
        )

    recovery_names = {
        "submission.json",
        "submission.json.tmp",
        "runner.lock",
    }

    def scan() -> list[Path]:
        found: list[Path] = []
        for name in sorted(recovery_names):
            found.extend(root.rglob(name))
        return sorted(set(found), key=lambda p: str(p))

    targets = scan()
    if not targets:
        print(
            f"runner recovery state already empty in volume {volume}",
            flush=True,
        )
        return

    for target in targets:
        if target.is_dir() and not target.is_symlink():
            raise DownError(
                f"refusing to remove recovery marker directory: {target}"
            )
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise DownError(
                f"cannot remove runner recovery marker {target}: {exc}"
            ) from exc
        else:
            print(
                f"removed runner recovery marker: "
                f"{target.relative_to(root)}",
                flush=True,
            )

    remaining = scan()
    if remaining:
        raise DownError(
            "runner recovery state survived down: "
            + ", ".join(str(path.relative_to(root)) for path in remaining)
        )

    print(
        f"runner recovery state verified empty in volume {volume}",
        flush=True,
    )
def _verify_no_execution_resources(project: str) -> None:
    project_containers = _container_ids(
        f"label=com.docker.compose.project={project}"
    )

    problems: list[str] = []
    if project_containers:
        problems.append(
            "project containers=" + ",".join(sorted(project_containers))
        )
    if problems:
        raise DownError(
            "down verification failed; execution resources remain: "
            + "; ".join(problems)
        )


def main() -> int:
    config = _compose_config()
    project = config["name"]
    configured_volumes = _configured_volumes(config)

    # Snapshot only. No resource creation is allowed anywhere in this script.
    preexisting_volumes = {
        actual
        for actual in configured_volumes.values()
        if _volume_exists(actual)
    }

    print(
        f"Down project {project!r}: stop/remove only; nothing will be started or created.",
        flush=True,
    )

    # Freeze the source of new mutations first: force-remove runner/auth/doctor
    # one-offs that already exist.
    runner_containers = _container_ids(
        f"label=com.docker.compose.project={project}",
        "label=com.docker.compose.service=runner",
    )
    _remove_containers(runner_containers)

    # If postgres already happens to be running, close DB 'running' rows before
    # stopping it. If it is not running, do not start it.
    postgres_container = _postgres_running_container(project)
    _interrupt_running_rows_if_possible(postgres_container)

    # Purge local recovery markers directly from an already-existing volume.
    _clear_runner_state_without_container(configured_volumes)

    # Destroy owned libvirt attempts while the trusted broker is still available.
    _run([sys.executable, "scripts/workstation_broker.py", "stop"])

    # This is the only Compose lifecycle command: DOWN. No --volumes.
    _run(
        [
            "docker",
            "compose",
            "--profile",
            "runner",
            "--profile",
            "app-tunnels",
            "down",
            "--remove-orphans",
            "--timeout",
            "10",
        ]
    )

    # Final idempotent cleanup/verification.
    _verify_no_execution_resources(project)

    # Prove down did not delete any persistent volume that existed beforehand.
    lost_volumes = sorted(
        name for name in preexisting_volumes if not _volume_exists(name)
    )
    if lost_volumes:
        raise DownError(
            "persistent volume(s) disappeared during down: "
            + ", ".join(lost_volumes)
        )

    preserved = ", ".join(sorted(preexisting_volumes)) or "(none existed)"
    print(
        "down complete: zero active project containers and workstation attempts; "
        f"pre-existing volumes preserved: {preserved}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"down failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

\
#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT_IMAGE_LABEL = "io.gpttrace.project=gpt-trace-extractor"
DELETE_VOLUMES = ("postgres_data", "runner_state", "browser_profile")
PRESERVE_VOLUMES = ("benchmark_sources",)
ATTEMPTS = Path("/var/lib/libvirt/images/gpt-trace/attempts")


class ThrowError(RuntimeError):
    pass


def show(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd), flush=True)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    show(cmd)
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode != 0:
        if capture:
            if proc.stdout:
                sys.stderr.write(proc.stdout)
            if proc.stderr:
                sys.stderr.write(proc.stderr)
        raise ThrowError(
            f"command failed with exit code {proc.returncode}: {' '.join(cmd)}"
        )
    return proc


def compose_config() -> dict:
    proc = run(
        [
            "docker",
            "compose",
            "--profile",
            "runner",
            "--profile",
            "app-tunnels",
            "--profile",
            "benchmark-fetch",
            "config",
            "--format",
            "json",
        ],
        capture=True,
    )
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ThrowError("docker compose config returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ThrowError("docker compose config returned a non-object")
    return value


def configured_volumes(config: dict) -> dict[str, str]:
    raw = config.get("volumes")
    if not isinstance(raw, dict):
        raise ThrowError("Compose volumes configuration is missing")
    result: dict[str, str] = {}
    for logical, item in raw.items():
        if not isinstance(logical, str) or not isinstance(item, dict):
            raise ThrowError("invalid Compose volume configuration")
        actual = item.get("name")
        if not isinstance(actual, str) or not actual:
            raise ThrowError(f"Compose volume {logical!r} has no resolved name")
        result[logical] = actual
    missing = (set(DELETE_VOLUMES) | set(PRESERVE_VOLUMES)) - set(result)
    if missing:
        raise ThrowError(f"required Compose volumes are missing: {sorted(missing)!r}")
    return result


def volume_exists(name: str) -> bool:
    return (
        run(["docker", "volume", "inspect", name], check=False, capture=True).returncode
        == 0
    )


def remove_volume(name: str) -> None:
    proc = run(["docker", "volume", "rm", "-f", name], check=False, capture=True)
    if proc.returncode != 0 and volume_exists(name):
        if proc.stdout:
            sys.stderr.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        raise ThrowError(f"failed to remove Docker volume {name}")


def tracked_files_under(path: Path) -> set[Path]:
    try:
        relative = path.relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise ThrowError(f"path is outside repository root: {path}") from exc

    proc = run(
        ["git", "ls-files", "-z", "--", relative],
        capture=True,
    )
    tracked: set[Path] = set()
    for item in proc.stdout.split("\0"):
        if not item:
            continue
        candidate = ROOT / item
        try:
            candidate.relative_to(path)
        except ValueError as exc:
            raise ThrowError(
                f"git returned tracked path outside requested directory: {item}"
            ) from exc
        tracked.add(candidate)
    return tracked


def clear_generated_directory(path: Path) -> None:
    # Delete generated entries while preserving every Git-tracked file.
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ThrowError(f"refusing to clear non-directory path: {path}")

    tracked = tracked_files_under(path)
    entries = sorted(
        path.rglob("*"),
        key=lambda entry: (len(entry.relative_to(path).parts), str(entry)),
        reverse=True,
    )
    for entry in entries:
        if entry in tracked:
            continue
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            try:
                entry.rmdir()
            except OSError:
                # It still contains a tracked file or one of its parent directories.
                pass
        else:
            raise ThrowError(
                f"refusing to remove special filesystem entry: {entry}"
            )


def verify_generated_directory_clean(path: Path) -> None:
    # Fail if any non-tracked file/symlink/special entry survived the wipe.
    if not path.is_dir() or path.is_symlink():
        raise ThrowError(f"expected repository directory after wipe: {path}")

    tracked = tracked_files_under(path)
    unexpected: list[str] = []
    for entry in sorted(path.rglob("*")):
        if entry.is_dir() and not entry.is_symlink():
            continue
        if entry not in tracked:
            unexpected.append(str(entry.relative_to(ROOT)))

    if unexpected:
        raise ThrowError(
            "generated entries survived wipe: " + ", ".join(unexpected)
        )


def remove_tree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise ThrowError(f"refusing to remove non-directory path: {path}")
    shutil.rmtree(path)


def project_container_ids(project: str) -> list[str]:
    proc = run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        capture=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def project_image_ids() -> list[str]:
    proc = run(
        [
            "docker",
            "image",
            "ls",
            "--filter",
            f"label={PROJECT_IMAGE_LABEL}",
            "--format",
            "{{.ID}}",
        ],
        capture=True,
    )
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


def remove_project_images() -> None:
    ids = project_image_ids()
    if ids:
        run(["docker", "image", "rm", "-f", *ids])


def verify_attempts_empty() -> None:
    if not ATTEMPTS.exists():
        return
    if ATTEMPTS.is_symlink() or not ATTEMPTS.is_dir():
        raise ThrowError(f"unexpected workstation attempts path: {ATTEMPTS}")
    remaining = sorted(entry.name for entry in ATTEMPTS.iterdir())
    if remaining:
        raise ThrowError(
            "workstation attempts survived destroy_all: " + ", ".join(remaining)
        )




def main() -> int:
    config = compose_config()
    project = config.get("name")
    if not isinstance(project, str) or not project:
        raise ThrowError("Compose project name is missing")
    volumes = configured_volumes(config)

    preserved_before = {
        logical: volume_exists(volumes[logical])
        for logical in PRESERVE_VOLUMES
    }

    print(
        "WARNING: destructive inter-generation reset.\n"
        "Deletes: active project containers/VM attempts, postgres_data, runner_state, "
        "browser_profile, exports, host runtime state, host broker venv, and final "
        "project Docker images.\n"
        "Preserves: benchmark_sources, Kali download/golden image, BuildKit cache, "
        ".env, .secrets and App/tunnel registration.",
        flush=True,
    )
    answer = input("Type THROW to continue: ")
    if answer != "THROW":
        raise SystemExit("aborted")

    # Reuse the canonical shutdown path: it terminalizes running DB rows,
    # clears recovery markers, destroys all project-owned libvirt/nft attempts,
    # and removes Compose containers/networks without touching persistent volumes.
    run([sys.executable, "scripts/down.py"])

    for logical in DELETE_VOLUMES:
        actual = volumes[logical]
        if volume_exists(actual):
            print(f"removing {logical}: {actual}", flush=True)
            remove_volume(actual)

    clear_generated_directory(ROOT / "exports")
    remove_tree(ROOT / "state")
    remove_tree(ROOT / ".venv-workstation-broker")

    # Runtime images are executable V2 artifacts. Remove them, but keep the
    # dedicated BuildKit cache so unchanged build layers remain cheap.
    remove_project_images()

    containers = project_container_ids(project)
    if containers:
        raise ThrowError(
            "project containers survived wipe: " + ", ".join(containers)
        )

    for logical in DELETE_VOLUMES:
        actual = volumes[logical]
        if volume_exists(actual):
            raise ThrowError(f"{logical} survived wipe: {actual}")

    for logical, existed in preserved_before.items():
        actual = volumes[logical]
        if existed and not volume_exists(actual):
            raise ThrowError(
                f"preserved upstream cache volume disappeared: {logical} ({actual})"
            )

    verify_generated_directory_clean(ROOT / "exports")
    if (ROOT / "state").exists():
        raise ThrowError("host runtime state directory survived wipe")
    if (ROOT / ".venv-workstation-broker").exists():
        raise ThrowError("host broker venv survived wipe")
    verify_attempts_empty()

    images = project_image_ids()
    if images:
        raise ThrowError(
            "final project Docker images survived wipe: " + ", ".join(images)
        )

    print(
        "throw complete: mutable generation state removed; pinned benchmark sources, "
        "Kali image/cache and BuildKit cache preserved.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"throw failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

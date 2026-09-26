#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

BUILDER_NAME = "gpt-trace-extractor-builder"
PROJECT_IMAGE_LABEL = "io.gpttrace.project=gpt-trace-extractor"
PROFILES = ("runner",)


def verify_host_requirements(root: Path) -> None:
    run([sys.executable, str(root / "scripts/host_requirements.py"), "--build"])


def build_host_broker(root: Path) -> None:
    venv = root / ".venv-workstation-broker"
    python = venv / "bin/python"
    if venv.exists() and not python.is_file():
        shutil.rmtree(venv)
    run([sys.executable, "-m", "venv", str(venv)])
    run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
         "-e", str(root / "apps/workstation-broker")])


def compose_service_image(root: Path, service: str) -> str:
    rendered = run(["docker", "compose", "config", "--format", "json"], capture=True).stdout
    try:
        config = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise RuntimeError("docker compose config returned invalid JSON") from exc
    if not isinstance(config, dict):
        raise RuntimeError("docker compose config did not return an object")
    project = config.get("name")
    services = config.get("services")
    if not isinstance(project, str) or not project or not isinstance(services, dict):
        raise RuntimeError("docker compose config is missing project/services metadata")
    service_config = services.get(service)
    if not isinstance(service_config, dict):
        raise RuntimeError(f"docker compose service is missing: {service}")
    image = service_config.get("image")
    if image is None:
        image = f"{project}-{service}"
    if not isinstance(image, str) or not image.strip():
        raise RuntimeError(f"cannot resolve image name for Compose service {service}")
    return image.strip()


def verify_manifests(root: Path) -> None:
    image = compose_service_image(root, "kali-workstation-controller")
    inspected = run(["docker", "image", "inspect", image], check=False, capture=True)
    if inspected.returncode != 0:
        detail = (inspected.stderr or inspected.stdout).strip()[:1000]
        raise RuntimeError(
            f"built Compose image is missing for kali-workstation-controller: {image}"
            + (f": {detail}" if detail else "")
        )
    code = (
        "from kali_workstation.contracts import manifest,canonical_bytes; "
        "import json,pathlib; "
        "p=pathlib.Path('/app/tool-manifest.json'); "
        "assert canonical_bytes(manifest())==canonical_bytes(json.loads(p.read_text()))"
    )
    run(["docker", "run", "--rm", "--entrypoint", "python", image, "-c", code])


def build_workstation_base_image(root: Path) -> None:
    run([sys.executable, str(root / "infra/workstation/image/build.py")])


def verify_workstation_image(root: Path) -> None:
    run([sys.executable, str(root / "infra/workstation/image/build.py")])


def build_control_plane(root: Path) -> None:
    build(root)


def run(argv: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(argv), flush=True)
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
    )


def builder_exists() -> bool:
    proc = subprocess.run(
        ["docker", "buildx", "inspect", BUILDER_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def ensure_builder(root: Path) -> None:
    if not builder_exists():
        config = root / "infra" / "buildkit" / "buildkitd.toml"
        run(
            [
                "docker",
                "buildx",
                "create",
                "--name",
                BUILDER_NAME,
                "--driver",
                "docker-container",
                "--buildkitd-config",
                str(config),
            ]
        )

    # The docker-container driver has to obtain the BuildKit image on first use.
    # Bootstrap separately so transient registry/auth timeouts are retried here,
    # rather than causing the whole Compose build to fail immediately.
    delays = (0, 3, 8, 15)
    last_rc = 1
    for attempt, delay in enumerate(delays, 1):
        if delay:
            import time
            time.sleep(delay)
        print(
            f"+ bootstrap builder {BUILDER_NAME} "
            f"(attempt {attempt}/{len(delays)})",
            flush=True,
        )
        proc = subprocess.run(
            ["docker", "buildx", "inspect", BUILDER_NAME, "--bootstrap"],
            text=True,
        )
        last_rc = proc.returncode
        if last_rc == 0:
            return

    raise subprocess.CalledProcessError(
        last_rc,
        ["docker", "buildx", "inspect", BUILDER_NAME, "--bootstrap"],
    )


def prune_project_dangling_images() -> None:
    # No -a: only dangling images. Positive image label makes this project-specific.
    run(
        [
            "docker",
            "image",
            "prune",
            "--force",
            "--filter",
            f"label={PROJECT_IMAGE_LABEL}",
        ]
    )


def build(root: Path) -> None:
    ensure_builder(root)
    argv = ["docker", "compose"]
    for profile in PROFILES:
        argv += ["--profile", profile]
    argv += ["build", "--builder", BUILDER_NAME]
    run(argv)

    # Safe after a successful build: old labeled project images become dangling.
    prune_project_dangling_images()

    # GC is already configured on the dedicated builder. Trigger a sweep too.
    # Prefer size-based pruning when supported by the installed buildx.
    help_proc = subprocess.run(
        ["docker", "buildx", "prune", "--help"],
        check=True,
        text=True,
        capture_output=True,
    )
    if "--max-used-space" in help_proc.stdout:
        run(
            [
                "docker",
                "buildx",
                "--builder",
                BUILDER_NAME,
                "prune",
                "--force",
                "--max-used-space",
                "4GB",
            ]
        )
    else:
        # Compatibility fallback: still project-isolated because this is a
        # dedicated builder, but age-based instead of strict size-based.
        run(
            [
                "docker",
                "buildx",
                "--builder",
                BUILDER_NAME,
                "prune",
                "--force",
                "--filter",
                "until=24h",
            ]
        )


def clean(root: Path) -> None:
    prune_project_dangling_images()
    if builder_exists():
        run(
            [
                "docker",
                "buildx",
                "--builder",
                BUILDER_NAME,
                "prune",
                "--all",
                "--force",
            ]
        )
    else:
        print(f"builder {BUILDER_NAME!r} does not exist; no project build cache to prune")


def status(root: Path) -> None:
    print(f"builder={BUILDER_NAME}")
    if builder_exists():
        run(["docker", "buildx", "--builder", BUILDER_NAME, "du"])
    else:
        print("dedicated builder: not created yet")

    print()
    print("labeled project images:")
    proc = run(
        [
            "docker",
            "image",
            "ls",
            "--filter",
            f"label={PROJECT_IMAGE_LABEL}",
            "--format",
            "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}",
        ],
        capture=True,
    )
    print(proc.stdout, end="")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hybrid host/KVM plus project-isolated Docker build/cache lifecycle."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--clean", action="store_true")
    mode.add_argument("--status", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if args.clean:
        clean(root)
    elif args.status:
        status(root)
    else:
        verify_host_requirements(root)
        build_host_broker(root)
        build_control_plane(root)
        verify_manifests(root)
        build_workstation_base_image(root)
        verify_workstation_image(root)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"build lifecycle command failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)

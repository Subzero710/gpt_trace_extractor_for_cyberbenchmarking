#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

BUILDER_NAME = "default"
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
         "-e", str(root / "shared"), "-e", str(root / "apps/workstation-broker")])


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



def verify_registry_manifest_pin(root: Path) -> None:
    manifest = json.loads(
        (root / 'apps/kali-workstation/tool-manifest.json').read_text(encoding='utf-8')
    )
    registry = json.loads(
        (root / 'apps/registry/apps.json').read_text(encoding='utf-8')
    )
    digest = hashlib.sha256(
        json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(',', ':')
        ).encode('utf-8')
    ).hexdigest()
    matches = [
        app for app in registry.get('apps', [])
        if isinstance(app, dict) and app.get('id') == 'kali-workstation'
    ]
    if len(matches) != 1 or matches[0].get('manifest_sha256') != digest:
        raise RuntimeError(
            f'kali-workstation registry manifest pin is stale; expected {digest}'
        )



def verify_storage_runtime(root: Path) -> None:
    image = compose_service_image(root, "storage")
    inspected = run(["docker", "image", "inspect", image], check=False, capture=True)
    if inspected.returncode != 0:
        detail = (inspected.stderr or inspected.stdout).strip()[:1000]
        raise RuntimeError(
            f"built Compose image is missing for storage: {image}"
            + (f": {detail}" if detail else "")
        )
    code = (
        "import greenlet; "
        "from sqlalchemy.ext.asyncio import create_async_engine; "
        "assert callable(create_async_engine)"
    )
    run(["docker", "run", "--rm", "--entrypoint", "python", image, "-c", code])



def verify_teacher_browser_runtime(root: Path) -> None:
    image = compose_service_image(root, "teacher-browser")
    inspected = run(["docker", "image", "inspect", image], check=False, capture=True)
    if inspected.returncode != 0:
        detail = (inspected.stderr or inspected.stdout).strip()[:1000]
        raise RuntimeError(
            f"built Compose image is missing for teacher-browser: {image}"
            + (f": {detail}" if detail else "")
        )
    probe = r"""
set -eu
command -v Xvnc >/dev/null
command -v kasmvncpasswd >/dev/null
version="$(Xvnc -version 2>&1 || true)"
printf '%s\n' "$version" | grep -F 'KasmVNC 1.5.0' >/dev/null
! command -v x11vnc >/dev/null 2>&1
! command -v websockify >/dev/null 2>&1
test ! -d /usr/share/novnc
grep -Eq '^  websocket_port: 6902$' /etc/kasmvnc/kasmvnc.yaml
grep -Eq '^    require_ssl: true$' /etc/kasmvnc/kasmvnc.yaml
test -x /usr/local/bin/kasm-healthcheck
test -x /usr/local/bin/kasm-auth-proxy
test -x /usr/local/bin/auth-proxy-healthcheck
/usr/bin/python3 -c 'import aiohttp'
"""
    run(["docker", "run", "--rm", "--entrypoint", "sh", image, "-ec", probe])

def verify_manifests(root: Path) -> None:
    verify_storage_runtime(root)
    verify_teacher_browser_runtime(root)
    verify_registry_manifest_pin(root)
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
    run([sys.executable, str(root / "infra/workstation/image/build.py"), "--local"])


def verify_workstation_image(root: Path) -> None:
    run([sys.executable, str(root / "infra/workstation/image/build.py"), "--verify"])


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


def ensure_builder(root: Path) -> None:
    """Require Docker Engine's built-in builder with isolated RUN networking."""
    inspected = run(["docker", "buildx", "inspect", BUILDER_NAME], capture=True).stdout
    driver = next((line for line in inspected.splitlines() if line.startswith("Driver:")), "")
    if driver.split(":", 1)[-1].strip() != "docker":
        raise RuntimeError("the default Buildx builder must use the Docker Engine driver")


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

    # Docker Engine's BuildKit cache is shared across projects.
    # Pruning it from this project could delete unrelated cached layers.


def clean(root: Path) -> None:
    prune_project_dangling_images()
    print("Docker Engine build cache is shared and was not pruned.")


def status(root: Path) -> None:
    ensure_builder(root)
    print(f"builder={BUILDER_NAME} (Docker Engine driver)")
    print("BuildKit cache is shared with other projects; no project-only cache usage is available.")

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
    parser = argparse.ArgumentParser(description="Role-aware source build and project build-cache lifecycle.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--clean", action="store_true")
    mode.add_argument("--status", action="store_true")
    args = parser.parse_args()
    import distributed
    if args.clean or args.status:
        cfg = distributed.config(credentials=False)
        distributed.host(cfg["deployment"]["role"], cfg, build_tools=True)
        (clean if args.clean else status)(Path(__file__).resolve().parents[1])
    else:
        distributed.main(["build"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"build lifecycle command failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)

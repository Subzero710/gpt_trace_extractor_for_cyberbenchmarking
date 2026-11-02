#!/usr/bin/env python3
"""CI discovery and syntax checks. Validate behavior and grammar, not snapshot values."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tokenize
import tomllib
from pathlib import Path


def components(root: Path, *, docker_only: bool = False) -> list[str]:
    """Discover every installable app that has executable pytest modules.

    Python test jobs are derived from test directories and package metadata;
    image build jobs are derived independently from Dockerfiles. Neither
    depends on snapshot service lists, package versions or test counts.
    """
    root = Path(root)
    app_root = root / "apps"
    if not app_root.is_dir() or app_root.is_symlink():
        raise ValueError("apps directory is missing or unsafe")
    discovered: list[str] = []
    for component in sorted(app_root.iterdir()):
        if component.is_symlink():
            raise ValueError(f"untrusted component directory: {component}")
        if not component.is_dir():
            continue
        project = component / "pyproject.toml"
        tests = component / "tests"
        dockerfile = component / "Dockerfile"
        if docker_only:
            if dockerfile.is_symlink():
                raise ValueError(f"untrusted Dockerfile: {dockerfile}")
            selected = dockerfile.is_file()
        else:
            if tests.is_symlink():
                raise ValueError(f"untrusted component tests path: {tests}")
            selected = tests.is_dir() and any(tests.rglob("test_*.py"))
            if selected:
                if project.is_symlink() or not project.is_file():
                    raise ValueError(f"testable app has no trusted Python metadata: {component}")
                with project.open("rb") as source:
                    metadata = tomllib.load(source)
                if not isinstance(metadata.get("project"), dict):
                    raise ValueError(f"invalid Python project metadata: {project}")
        if selected:
            discovered.append(component.relative_to(root).as_posix())
    if not discovered:
        raise ValueError("no matching testable services or Dockerfiles were discovered")
    return discovered



def _docker_copy_sources(dockerfile: Path) -> tuple[str, ...]:
    """Return local build-context sources referenced by COPY/ADD instructions."""
    logical: list[str] = []
    pending = ""
    for raw in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending = pending + stripped if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)

    sources: list[str] = []
    for instruction in logical:
        head, separator, payload = instruction.partition(" ")
        if not separator or head.upper() not in {"COPY", "ADD"}:
            continue
        payload = payload.strip()
        from_stage = False
        while payload.startswith("--"):
            flag, separator, remainder = payload.partition(" ")
            if not separator:
                raise ValueError(f"invalid Docker {head} flags: {dockerfile}")
            payload = remainder.lstrip()
            if flag == "--from":
                _stage, separator, remainder = payload.partition(" ")
                if not separator:
                    raise ValueError(f"invalid Docker {head} --from flag: {dockerfile}")
                payload = remainder.lstrip()
                from_stage = True
            elif flag.startswith("--from="):
                from_stage = True
        if from_stage:
            continue
        if payload.startswith("["):
            values = json.loads(payload)
            if not isinstance(values, list) or len(values) < 2 or any(not isinstance(item, str) for item in values):
                raise ValueError(f"invalid JSON-form Docker {head}: {dockerfile}")
            candidates = values[:-1]
        else:
            tokens = shlex.split(payload, comments=False, posix=True)
            if len(tokens) < 2:
                raise ValueError(f"invalid Docker {head}: {dockerfile}")
            candidates = tokens[:-1]
        for source in candidates:
            if source.startswith(("http://", "https://")):
                continue
            if not source or source.startswith("/") or "\x00" in source or "$" in source:
                raise ValueError(f"unsupported local Docker source {source!r}: {dockerfile}")
            relative = Path(source)
            if ".." in relative.parts:
                raise ValueError(f"Docker source escapes its context: {source!r}")
            sources.append(source)
    return tuple(sources)


def _context_contains_source(context: Path, source: str) -> bool:
    import glob
    pattern = context / source
    matches = [Path(item) for item in glob.glob(str(pattern), recursive=True)]
    if not matches and not any(char in source for char in "*?["):
        matches = [pattern] if pattern.exists() else []
    context = context.resolve()
    return bool(matches) and all(item.resolve().is_relative_to(context) for item in matches)


def docker_context(root: Path, component: str) -> str:
    """Derive the unique Docker build context from the Dockerfile's local COPY/ADD sources."""
    root = Path(root).resolve()
    relative = Path(component)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"invalid component path: {component}")
    directory = (root / relative).resolve()
    if not directory.is_relative_to(root) or not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"component directory is missing or unsafe: {component}")
    dockerfile = directory / "Dockerfile"
    if dockerfile.is_symlink() or not dockerfile.is_file():
        raise ValueError(f"trusted Dockerfile is missing: {dockerfile}")
    sources = _docker_copy_sources(dockerfile)
    if not sources:
        raise ValueError(f"Dockerfile has no local COPY/ADD source to derive context: {dockerfile}")
    candidates = []
    for candidate in (root, directory):
        if all(_context_contains_source(candidate, source) for source in sources):
            candidates.append(candidate)
    if len(candidates) != 1:
        raise ValueError(
            f"Docker build context is not uniquely derivable for {component}: "
            + ", ".join(str(path) for path in candidates)
        )
    selected = candidates[0]
    return "." if selected == root else selected.relative_to(root).as_posix()



def tracked_paths(root: Path) -> list[Path]:
    """Use Git's actual tracked files, not filesystem snapshots or magic counts."""
    process = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--",
         "*.py", "*.json", "*.toml", "*.yaml", "*.yml"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    paths = []
    for raw in process.stdout.split(b"\x00"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid tracked file path: {relative}")
        paths.append(relative)
    if not paths:
        raise ValueError("no tracked source/configuration files found")
    return paths


def validate_file(root: Path, relative: Path) -> bool:
    """Parse checked-in code/configurations without asserting their current values.

    Intentional malformed samples under test fixtures and immutable upstream
    source snapshots are *data*, not active configuration or Python modules.
    """
    if {"fixtures", "upstream"} & set(relative.parts):
        return False
    file = root / relative
    if file.is_symlink() or not file.is_file():
        raise ValueError(f"tracked source is not a regular file: {relative}")
    extension = file.suffix.lower()
    if extension == ".py":
        with tokenize.open(file) as stream:
            source = stream.read()
        compile(source, str(relative), "exec", dont_inherit=True)
    elif extension == ".toml":
        with file.open("rb") as stream:
            tomllib.load(stream)
    elif extension == ".json":
        with file.open("r", encoding="utf-8") as stream:
            json.load(stream)
    elif extension in {".yaml", ".yml"}:
        import yaml  # Dependency installed explicitly in the validation job.
        with file.open("r", encoding="utf-8") as stream:
            yaml.safe_load(stream)
    else:
        raise ValueError(f"unexpected file extension: {relative}")
    return True


def validate(root: Path) -> int:
    parsed = sum(validate_file(root, path) for path in tracked_paths(root))
    if not parsed:
        raise ValueError("no active source/configuration files were parsed")
    return parsed


def gate(needs: dict) -> None:
    """A required check must fail for *every* unsuccessful or skipped dependency."""
    if not isinstance(needs, dict) or not needs:
        raise ValueError("missing prerequisite job results")
    failures = {
        name: value.get("result") if isinstance(value, dict) else "invalid"
        for name, value in needs.items()
        if not isinstance(value, dict) or value.get("result") != "success"
    }
    if failures:
        raise ValueError("required CI jobs did not succeed: " + json.dumps(failures, sort_keys=True))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("matrix", "validate", "gate", "docker-context"))
    parser.add_argument("--mode", choices=("tests", "docker"), default="tests")
    parser.add_argument("--component")
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    if args.command == "matrix":
        print(json.dumps(components(args.root, docker_only=args.mode == "docker"), separators=(",", ":")))
    elif args.command == "validate":
        print(f"Validated syntax of {validate(args.root)} tracked source/configuration files")
    elif args.command == "docker-context":
        if not args.component:
            raise ValueError("--component is required for docker-context")
        print(docker_context(args.root, args.component))
    else:
        gate(json.loads(os.environ["CI_NEEDS"]))
        print("All CI prerequisites succeeded")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, SyntaxError, UnicodeError) as exc:
        print(f"CI validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

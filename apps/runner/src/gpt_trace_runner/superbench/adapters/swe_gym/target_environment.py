"""Authoritative target interpreter identities used by acquisition and replay.

All cross-target decisions are derived from immutable Conda lock transactions
and from marker/tag data captured inside the verified Kali golden guest.  The
fetch host is never used as a proxy for the target kernel, glibc, architecture,
Python patch version, ABI, or wheel compatibility set.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from packaging.markers import default_environment
from packaging.tags import compatible_tags, cpython_tags, sys_tags

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FULL_PYTHON = re.compile(r"(\d+)\.(\d+)\.(\d+)\Z")
_REQUIRED_MARKERS = {
    "implementation_name", "implementation_version", "os_name",
    "platform_machine", "platform_release", "platform_system",
    "platform_version", "python_full_version", "python_version",
    "platform_python_implementation", "sys_platform",
}


@dataclass(frozen=True)
class TargetEnvironment:
    """Serializable PEP 508 and wheel compatibility identity."""

    markers: dict[str, str]
    tags: tuple[str, ...]
    implementation: str
    abi: str
    architecture: str
    source: str
    interpreter_sha256: str | None = None
    python_artifact_sha256: str | None = None

    @property
    def python_version(self) -> str:
        return self.markers["python_version"]

    @property
    def python_full_version(self) -> str:
        return self.markers["python_full_version"]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": 2,
            "markers": dict(sorted(self.markers.items())),
            "tags": list(self.tags),
            "implementation": self.implementation,
            "abi": self.abi,
            "architecture": self.architecture,
            "source": self.source,
            "interpreter_sha256": self.interpreter_sha256,
            "python_artifact_sha256": self.python_artifact_sha256,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TargetEnvironment":
        if not isinstance(value, dict) or value.get("schema") not in {1, 2}:
            raise ValueError("target environment schema is unsupported")
        markers = value.get("markers")
        tags = value.get("tags")
        if not isinstance(markers, dict) or set(markers) != _REQUIRED_MARKERS:
            raise ValueError("target marker environment is incomplete")
        if not all(isinstance(key, str) and isinstance(item, str) and item
                   for key, item in markers.items()):
            raise ValueError("target marker values are invalid")
        if _FULL_PYTHON.fullmatch(markers["python_full_version"]) is None:
            raise ValueError("target Python full version is invalid")
        if markers["python_version"] != ".".join(markers["python_full_version"].split(".")[:2]):
            raise ValueError("target Python marker versions disagree")
        if not isinstance(tags, list) or not tags or len(tags) != len(set(tags)):
            raise ValueError("target wheel tags are incomplete")
        if not all(isinstance(tag, str) and tag for tag in tags):
            raise ValueError("target wheel tag is invalid")
        implementation = value.get("implementation")
        abi = value.get("abi")
        architecture = value.get("architecture")
        if not isinstance(implementation, str) or not implementation:
            raise ValueError("target implementation is invalid")
        if not isinstance(abi, str) or not abi:
            raise ValueError("target ABI is invalid")
        if not isinstance(architecture, str) or not architecture:
            raise ValueError("target architecture is invalid")
        interpreter = value.get("interpreter_sha256")
        artifact = value.get("python_artifact_sha256")
        for label, digest in (("interpreter", interpreter), ("Python artifact", artifact)):
            if digest is not None and (not isinstance(digest, str) or SHA256.fullmatch(digest) is None):
                raise ValueError(f"target {label} digest is invalid")
        return cls(
            markers=dict(markers), tags=tuple(tags), implementation=implementation,
            abi=abi, architecture=architecture, source=str(value.get("source", "unknown")),
            interpreter_sha256=interpreter, python_artifact_sha256=artifact,
        )


def _cpython_abi(full_version: str) -> str:
    match = _FULL_PYTHON.fullmatch(full_version)
    if match is None:
        raise ValueError("target Python identity must include major, minor and patch")
    return "cp" + match.group(1) + match.group(2)


def _platforms_from_tags(tags: Iterable[str]) -> tuple[str, ...]:
    platforms: list[str] = []
    for raw in tags:
        parts = str(raw).split("-", 2)
        if len(parts) != 3 or not parts[2]:
            raise ValueError("invalid target wheel tag: " + str(raw))
        for platform_tag in parts[2].split("."):
            if platform_tag and platform_tag != 'any' and platform_tag not in platforms:
                platforms.append(platform_tag)
    if not platforms:
        raise ValueError("target wheel compatibility set has no platforms")
    return tuple(platforms)


def _retarget_markers(base: TargetEnvironment, full_version: str) -> dict[str, str]:
    match = _FULL_PYTHON.fullmatch(full_version)
    if match is None:
        raise ValueError("target Python identity must include major, minor and patch")
    markers = dict(base.markers)
    markers.update({
        "python_version": f"{match.group(1)}.{match.group(2)}",
        "python_full_version": full_version,
        "implementation_name": "cpython",
        "implementation_version": full_version,
        "platform_python_implementation": "CPython",
    })
    return markers


def conda_target(*, full_version: str, base_target: TargetEnvironment,
                 python_artifact_sha256: str, source: str) -> TargetEnvironment:
    """Retarget verified guest platform evidence to one exact locked CPython.

    Kernel/OS/architecture/manylinux compatibility is copied from the golden
    guest.  Only Python-specific marker and interpreter-tag components change.
    """
    if not isinstance(base_target, TargetEnvironment):
        raise TypeError("base_target must be a verified TargetEnvironment")
    if SHA256.fullmatch(str(python_artifact_sha256)) is None:
        raise ValueError("locked Python artifact SHA-256 is invalid")
    abi = _cpython_abi(full_version)
    major, minor, _patch = (int(item) for item in full_version.split("."))
    platforms = _platforms_from_tags(base_target.tags)
    generated = list(cpython_tags((major, minor), abis=(abi,), platforms=platforms))
    generated.extend(compatible_tags((major, minor), platforms=platforms))
    tags = tuple(dict.fromkeys(str(tag) for tag in generated))
    if not tags:
        raise ValueError("locked target produced no wheel compatibility tags")
    return TargetEnvironment(
        markers=_retarget_markers(base_target, full_version), tags=tags,
        implementation="cpython", abi=abi, architecture=base_target.architecture,
        source=source, python_artifact_sha256=python_artifact_sha256,
    )


def guest_target(provenance: dict[str, Any]) -> TargetEnvironment:
    """Load the exact target identity emitted by the verified golden guest."""
    if not isinstance(provenance, dict):
        raise ValueError("golden provenance is not an object")
    value = TargetEnvironment.from_dict(provenance["target_environment"])
    if value.source != "verified-target-interpreter":
        raise ValueError("golden target provenance has the wrong source")
    if provenance.get("architecture") != value.architecture:
        raise ValueError("golden architecture and target identity disagree")
    if provenance.get("platform_tags") != list(value.tags):
        raise ValueError("golden platform tags and target identity disagree")
    return value


def capture_current(*, source: str = "verified-target-interpreter") -> TargetEnvironment:
    """Capture marker/tag identity while executing inside the actual target."""
    environment = {key: str(value) for key, value in default_environment().items()}
    if set(environment) != _REQUIRED_MARKERS:
        missing = sorted(_REQUIRED_MARKERS - set(environment))
        extra = sorted(set(environment) - _REQUIRED_MARKERS)
        raise RuntimeError(f"packaging marker environment shape changed; missing={missing}, extra={extra}")
    full_version = platform.python_version()
    if _FULL_PYTHON.fullmatch(full_version) is None:
        raise RuntimeError("target interpreter reports an invalid Python version")
    environment["python_full_version"] = full_version
    environment["python_version"] = ".".join(full_version.split(".")[:2])
    ordered_tags = tuple(dict.fromkeys(str(tag) for tag in sys_tags()))
    if not ordered_tags:
        raise RuntimeError("target interpreter reports no wheel tags")
    first = ordered_tags[0].split("-", 2)
    if len(first) != 3 or not first[1]:
        raise RuntimeError("target interpreter reports an invalid first wheel tag")
    executable = Path(sys.executable).resolve(strict=True)
    return TargetEnvironment(
        markers=environment, tags=ordered_tags, implementation=sys.implementation.name,
        abi=first[1], architecture=platform.machine(), source=source,
        interpreter_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )


def _transaction_python(lock: dict[str, Any], transaction: dict[str, Any]) -> tuple[str, str]:
    artifacts = lock.get("artifacts")
    packages = transaction.get("packages")
    if not isinstance(artifacts, dict) or not isinstance(packages, list):
        raise ValueError("Conda lock transaction is incomplete")
    matches: list[tuple[str, str]] = []
    for digest in packages:
        item = artifacts.get(digest)
        if isinstance(item, dict) and item.get("name") == "python":
            version = str(item.get("version", ""))
            if _FULL_PYTHON.fullmatch(version) is None or SHA256.fullmatch(str(digest)) is None:
                raise ValueError("Conda lock Python package identity is invalid")
            matches.append((version, str(digest)))
    if len(matches) != 1:
        raise ValueError("Conda transaction must contain exactly one Python package")
    return matches[0]


def locked_transaction_target(lock: dict[str, Any], env_hash: str, transaction_key: str,
                              *, base_target: TargetEnvironment) -> TargetEnvironment:
    row = (lock.get("environments") or {}).get(env_hash)
    if not isinstance(row, dict):
        raise ValueError("Conda lock environment is absent: " + str(env_hash))
    transactions = row.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError("Conda lock environment has no transactions")
    selected = [item for item in transactions
                if isinstance(item, dict) and item.get("key") == transaction_key]
    if len(selected) != 1:
        raise ValueError("Conda lock transaction key is absent or ambiguous: " + str(transaction_key))
    full_version, artifact_sha = _transaction_python(lock, selected[0])
    minor = ".".join(full_version.split(".")[:2])
    if selected[0].get("python") != minor:
        raise ValueError("Conda transaction Python summary differs from locked package")
    return conda_target(full_version=full_version, base_target=base_target,
                        python_artifact_sha256=artifact_sha,
                        source="locked-conda:" + env_hash + ":" + transaction_key)


def locked_conda_targets(lock: dict[str, Any], *, base_target: TargetEnvironment) -> dict[str, TargetEnvironment]:
    """Return every lock transaction target keyed by its immutable transaction key."""
    result: dict[str, TargetEnvironment] = {}
    environments = lock.get("environments")
    if not isinstance(environments, dict) or not environments:
        raise ValueError("Conda lock contains no environments")
    for env_hash, row in sorted(environments.items()):
        transactions = row.get("transactions") if isinstance(row, dict) else None
        if not isinstance(transactions, list) or not transactions:
            raise ValueError("Conda lock environment has no transactions: " + str(env_hash))
        for transaction in transactions:
            if not isinstance(transaction, dict) or not isinstance(transaction.get("key"), str):
                raise ValueError("invalid Conda lock transaction")
            key = transaction["key"]
            if key in result:
                raise ValueError("duplicate Conda transaction key: " + key)
            result[key] = locked_transaction_target(lock, env_hash, key, base_target=base_target)
    return result


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"target provenance is not an object: {path}")
    return value

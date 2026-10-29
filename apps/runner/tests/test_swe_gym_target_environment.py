from __future__ import annotations

from gpt_trace_runner.superbench.adapters.swe_gym.target_environment import (
    TargetEnvironment,
    conda_target,
    locked_conda_targets,
)


def _base(platform_tag: str = "manylinux_2_28_x86_64") -> TargetEnvironment:
    markers = {
        "implementation_name": "cpython",
        "implementation_version": "3.13.7",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "platform_release": "fixture-kernel",
        "platform_system": "Linux",
        "platform_version": "fixture-platform",
        "python_full_version": "3.13.7",
        "python_version": "3.13",
        "platform_python_implementation": "CPython",
        "sys_platform": "linux",
    }
    return TargetEnvironment(markers=markers,
        tags=(f"cp313-cp313-{platform_tag}", f"py3-none-{platform_tag}"),
        implementation="cpython", abi="cp313", architecture="x86_64",
        source="verified-target-interpreter", interpreter_sha256="c" * 64)


def test_marker_identity_keeps_the_locked_patch_version() -> None:
    target = conda_target(
        full_version="3.10.14", base_target=_base(),
        python_artifact_sha256="a" * 64, source="fixture",
    )
    assert target.markers["python_version"] == "3.10"
    assert target.markers["python_full_version"] == "3.10.14"
    assert "cp310-cp310-manylinux_2_28_x86_64" in target.tags
    assert TargetEnvironment.from_dict(target.as_dict()) == target


def test_locked_targets_are_transaction_specific() -> None:
    a, b = "a" * 64, "b" * 64
    lock = {
        "artifacts": {
            a: {"name": "python", "version": "3.10.14"},
            b: {"name": "python", "version": "3.10.15"},
        },
        "environments": {
            "first": {"transactions": [{"key": "env-first", "python": "3.10", "packages": [a]}]},
            "second": {"transactions": [{"key": "env-second", "python": "3.10", "packages": [b]}]},
        },
    }
    targets = locked_conda_targets(lock, base_target=_base())
    assert targets["env-first"].python_full_version == "3.10.14"
    assert targets["env-second"].python_full_version == "3.10.15"
    assert targets["env-first"].python_artifact_sha256 == a
    assert targets["env-second"].python_artifact_sha256 == b


def test_target_platforms_come_from_verified_guest_tags() -> None:
    old = conda_target(full_version="3.10.14", base_target=_base("manylinux_2_17_x86_64"),
                       python_artifact_sha256="a" * 64, source="fixture")
    new = conda_target(full_version="3.10.14", base_target=_base("manylinux_2_28_x86_64"),
                       python_artifact_sha256="a" * 64, source="fixture")
    assert old.tags != new.tags

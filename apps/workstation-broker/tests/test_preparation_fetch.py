from __future__ import annotations

import os
import hashlib
import subprocess
import sys
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from workstation_broker import preparation as jobs
from workstation_broker.fetch_egress import FETCH_WORKER_UMASK, fetch_worker_command, source_network
from gpt_trace_transport import local_templates as templates


def _source_tree(root: Path) -> None:
    for relative in jobs.FETCH_SOURCE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith('/Cargo.toml'):
            path.write_bytes((Path(__file__).resolve().parents[3] / relative).read_bytes())
        else:
            path.write_text(relative + "\n")
    for relative in jobs.fetch_runtime_executables(root):
        executable = root / relative
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(relative.encode())
        executable.chmod(0o555)
    # The fixture must satisfy the real attestation contract rather than
    # bypassing the production check or copying a machine-specific binary.
    identity = root / jobs.fetch_runtime_build_identity_path(root)
    identity.parent.mkdir(parents=True, exist_ok=True)
    identity.write_bytes(templates.canonical(templates.fetch_runtime_build_identity(root)) + b"\n")
    identity.chmod(0o444)


def test_known_pre_download_failures_retry_only_before_any_pool_bytes(tmp_path, monkeypatch):
    base = tmp_path / "golden.qcow2"
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    original_stat = Path.stat
    def root_owned_pool(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if Path(path) == pool:
            fields = list(result)
            fields[4] = 0
            return os.stat_result(fields)
        return result
    monkeypatch.setattr(Path, "stat", root_owned_pool)
    state = {
        "phase": "interrupted",
        "result": None,
        "error": "PermissionError: [Errno 13] Permission denied: "
                 "'/private/repo/.venv-workstation-broker/bin/python'",
    }
    assert jobs.pre_download_fetch_retryable(state, base)
    state["error"] = (
        "RuntimeError: trusted system Python cannot import pip required by dependency fetch"
    )
    assert jobs.pre_download_fetch_retryable(state, base)
    state["error"] = "RuntimeError: arbitrary worker failure"
    assert not jobs.pre_download_fetch_retryable(state, base)
    state["error"] = (
        "RuntimeError: trusted system Python cannot import pip required by dependency fetch"
    )
    (pool / "incoming").mkdir()
    assert not jobs.pre_download_fetch_retryable(state, base)


def test_fetch_sources_are_staged_outside_private_repo_and_sealed(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root ownership is required for fetch source sealing")
    private = tmp_path / "private-repo"
    private.mkdir(mode=0o700)
    _source_tree(private)
    (private / "config/preparation.toml").write_text("[acquisition]\ntimeout_seconds = 180\n")
    pool = tmp_path / "dependency-pool"
    pool.mkdir()
    dependency = {"schema": 1, "target_environment": {"schema": 2}, "npm_version": "10.9.9"}
    packages = tmp_path / "kali-packages.txt"
    packages.write_bytes(b"fixture-package 1\n")
    packages.chmod(0o444)
    dependency["apt_package_manifest_sha256"] = hashlib.sha256(packages.read_bytes()).hexdigest()
    manager = SimpleNamespace(source_root=private, base=tmp_path / "golden.qcow2")
    manager.base.write_bytes(b"fixture image")
    manager.base.chmod(0o444)
    status = b"Package: fixture-package\nVersion: 1\nArchitecture: all\nStatus: install ok installed\nProvides: fixture-virtual\n\n"
    original_check_output = jobs.subprocess.check_output
    def read_status(command, **kwargs):
        if command[0] == "virt-cat":
            assert command == ["virt-cat", "-a", str(manager.base), "/var/lib/dpkg/status"]
            return status
        return original_check_output(command, **kwargs)
    monkeypatch.setattr(jobs.subprocess, "check_output", read_status)
    original_run = jobs.subprocess.run
    header_archive = b"fixture header tar"
    def export_headers(command, **kwargs):
        if command[0] == "guestfish":
            assert command[:-1] == ["guestfish", "--ro", "--format=qcow2", "-a", str(manager.base),
                                    "-i", "tar-out", "/usr/include"]
            Path(command[-1]).write_bytes(header_archive)
            return subprocess.CompletedProcess(command, 0)
        return original_run(command, **kwargs)
    monkeypatch.setattr(jobs.subprocess, "run", export_headers)
    original_identity = jobs.golden_dependency_identity
    jobs.golden_dependency_identity = lambda *args, **kwargs: dependency
    try:
        expected_sources = {name: hashlib.sha256((private/name).read_bytes()).hexdigest()
                            for name in jobs.FETCH_SOURCE_FILES}
        source_root, program = jobs.stage_fetch_sources(manager, pool, golden_dependency=dependency,
                                                       expected_sources=expected_sources)
    finally:
        jobs.golden_dependency_identity = original_identity
    assert source_root == pool / "source"
    assert program == source_root / "scripts/superbench_pool.py"
    assert "config/preparation.toml" in jobs.FETCH_SOURCE_FILES
    for relative in jobs.FETCH_SOURCE_FILES:
        original = private / relative
        staged = source_root / relative
        assert staged.read_bytes() == original.read_bytes()
        assert staged.stat().st_uid == 0
        assert stat.S_IMODE(staged.stat().st_mode) == 0o444
    for relative in jobs.fetch_runtime_executables(private):
        executable = source_root / relative
        assert executable.read_bytes() == (private / relative).read_bytes()
        assert executable.stat().st_uid == 0
        assert stat.S_IMODE(executable.stat().st_mode) == 0o555
    identity_relative = jobs.fetch_runtime_build_identity_path(private)
    original_identity = private / identity_relative
    staged_identity = source_root / identity_relative
    assert staged_identity.read_bytes() == original_identity.read_bytes()
    assert staged_identity.stat().st_uid == 0
    assert stat.S_IMODE(staged_identity.stat().st_mode) == 0o444
    assert jobs.verify_fetch_runtime_build_identity(source_root) == templates.fetch_runtime_build_identity(private)
    staged_dependency = source_root / "golden-dependency.json"
    assert staged_dependency.read_bytes() == jobs.canonical(dependency) + b"\n"
    assert staged_dependency.stat().st_uid == 0
    assert (source_root / "golden-packages.txt").read_bytes() == packages.read_bytes()
    assert stat.S_IMODE(staged_dependency.stat().st_mode) == 0o444
    assert (source_root / "golden-dpkg-status").read_bytes() == status
    assert stat.S_IMODE((source_root / "golden-dpkg-status").stat().st_mode) == 0o444
    assert (source_root / "golden-include.tar").read_bytes() == header_archive
    assert stat.S_IMODE((source_root / "golden-include.tar").stat().st_mode) == 0o444
    assert stat.S_IMODE(source_root.stat().st_mode) == 0o555


def test_fetch_worker_uses_system_python_not_broker_venv():
    source = Path(jobs.__file__).read_text()
    physical = source.split("def _prepare(manager, state):", 1)[1].split(
        "def worker(operation_id, slot_fd):", 1
    )[0]
    assert "trusted_fetch_python()" in physical
    assert "state['compatibility']['golden_dependency']" in physical
    assert 'subprocess.Popen(fetch_worker_command(account, interpreter,' in physical
    assert "umask=FETCH_WORKER_UMASK" in physical
    assert "sys.executable" not in physical
    trusted = source.split("def trusted_fetch_python():", 1)[1].split(
        "def stage_fetch_sources", 1
    )[0]
    assert '"-m", "pip", "--version"' in trusted


def test_fetch_worker_umask_is_applied_by_subprocess_not_setpriv():
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    command = fetch_worker_command(account, sys.executable, ("worker.py",))
    assert command[:4] == ["ip", "netns", "exec", source_network()]
    assert "setpriv" in command
    assert not any(argument.startswith("--umask") for argument in command)
    for security_option in ("--clear-groups", "--no-new-privs", "--inh-caps=-all",
                            "--ambient-caps=-all", "--bounding-set=-all"):
        assert security_option in command
    assert FETCH_WORKER_UMASK == 0o077
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c",
         "import os; old = os.umask(0o077); print(oct(old))"],
        capture_output=True, check=True, text=True, umask=FETCH_WORKER_UMASK)
    assert result.stdout.strip() == oct(FETCH_WORKER_UMASK)


def test_resume_compatibility_is_structural_not_fetch_source_identity():
    first = {
        "fetch_kind": "download-only-pool-v4",
        "pool_schema": 4,
        "platform": "linux-x86_64",
        "pins": {"revision": "old"},
        "conda_lock_sha256": "1" * 64,
        "fetcher_sha256": "2" * 64,
        "fetch_sources": {"worker": "2" * 64, "contract": "3" * 64},
        "golden_dependency": {"identity": "old"},
    }
    changed = {
        **first,
        "pins": {"revision": "new"},
        "conda_lock_sha256": "4" * 64,
        "fetcher_sha256": "5" * 64,
        "fetch_sources": {"worker": "5" * 64, "contract": "6" * 64},
        "golden_dependency": {"identity": "new"},
    }
    assert jobs._salvage_identity(first) == jobs._salvage_identity(changed)
    incompatible = {**changed, "pool_schema": 5}
    assert jobs._salvage_identity(first) != jobs._salvage_identity(incompatible)


def test_retained_stage_score_prefers_existing_cas_over_newer_empty_stage(tmp_path):
    rich = tmp_path / "rich"
    empty = tmp_path / "empty"
    rich.mkdir()
    empty.mkdir()
    sha = "a" * 64
    obj = rich / "objects" / "sha256" / sha[:2] / sha
    obj.parent.mkdir(parents=True)
    obj.write_bytes(b"reusable")
    newer = rich.stat().st_mtime_ns + 10_000_000
    os.utime(empty, ns=(newer, newer))
    assert jobs._retained_stage_score(rich) > jobs._retained_stage_score(empty)


def test_fetch_snapshot_rejects_stale_rust_build_attestation(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root ownership is required for build attestation")
    private = tmp_path / "private-repo"
    private.mkdir(mode=0o700)
    _source_tree(private)
    rust_source = next(relative for relative in jobs.FETCH_SOURCE_FILES if relative.endswith('.rs'))
    source = private / rust_source
    source.write_bytes(source.read_bytes() + b"\nmodified after build attestation\n")
    with pytest.raises(RuntimeError, match="identity mismatch"):
        jobs.verify_fetch_runtime_build_identity(private)

"""Role-specific host prerequisites and the native Rust offline closure."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts import host_requirements as requirements


def _rust_tree(root: Path) -> Path:
    source = Path(__file__).resolve().parents[2] / "rust/verified-resolver"
    project = root / "rust/verified-resolver"
    project.mkdir(parents=True)
    for name in ("Cargo.toml", "Cargo.lock"):
        (project / name).write_bytes((source / name).read_bytes())
    policy = root / "config/preparation.toml"
    policy.parent.mkdir()
    policy.write_bytes((Path(__file__).resolve().parents[2] / "config/preparation.toml").read_bytes())
    return project


def test_cargo_acquires_locked_closure_and_then_proves_offline_replay(tmp_path, monkeypatch):
    _rust_tree(tmp_path)
    monkeypatch.delenv("CARGO_HOME", raising=False)
    monkeypatch.setattr(requirements.shutil, "which", lambda name: "/usr/bin/" + name)
    commands = []

    def probe(argv, timeout=30, *, env=None, cwd=None):
        commands.append((tuple(argv), timeout, env, cwd))
        return True, ""

    monkeypatch.setattr(requirements, "_probe", probe)
    assert requirements.verify_rust_dependencies(tmp_path, acquire=True) == (True, "")
    assert len(commands) == 2
    online, offline = (record[0] for record in commands)
    assert online[-1] == "--locked"
    assert offline == (*online, "--offline")
    for command, timeout, env, cwd in commands:
        assert cwd == tmp_path
        assert timeout == 180
        assert env["CARGO_HOME"] == str(tmp_path / ".cargo-host")
        assert env["CARGO_TARGET_DIR"] == str(tmp_path / "rust/verified-resolver/target")


def test_cargo_verification_never_downloads_in_build_preflight(tmp_path, monkeypatch):
    _rust_tree(tmp_path)
    monkeypatch.delenv("CARGO_HOME", raising=False)
    monkeypatch.setattr(requirements.shutil, "which", lambda name: "/usr/bin/" + name)
    commands = []

    def probe(argv, **_):
        commands.append(tuple(argv))
        return False, "no matching package named `libc` found"

    monkeypatch.setattr(requirements, "_probe", probe)
    ok, detail = requirements.verify_rust_dependencies(tmp_path, acquire=False)
    assert not ok and "libc" in detail
    assert "make requirements" in detail
    assert len(commands) == 1 and commands[0][-1] == "--offline"


def test_cargo_acquisition_failure_cannot_be_reported_as_success(tmp_path, monkeypatch):
    _rust_tree(tmp_path)
    monkeypatch.delenv("CARGO_HOME", raising=False)
    monkeypatch.setattr(requirements.shutil, "which", lambda name: "/usr/bin/" + name)
    commands = []

    def probe(argv, **_):
        commands.append(tuple(argv))
        return False, "registry unreachable"

    monkeypatch.setattr(requirements, "_probe", probe)
    result = requirements.verify_rust_dependencies(tmp_path, acquire=True)
    assert result[0] is False and "registry unreachable" in result[1]
    assert len(commands) == 1 and "--offline" not in commands[0]


def test_explicit_invalid_or_symlink_cargo_home_is_rejected(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(home, target_is_directory=True)
    for invalid in ("", "relative/cache", str(alias)):
        monkeypatch.setenv("CARGO_HOME", invalid)
        with pytest.raises(RuntimeError, match="CARGO_HOME"):
            requirements.cargo_build_environment(tmp_path)


def test_rust_lockfile_is_mandatory_and_no_silent_recovery(tmp_path, monkeypatch):
    _rust_tree(tmp_path)
    (tmp_path / "rust/verified-resolver/Cargo.lock").unlink()
    monkeypatch.setattr(requirements.shutil, "which", lambda name: "/usr/bin/" + name)
    assert requirements.verify_rust_dependencies(tmp_path, acquire=True)[0] is False


def _set_host_checks(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "requirements.txt").write_text("cargo\nrustc\npython3-pip\npython3-venv\nca-certificates\n")
    (tmp_path / "requirements-control.txt").write_text("curl\nca-certificates\n")
    (tmp_path / "requirements-golden-build.txt").write_text("python3-packaging\n")
    (tmp_path / "compose.control.yaml").write_text(json.dumps({"services": {}}))
    monkeypatch.setattr(requirements, "ROOT", tmp_path)
    monkeypatch.setattr(requirements, "REQUIREMENTS", tmp_path / "requirements.txt")
    monkeypatch.setattr(requirements, "GOLDEN_BUILD_REQUIREMENTS", tmp_path / "requirements-golden-build.txt")
    monkeypatch.setattr(requirements, "_debian_like", lambda: True)
    monkeypatch.setattr(requirements, "_package_installed", lambda name: True)
    monkeypatch.setattr(requirements, "_probe", lambda *a, **kw: (True, ""))
    monkeypatch.setattr(requirements, "_probe_venv", lambda: (True, ""))
    monkeypatch.setattr(requirements, "_verify_ca_bundle", lambda: (True, ""))
    monkeypatch.setattr(requirements, "_verify_docker_buildx", lambda: (True, ""))
    monkeypatch.setattr(requirements.shutil, "which", lambda name: "/usr/bin/" + name)


def test_control_rejects_rust_acquisition_and_never_checks_execution_crates(tmp_path, monkeypatch):
    _set_host_checks(tmp_path, monkeypatch)
    def forbidden(*a, **kw):
        raise AssertionError("control must not touch execution Rust dependencies")
    monkeypatch.setattr(requirements, "verify_rust_dependencies", forbidden)
    assert requirements.verify_host_requirements(role="control", verbose=False)
    with pytest.raises(ValueError, match="only to execution"):
        requirements.verify_host_requirements(role="control", acquire=True)
    with pytest.raises(RuntimeError, match="requires the execution host"):
        requirements.verify_host_requirements(role="control", golden_build=True)


def test_execution_checks_cargo_offline_and_never_checks_buildx(tmp_path, monkeypatch, capsys):
    _set_host_checks(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(requirements, "_verify_docker_buildx", lambda: (_ for _ in ()).throw(AssertionError("execution Buildx not needed")))
    monkeypatch.setattr(requirements, "verify_rust_dependencies", lambda root, *, acquire: (calls.append(acquire) or (False, "offline libc absent")))
    assert not requirements.verify_host_requirements(role="execution", golden_build=True, verbose=False)
    assert calls == [False]
    assert "offline libc absent" in capsys.readouterr().err
    assert not requirements.verify_host_requirements(role="execution", golden_build=True, acquire=True, verbose=False)
    assert calls == [False, True]


def test_control_missing_compose_device_is_a_failure(tmp_path, monkeypatch):
    _set_host_checks(tmp_path, monkeypatch)
    (tmp_path / "compose.control.yaml").write_text(json.dumps({"services": {
        "teacher-browser": {"devices": ["/dev/device-that-does-not-exist:/dev/example"]}
    }}))
    assert not requirements.verify_host_requirements(role="control", verbose=False)


def test_native_python_import_failure_is_a_failure(tmp_path, monkeypatch):
    _set_host_checks(tmp_path, monkeypatch)
    monkeypatch.setattr(requirements, "_verify_system_python_modules",
                        lambda names: (False, "packaging unavailable"))
    monkeypatch.setattr(requirements, "verify_rust_dependencies",
                        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should preflight first")))
    assert not requirements.verify_host_requirements(role="execution", golden_build=True, verbose=False)


def test_dispatch_uses_credentials_even_for_requirements(monkeypatch):
    from scripts import distributed
    import types

    observations = []
    monkeypatch.setattr(distributed, "config", lambda *, credentials: (
        observations.append(credentials) or {"deployment": {"role": "control"}}))
    monkeypatch.setattr(distributed, "control", lambda cfg, action, args: observations.append(action))
    distributed.main(["requirements"])
    assert observations == [True, "requirements"]


def test_execution_requirements_validate_goldens_and_compose_without_buildx(monkeypatch):
    from scripts import distributed
    import sys
    from types import SimpleNamespace

    events = []
    monkeypatch.setattr(distributed, "host", lambda *a, **kw: events.append(("host", a[0])))
    monkeypatch.setattr(requirements, "verify_host_requirements", lambda **kw: (
        events.append(("verify", kw)) or True))
    monkeypatch.setitem(sys.modules, "host_requirements", requirements)
    image = SimpleNamespace(
        preflight=lambda: events.append(("golden", "pins")),
        _safe_parent=lambda: events.append(("golden", "mount")),
        require_host_build_runtime=lambda: events.append(("golden", "tools")),
    )
    monkeypatch.setitem(sys.modules, "build", SimpleNamespace(_workstation_image_builder=lambda root: image))
    runtime = (Path(__file__).resolve().parents[2] / "state" / "broker").resolve()
    token = "a" * 40
    monkeypatch.setenv("DIST_BROKER_RUNTIME_DIR", "/stale/unrelated/runtime")
    monkeypatch.setenv("DIST_BROKER_TUNNEL_TOKEN", "stale-token")

    def capture_command(args, **kw):
        events.append(("command", tuple(map(str, args))))
        assert os.environ["DIST_BROKER_RUNTIME_DIR"] == str(runtime)
        assert os.environ["DIST_BROKER_TUNNEL_TOKEN"] == token

    monkeypatch.setattr(distributed, "run", capture_command)
    cfg = {"local": {"DIST_BROKER_TUNNEL_TOKEN": token},
           "paths": {"broker_runtime_directory": runtime}}
    distributed.execution(cfg, "requirements", SimpleNamespace())
    assert ("verify", {"require_root": True, "role": "execution", "golden_build": True, "acquire": True, "verbose": False}) in events
    assert ("golden", "pins") in events
    assert ("golden", "mount") in events
    assert ("golden", "tools") in events
    assert any(row[0] == "command" and row[1][-2:] == ("config", "--quiet") for row in events)


def test_control_requirements_do_not_activate_execution_checks(monkeypatch):
    from scripts import distributed
    from types import SimpleNamespace
    import sys

    events = []
    monkeypatch.setattr(distributed, "host", lambda *a, **kw: events.append(("host", a[0])))
    monkeypatch.setattr(distributed, "environment", lambda cfg: events.append(("env",)))
    monkeypatch.setattr(distributed, "compose", lambda *a, **kw: events.append(("compose", a)))
    monkeypatch.setattr(requirements, "verify_host_requirements", lambda **kw: (
        events.append(("verify", kw)) or True))
    monkeypatch.setitem(sys.modules, "host_requirements", requirements)
    monkeypatch.setitem(sys.modules, "project_state", SimpleNamespace(
        ENV_PATH=Path("/not-used"),
        parse_env=lambda path: events.append(("parse",)) or {},
        validate_core_inputs=lambda data: events.append(("secrets",))))
    distributed.control({"deployment": {"role": "control"}}, "requirements", SimpleNamespace())
    assert events == [("host", "control"), ("verify", {"role": "control", "verbose": False}),
                      ("parse",), ("secrets",), ("env",), ("compose", ("config", "--quiet"))]


def test_control_preflight_uses_pure_runtime_secret_validation(tmp_path, monkeypatch):
    from scripts import project_state

    monkeypatch.setattr(project_state, "SECRETS_DIR", tmp_path / ".secrets")
    monkeypatch.setattr(project_state, "TEACHER_BROWSER_PASSWORD", tmp_path / ".secrets/teacher_browser_password")
    values = {
        "POSTGRES_PASSWORD": "database-value",
        "TEACHER_BROWSER_TUNNEL_TOKEN": "remote-tunnel-token",
        "TEACHER_BROWSER_PASSWORD": "a-password-longer-than-12",
        "APP_CONTROL_TOKEN": "a" * 48,
        "DIST_BROKER_ADMIN_TOKEN": "b" * 48,
        "DIST_BROKER_CONTROLLER_TOKEN": "c" * 48,
        "TEACHER_BROWSER_PUBLIC_URL": "https://example.test",
    }
    project_state.validate_core_inputs(values)
    assert not project_state.SECRETS_DIR.exists(), "preflight must not materialize secrets"
    for invalid in ("TEACHER_BROWSER_PASSWORD", "APP_CONTROL_TOKEN", "POSTGRES_PASSWORD"):
        with pytest.raises(SystemExit):
            project_state.validate_core_inputs({**values, invalid: ""})
    project_state.SECRETS_DIR.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SystemExit, match=".secrets must not be a symlink"):
        project_state.validate_core_inputs(values)


def test_execution_tunnel_requirements_and_runtime_share_interpolation(tmp_path, monkeypatch):
    from scripts import distributed

    runtime = tmp_path / "broker"
    token = "token_" + "b" * 36
    cfg = {"local": {"DIST_BROKER_TUNNEL_TOKEN": token},
           "paths": {"broker_runtime_directory": runtime}}
    observed = []
    monkeypatch.setenv("DIST_BROKER_RUNTIME_DIR", "/wrong/from/host")
    monkeypatch.setenv("DIST_BROKER_TUNNEL_TOKEN", "wrong-from-host")

    def record(command, **kwargs):
        observed.append((tuple(map(str, command)), os.environ["DIST_BROKER_RUNTIME_DIR"],
                         os.environ["DIST_BROKER_TUNNEL_TOKEN"]))

    monkeypatch.setattr(distributed, "run", record)
    distributed.execution_tunnel(cfg, "up")
    assert len(observed) == 1
    assert observed[0][0][-5:] == ("up", "-d", "--wait", "--wait-timeout", "120")
    assert observed[0][1:] == (str(runtime), token)
    assert distributed.execution_tunnel_environment(cfg, require_token=True) == {
        "DIST_BROKER_RUNTIME_DIR": str(runtime), "DIST_BROKER_TUNNEL_TOKEN": token}


def test_execution_tunnel_interpolation_rejects_invalid_inputs(tmp_path):
    from scripts import distributed

    cfg = {"local": {"DIST_BROKER_TUNNEL_TOKEN": "a" * 40},
           "paths": {"broker_runtime_directory": tmp_path / "broker"}}
    for token in ("", "bad value", "a" * 29, "x" * 2049):
        with pytest.raises(ValueError, match="DIST_BROKER_TUNNEL_TOKEN"):
            distributed.execution_tunnel_environment(
                {**cfg, "local": {"DIST_BROKER_TUNNEL_TOKEN": token}}, require_token=True)
    for path in ("relative", Path("relative"), None):
        with pytest.raises(ValueError, match="absolute"):
            distributed.execution_tunnel_environment(
                {**cfg, "paths": {"broker_runtime_directory": path}}, require_token=True)
    assert distributed.execution_tunnel_environment(cfg, require_token=False) == {
        "DIST_BROKER_RUNTIME_DIR": str(tmp_path / "broker")}

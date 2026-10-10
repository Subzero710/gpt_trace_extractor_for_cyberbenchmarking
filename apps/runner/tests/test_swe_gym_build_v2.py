from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import os
import subprocess
import shutil
from pathlib import Path

import pytest

from gpt_trace_runner.superbench.adapters.swe_gym import guest_runtime, os_packages

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("lite_template_builder", ROOT / "scripts/build_swe_gym_lite_templates.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


@pytest.fixture
def deb(tmp_path):
    folder = tmp_path / "package"
    (folder / "DEBIAN").mkdir(parents=True)
    (folder / "DEBIAN/control").write_text("Package: codex-template-test\nVersion: 1.0-1\nArchitecture: all\nMaintainer: Test <test@example.test>\nDescription: reproducibility fixture\n")
    (folder / "usr/share/codex-template-test").mkdir(parents=True)
    (folder / "usr/share/codex-template-test/data").write_text("exact Debian package bytes\n")
    output = tmp_path / "codex-template-test_1.0-1_all.deb"
    subprocess.run(["dpkg-deb", "--build", str(folder), str(output)], env={**os.environ,"TMPDIR":str(tmp_path)}, check=True, capture_output=True)
    record = {**os_packages.deb_identity(output), "sha256": os_packages.digest(output), "size": output.stat().st_size}
    return output, {"schema_version": 1, "artifacts": {output.name: record}, "installed_before": {}, "installed_after": {}}


@pytest.mark.parametrize("attack", ["missing", "bytes", "size", "metadata", "symlink"])
def test_resolved_debs_fail_closed_on_any_mutation(deb, tmp_path, attack):
    path, manifest = deb
    if attack == "missing": path.unlink()
    elif attack == "bytes": path.write_bytes(b"corrupted deb")
    elif attack == "size": manifest["artifacts"][path.name]["size"] += 1
    elif attack == "metadata": manifest["artifacts"][path.name]["version"] = "2.0"
    else:
        target = tmp_path / "actual.deb.bin"
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(RuntimeError): os_packages.verify_artifacts(path.parent, manifest)


def test_common_os_replay_has_no_network_or_package_resolution(deb, monkeypatch):
    path, manifest = deb
    os_packages.verify_artifacts(path.parent, manifest)
    monkeypatch.setattr(os_packages, "installed", lambda: {})
    calls = []
    original_run = subprocess.run
    monkeypatch.setattr(os_packages.subprocess, "run", lambda args, **kw: calls.append(args) if args[0] == "unshare" else original_run(args, **kw))
    os_packages.install(path.parent, manifest)
    assert len(calls) == 1
    command = calls[0]
    assert command[:3] == ["unshare", "--net", "apt-get"]
    assert "--no-download" in command and "--no-remove" in command
    assert str(path) in command and "update" not in command and "upgrade" not in command
    assert "Dir::State::Lists=" + str(path.parent / "empty-lists") in command


def test_os_replay_rejects_wrong_golden_or_result_inventory(deb, monkeypatch):
    path, manifest = deb
    monkeypatch.setattr(os_packages, "installed", lambda: {"wrong": {"version": "1", "architecture": "all"}})
    with pytest.raises(RuntimeError, match="golden"):
        os_packages.install(path.parent, manifest)
    calls = iter([{}, {"new": {"version": "2", "architecture": "all"}}])
    monkeypatch.setattr(os_packages, "installed", lambda: next(calls))
    original_run = subprocess.run
    monkeypatch.setattr(os_packages.subprocess, "run", lambda args, **kw: None if args[0] == "unshare" else original_run(args, **kw))
    with pytest.raises(RuntimeError, match="inventory"):
        os_packages.install(path.parent, manifest)


def test_two_phase_resolution_preserves_real_deb_bytes_and_exact_inventory(deb, tmp_path, monkeypatch):
    artifact, _ = deb
    output = tmp_path / "resolved"
    state = iter([{}, {}, {"codex-template-test":{"version":"1.0-1","architecture":"all"}}])
    monkeypatch.setattr(os_packages,"installed",lambda:next(state))
    monkeypatch.setattr(os_packages,"PACKAGES",("codex-template-test",))
    monkeypatch.setattr(os_packages,"repository_metadata",lambda:{"signed-apt-index":{"sha256":"a"*64,"size":10}})
    calls, original = [], subprocess.run
    def run(args, **kwargs):
        if args[0] not in {"apt-get","unshare"}: return original(args, **kwargs)
        calls.append(args)
        if "--download-only" in args: shutil.copyfile(artifact, output / artifact.name)
    monkeypatch.setattr(os_packages.subprocess,"run",run)
    manifest = os_packages.resolve(output)
    assert calls[0] == ["apt-get","update"]
    assert "--download-only" in calls[1] and "--reinstall" in calls[1]
    assert calls[2][:3] == ["unshare","--net","apt-get"] and "--no-download" in calls[2]
    assert "upgrade" not in {arg for call in calls for arg in call}
    assert manifest["artifacts"][artifact.name]["sha256"] == os_packages.digest(artifact)
    assert (output / artifact.name).read_bytes() == artifact.read_bytes()
    assert json.loads((output / "manifest.json").read_text()) == manifest


@pytest.mark.parametrize("component", ["os-version", "deb-bytes", "env-inventory", "vcs", "downloads", "source", "recipe", "qcow"])
def test_any_resolved_dependency_change_changes_final_generation(component):
    resolved = {"recipe_version": 2, "resolved_os": {"package": {"version": "1", "sha256": "a"*64}},
        "environments": {"e": {"pip": "a==1"}}, "vcs": {"commit": "b"*40}, "downloads": "c"*64,
        "artifacts": {"source": "d"*64}, "templates": {"qcow": "e"*64}}
    changed = copy.deepcopy(resolved)
    if component == "os-version": changed["resolved_os"]["package"]["version"] = "2"
    elif component == "deb-bytes": changed["resolved_os"]["package"]["sha256"] = "f"*64
    elif component == "env-inventory": changed["environments"]["e"]["pip"] = "a==2"
    elif component == "vcs": changed["vcs"]["commit"] = "f"*40
    elif component == "downloads": changed["downloads"] = "f"*64
    elif component == "source": changed["artifacts"]["source"] = "f"*64
    elif component == "recipe": changed["recipe_version"] = 3
    else: changed["templates"]["qcow"] = "f"*64
    assert builder.generation_identity(resolved) != builder.generation_identity(changed)


def test_publication_validates_immutable_generation_before_atomic_registry_replace(tmp_path):
    target = tmp_path / "templates"
    target.mkdir()
    registry = target / "registry.json"
    registry.write_text('{"old":"registry"}')
    old = registry.read_bytes()
    staged = target / ".build-new"
    staged.mkdir()
    (staged / "disk.qcow2").write_bytes(b"disk")
    manifest = {"generation": "a"*64}
    def reject(final, generation):
        assert registry.read_bytes() == old and generation == "a"*64
        assert not final.stat().st_mode & 0o222
        assert not (final / "disk.qcow2").stat().st_mode & 0o222
        raise RuntimeError("publication validation failed")
    with pytest.raises(RuntimeError): builder.publish(staged, target, manifest, reject)
    assert registry.read_bytes() == old
    second = target / ".build-ok"
    second.mkdir()
    (second / "disk.qcow2").write_bytes(b"new disk")
    builder.publish(second, target, {"generation":"b"*64}, lambda *args: None)
    assert json.loads(registry.read_text()) == {"schema_version":2,"generation":"b"*64}
    assert not registry.stat().st_mode & 0o222


@pytest.mark.parametrize("payload", ["builder-mirrors", "repos", "task-sources", "dependency.git"])
def test_guest_publication_rejects_every_source_directory(tmp_path, monkeypatch, payload):
    root = tmp_path / "guest"
    root.mkdir()
    monkeypatch.setattr(guest_runtime, "ROOT", root)
    assert guest_runtime.validate_publication() == {"builder_mirrors":0,"repo_mirrors":0,"task_sources":0,"checkouts":0}
    (root / payload).mkdir()
    with pytest.raises(RuntimeError): guest_runtime.validate_publication()


def test_common_recipe_never_runs_floating_apt_or_builds_task_sources():
    common = inspect.getsource(guest_runtime.build_common)
    assert "apt-get" not in common
    assert "warm_task" not in common and "builder-mirrors" not in common
    assert "upgrade" not in inspect.getsource(os_packages.resolve)
    builder_source = inspect.getsource(builder.build)
    assert builder_source.index("generation = generation_identity(resolved)") > builder_source.index("qemu-img\", \"check")
    assert "builder-mirrors" not in builder_source

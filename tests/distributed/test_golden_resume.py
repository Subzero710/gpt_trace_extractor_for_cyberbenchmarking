"""Real journals/files/signatures with explicit software fixtures at VM/network boundaries.

No guest, KVM, Docker service, browser or network connection is started here.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / "infra/workstation/image"
sys.path.insert(0, str(IMAGE))
import golden_assets as assets
import golden_lock
import guest_build as guest


def load_builder():
    spec = importlib.util.spec_from_file_location("golden_resume_test_builder", IMAGE / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return json.dumps(value, sort_keys=True).encode() + b"\n"


class VMFixture:
    """Only conversion, offline injection and KVM are software boundaries."""
    def __init__(self, root, monkeypatch):
        self.b = load_builder()
        self.root = root
        root.mkdir(mode=0o700)
        self.guests = {}
        self.calls = {"conversion": 0, "offline": 0, "qemu": 0, "browser_download": 0}
        b = self.b
        monkeypatch.setattr(b, "DEST", root / "kali-base.qcow2")
        monkeypatch.setattr(b, "CACHE_DIR", root / "cache")
        monkeypatch.setattr(b, "CACHE_ARCHIVE", root / "cache" / b.ARCHIVE)
        monkeypatch.setattr(b, "require_execution_role", lambda: None)
        monkeypatch.setattr(b, "_safe_parent", lambda: assets.safe(root, directory=True))
        monkeypatch.setattr(b, "require_host_build_runtime", lambda: None)
        monkeypatch.setattr(b, "repo_commit", lambda: "1" * 40)
        monkeypatch.setattr(b, "image_info", lambda path: assets.safe(path))
        monkeypatch.setattr(b, "cached_archive", self.archive)
        monkeypatch.setattr(b, "_convert", self.convert)
        monkeypatch.setattr(b, "prepare_offline", self.offline)
        monkeypatch.setattr(b, "provision_in_real_guest", self.provision)
        monkeypatch.setattr(b, "guest_read", self.read)
        monkeypatch.setattr(b, "guest_listing", lambda image: {Path(p).name for p in self.guests.get(image, {})})

    def archive(self):
        cache = assets.mkdir(self.b.CACHE_DIR)
        path = cache / self.b.ARCHIVE
        if not path.exists():
            assets.atomic_bytes(path, b"synthetic-official-archive", 0o444)
        return path

    def convert(self, archive, stage, state):
        self.calls["conversion"] += 1
        (stage / self.b.DEST.name).write_bytes(b"synthetic-conversion:" + state["fingerprint"].encode())

    def offline(self, image, stage, state):
        self.calls["offline"] += 1
        self.guests.setdefault(image, {})[str(guest.INPUT)] = encoded(self.b._guest_identity(state))

    def read(self, image, name):
        if name not in self.guests.get(image, {}):
            raise ValueError("required guest artifact unavailable: " + name)
        return self.guests[image][name]

    def provision(self, image):
        self.calls["qemu"] += 1
        cache = assets.mkdir(self.b.CACHE_DIR)
        binary = cache / "synthetic-browser-download"
        if not binary.exists():
            self.calls["browser_download"] += 1
            assets.atomic_bytes(binary, b"synthetic-browser-cache", 0o444)
        g = self.guests[image]
        identity = json.loads(g[str(guest.INPUT)])
        target = {"schema": 2, "source": "verified-target-interpreter", "implementation": "cpython",
            "abi": "cp313", "architecture": "x86_64", "interpreter_sha256": "2"*64,
            "python_artifact_sha256": None, "tags": ["cp313-cp313-manylinux_2_28_x86_64"],
            "markers": {"implementation_name": "cpython", "implementation_version": "3.13.7", "os_name": "posix",
                "platform_machine": "x86_64", "platform_release": "fixture-kernel", "platform_system": "Linux",
                "platform_version": "fixture-platform", "python_full_version": "3.13.7", "python_version": "3.13",
                "platform_python_implementation": "CPython", "sys_platform": "linux"}}
        browser = {"schema": 2, "artifact": {"wrapper": "0.4.8", "platform": "linux-x64", "version": "1.2.3.4",
                "archive_sha256": "3"*64, "manifest_sha256": "4"*64, "signature_sha256": "5"*64,
                "verification": "upstream-ed25519-and-sha256"}, "binary_sha256": "6"*64,
                "executable_version": "synthetic-test-browser", "files": {"chrome": {"size": 1, "mode": 365, "sha256": "6"*64}}}
        values = {"packages": b"nodejs synthetic\nnpm synthetic\n",
            "python_packages": ("\n".join(row["name"] + "==" + row["version"] for row in golden_lock.load()["packages"]) + "\n").encode(),
            "target_environment": encoded(target), "system_python": encoded({"full_version": "3.13.7",
                "executable": "/usr/bin/python3.13", "interpreter_sha256": "2"*64}),
            "npm": b"10.9.9\n", "node": encoded({"version": "v22.0.0", "executable": "/usr/bin/node", "sha256": "7"*64}),
            "browser_runtime": encoded(browser)}
        g.update({guest.MANIFESTS[key]: raw for key, raw in values.items()})
        g.pop(str(guest.FAILED), None)
        g[str(guest.PROOF)] = encoded({**identity, "manifests": {key: {
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for key, raw in values.items()}})
        g[str(guest.COMPLETE)] = b"ok\n"
        image.write_bytes(image.read_bytes() + b"|synthetic-provisioned")

    def state(self):
        return json.loads((self.root / "golden-install.json").read_bytes())


@pytest.fixture
def vm(tmp_path, monkeypatch):
    return VMFixture(tmp_path / "storage", monkeypatch)


def fail_once(monkeypatch, module, name, *, phase=None, after=False):
    original = getattr(module, name)
    attempted = False
    def wrapped(*args, **kwargs):
        nonlocal attempted
        matches = phase is None or (name == "checkpoint" and args[1] == phase)
        if matches and not attempted:
            attempted = True
            if after:
                original(*args, **kwargs)
            raise RuntimeError("synthetic interruption")
        return original(*args, **kwargs)
    monkeypatch.setattr(module, name, wrapped)


def test_generated_firstboot_and_every_separate_python_program_compile():
    b = load_builder()
    script = b.firstboot_script()
    subprocess.run(["bash", "-n"], input=script, text=True, check=True)
    assert "set -Eeuo pipefail" in script and "<<" not in script
    assert "printf '[Seat:*]\\nautologin-user=kali" in script
    for name in ("guest_build.py", "golden_assets.py", "golden_lock.py"):
        compile((IMAGE / name).read_bytes(), name, "exec")
    b.preflight()


def test_runtime_imports_and_direct_packaging_dependency_are_locked(monkeypatch):
    b = load_builder()
    value = golden_lock.check()
    missing = copy.deepcopy(value)
    missing["packages"] = [r for r in missing["packages"] if r["name"] != "packaging"]
    with pytest.raises(ValueError, match="direct dependency"):
        golden_lock.validate_project(missing, ROOT / "apps/kali-workstation/pyproject.toml")
    monkeypatch.setattr(golden_lock, "check", lambda root: missing)
    with pytest.raises(ValueError, match="imports absent"):
        b.preflight()


def test_npm_is_required_on_both_sides(monkeypatch):
    b = load_builder()
    assert {"nodejs", "npm"} <= set(b.GUEST_PACKAGES)
    assert {"node", "npm"} <= set(guest.MANIFESTS)
    monkeypatch.setattr(b, "GUEST_PACKAGES", tuple(p for p in b.GUEST_PACKAGES if p != "npm"))
    with pytest.raises(ValueError, match="Node/npm"):
        b.preflight()


def test_locked_metadata_catches_transitive_dependency_and_extra_omissions_before_kvm():
    value = golden_lock.load()
    metadata = golden_lock.load_metadata(IMAGE / "python-metadata.json")
    golden_lock.validate_metadata(value, metadata)
    assert "pyjwt" in metadata["distributions"]
    assert any("pyjwt[crypto]" in text.lower() for text in metadata["distributions"]["mcp"]["requires_dist"])
    broken = copy.deepcopy(value)
    broken["packages"] = [row for row in broken["packages"] if row["name"] != "pyjwt"]
    broken_metadata = copy.deepcopy(metadata)
    broken_metadata["distributions"].pop("pyjwt")
    with pytest.raises(ValueError, match="before KVM: mcp -> pyjwt"):
        golden_lock.validate_metadata(broken, broken_metadata)
    broken = copy.deepcopy(value)
    broken["packages"] = [row for row in broken["packages"] if row["name"] != "cryptography"]
    broken_metadata = copy.deepcopy(metadata)
    broken_metadata["distributions"].pop("cryptography")
    with pytest.raises(ValueError, match="before KVM"):
        golden_lock.validate_metadata(broken, broken_metadata)


@pytest.mark.parametrize("missing", list(guest.MANIFESTS))
def test_complete_marker_requires_every_guest_manifest(tmp_path, monkeypatch, missing):
    paths = {key: str(tmp_path / (key + ".txt")) for key in guest.MANIFESTS}
    for key, name in paths.items():
        if key != missing:
            Path(name).write_bytes(b"real-nonempty-fixture\n")
    monkeypatch.setattr(guest, "MANIFESTS", paths)
    monkeypatch.setattr(guest, "COMPLETE", tmp_path / "complete")
    monkeypatch.setattr(guest, "PROOF", tmp_path / "proof.json")
    monkeypatch.setattr(guest, "FAILED", tmp_path / "failed")
    monkeypatch.setattr(guest, "input_identity", lambda: {"schema": 2, "build_input_sha256": "a"*64, "repo_commit": "b"*40})
    with pytest.raises(FileNotFoundError):
        guest.complete()
    assert not guest.COMPLETE.exists() and not guest.PROOF.exists()


@pytest.mark.parametrize("method,phase,after", [
    ("collect_manifests", None, False), ("collect_manifests", None, True),
    ("provenance", None, False), ("checkpoint", "guest_complete", False),
    ("checkpoint", "base_converted", True), ("prepare_offline", None, True),
    ("_commit_prepared", None, False), ("checkpoint", "manifests_collected", True),
    ("checkpoint", "provenance_generated", True),
])
def test_recovery_preserves_proven_work_without_new_conversion_or_guest(vm, monkeypatch, method, phase, after):
    fail_once(monkeypatch, vm.b, method, phase=phase, after=after)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        vm.b.build()
    previous = vm.state()
    assert previous["status"] in {"failed", "prepared"}
    vm.b.build()
    assert vm.state()["phase"] == "installed"
    assert vm.calls == {"conversion": 1, "offline": 2 if method == "prepare_offline" else 1,
                        "qemu": 1, "browser_download": 1}
    assert len(list(vm.root.glob(".golden-build-*"))) == 1


def test_post_provision_failure_is_not_a_guest_provisioning_failure(vm, monkeypatch):
    fail_once(monkeypatch, vm.b, "collect_manifests")
    with pytest.raises(RuntimeError, match="phase=guest_complete"):
        vm.b.build()
    assert vm.state()["phase"] == "guest_complete"
    assert "action=preserve-stage-and-checkpoint" in vm.state()["error"]
    vm.b.build()
    assert vm.calls["qemu"] == 1 and vm.calls["conversion"] == 1


@pytest.mark.parametrize("after_base", [False, True])
def test_crash_during_atomic_activation_recovers_without_provisioning(vm, monkeypatch, after_base):
    original = os.link
    interrupted = False
    def link(source, target, **kwargs):
        nonlocal interrupted
        if not interrupted and ((Path(target) == vm.b.DEST) == after_base):
            interrupted = True
            if after_base:
                original(source, target, **kwargs)
            raise RuntimeError("synthetic activation crash")
        return original(source, target, **kwargs)
    monkeypatch.setattr(os, "link", link)
    with pytest.raises(RuntimeError, match="activation crash"):
        vm.b.build()
    assert vm.state()["phase"] == "prepared"
    vm.b.build()
    assert vm.state()["phase"] == "installed" and vm.calls["qemu"] == 1


def test_existing_valid_permanent_image_is_only_verified(vm):
    vm.b.build()
    before = {p: p.read_bytes() for p in vm.b.artifact_paths()}
    vm.b.build()
    assert before == {p: p.read_bytes() for p in vm.b.artifact_paths()}
    assert vm.calls["qemu"] == vm.calls["conversion"] == 1


def test_existing_incompatible_permanent_image_is_preserved(vm, monkeypatch):
    vm.b.build()
    before = vm.b.DEST.read_bytes()
    monkeypatch.setattr(vm.b, "golden_build_input_sha256", lambda: "a"*64)
    with pytest.raises(RuntimeError, match="incompatible"):
        vm.b.build()
    assert vm.b.DEST.read_bytes() == before and vm.calls["qemu"] == 1


def test_changed_inputs_preserve_old_stage_and_build_exactly_one_new_identity(vm, monkeypatch):
    fail_once(monkeypatch, vm.b, "collect_manifests")
    with pytest.raises(RuntimeError):
        vm.b.build()
    old = vm.root / vm.state()["stage"]
    previous = (old / vm.b.DEST.name).read_bytes()
    monkeypatch.setattr(vm.b, "golden_build_input_sha256", lambda: "a"*64)
    vm.b.build()
    assert (old / vm.b.DEST.name).read_bytes() == previous
    assert len(list(vm.root.glob(".golden-build-*"))) == 2
    assert vm.calls["conversion"] == vm.calls["qemu"] == 2
    assert vm.calls["browser_download"] == 1


def test_corrupt_checkpoint_is_rejected_without_a_new_stage(vm, monkeypatch):
    fail_once(monkeypatch, vm.b, "collect_manifests")
    with pytest.raises(RuntimeError):
        vm.b.build()
    image = vm.root / vm.state()["stage"] / vm.b.DEST.name
    image.write_bytes(b"corrupt-fixture-image")
    with pytest.raises(RuntimeError, match="corrupt"):
        vm.b.build()
    assert image.read_bytes() == b"corrupt-fixture-image" and not vm.b.DEST.exists()
    assert vm.calls["qemu"] == 1


@pytest.mark.parametrize("target", ["journal", "stage", "cache"])
def test_symlink_is_rejected_before_guest_start(vm, target):
    other = vm.root / "foreign"
    other.mkdir(mode=0o700)
    name = {"journal": "golden-install.json", "stage": ".golden-build-" + vm.b.preflight(), "cache": "cache"}[target]
    (vm.root / name).symlink_to(other)
    with pytest.raises((ValueError, RuntimeError), match="symlink"):
        vm.b.build()
    assert not list(other.iterdir()) and vm.calls["qemu"] == 0


@pytest.mark.parametrize("bad", [{"schema": 99}, [], {"schema": 2, "status": "failed"}])
def test_invalid_journal_is_rejected_before_any_conversion(vm, bad):
    assets.atomic_json(vm.root / "golden-install.json", bad)
    with pytest.raises(RuntimeError, match="journal"):
        vm.b.build()
    assert vm.calls["conversion"] == vm.calls["qemu"] == 0


def test_duplicate_and_nonprivate_journals_fail_before_conversion(vm):
    path = vm.root / "golden-install.json"
    assets.atomic_bytes(path, b'{"schema":1,"schema":2}\n')
    with pytest.raises(RuntimeError, match="duplicate golden JSON key"):
        vm.b.build()
    assets.atomic_bytes(path, b'{}\n', 0o644)
    with pytest.raises(RuntimeError, match="JSON permissions"):
        vm.b.build()
    assert vm.calls["conversion"] == vm.calls["qemu"] == 0


def test_multiple_old_stages_are_not_selected_by_recency(vm):
    originals = {}
    for number in range(3):
        stage = vm.root / (".golden-build-" + str(number)*32)
        stage.mkdir(mode=0o700)
        image = stage / vm.b.DEST.name
        image.write_bytes(str(number).encode())
        originals[image] = image.read_bytes()
    vm.b.build()
    assert originals == {path: path.read_bytes() for path in originals}
    assert vm.state()["stage"] == ".golden-build-" + vm.b.preflight()


def test_observed_legacy_post_provision_failure_is_explicitly_rejected_and_preserved(vm):
    stage = vm.root / (".golden-build-" + "2"*32)
    stage.mkdir(mode=0o700)
    image = stage / vm.b.DEST.name
    image.write_bytes(b"legacy-successful-provisioning-without-current-proof")
    vm.guests[image] = {str(guest.COMPLETE): b"ok\n"}
    original = {"schema": 1, "status": "failed", "stage": stage.name,
                "error": "virt-cat /etc/gpt-trace-npm-version.txt returned 1"}
    assets.atomic_json(vm.root / "golden-install.json", original)
    vm.b.build()
    assessment = json.loads((stage / "legacy-assessment.json").read_bytes())
    assert assessment["guest_complete"] and not assessment["guest_failed"]
    assert assessment["recoverable"] is False and "proof" in assessment["reason"]
    assert json.loads((stage / "legacy-journal.json").read_bytes()) == original
    assert image.read_bytes() == b"legacy-successful-provisioning-without-current-proof"
    assert vm.calls["qemu"] == vm.calls["conversion"] == 1


def test_legacy_journal_with_provably_current_guest_can_resume(vm, monkeypatch):
    fail_once(monkeypatch, vm.b, "collect_manifests")
    with pytest.raises(RuntimeError):
        vm.b.build()
    state = vm.state()
    assets.atomic_json(vm.root / "golden-install.json", {"schema": 1, "status": "failed", "stage": state["stage"], "error": "post-provision collection"})
    vm.b.build()
    assert vm.calls["qemu"] == vm.calls["conversion"] == 1
    assessment = json.loads((vm.root / state["stage"] / "legacy-assessment.json").read_bytes())
    assert assessment["recoverable"] is True


@pytest.fixture
def browser_source(tmp_path, monkeypatch):
    from cloakbrowser import download as upstream
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(upstream, "BINARY_SIGNING_PUBKEYS", [base64.b64encode(public).decode()])
    identity = assets.browser_identity()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        member = tarfile.TarInfo("browser/chrome")
        raw = b"synthetic-browser-executable\n"
        member.size, member.mode = len(raw), 0o755
        tar.addfile(member, io.BytesIO(raw))
    archive = stream.getvalue()
    from cloakbrowser.config import get_archive_name
    manifest = ("version=" + identity["version"] + "\n" + hashlib.sha256(archive).hexdigest() + "  " + get_archive_name(identity["platform"]) + "\n").encode()
    source = {"SHA256SUMS": manifest, "SHA256SUMS.sig": base64.b64encode(key.sign(manifest)),
              get_archive_name(identity["platform"]): archive}
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    calls = []
    def curl(argv, **kwargs):
        assert argv[:3] == ["curl", "--fail", "--location"]
        calls.append(argv[-1])
        Path(argv[argv.index("--output") + 1]).write_bytes(source[argv[-1].rsplit("/", 1)[1]])
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(assets.subprocess, "run", curl)
    return SimpleNamespace(cache=cache, identity=identity, source=source, calls=calls,
                           public=base64.b64encode(public).decode())


def test_signed_browser_cache_is_reused_without_network(browser_source):
    s = browser_source
    archive, evidence = assets.browser_archive(s.cache, s.identity)
    count = len(s.calls)
    second, proof = assets.browser_archive(s.cache, s.identity)
    assert count == 3 and len(s.calls) == count
    assert archive == second and evidence == proof


def test_host_authenticates_cache_from_hash_locked_wheel_before_kvm(browser_source):
    import host_cache
    s = browser_source
    archive, _proof = assets.browser_archive(s.cache, s.identity)
    code = ("PLATFORM_CHROMIUM_VERSIONS = " + repr({s.identity["platform"]: s.identity["version"]}) + "\n"
        + "SUPPORTED_PLATFORMS = " + repr({("Linux", "x86_64"): s.identity["platform"]}) + "\n"
        + "BINARY_SIGNING_PUBKEYS = " + repr([s.public]) + "\n")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr("cloakbrowser/config.py", code)
    raw = stream.getvalue()
    sha = hashlib.sha256(raw).hexdigest()
    objects = assets.mkdir(assets.mkdir(s.cache / "python") / "objects")
    path = assets.mkdir(objects / sha) / "cloakbrowser-fixture.whl"
    assets.atomic_bytes(path, raw, 0o444)
    graph = {"packages": [{"name": "cloakbrowser", "version": s.identity["wrapper"], "hashes": [sha]}]}
    host_cache.verify(s.cache, graph, system="Linux", architecture="x86_64")
    calls = len(s.calls)
    assets.atomic_bytes(archive, b"corrupt-cache", 0o444)
    with pytest.raises(ValueError, match="hash mismatch before KVM"):
        host_cache.verify(s.cache, graph, system="Linux", architecture="x86_64")
    assert len(s.calls) == calls
    archive.unlink()
    assets.atomic_bytes(archive.parent / "SHA256SUMS.sig", base64.b64encode(b"x"*64), 0o444)
    with pytest.raises(ValueError, match="signature verification failed before KVM"):
        host_cache.verify(s.cache, graph, system="Linux", architecture="x86_64")
    assert len(s.calls) == calls


def test_interrupted_guest_replays_same_image_and_reuses_browser_download(vm, monkeypatch):
    original = vm.b.provision_in_real_guest
    failed = False
    def interrupt(image):
        nonlocal failed
        original(image)
        if not failed:
            failed = True
            vm.guests[image].pop(str(guest.COMPLETE))
            vm.guests[image][str(guest.FAILED)] = b"phase=metadata exit=1\n"
    monkeypatch.setattr(vm.b, "provision_in_real_guest", interrupt)
    with pytest.raises(RuntimeError, match="guest provisioning failed"):
        vm.b.build()
    stage = vm.state()["stage"]
    vm.b.build()
    assert vm.state()["stage"] == stage
    assert vm.calls == {"conversion": 1, "offline": 1, "qemu": 2, "browser_download": 1}


def test_fingerprint_includes_injection_semantics_but_ignores_unrelated_host_code(monkeypatch):
    b = load_builder()
    original = Path.read_bytes
    baseline = b.golden_build_input_sha256()
    kind = "host"
    def read(path):
        raw = original(path)
        if path == IMAGE / "build.py":
            if kind == "host":
                return raw.replace(b'print("+ "', b'print("host log: "', 1)
            return raw.replace(b'systemctl enable gpt-trace-golden-build.service', b'systemctl disable gpt-trace-golden-build.service')
        return raw
    monkeypatch.setattr(Path, "read_bytes", read)
    assert b.golden_build_input_sha256() == baseline
    kind = "injection"
    assert b.golden_build_input_sha256() != baseline


def test_offline_injection_uses_fingerprint_verified_private_snapshots(tmp_path, monkeypatch):
    b = load_builder()
    fingerprint = b.golden_build_input_sha256()
    state = {"fingerprint": fingerprint, "repo_commit": "a"*40}
    virtual_guest = {}
    inputs = {path: path.read_bytes() for path in b.input_files()}
    def customize(*args):
        assert args[0] == "virt-customize" and "--no-network" in args
        for index, token in enumerate(args):
            if token != "--copy-in":
                continue
            raw, destination = args[index + 1].rsplit(":", 1)
            source = Path(raw)
            assert source.is_relative_to(tmp_path)
            if source.is_dir():
                for path in source.rglob("*"):
                    if path.is_file():
                        virtual_guest[destination + "/" + source.name + "/" + path.relative_to(source).as_posix()] = path.read_bytes()
            else:
                virtual_guest[destination + "/" + source.name] = source.read_bytes()
    monkeypatch.setattr(b, "run", customize)
    monkeypatch.setattr(b, "guest_read", lambda image, path: virtual_guest[path])
    b.prepare_offline(tmp_path / "image.qcow2", tmp_path, state)
    source_root = ROOT / "apps/kali-workstation/src"
    for path, content in inputs.items():
        if path.is_relative_to(source_root):
            assert virtual_guest["/opt/gpt-trace/bundle/src/" + path.relative_to(source_root).as_posix()] == content
    broken = dict(inputs)
    path = ROOT / "apps/kali-workstation/src/kali_workstation/guest/agent.py"
    broken[path] += b"\n# semantic snapshot change\n"
    assert b.golden_build_input_sha256(inputs) == fingerprint
    assert b.golden_build_input_sha256(broken) != fingerprint


@pytest.mark.parametrize("attack", ["signature", "hash"])
def test_invalid_browser_signature_or_hash_cannot_be_activated(browser_source, attack):
    s = browser_source
    name = "SHA256SUMS.sig" if attack == "signature" else next(k for k in s.source if k.endswith(".tar.gz"))
    s.source[name] = b"corrupt-download"
    with pytest.raises((ValueError, RuntimeError), match="signature|hash"):
        assets.browser_archive(s.cache, s.identity)
    assert not list(s.cache.rglob("*.tar.gz"))


def test_partial_browser_transport_failure_preserves_part_without_activation(browser_source, monkeypatch):
    s = browser_source
    original = assets.subprocess.run
    def interrupted(argv, **kwargs):
        if argv[-1].endswith(".tar.gz"):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"partial")
            raise subprocess.CalledProcessError(28, argv)
        return original(argv, **kwargs)
    monkeypatch.setattr(assets.subprocess, "run", interrupted)
    with pytest.raises(subprocess.CalledProcessError):
        assets.browser_archive(s.cache, s.identity)
    assert list(s.cache.rglob("*.part")) and not list(s.cache.rglob("*.tar.gz"))


def test_kali_part_uses_resume_and_verified_atomic_promotion(tmp_path, monkeypatch):
    target = tmp_path / "kali.7z"
    target.with_name(target.name + ".part").write_bytes(b"partial")
    expected = hashlib.sha256(b"complete-archive").hexdigest()
    calls = []
    def curl(argv, **kwargs):
        assert argv[argv.index("--continue-at") + 1] == "-"
        assert target.with_name(target.name + ".part").read_bytes() == b"partial"
        calls.append(argv)
        Path(argv[argv.index("--output") + 1]).write_bytes(b"complete-archive")
    monkeypatch.setattr(assets.subprocess, "run", curl)
    assert assets.download("https://fixture.invalid/kali", target, expected).read_bytes() == b"complete-archive"
    assets.download("https://fixture.invalid/kali", target, expected)
    assert len(calls) == 1


def test_complete_hash_valid_part_recovers_without_any_network(tmp_path, monkeypatch):
    target = tmp_path / "artifact.tar.gz"
    raw = b"hash-proven-download-finished-before-parent-crash"
    target.with_name(target.name + ".part").write_bytes(raw)
    def forbidden(*args, **kwargs):
        pytest.fail("a complete hash-valid partial must not trigger a download")
    monkeypatch.setattr(assets.subprocess, "run", forbidden)
    assert assets.download("https://fixture.invalid/artifact", target, hashlib.sha256(raw).hexdigest()).read_bytes() == raw
    assert not target.with_name(target.name + ".part").exists()


def test_host_archive_downloader_inherits_the_actual_exclusive_lock(tmp_path, monkeypatch):
    import fcntl
    b = load_builder()
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    body = b"synthetic-resumable-kali-download"
    monkeypatch.setattr(b, "CACHE_DIR", cache)
    monkeypatch.setattr(b, "CACHE_ARCHIVE", cache / "kali.7z")
    monkeypatch.setattr(b, "ARCHIVE_SHA256", hashlib.sha256(body).hexdigest())
    fd = os.open(tmp_path / "build.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(b, "BUILD_LOCK", fd)
    original = subprocess.run
    def curl(argv, **kwargs):
        part = argv[argv.index("--output") + 1]
        program = "import os,sys; from pathlib import Path; os.fstat(int(sys.argv[1])); Path(sys.argv[2]).write_bytes(bytes.fromhex(sys.argv[3]))"
        return original([sys.executable, "-c", program, str(fd), part, body.hex()], **kwargs)
    monkeypatch.setattr(assets.subprocess, "run", curl)
    try:
        assert b.cached_archive().read_bytes() == body
    finally:
        os.close(fd)


@pytest.mark.parametrize("name", ["../outside", "/absolute", "folder/../../outside"])
def test_browser_archive_path_traversal_is_rejected(tmp_path, name):
    archive = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo(name)
        member.size = 1
        tar.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsafe"):
        assets.extract_browser(archive, tmp_path / "browser")
    assert not (tmp_path / "browser").exists()


def test_measured_target_wheel_cache_reuses_hash_validated_bytes(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr("demo/__init__.py", "")
    raw = stream.getvalue()
    sha = hashlib.sha256(raw).hexdigest()
    bundle, cache = tmp_path / "bundle", tmp_path / "cache"
    bundle.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    assets.atomic_json(bundle / "python-lock.json", {"schema": 1, "requires_python": ">=3.12",
        "packages": [{"name": "demo", "version": "1.0", "hashes": [sha]}]})
    calls = []
    def acquire(*args):
        calls.append(args)
        assert "--require-hashes" in args and "--only-binary=:all:" in args
        assert "--platform" not in args and "--python-version" not in args
        incoming = Path(args[args.index("--dest") + 1])
        (incoming / "demo-1.0-py3-none-any.whl").write_bytes(raw)
    first = guest.wheelhouse(cache, bundle, invoke=acquire)
    second = guest.wheelhouse(cache, bundle, invoke=acquire)
    assert first == second and len(calls) == 1
    path = second["demo"]
    path.chmod(0o644)
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="corruption"):
        guest.wheelhouse(cache, bundle, invoke=acquire)
    assert len(calls) == 1


def test_control_role_cannot_construct_a_golden(monkeypatch):
    b = load_builder()
    import distributed
    monkeypatch.setattr(distributed, "config", lambda **kw: {"deployment": {"role": "control"}})
    def forbidden():
        pytest.fail("control reached KVM/storage construction")
    monkeypatch.setattr(b, "require_host_build_runtime", forbidden)
    monkeypatch.setattr(b, "_safe_parent", forbidden)
    with pytest.raises(RuntimeError, match="execution role"):
        b.build()

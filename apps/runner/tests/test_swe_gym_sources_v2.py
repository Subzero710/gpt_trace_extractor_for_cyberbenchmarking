from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from gpt_trace_runner.superbench.adapters.swe_gym import guest_runtime, source, task_sources as tools
from gpt_trace_runner.superbench.adapters.swe_gym_lite import SWEGymLiteAdapter
from gpt_trace_runner.superbench.models import run_task_id


def git(folder, *args, input=None):
    return subprocess.run(["git", "-C", str(folder), *args], input=input, check=True, capture_output=True).stdout


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "trusted-host-repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.test")
    git(repo, "config", "user.name", "test")
    (repo / "setup.py").write_text("BASE SETUP\n")
    (repo / ".gitignore").write_text("*.ignored\n")
    (repo / "data.bin").write_bytes(b"\0base\xff")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "ancestor")
    ancestor = git(repo, "rev-parse", "HEAD").decode().strip()
    (repo / "source.py").write_text("task base\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "exact task base")
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    (repo / "source.py").write_text("FUTURE FIX MUST NOT LEAK\n")
    git(repo, "commit", "-am", "future fix")
    future = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "tag", "future-release")
    git(repo, "branch", "another-task")
    item = {"instance_id": "repo-1", "repo": "owner/repo", "base_commit": base,
            "template_id": "swe-gym-lite/owner_repo", "env_hash": "e"*22}
    archive = tmp_path / "source.tar.gz"
    record = tools.build_artifact(item, repo, archive)
    return repo, item, archive, record, future, ancestor


def test_source_is_deterministic_exact_original_single_commit_and_no_future(history, tmp_path):
    repo, item, archive, record, future, ancestor = history
    second = tmp_path / "second.tar.gz"
    assert tools.build_artifact(item, repo, second) == record
    assert archive.read_bytes() == second.read_bytes()
    extracted = tmp_path / "extracted"
    tools.extract(archive, extracted, sha256=record["sha256"], size=record["size"])
    assert git(extracted, "rev-parse", "HEAD").decode().strip() == item["base_commit"]
    assert git(extracted, "rev-list", "HEAD").decode().splitlines() == [item["base_commit"]]
    assert git(extracted, "remote") == git(extracted, "for-each-ref") == b""
    assert git(extracted, "status", "--porcelain") == b""
    assert git(extracted, "fsck", "--unreachable", "--no-reflogs") == b""
    assert (extracted / "source.py").read_text() == "task base\n"
    assert (extracted / "data.bin").read_bytes() == b"\0base\xff"
    for commit in (future, ancestor):
        assert subprocess.run(["git", "-C", str(extracted), "cat-file", "-e", commit], capture_output=True).returncode != 0


@pytest.mark.parametrize("attack", ["remote", "tag", "other-ref", "unreachable-future", "dirty", "ignored-file", "wrong-boundary", "hook", "alternate"])
def test_source_validator_rejects_history_and_control_data_attacks(history, tmp_path, attack):
    repo, item, archive, record, future, ancestor = history
    checkout = tmp_path / "checkout"
    tools.extract(archive, checkout, sha256=record["sha256"], size=record["size"])
    if attack == "remote": git(checkout, "remote", "add", "origin", str(repo))
    elif attack == "tag": git(checkout, "update-ref", "refs/tags/leak", item["base_commit"])
    elif attack == "other-ref": git(checkout, "update-ref", "refs/heads/other-task", item["base_commit"])
    elif attack == "unreachable-future":
        raw = git(repo, "cat-file", "commit", future)
        assert git(checkout, "hash-object", "-t", "commit", "-w", "--stdin", input=raw).decode().strip() == future
    elif attack == "dirty": (checkout / "source.py").write_text("changed")
    elif attack == "ignored-file": (checkout / "future.ignored").write_text("future source")
    elif attack == "wrong-boundary": (checkout / ".git/shallow").write_text(ancestor + "\n")
    elif attack == "hook": (checkout / ".git/hooks").mkdir()
    elif attack == "alternate":
        (checkout / ".git/objects/info").mkdir(exist_ok=True)
        (checkout / ".git/objects/info/alternates").write_text(str(repo / ".git/objects"))
    with pytest.raises(ValueError): tools.validate_checkout(checkout, item["base_commit"])


@pytest.mark.parametrize("key,value", [("instance_id", "another-task"), ("repo", "another/repo"), ("base_commit", "0"*40), ("template_id", "swe-gym-lite/another")])
def test_source_association_is_exact(history, key, value):
    _, item, archive, record, *_ = history
    with pytest.raises(ValueError, match="association"):
        tools.validate_artifact({**item, key: value}, archive, record)


@pytest.mark.parametrize("entry", ["../outside", "/outside", "link", "special"])
def test_extraction_never_follows_links_or_special_entries(tmp_path, entry):
    path = tmp_path / "bad.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(entry)
        if entry == "link": info.type, info.linkname = tarfile.SYMTYPE, "../../outside"
        elif entry == "special": info.type = tarfile.FIFOTYPE
        else: info.size = 4
        archive.addfile(info, io.BytesIO(b"data") if info.isfile() else None)
    with pytest.raises(ValueError):
        tools.extract(path, tmp_path / "out", sha256=tools.digest(path), size=path.stat().st_size)
    assert not (tmp_path / "outside").exists()


def test_exact_submodule_gitlink_has_its_own_single_commit(history, tmp_path):
    repo, _, _, _, future, _ = history
    git(repo, "checkout", "--detach", future)
    (repo / ".gitmodules").write_text('[submodule "different-name"]\n\tpath = nested/typeshed\n\turl = https://example.test/typeshed.git\n')
    sub = tmp_path / "sub-host"
    sub.mkdir()
    git(sub, "init")
    git(sub, "config", "user.email", "test@example.test")
    git(sub, "config", "user.name", "test")
    (sub / "types.pyi").write_text("exact types\n")
    git(sub, "add", ".")
    git(sub, "commit", "-m", "pinned submodule")
    commit = git(sub, "rev-parse", "HEAD").decode().strip()
    git(repo, "add", ".gitmodules")
    git(repo, "update-index", "--add", "--cacheinfo", "160000," + commit + ",nested/typeshed")
    git(repo, "commit", "-m", "gitlink")
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    (sub / "types.pyi").write_text("FUTURE TYPES\n")
    git(sub, "commit", "-am", "future types")
    item = {"instance_id":"sub-1","repo":"owner/repo","base_commit":base,"template_id":"swe-gym-lite/owner_repo"}
    def resolve(url, sha):
        assert url == "https://example.test/typeshed.git" and sha == commit
        return sub
    proof = tools.build_artifact(item, repo, tmp_path / "sub.tar.gz", submodule_mirror=resolve)
    assert proof["validation"]["submodules"]["nested/typeshed"]["reachable_commits"] == 1


def test_candidate_verification_extracts_own_source_and_preserves_binary_semantics(history, tmp_path):
    _, item, archive, record, *_ = history
    teacher = tmp_path / "teacher"
    artifact = {**record, "path": str(archive)}
    guest_runtime.clean_checkout(item, artifact, teacher)
    (teacher / "source.py").unlink()
    (teacher / "data.bin").write_bytes(b"\0new\xfe")
    (teacher / "new.py").write_text("new candidate\n")
    before = (teacher / ".git/index").read_bytes()
    patch = tmp_path / "candidate.patch"
    guest_runtime.candidate_patch(teacher, item["base_commit"], patch)
    fresh = tmp_path / "verify"
    guest_runtime.verify_candidate(item, patch, artifact, fresh)
    assert before == (teacher / ".git/index").read_bytes()
    assert not (fresh / "source.py").exists()
    assert (fresh / "new.py").read_text() == "new candidate\n"
    assert (fresh / "data.bin").read_bytes() == b"\0new\xfe"


def test_versions_invalidate_unsafe_completed_rows_without_changing_source_ids():
    assert source.PINS["recipe_version"] == source.PINS["schema_version"] == 2
    assert SWEGymLiteAdapter.adapter_version == "2"
    ids = list(source.contract()["tasks"])
    assert len(ids) == 230
    for logical in ids:
        assert run_task_id(logical, "c"*64, "swe-gym-lite", "1") != run_task_id(logical, "c"*64, "swe-gym-lite", "2")


def test_harness_and_safe_contract_bytes_are_unchanged():
    root = Path(source.__file__).parent
    assert tools.digest(root / "contract.json") == "fbb8b762277d09b6732a9697735889f761cf5d1920df0cafb5320809f834f38f"
    assert source.PINS["dataset_revision"] == "f70b1a29ab120eb0a0ee7a1deb029825e735b2b0"
    assert source.PINS["harness_commit"] == "16dd480cce9b27bf111a362d280881c6def5d2a7"
    for name, sha in source.PINS["upstream_files"].items():
        assert tools.digest(root / "upstream" / name) == sha

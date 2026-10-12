"""Deterministic, single-commit sources. Full mirrors are host inputs only.

The same strict extractor/validator runs on the host and in trusted guest setup.
No Git alternates, hooks, reflogs, tags, promisor objects or parent objects are
published. Gitlinks have independent single-commit checkouts at their exact SHA.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def stable(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def artifact_id(kind, instance_id):
    return hashlib.sha256(stable({"kind": kind, "logical_task_id": instance_id})).hexdigest()


def git(folder, *args, input=None):
    # Neither host gitconfig nor environment can add objects, hooks or filters.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    return subprocess.run(["git", "-C", str(folder), *args], input=input, env=env,
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def _safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name:
        raise ValueError("unsafe artifact archive path")
    return path


def _safe_link(name, target, allowed_absolute_links=()):
    if PurePosixPath(target).is_absolute() and any(PurePosixPath(target).is_relative_to(root) for root in allowed_absolute_links) and ".." not in PurePosixPath(target).parts:
        return
    if not target or PurePosixPath(target).is_absolute() or "\\" in target or "\x00" in target:
        raise ValueError("unsafe artifact symlink")
    depth = len(PurePosixPath(name).parent.parts)
    for part in PurePosixPath(target).parts:
        depth += -1 if part == ".." else 0 if part == "." else 1
        if depth < 0:
            raise ValueError("artifact symlink escapes checkout")
    if ".git" in PurePosixPath(name).parts:
        raise ValueError("symlink inside Git control data")


def extract(archive_path, destination, *, sha256, size, allowed_absolute_links=()):
    """Hash before extraction; never follow archive links or accept special files."""
    archive_path, destination = Path(archive_path), Path(destination)
    if archive_path.is_symlink() or not archive_path.is_file() or archive_path.stat().st_size != size or digest(archive_path) != sha256:
        raise ValueError("task artifact SHA256/size mismatch")
    if destination.exists() or destination.is_symlink():
        raise ValueError("artifact extraction requires an absent destination")
    destination.mkdir(parents=True)
    names, links = set(), []
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            path = _safe_name(member.name)
            if str(path) in names or member.mode & 0o7000 or not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError("unsafe/duplicate artifact member")
            names.add(str(path))
            target = destination / path
            # Links are created last, so no earlier member can redirect a write.
            if any(parent in {name for name, _ in links} for parent in (str(p) for p in path.parents)):
                raise ValueError("archive member traverses symlink")
            if member.issym():
                _safe_link(str(path), member.linkname, allowed_absolute_links)
                links.append((str(path), member.linkname))
            elif member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    for name, target in links:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def pack(folder, output, *, allowed_absolute_links=()):
    """Canonical tar metadata and gzip header; no inode-dependent hardlinks."""
    folder, output = Path(folder), Path(output)
    with output.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(folder.rglob("*")):
                name = path.relative_to(folder).as_posix()
                _safe_name(name)
                info = tarfile.TarInfo(name)
                info.uid = info.gid = info.mtime = 0
                if path.is_symlink():
                    _safe_link(name, os.readlink(path), allowed_absolute_links)
                    info.type, info.linkname, info.mode = tarfile.SYMTYPE, os.readlink(path), 0o777
                    archive.addfile(info)
                elif path.is_dir():
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(info)
                elif path.is_file():
                    info.size, info.mode = path.stat().st_size, 0o755 if path.stat().st_mode & 0o111 else 0o644
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    raise ValueError("special file in artifact")
        compressed.close()
        raw.flush()
        os.fsync(raw.fileno())
    return {"sha256": digest(output), "size": output.stat().st_size}


def validate_checkout(folder, base_commit):
    folder = Path(folder)
    if not (folder / ".git").is_dir() or (folder / ".git").is_symlink():
        raise ValueError("checkout needs an independent Git object directory")
    if git(folder, "rev-parse", "HEAD").decode().strip() != base_commit:
        raise ValueError("task source HEAD differs from exact base_commit")
    if git(folder, "remote") or git(folder, "for-each-ref"):
        raise ValueError("task source contains remotes/tags/other refs")
    if (folder / ".git/shallow").read_text() != base_commit + "\n" or git(folder, "rev-list", "HEAD").decode().splitlines() != [base_commit]:
        raise ValueError("task source has an incorrect shallow boundary/commit graph")
    for name in ("objects/info/alternates", "objects/info/http-alternates", "hooks", "logs", "FETCH_HEAD", "config.worktree"):
        if (folder / ".git" / name).exists():
            raise ValueError("task source contains external/history Git control data")
    if git(folder, "config", "--local", "--list").decode().splitlines() != [
        "core.repositoryformatversion=0", "core.filemode=true", "core.bare=false", "core.logallrefupdates=false"]:
        raise ValueError("unexpected task source Git configuration")
    reachable = set(git(folder, "rev-list", "--objects", "--no-object-names", "HEAD").decode().splitlines())
    objects = set(git(folder, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)").decode().splitlines())
    if objects != reachable:
        raise ValueError("task source contains an unreachable object corpus")
    if git(folder, "fsck", "--full", "--no-reflogs", "--unreachable").strip():
        raise ValueError("task source object validation failed")
    if git(folder, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("task source working tree is not pristine")
    expected_files, submodules = set(), {}
    for raw in git(folder, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not raw:
            continue
        header, name = raw.split(b"\t", 1)
        mode, kind, sha = header.decode().split()
        name = name.decode()
        _safe_name(name)
        if kind == "commit":
            submodules[name] = validate_checkout(folder / name, sha)
        else:
            expected_files.add(name)
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if (p.is_symlink() or not p.is_dir()) and
              ".git" not in p.relative_to(folder).parts and not any(p.is_relative_to(folder / sub) for sub in submodules)}
    if actual != expected_files:
        raise ValueError("task source contains extra/missing ignored working-tree files")
    return {"base_commit": base_commit, "reachable_commits": 1, "objects": len(objects), "submodules": submodules}


def _sanitize(folder, base):
    control = folder / ".git"
    for name in ("hooks", "logs", "FETCH_HEAD", "ORIG_HEAD", "description", "info"):
        path = control / name
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    (control / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n")
    git(folder, "reflog", "expire", "--expire=now", "--all")
    git(folder, "prune", "--expire=now")
    # read-tree writes a canonical index with no machine-dependent stat cache.
    (control / "index").unlink(missing_ok=True)
    git(folder, "read-tree", base)


def _checkout(mirror, folder, base, *, submodule_mirror=None, ancestry=()):
    if base in ancestry:
        raise ValueError("recursive submodule cycle")
    folder.mkdir()
    git(folder, "init", "--template=")
    git(folder, "-c", "protocol.file.allow=always", "fetch", "--depth=1", "--no-tags", str(mirror), base)
    git(folder, "checkout", "--detach", base)
    links = [row for row in git(folder, "ls-tree", "-rz", "HEAD").split(b"\0") if row.startswith(b"160000 commit ")]
    for link in links:
        head, raw_name = link.split(b"\t", 1)
        commit, name = head.decode().split()[2], raw_name.decode()
        _safe_name(name)
        if submodule_mirror is None:
            raise ValueError("exact submodule source is missing")
        paths = git(folder, "config", "--file", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$").decode().splitlines()
        keys = [line.split(" ", 1)[0][:-5] for line in paths if line.split(" ", 1)[1] == name]
        if len(keys) != 1:
            raise ValueError("submodule path has no unique pinned URL")
        url = git(folder, "config", "--file", ".gitmodules", "--get", keys[0] + ".url").decode().strip()
        selected = submodule_mirror(url, commit)
        target = folder / name
        target.rmdir()
        target.parent.mkdir(parents=True, exist_ok=True)
        _checkout(selected, target, commit, submodule_mirror=submodule_mirror, ancestry=(*ancestry, base))
    _sanitize(folder, base)
    return validate_checkout(folder, base)


def build_artifact(item, mirror, output, *, submodule_mirror=None):
    """Fresh object store fetches only base, then validates the packed extraction."""
    with tempfile.TemporaryDirectory(dir=Path(output).parent, prefix=".source-") as temporary:
        checkout = Path(temporary) / "checkout"
        proof = _checkout(Path(mirror).absolute(), checkout, item["base_commit"], submodule_mirror=submodule_mirror)
        integrity = pack(checkout, output)
        record = {**integrity, "kind": "task_source", "logical_task_id": item["instance_id"],
                  "allowed_template_id": item["template_id"],
                  "source_identity": {key: item[key] for key in ("instance_id", "repo", "base_commit")},
                  "validation": proof}
        validate_artifact(item, output, record)
    return record


def validate_artifact(item, archive, record):
    if record.get("logical_task_id") != item["instance_id"] or record.get("allowed_template_id") != item["template_id"] or record.get("source_identity") != {key: item[key] for key in ("instance_id", "repo", "base_commit")}:
        raise ValueError("task source instance/repo/base/template association mismatch")
    with tempfile.TemporaryDirectory(dir=Path(archive).parent, prefix=".validate-") as temporary:
        folder = Path(temporary) / "checkout"
        extract(archive, folder, sha256=record["sha256"], size=record["size"])
        proof = validate_checkout(folder, item["base_commit"])
        if proof != record["validation"]:
            raise ValueError("task source extraction changed the checkout")
    return proof

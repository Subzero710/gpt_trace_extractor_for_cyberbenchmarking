from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .exceptions import BenchmarkError

MAX_INITIAL_WORKSPACE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 640 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    sha256: str
    files: int
    bytes: int


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_entries(root: Path) -> list[Path]:
    if not root.is_dir():
        raise BenchmarkError(f"initial workspace is not a directory: {root}")
    entries: list[Path] = []
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        dirs.sort()
        files.sort()
        for name in [*dirs, *files]:
            path = base_path / name
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise BenchmarkError(f"cannot stat initial workspace entry: {path}") from exc
            if stat.S_ISLNK(mode):
                raise BenchmarkError(f"initial workspace must not contain symlinks: {path}")
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise BenchmarkError(f"initial workspace contains a special file: {path}")
            entries.append(path)
    entries.sort(key=lambda p: _relative(root, p))
    return entries


def snapshot(root: Path | None) -> WorkspaceSnapshot:
    digest = hashlib.sha256()
    files = 0
    total = 0
    if root is None:
        digest.update(b"empty\0")
        return WorkspaceSnapshot(digest.hexdigest(), 0, 0)

    root = root.resolve()
    for path in _iter_entries(root):
        rel = _relative(root, path)
        st = path.lstat()
        executable = bool(st.st_mode & 0o111)
        if path.is_dir():
            digest.update(b"d\0")
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            continue
        size = st.st_size
        total += size
        files += 1
        if total > MAX_INITIAL_WORKSPACE_BYTES:
            raise BenchmarkError(
                f"initial workspace exceeds {MAX_INITIAL_WORKSPACE_BYTES} bytes: {root}"
            )
        digest.update(b"f\0")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(b"x\0" if executable else b"-\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return WorkspaceSnapshot(digest.hexdigest(), files, total)


def build_workspace_archive(initial_workspace: Path | None, attachments: tuple[Path, ...]) -> bytes:
    """Create a deterministic tar archive rooted at the task workspace.

    Initial workspace files are placed at `/workspace/<relative path>`. User-visible
    attachments are placed under `/workspace/attachments/<basename>`.
    """
    buffer = io.BytesIO()
    occupied: set[str] = set()
    total = 0

    def add_dir(tf: tarfile.TarFile, rel: str) -> None:
        normalized = rel.rstrip("/")
        if not normalized or normalized in occupied:
            return
        info = tarfile.TarInfo(normalized)
        info.type = tarfile.DIRTYPE
        info.mode = 0o770
        info.uid = 0
        info.gid = 0
        info.mtime = 0
        tf.addfile(info)
        occupied.add(normalized)

    def add_file(tf: tarfile.TarFile, rel: str, path: Path) -> None:
        nonlocal total
        if rel in occupied:
            raise BenchmarkError(f"workspace seed path collision: {rel}")
        data = path.read_bytes()
        total += len(data)
        if total > MAX_ARCHIVE_BYTES:
            raise BenchmarkError(f"workspace seed/archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        info = tarfile.TarInfo(rel)
        info.size = len(data)
        info.mode = 0o770 if (path.stat().st_mode & 0o111) else 0o660
        info.uid = 0
        info.gid = 0
        info.mtime = 0
        tf.addfile(info, io.BytesIO(data))
        occupied.add(rel)

    with tarfile.open(fileobj=buffer, mode="w") as tf:
        if initial_workspace is not None:
            root = initial_workspace.resolve()
            for path in _iter_entries(root):
                rel = _relative(root, path)
                if path.is_dir():
                    add_dir(tf, rel)
                else:
                    parent = Path(rel).parent
                    chain: list[str] = []
                    while parent.as_posix() not in {".", ""}:
                        chain.append(parent.as_posix())
                        parent = parent.parent
                    for item in reversed(chain):
                        add_dir(tf, item)
                    add_file(tf, rel, path)

        if attachments:
            add_dir(tf, "attachments")
            for path in sorted(attachments, key=lambda p: p.name):
                add_file(tf, f"attachments/{path.name}", path)

    return buffer.getvalue()

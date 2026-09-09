from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import json
import os
import resource
import shutil
import signal
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_ATTACHMENT_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
STATE_FILE = "active.json"


class WorkspaceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ActiveWorkspace:
    task_id: str
    environment_id: str
    task_fingerprint: str
    status: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_identity(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise WorkspaceError(f"{label} must be a string")
    text = value
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
    if not text or len(text) > 255 or any(ch not in allowed for ch in text):
        raise WorkspaceError(f"invalid {label}")
    return text


def _valid_fingerprint(value: object) -> str:
    if not isinstance(value, str):
        raise WorkspaceError("task_fingerprint must be a string")
    text = value
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise WorkspaceError("invalid task_fingerprint")
    return text


class WorkspaceManager:
    def __init__(
        self,
        workspace_root: Path,
        state_root: Path,
        *,
        sandbox_uid: int = 10002,
        sandbox_gid: int = 10002,
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.state_root = state_root.resolve()
        self.sandbox_uid = sandbox_uid
        self.sandbox_gid = sandbox_gid
        self.lock = asyncio.Lock()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.state_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_root, 0o700)

    @property
    def state_path(self) -> Path:
        return self.state_root / STATE_FILE

    def _chown_sandbox(self, path: Path) -> None:
        if os.geteuid() != 0:
            return
        os.chown(path, self.sandbox_uid, self.sandbox_gid, follow_symlinks=False)

    def load_state(self) -> ActiveWorkspace | None:
        if not self.state_path.exists():
            return None
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            state = ActiveWorkspace(**raw)
        except Exception as exc:
            raise WorkspaceError("workspace state is unreadable") from exc
        _valid_identity(state.task_id, "task_id")
        _valid_identity(state.environment_id, "environment_id")
        _valid_fingerprint(state.task_fingerprint)
        if state.status not in {"preparing", "ready"}:
            raise WorkspaceError("workspace state has an invalid status")
        return state

    def _write_state(self, state: ActiveWorkspace) -> None:
        self.state_root.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".active-", dir=self.state_root)
        tmp = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(state), handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.state_path)
            self._fsync_dir(self.state_root)
        finally:
            if tmp.exists():
                tmp.unlink()

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _clear_workspace(self) -> None:
        for child in list(self.workspace_root.iterdir()):
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        self._fsync_dir(self.workspace_root)

    def _same_identity(self, state: ActiveWorkspace, payload: dict[str, Any]) -> bool:
        return (
            state.task_id == payload["task_id"]
            and state.environment_id == payload["environment_id"]
            and state.task_fingerprint == payload["task_fingerprint"]
        )

    def _relative_path(self, value: object) -> Path:
        if not isinstance(value, str):
            raise WorkspaceError("path must be a string")
        text = value
        if not text or "\x00" in text:
            raise WorkspaceError("path must be a non-empty relative path")
        relative = Path(text)
        if relative.is_absolute() or any(part in {"", ".."} for part in relative.parts):
            raise WorkspaceError("path escapes the task workspace")
        return relative

    def safe_path(
        self,
        value: object,
        *,
        must_exist: bool = False,
        allow_root: bool = False,
    ) -> Path:
        text = value if isinstance(value, str) else ""
        if isinstance(value, str) and text in {"", "."} and allow_root:
            return self.workspace_root
        relative = self._relative_path(value)
        candidate = self.workspace_root / relative
        current = self.workspace_root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise WorkspaceError("symlinks are not accepted for workspace file operations")
            if not current.exists():
                break
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.workspace_root)
        except (OSError, ValueError) as exc:
            raise WorkspaceError("path escapes the task workspace") from exc
        if must_exist and not resolved.exists():
            raise WorkspaceError(f"workspace path does not exist: {relative.as_posix()}")
        return resolved

    def _atomic_write(self, path: Path, data: bytes) -> None:
        if len(data) > MAX_FILE_BYTES:
            raise WorkspaceError(f"file exceeds {MAX_FILE_BYTES} bytes")
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in [path.parent, *path.parent.parents]:
            if parent == self.workspace_root.parent:
                break
            if parent.is_symlink():
                raise WorkspaceError("symlink parent is not accepted")
            os.chmod(parent, 0o770)
            self._chown_sandbox(parent)
            if parent == self.workspace_root:
                break
        fd, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        tmp = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o660)
            self._chown_sandbox(tmp)
            os.replace(tmp, path)
            self._fsync_dir(path.parent)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _decode_attachments(self, value: object) -> list[tuple[Path, bytes, str]]:
        if not isinstance(value, list):
            raise WorkspaceError("attachments must be a list")
        decoded: list[tuple[Path, bytes, str]] = []
        seen: set[str] = set()
        total = 0
        for item in value:
            if not isinstance(item, dict):
                raise WorkspaceError("attachment entry must be an object")
            relative = self._relative_path(item.get("path"))
            normalized = relative.as_posix()
            if normalized in seen:
                raise WorkspaceError("duplicate attachment path")
            encoded = item.get("content_base64")
            if not isinstance(encoded, str):
                raise WorkspaceError(f"attachment content_base64 must be a string: {normalized}")
            try:
                content = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise WorkspaceError(f"invalid base64 attachment: {normalized}") from exc
            declared_size = item.get("size")
            if isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size != len(content):
                raise WorkspaceError(f"attachment size mismatch: {normalized}")
            digest = _valid_fingerprint(item.get("sha256"))
            if _sha256(content) != digest:
                raise WorkspaceError(f"attachment SHA-256 mismatch: {normalized}")
            total += len(content)
            if total > MAX_ATTACHMENT_BYTES:
                raise WorkspaceError("task attachments exceed workspace limit")
            decoded.append((relative, content, digest))
            seen.add(normalized)
        decoded.sort(key=lambda item: item[0].as_posix())
        return decoded

    async def prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "task_id": _valid_identity(payload.get("task_id"), "task_id"),
            "environment_id": _valid_identity(payload.get("environment_id"), "environment_id"),
            "task_fingerprint": _valid_fingerprint(payload.get("task_fingerprint")),
        }
        attachments = self._decode_attachments(payload.get("attachments", []))
        async with self.lock:
            state = self.load_state()
            if state is not None and not self._same_identity(state, normalized):
                raise WorkspaceError(
                    f"workspace is owned by task {state.task_id!r} environment {state.environment_id!r}"
                )
            if state is None and any(self.workspace_root.iterdir()):
                raise WorkspaceError("workspace contains data without an ownership state")
            if state is not None and state.status == "ready":
                for relative, _, digest in attachments:
                    path = self.safe_path(relative.as_posix(), must_exist=True)
                    if not path.is_file() or _sha256(path.read_bytes()) != digest:
                        raise WorkspaceError("ready workspace attachment integrity mismatch")
                return {**asdict(state), "workspace": str(self.workspace_root)}

            preparing = ActiveWorkspace(**normalized, status="preparing")
            self._write_state(preparing)
            self._clear_workspace()
            for relative, content, _ in attachments:
                path = self.safe_path(relative.as_posix())
                self._atomic_write(path, content)
            os.chmod(self.workspace_root, 0o770)
            self._chown_sandbox(self.workspace_root)
            ready = ActiveWorkspace(**normalized, status="ready")
            self._write_state(ready)
            return {**asdict(ready), "workspace": str(self.workspace_root)}

    async def assert_resume(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "task_id": _valid_identity(payload.get("task_id"), "task_id"),
            "environment_id": _valid_identity(payload.get("environment_id"), "environment_id"),
            "task_fingerprint": _valid_fingerprint(payload.get("task_fingerprint")),
        }
        async with self.lock:
            state = self.load_state()
            if state is None or state.status != "ready" or not self._same_identity(state, normalized):
                raise WorkspaceError("the exact workspace environment is not available for recovery")
            return {**asdict(state), "workspace": str(self.workspace_root)}

    async def reset(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "task_id": _valid_identity(payload.get("task_id"), "task_id"),
            "environment_id": _valid_identity(payload.get("environment_id"), "environment_id"),
            "task_fingerprint": _valid_fingerprint(payload.get("task_fingerprint")),
        }
        async with self.lock:
            state = self.load_state()
            if state is None:
                if any(self.workspace_root.iterdir()):
                    raise WorkspaceError("workspace data exists without state; refusing blind reset")
                return {**normalized, "status": "idle"}
            if not self._same_identity(state, normalized):
                raise WorkspaceError("reset identity does not own the active workspace")
            self._clear_workspace()
            self.state_path.unlink()
            self._fsync_dir(self.state_root)
            return {**normalized, "status": "idle"}

    def require_ready(self) -> ActiveWorkspace:
        state = self.load_state()
        if state is None or state.status != "ready":
            raise WorkspaceError("no ready task workspace is active")
        return state

    def state_response(self) -> dict[str, Any]:
        state = self.load_state()
        if state is None:
            return {"status": "idle"}
        return asdict(state)

    def read_file(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        path = self.safe_path(args.get("path"), must_exist=True)
        if not path.is_file():
            raise WorkspaceError("read_file path is not a regular file")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise WorkspaceError(f"file exceeds {MAX_FILE_BYTES} byte read limit")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceError("read_file accepts UTF-8 text files only") from exc
        start = args.get("start_line", 1)
        end_raw = args.get("end_line")
        max_bytes = args.get("max_bytes", 262144)
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or (end_raw is not None and (isinstance(end_raw, bool) or not isinstance(end_raw, int)))
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
        ):
            raise WorkspaceError("read_file bounds must be integers")
        end = end_raw
        if start < 1 or (end is not None and end < start) or not 1 <= max_bytes <= 1048576:
            raise WorkspaceError("invalid read_file line or byte bounds")
        lines = text.splitlines(keepends=True)
        selected = "".join(lines[start - 1 : end])
        encoded = selected.encode("utf-8")
        truncated = len(encoded) > max_bytes
        if truncated:
            selected = encoded[:max_bytes].decode("utf-8", errors="ignore")
        relative = path.relative_to(self.workspace_root).as_posix()
        return {
            "path": relative,
            "content": selected,
            "sha256": _sha256(path.read_bytes()),
            "size": path.stat().st_size,
            "start_line": start,
            "end_line": min(end or len(lines), len(lines)),
            "truncated": truncated,
        }

    def write_file(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        path = self.safe_path(args.get("path"))
        content = args.get("content")
        if not isinstance(content, str):
            raise WorkspaceError("content must be a string")
        overwrite = args.get("overwrite", True)
        create_parents = args.get("create_parents", True)
        if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
            raise WorkspaceError("overwrite and create_parents must be booleans")
        expected = args.get("expected_sha256")
        if expected is not None:
            expected = _valid_fingerprint(expected)
        existed = path.exists()
        if existed:
            if path.is_symlink() or not path.is_file():
                raise WorkspaceError("write_file target must be a regular file")
            if not overwrite:
                raise WorkspaceError("write_file target already exists")
            if path.stat().st_size > MAX_FILE_BYTES:
                raise WorkspaceError("write_file refuses to replace an oversized file")
            current = _sha256(path.read_bytes())
            if expected is not None and current != expected:
                raise WorkspaceError("write_file expected_sha256 mismatch")
        elif expected is not None:
            raise WorkspaceError("write_file expected an existing file")
        if not path.parent.exists() and not create_parents:
            raise WorkspaceError("write_file parent does not exist")
        data = content.encode("utf-8")
        self._atomic_write(path, data)
        return {
            "path": path.relative_to(self.workspace_root).as_posix(),
            "sha256": _sha256(data),
            "size": len(data),
            "created": not existed,
        }

    def apply_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        path = self.safe_path(args.get("path"), must_exist=True)
        if not path.is_file():
            raise WorkspaceError("apply_patch target is not a regular file")
        expected = _valid_fingerprint(args.get("expected_sha256"))
        if path.stat().st_size > MAX_FILE_BYTES:
            raise WorkspaceError("apply_patch target is too large")
        original_bytes = path.read_bytes()
        if _sha256(original_bytes) != expected:
            raise WorkspaceError("apply_patch expected_sha256 mismatch")
        try:
            content = original_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceError("apply_patch accepts UTF-8 text files only") from exc
        replacements = args.get("replacements")
        if not isinstance(replacements, list) or not replacements:
            raise WorkspaceError("replacements must be a non-empty list")
        applied: list[dict[str, int]] = []
        for index, item in enumerate(replacements):
            if not isinstance(item, dict):
                raise WorkspaceError("replacement must be an object")
            old = item.get("old")
            new = item.get("new")
            count = item.get("expected_count", 1)
            if not isinstance(old, str) or not old or not isinstance(new, str):
                raise WorkspaceError("replacement old/new must be non-empty/string")
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                raise WorkspaceError("expected_count must be a positive integer")
            actual = content.count(old)
            if actual != count:
                raise WorkspaceError(
                    f"replacement {index} expected {count} occurrence(s), found {actual}"
                )
            content = content.replace(old, new, count)
            applied.append({"index": index, "count": count})
        data = content.encode("utf-8")
        self._atomic_write(path, data)
        return {
            "path": path.relative_to(self.workspace_root).as_posix(),
            "before_sha256": expected,
            "after_sha256": _sha256(data),
            "replacements": applied,
        }

    def list_directory(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        root = self.safe_path(args.get("path", "."), must_exist=True, allow_root=True)
        if not root.is_dir():
            raise WorkspaceError("list_directory path is not a directory")
        recursive = args.get("recursive", False)
        max_entries = args.get("max_entries", 1000)
        if (
            not isinstance(recursive, bool)
            or isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or not 1 <= max_entries <= 10000
        ):
            raise WorkspaceError("invalid list_directory options")
        candidates = root.rglob("*") if recursive else root.iterdir()
        entries: list[dict[str, Any]] = []
        truncated = False
        for path in sorted(candidates, key=lambda p: p.relative_to(self.workspace_root).as_posix()):
            if len(entries) >= max_entries:
                truncated = True
                break
            relative = path.relative_to(self.workspace_root).as_posix()
            if path.is_symlink():
                kind = "symlink"
                size = None
            elif path.is_dir():
                kind = "directory"
                size = None
            elif path.is_file():
                kind = "file"
                size = path.stat().st_size
            else:
                kind = "other"
                size = None
            entries.append({"path": relative, "type": kind, "size": size})
        return {"path": root.relative_to(self.workspace_root).as_posix() or ".", "entries": entries, "truncated": truncated}

    def search_files(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        query = args.get("query")
        if not isinstance(query, str) or not query:
            raise WorkspaceError("query must be a non-empty string")
        root = self.safe_path(args.get("path", "."), must_exist=True, allow_root=True)
        if not root.is_dir():
            raise WorkspaceError("search_files path is not a directory")
        file_glob = args.get("file_glob", "**/*")
        case_sensitive = args.get("case_sensitive", False)
        max_results = args.get("max_results", 100)
        if (
            not isinstance(file_glob, str)
            or not file_glob
            or "\x00" in file_glob
            or Path(file_glob).is_absolute()
            or ".." in Path(file_glob).parts
        ):
            raise WorkspaceError("file_glob must stay relative")
        if (
            not isinstance(case_sensitive, bool)
            or isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= 1000
        ):
            raise WorkspaceError("invalid search_files options")
        needle = query if case_sensitive else query.casefold()
        matches: list[dict[str, Any]] = []
        files = sorted(
            (p for p in root.rglob("*") if p.is_file() and not p.is_symlink()),
            key=lambda p: p.relative_to(self.workspace_root).as_posix(),
        )
        truncated = False
        for path in files:
            relative = path.relative_to(self.workspace_root).as_posix()
            relative_from_root = path.relative_to(root).as_posix()
            glob_matches = (
                file_glob == "**/*"
                or fnmatch.fnmatch(relative_from_root, file_glob)
                or fnmatch.fnmatch(relative, file_glob)
            )
            if not glob_matches:
                continue
            if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for line_number, line in enumerate(lines, 1):
                haystack = line if case_sensitive else line.casefold()
                start = 0
                while True:
                    column = haystack.find(needle, start)
                    if column < 0:
                        break
                    matches.append({"path": relative, "line": line_number, "column": column + 1, "text": line[:2000]})
                    if len(matches) >= max_results:
                        truncated = True
                        return {"query": query, "matches": matches, "truncated": truncated}
                    start = column + max(1, len(needle))
        return {"query": query, "matches": matches, "truncated": truncated}

    def _sandbox_preexec(self) -> None:
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
        except (ValueError, OSError):
            pass
        if os.geteuid() == 0 and (self.sandbox_uid != 0 or self.sandbox_gid != 0):
            os.setgroups([])
            os.setgid(self.sandbox_gid)
            os.setuid(self.sandbox_uid)
        os.umask(0o077)

    @staticmethod
    async def _read_bounded(stream: asyncio.StreamReader) -> tuple[bytes, bool]:
        kept = bytearray()
        total = 0
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if len(kept) < MAX_OUTPUT_BYTES:
                kept.extend(chunk[: MAX_OUTPUT_BYTES - len(kept)])
        return bytes(kept), total > MAX_OUTPUT_BYTES

    @staticmethod
    async def _kill_group(pid: int, sig: signal.Signals) -> None:
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            return

    async def exec_command(self, args: dict[str, Any]) -> dict[str, Any]:
        self.require_ready()
        command = args.get("command")
        cwd_value = args.get("cwd", ".")
        timeout_seconds = args.get("timeout_seconds", 120)
        if not isinstance(command, str) or not command or "\x00" in command or len(command.encode("utf-8")) > 1048576:
            raise WorkspaceError("command must be a non-empty string")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 1800:
            raise WorkspaceError("timeout_seconds must be between 1 and 1800")
        cwd = self.safe_path(cwd_value, must_exist=True, allow_root=True)
        if not cwd.is_dir():
            raise WorkspaceError("cwd is not a directory")
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.workspace_root),
            "TMPDIR": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        proc = await asyncio.create_subprocess_shell(
            command,
            executable="/bin/bash",
            cwd=cwd,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=self._sandbox_preexec,
        )
        assert proc.stdout is not None and proc.stderr is not None
        stdout_task = asyncio.create_task(self._read_bounded(proc.stdout))
        stderr_task = asyncio.create_task(self._read_bounded(proc.stderr))
        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), timeout=float(timeout_seconds))
        except TimeoutError:
            timed_out = True
            await self._kill_group(proc.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except TimeoutError:
                await self._kill_group(proc.pid, signal.SIGKILL)
                await proc.wait()
        finally:
            # A successful shell can leave background descendants. The task tool
            # contract never permits them to survive the call boundary.
            await self._kill_group(proc.pid, signal.SIGTERM)
            await asyncio.sleep(0)
            await self._kill_group(proc.pid, signal.SIGKILL)
        stdout, stdout_truncated = await stdout_task
        stderr, stderr_truncated = await stderr_task
        return {
            "command": command,
            "cwd": cwd.relative_to(self.workspace_root).as_posix() or ".",
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }

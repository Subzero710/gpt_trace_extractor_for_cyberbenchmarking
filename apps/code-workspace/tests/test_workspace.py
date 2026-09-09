from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

import pytest
import pytest_asyncio

from code_workspace.core import WorkspaceError, WorkspaceManager


def attachment(path: str, content: bytes) -> dict:
    return {
        "path": path,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def identity(task: str = "task", environment: str = "env") -> dict:
    return {
        "task_id": task,
        "environment_id": environment,
        "task_fingerprint": "a" * 64,
    }


@pytest_asyncio.fixture
async def manager(tmp_path: Path) -> WorkspaceManager:
    item = WorkspaceManager(
        tmp_path / "workspace",
        tmp_path / "state",
        sandbox_uid=os.getuid(),
        sandbox_gid=os.getgid(),
    )
    await item.prepare({**identity(), "attachments": [attachment("fixtures/a.txt", b"hello\nworld\n")]})
    return item


@pytest.mark.asyncio
async def test_prepare_is_idempotent_and_reset_is_owned(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "workspace", tmp_path / "state", sandbox_uid=os.getuid(), sandbox_gid=os.getgid())
    payload = {**identity(), "attachments": [attachment("repo.txt", b"x")]}
    first = await manager.prepare(payload)
    second = await manager.prepare(payload)
    assert first["status"] == second["status"] == "ready"
    with pytest.raises(WorkspaceError, match="does not own"):
        await manager.reset({**identity(environment="different")})
    await manager.reset(identity())
    assert manager.state_response() == {"status": "idle"}
    assert list(manager.workspace_root.iterdir()) == []


def test_read_write_patch_list_and_search_are_deterministic(manager: WorkspaceManager) -> None:
    read = manager.read_file({"path": "fixtures/a.txt"})
    assert read["content"] == "hello\nworld\n"
    created = manager.write_file({"path": "src/z.py", "content": "needle\n"})
    assert created["created"] is True
    manager.write_file({"path": "src/a.py", "content": "needle\n"})
    patched = manager.apply_patch({
        "path": "src/z.py",
        "expected_sha256": created["sha256"],
        "replacements": [{"old": "needle", "new": "fixed"}],
    })
    assert patched["after_sha256"] != patched["before_sha256"]
    listing = manager.list_directory({"recursive": True})
    paths = [entry["path"] for entry in listing["entries"]]
    assert paths == sorted(paths)
    found = manager.search_files({"query": "needle"})
    assert found["matches"] == [{"path": "src/a.py", "line": 1, "column": 1, "text": "needle"}]

    root_file = manager.write_file({"path": "root.txt", "content": "needle\n"})
    assert root_file["created"] is True
    assert any(match["path"] == "root.txt" for match in manager.search_files({"query": "needle"})["matches"])


def test_traversal_and_symlink_escape_are_rejected(manager: WorkspaceManager, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    with pytest.raises(WorkspaceError, match="escapes"):
        manager.read_file({"path": "../outside.txt"})
    link = manager.workspace_root / "link"
    link.symlink_to(outside)
    with pytest.raises(WorkspaceError, match="symlink"):
        manager.read_file({"path": "link"})
    with pytest.raises(WorkspaceError, match="symlink"):
        manager.write_file({"path": "link", "content": "overwrite"})
    assert outside.read_text() == "secret"


def test_tool_arguments_do_not_coerce_invalid_types(manager: WorkspaceManager) -> None:
    with pytest.raises(WorkspaceError, match="bounds must be integers"):
        manager.read_file({"path": "fixtures/a.txt", "start_line": "1"})
    with pytest.raises(WorkspaceError, match="path must be a string"):
        manager.read_file({"path": None})


@pytest.mark.asyncio
async def test_exec_command_returns_streams_status_and_timeout(manager: WorkspaceManager) -> None:
    result = await manager.exec_command({
        "command": "printf out; printf err >&2; exit 7",
        "timeout_seconds": 5,
    })
    assert result["stdout"] == "out"
    assert result["stderr"] == "err"
    assert result["exit_code"] == 7
    assert result["timed_out"] is False

    timed = await manager.exec_command({
        "command": "sleep 30 & child=$!; printf %s $child > child.pid; wait",
        "timeout_seconds": 1,
    })
    assert timed["timed_out"] is True
    pid = int((manager.workspace_root / "child.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.asyncio
async def test_recovery_requires_exact_environment(manager: WorkspaceManager) -> None:
    assert (await manager.assert_resume(identity()))["status"] == "ready"
    with pytest.raises(WorkspaceError, match="exact workspace"):
        await manager.assert_resume(identity(environment="other"))

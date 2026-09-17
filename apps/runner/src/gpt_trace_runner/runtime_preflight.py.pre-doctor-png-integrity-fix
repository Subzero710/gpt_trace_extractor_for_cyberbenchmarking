from __future__ import annotations

import base64
import json
import shlex
from dataclasses import replace
from typing import Any, Sequence
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from rich.console import Console

from .app_lifecycle import AppLifecycle
from .exceptions import AppInfrastructureError
from .models import BenchmarkTask, BenchmarkTool, task_fingerprint


CHATGPT_BLOCKED_HOST = "chatgpt.com"


def _expected_gateway_host(app_id: str) -> str:
    if app_id == "code-workspace":
        return "workspace-gateway"
    if app_id == "browser":
        return "browser-gateway"
    raise AppInfrastructureError(f"unsupported local App in doctor: {app_id!r}")


def _validate_mcp_endpoint(tool: BenchmarkTool) -> str:
    if not tool.mcp_endpoint:
        raise AppInfrastructureError(f"local App {tool.app_id!r} has no MCP endpoint")
    try:
        parsed = urlparse(tool.mcp_endpoint)
        port = parsed.port
    except ValueError as exc:
        raise AppInfrastructureError(f"invalid MCP endpoint for {tool.app_id}") from exc
    expected_host = _expected_gateway_host(tool.app_id)
    if (
        parsed.scheme != "http"
        or parsed.hostname != expected_host
        or port != 8000
        or parsed.path.rstrip("/") != "/mcp"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AppInfrastructureError(
            f"local App {tool.app_id!r} MCP endpoint must be internal "
            f"http://{expected_host}:8000/mcp"
        )
    return tool.mcp_endpoint


def _manifest_contract(tool: BenchmarkTool) -> dict[str, dict[str, Any]]:
    rows = tool.tool_manifest.get("tools")
    if not isinstance(rows, list):
        raise AppInfrastructureError(f"{tool.app_id} tool manifest has no tools list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise AppInfrastructureError(f"{tool.app_id} tool manifest is malformed")
        result[row["name"]] = row
    return result


def _actual_contract(items: Sequence[Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        name = getattr(item, "name", None)
        if not isinstance(name, str):
            raise AppInfrastructureError("MCP tools/list returned a tool without a name")
        result[name] = {
            "name": name,
            "description": getattr(item, "description", None),
            "inputSchema": getattr(item, "inputSchema", None),
        }
    return result


async def _assert_manifest(session: ClientSession, tool: BenchmarkTool) -> None:
    listed = await session.list_tools()
    expected = _manifest_contract(tool)
    actual = _actual_contract(listed.tools)
    if set(actual) != set(expected):
        raise AppInfrastructureError(
            f"{tool.app_id} runtime MCP tool names differ from registry manifest: "
            f"expected={sorted(expected)}, actual={sorted(actual)}"
        )
    for name in sorted(expected):
        row = expected[name]
        if actual[name]["description"] != row.get("description"):
            raise AppInfrastructureError(f"{tool.app_id} MCP description drift for {name}")
        if actual[name]["inputSchema"] != row.get("inputSchema"):
            raise AppInfrastructureError(f"{tool.app_id} MCP input schema drift for {name}")


def _tool_payload(result: Any, *, app_id: str, name: str) -> dict[str, Any]:
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        detail = " | ".join(
            str(getattr(item, "text", ""))[:1000]
            for item in getattr(result, "content", [])
        )
        raise AppInfrastructureError(f"{app_id} MCP {name} returned an error: {detail}")
    texts = [
        getattr(item, "text", None)
        for item in getattr(result, "content", [])
        if isinstance(getattr(item, "text", None), str)
    ]
    if len(texts) != 1:
        raise AppInfrastructureError(
            f"{app_id} MCP {name} must return exactly one JSON text content block"
        )
    try:
        value = json.loads(texts[0])
    except ValueError as exc:
        raise AppInfrastructureError(f"{app_id} MCP {name} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AppInfrastructureError(f"{app_id} MCP {name} returned a non-object")
    return value


async def _call(
    session: ClientSession,
    tool: BenchmarkTool,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    try:
        result = await session.call_tool(name, arguments)
    except Exception as exc:
        raise AppInfrastructureError(f"{tool.app_id} MCP {name} transport/call failed") from exc
    return _tool_payload(result, app_id=tool.app_id, name=name)


async def _assert_rejected(
    session: ClientSession,
    tool: BenchmarkTool,
    name: str,
    arguments: dict[str, Any],
    *,
    contains: str,
) -> None:
    try:
        result = await session.call_tool(name, arguments)
    except Exception as exc:
        text = str(exc)
        if contains.casefold() in text.casefold():
            return
        raise AppInfrastructureError(
            f"{tool.app_id} MCP {name} rejection did not prove the ChatGPT guard: {text}"
        ) from exc
    if not bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        raise AppInfrastructureError(
            f"{tool.app_id} unexpectedly allowed forbidden target {arguments!r}"
        )
    detail = " | ".join(
        str(getattr(item, "text", "")) for item in getattr(result, "content", [])
    )
    if contains.casefold() not in detail.casefold():
        raise AppInfrastructureError(
            f"{tool.app_id} rejected forbidden target for the wrong reason: {detail[:1000]}"
        )


async def _workspace_smoke(
    session: ClientSession,
    tool: BenchmarkTool,
    *,
    index: int,
    previous_marker: str | None,
) -> str:
    listing = await _call(session, tool, "list_directory", {"path": ".", "recursive": False})
    entries = listing.get("entries")
    if not isinstance(entries, list):
        raise AppInfrastructureError("code-workspace list_directory returned invalid entries")
    paths = {row.get("path") for row in entries if isinstance(row, dict)}
    if previous_marker is not None and previous_marker in paths:
        raise AppInfrastructureError(
            f"workspace isolation failed: previous doctor marker survived: {previous_marker}"
        )

    marker = f".doctor-workspace-{index}.txt"
    value = f"doctor-workspace-{index}"
    command = f"printf '%s\\n' {shlex.quote(value)} > {shlex.quote(marker)}"
    executed = await _call(session, tool, "exec_command", {"command": command})
    if executed.get("exit_code") != 0 or executed.get("timed_out") is True:
        raise AppInfrastructureError(f"code-workspace exec_command failed: {executed}")

    read = await _call(session, tool, "read_file", {"path": marker})
    if read.get("content") != value + "\n":
        raise AppInfrastructureError("code-workspace exec/read round-trip corrupted data")

    write_path = f".doctor-write-{index}.txt"
    written = await _call(
        session,
        tool,
        "write_file",
        {"path": write_path, "content": "doctor-alpha\n"},
    )
    digest = written.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise AppInfrastructureError("code-workspace write_file returned invalid SHA-256")

    patched = await _call(
        session,
        tool,
        "apply_patch",
        {
            "path": write_path,
            "expected_sha256": digest,
            "replacements": [
                {"old": "doctor-alpha", "new": "doctor-beta", "expected_count": 1}
            ],
        },
    )
    if patched.get("before_sha256") != digest:
        raise AppInfrastructureError("code-workspace apply_patch did not honor expected SHA-256")

    read_back = await _call(session, tool, "read_file", {"path": write_path})
    if read_back.get("content") != "doctor-beta\n":
        raise AppInfrastructureError("code-workspace apply_patch/read verification failed")

    searched = await _call(
        session,
        tool,
        "search_files",
        {"path": ".", "query": "doctor-beta", "file_glob": "**/*"},
    )
    if write_path not in json.dumps(searched, ensure_ascii=False, sort_keys=True):
        raise AppInfrastructureError("code-workspace search_files did not find its smoke marker")

    recursive = await _call(
        session,
        tool,
        "list_directory",
        {"path": ".", "recursive": True, "max_entries": 1000},
    )
    if marker not in json.dumps(recursive, ensure_ascii=False, sort_keys=True):
        raise AppInfrastructureError("code-workspace recursive listing lost its smoke marker")
    return marker


async def _browser_smoke(
    session: ClientSession,
    tool: BenchmarkTool,
    *,
    previous_example_tab: bool,
    require_chatgpt_block: bool,
) -> bool:
    tabs = await _call(session, tool, "tabs", {"action": "list"})
    rows = tabs.get("tabs")
    if not isinstance(rows, list):
        raise AppInfrastructureError("browser tabs returned an invalid list")
    if previous_example_tab:
        for row in rows:
            if not isinstance(row, dict):
                continue
            host = (urlparse(str(row.get("url", ""))).hostname or "").casefold()
            if host == "example.com" or host.endswith(".example.com"):
                raise AppInfrastructureError(
                    "browser isolation failed: previous Example Domain tab survived"
                )

    if require_chatgpt_block:
        # Prove the doctor-specific prohibition is active. BrowserPolicy rejects this
        # before DNS lookup or navigation, so this assertion itself does not touch ChatGPT.
        await _assert_rejected(
            session,
            tool,
            "navigate",
            {"url": "https://chatgpt.com/", "wait_until": "domcontentloaded"},
            contains="blocked host",
        )

    nav = await _call(
        session,
        tool,
        "navigate",
        {"url": "https://example.com/", "wait_until": "domcontentloaded"},
    )
    if (urlparse(str(nav.get("url", ""))).hostname or "").casefold() != "example.com":
        raise AppInfrastructureError(f"browser navigate did not reach example.com: {nav}")

    page = await _call(
        session,
        tool,
        "read_page",
        {"include_elements": True, "max_chars": 20000, "max_elements": 100},
    )
    if page.get("title") != "Example Domain" or "Example Domain" not in str(page.get("text", "")):
        raise AppInfrastructureError("browser read_page did not return the expected Example Domain page")

    await _call(session, tool, "wait", {"seconds": 0.05})
    await _call(session, tool, "press", {"key": "Home"})

    image = await _call(session, tool, "screenshot", {"full_page": False})
    encoded = image.get("content_base64")
    if image.get("mime_type") != "image/png" or not isinstance(encoded, str):
        raise AppInfrastructureError("browser screenshot returned invalid metadata")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise AppInfrastructureError("browser screenshot base64 is invalid") from exc
    if not raw.startswith(b"\\x89PNG\\r\\n\\x1a\\n") or image.get("size") != len(raw):
        raise AppInfrastructureError("browser screenshot content/integrity mismatch")

    new_tab = await _call(session, tool, "tabs", {"action": "new"})
    active = new_tab.get("active_index")
    if isinstance(active, bool) or not isinstance(active, int):
        raise AppInfrastructureError("browser tabs new returned invalid active_index")
    await _call(session, tool, "tabs", {"action": "close", "index": active})

    final_tabs = await _call(session, tool, "tabs", {"action": "list"})
    if "example.com" not in json.dumps(final_tabs, ensure_ascii=False, sort_keys=True):
        raise AppInfrastructureError("browser tab state lost the navigated Example Domain page")
    return True


async def _smoke_tool(
    tool: BenchmarkTool,
    *,
    index: int,
    previous_workspace_marker: str | None,
    previous_example_tab: bool,
    require_chatgpt_block: bool,
) -> tuple[str | None, bool]:
    endpoint = _validate_mcp_endpoint(tool)
    try:
        async with streamable_http_client(endpoint) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                await _assert_manifest(session, tool)
                if tool.app_id == "code-workspace":
                    marker = await _workspace_smoke(
                        session,
                        tool,
                        index=index,
                        previous_marker=previous_workspace_marker,
                    )
                    return marker, previous_example_tab
                if tool.app_id == "browser":
                    seen = await _browser_smoke(
                        session,
                        tool,
                        previous_example_tab=previous_example_tab,
                        require_chatgpt_block=require_chatgpt_block,
                    )
                    return previous_workspace_marker, seen
                raise AppInfrastructureError(f"doctor has no smoke implementation for {tool.app_id!r}")
    except AppInfrastructureError:
        raise
    except Exception as exc:
        raise AppInfrastructureError(f"{tool.app_id} MCP session failed during doctor smoke") from exc


async def preflight_tasks(
    lifecycle: AppLifecycle,
    tasks: Sequence[BenchmarkTask],
    *,
    console: Console,
    require_chatgpt_block: bool = False,
) -> None:
    """Maximal preflight of every non-ChatGPT runtime path used by the benchmark."""
    if not tasks:
        raise AppInfrastructureError("runtime preflight selection is empty")

    previous_workspace_marker: str | None = None
    previous_example_tab = False

    for index, task in enumerate(tasks, 1):
        source_fingerprint = task_fingerprint(task)
        probe = replace(
            task,
            task_id=f"doctor-{index}-{source_fingerprint[:16]}",
        )
        fingerprint = task_fingerprint(probe)
        attempt = 1
        environments = lifecycle.environment_ids(
            probe,
            attempt=attempt,
            fingerprint=fingerprint,
        )

        console.print(f"[dim]doctor preflight {index}/{len(tasks)}: {task.task_id}[/]")

        primary_error: Exception | None = None
        prepared = False
        try:
            await lifecycle.health(probe)
            await lifecycle.prepare(
                probe,
                environments,
                fingerprint,
                attempt=attempt,
            )
            prepared = True

            for tool in probe.tools:
                if tool.kind != "local_mcp":
                    continue
                previous_workspace_marker, previous_example_tab = await _smoke_tool(
                    tool,
                    index=index,
                    previous_workspace_marker=previous_workspace_marker,
                    previous_example_tab=previous_example_tab,
                    require_chatgpt_block=require_chatgpt_block,
                )
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            cleanup_error: Exception | None = None
            try:
                # reset() is intentionally attempted even after a partial prepare;
                # both gateway deactivation and Docker destroy are idempotent.
                await lifecycle.reset(
                    probe,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
                await lifecycle.assert_clean(
                    probe,
                    environments,
                    fingerprint,
                    attempt=attempt,
                )
            except Exception as exc:
                cleanup_error = exc

            if cleanup_error is not None:
                if primary_error is None:
                    raise cleanup_error
                raise AppInfrastructureError(
                    f"doctor preflight for {task.task_id!r} failed with "
                    f"{type(primary_error).__name__}: {primary_error}; "
                    f"cleanup verification also failed with "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                ) from primary_error

        if not prepared:
            raise AppInfrastructureError(f"doctor preflight did not prepare {task.task_id}")
        console.print(f"[green]doctor preflight: {task.task_id}: ok[/]")

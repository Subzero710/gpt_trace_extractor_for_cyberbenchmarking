from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


EXPECTED = {
    "probe_ping": True,
    "probe_read_state": True,
    "probe_write_state": False,
}


def _payload(result: Any) -> dict[str, Any]:
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        detail = " | ".join(
            str(getattr(item, "text", "")) for item in getattr(result, "content", [])
        )
        raise RuntimeError(f"MCP tool returned an error: {detail}")
    texts = [
        getattr(item, "text", None)
        for item in getattr(result, "content", [])
        if isinstance(getattr(item, "text", None), str)
    ]
    if len(texts) != 1:
        raise RuntimeError("expected exactly one text content block")
    value = json.loads(texts[0])
    if not isinstance(value, dict):
        raise RuntimeError("tool result is not a JSON object")
    return value


async def run(url: str) -> None:
    async with streamable_http_client(url) as (
        read_stream,
        write_stream,
        _get_session_id,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            if set(tools) != set(EXPECTED):
                raise RuntimeError(
                    f"unexpected tool set: expected={sorted(EXPECTED)}, actual={sorted(tools)}"
                )

            for name, expected_read_only in EXPECTED.items():
                annotations = getattr(tools[name], "annotations", None)
                actual = getattr(annotations, "readOnlyHint", None)
                if actual is None:
                    actual = getattr(annotations, "read_only_hint", None)
                if actual is not expected_read_only:
                    raise RuntimeError(
                        f"{name} readOnlyHint mismatch: expected={expected_read_only}, actual={actual}"
                    )

            ping = _payload(await session.call_tool("probe_ping", {}))
            if ping.get("ok") is not True:
                raise RuntimeError(f"invalid ping result: {ping!r}")

            before = _payload(await session.call_tool("probe_read_state", {}))
            written = _payload(
                await session.call_tool(
                    "probe_write_state",
                    {"value": "local-smoke"},
                )
            )
            after = _payload(await session.call_tool("probe_read_state", {}))

            if written.get("value") != "local-smoke":
                raise RuntimeError(f"write result was not persisted: {written!r}")
            if after != written:
                raise RuntimeError(
                    f"read-after-write mismatch: written={written!r}, after={after!r}"
                )
            if not isinstance(before.get("revision"), int):
                raise RuntimeError(f"invalid initial state: {before!r}")

            print(
                json.dumps(
                    {
                        "status": "ok",
                        "url": url,
                        "tools": sorted(tools),
                        "before": before,
                        "after": after,
                    },
                    sort_keys=True,
                )
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/mcp/",
        help="MCP Streamable HTTP endpoint; keep the trailing slash.",
    )
    args = parser.parse_args()
    asyncio.run(run(args.url))


if __name__ == "__main__":
    main()

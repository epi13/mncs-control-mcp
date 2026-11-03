"""Bounded fresh-connection consumer of the canonical Environment MCP tool.

This is deliberately a client, not another Environment entry implementation.
It never reads the Store, supplies a principal, or replays a failed mutation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import timedelta
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

MAX_REQUEST_BYTES = 256 * 1024


def validate_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) - {"project", "cwd", "operation", "arguments"}:
        raise ValueError("expected only project, cwd, operation, and arguments")
    for field in ("project", "operation"):
        if not isinstance(request.get(field), str) or not request[field]:
            raise ValueError(f"{field} is required")
    if "cwd" in request and not isinstance(request["cwd"], str):
        raise ValueError("cwd must be text")
    if "arguments" in request and not isinstance(request["arguments"], dict):
        raise ValueError("arguments must be an object")
    return request


async def call_environment(request: dict[str, Any]) -> dict[str, Any]:
    """Open one real MCP connection, call once, and release the provider.

    Each call loads published bridge source and obtains a new PID-bound grant.
    Exact durable selectors are checked by Control, never trusted by this client.
    A closed connection cannot establish whether a mutation committed; do not retry.
    """
    validate_request(request)
    parameters = StdioServerParameters(
        command=sys.executable,
        env=dict(os.environ),
        args=["-B", "-m", "mncs_control_mcp.local_environment_mcp"],
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "mncs_environment", request,
                read_timeout_seconds=timedelta(seconds=86500),
            )
            return result.model_dump(mode="json", exclude_none=True)


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("Environment MCP request exceeds 256 KiB")
        request = validate_request(json.loads(payload))
        result = asyncio.run(call_environment(request))
        print(json.dumps(result, ensure_ascii=False))
        structured = result.get("structuredContent", {})
        return int(bool(result.get("isError") or structured.get("ok") is False))
    except Exception as error:
        print(json.dumps({"ok": False, "error": {
            "code": "ENVIRONMENT_MCP_CONNECTION_FAILED",
            "message": str(error)[:1200],
            "next": "Check Control RPC readiness. Do not blindly replay a mutation; "
                    "inspect the exact durable session through a fresh connection first.",
        }}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only stdio MCP smoke test for deployment diagnostics."""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

REQUIRED_TOOLS = {"control_capabilities", "fabric_status", "workspace_info", "list_projects"}


def read_response(stream, process: subprocess.Popen[str], request_id: int, timeout: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([stream], [], [], max(0.05, deadline - time.monotonic()))
        if not ready:
            continue
        line = stream.readline()
        if not line:
            break
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("id") == request_id:
            return value
    detail = "MCP process exited without a response" if process.poll() is not None else "MCP response timed out"
    raise RuntimeError(detail)


def request(process: subprocess.Popen[str], request_id: int, method: str, params: dict[str, object]) -> dict[str, object]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n")
    process.stdin.flush()
    response = read_response(process.stdout, process, request_id, 15.0)
    if "error" in response:
        raise RuntimeError(f"{method} returned JSON-RPC error")
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"{method} returned malformed result")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("control.toml"))
    parser.add_argument("--executable", type=Path, help="configured MCP executable; defaults to this interpreter")
    args = parser.parse_args(argv)
    command = [str(args.executable), "--config", str(args.config)] if args.executable else [sys.executable, "-m", "mncs_control_mcp", "--config", str(args.config)]
    environment = dict(os.environ)
    if args.executable is None:
        source = Path(__file__).parents[1] / "src"
        environment["PYTHONPATH"] = os.pathsep.join(filter(None, [str(source), environment.get("PYTHONPATH", "")]))
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    report: dict[str, object] = {"status": "FAIL", "config": str(args.config), "command": command}
    try:
        initialize = request(process, 1, "initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mncs-control-mcp-smoke", "version": "1"},
        })
        assert process.stdin is not None
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        process.stdin.flush()
        tools = request(process, 2, "tools/list", {})
        tool_items = tools.get("tools", [])
        names = {item.get("name") for item in tool_items if isinstance(item, dict)}
        missing = sorted(REQUIRED_TOOLS - names)
        if missing:
            raise RuntimeError("missing required tools: " + ", ".join(missing))
        calls: dict[str, object] = {}
        for index, name in enumerate(sorted(REQUIRED_TOOLS), start=3):
            result = request(process, index, "tools/call", {"name": name, "arguments": {}})
            structured = result.get("structuredContent")
            if not isinstance(structured, dict):
                raise RuntimeError(f"{name} returned malformed structured output")
            calls[name] = structured
        fabric = calls.get("fabric_status")
        if not isinstance(fabric, dict):
            raise RuntimeError("fabric_status did not return structured output")
        if fabric.get("fabric_mode") == "service" and fabric.get("controller_connected") is not True:
            raise RuntimeError("persistent Fabric consumer connection failed")
        report.update({"status": "PASS", "initialize": initialize.get("serverInfo", initialize.get("server_info")), "tool_count": len(names), "calls": calls})
    except (OSError, RuntimeError, AssertionError) as exc:
        report["error"] = str(exc)[:500]
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

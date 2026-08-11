from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_mcp_server_starts_and_tool_discovery_works(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    config_path = tmp_path / "control.toml"
    config_path.write_text(f"[mncs]\nprojects_root = {str(tmp_path)!r}\n", encoding="utf-8")
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    process = subprocess.Popen(
        [sys.executable, "-m", "mncs_control_mcp", "--config", str(config_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).parents[1],
    )
    assert process.stdin is not None
    process.stdin.write("\n".join(json.dumps(item) for item in requests) + "\n")
    process.stdin.flush()
    assert process.stdout is not None
    responses = [json.loads(process.stdout.readline()) for _ in range(2)]
    process.terminate()
    _, stderr = process.communicate(timeout=10)
    assert process.returncode in {-15, 0}, stderr
    assert any(item.get("id") == 1 and "result" in item for item in responses)
    tools = next(item["result"]["tools"] for item in responses if item.get("id") == 2)
    names = {item["name"] for item in tools}
    assert {"system_status", "list_repositories", "repo_status", "fabric_status", "model_status", "run_tests"} <= names

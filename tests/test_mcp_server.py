from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


class StdioClient:
    def __init__(self, config_path: Path, cwd: Path) -> None:
        self.process = subprocess.Popen(
            [shutil.which("python") or sys.executable, "-m", "mncs_control_mcp", "--config", str(config_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env={**os.environ, "PYTHONPATH": str(cwd / "src")},
        )
        self.next_id = 1

    def notify(self, method: str, params: dict[str, object]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        request_id = self.next_id
        self.next_id += 1
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 20)
        if not ready:
            self.close()
            raise AssertionError("timed out waiting for MCP response")
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise AssertionError("MCP server exited: " + self.process.stderr.read())
        response = json.loads(line)
        assert response.get("id") == request_id
        assert "error" not in response, response
        return response["result"]

    def call(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        assert result.get("isError") is False, result
        return result["structuredContent"]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_stdio_mcp_end_to_end_developer_workspace(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    workspace = tmp_path / "projects"
    workspace.mkdir()
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        f"""
[workspace]
root = {str(workspace)!r}
[sandbox]
backend = "bwrap"
require_real_sandbox = true
home = {str(tmp_path / 'sandbox-home')!r}
[terminal]
job_state_path = {str(tmp_path / 'state' / 'jobs.json')!r}
[server]
audit_path = {str(tmp_path / 'state' / 'audit.jsonl')!r}
""",
        encoding="utf-8",
    )
    client = StdioClient(config_path, Path(__file__).parents[1])
    try:
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1"},
            },
        )
        assert initialized["serverInfo"]["name"] == "mncs-control-mcp"
        client.notify("notifications/initialized", {})
        tools = client.request("tools/list", {})["tools"]
        names = {item["name"] for item in tools}
        assert {
            "workspace_info", "list_projects", "file_write", "file_read", "terminal_exec",
            "terminal_start", "git_status", "git_commit", "tool_inventory", "fabric_status",
        } <= names
        terminal = next(item for item in tools if item["name"] == "terminal_exec")
        assert terminal["annotations"]["destructiveHint"] is True
        assert terminal["annotations"]["openWorldHint"] is True

        info = client.call("workspace_info", {})
        assert info["root"] == str(workspace)
        client.call("project_create", {"name": "e2e", "kind": "empty", "git_init": False})
        client.call("file_write", {"path": "e2e/hello.py", "content": "print('hello')\n"})
        read = client.call("file_read", {"path": "e2e/hello.py"})
        assert read["content"] == "print('hello')\n"
        shell = client.call(
            "terminal_exec",
            {"command": "python hello.py", "scope": "project", "project": "e2e", "network": False},
        )
        assert shell["exit_code"] == 0
        assert shell["stdout"] == "hello\n"
        client.call(
            "terminal_exec",
            {"command": "git init -q; git config user.email test@example.invalid; git config user.name Test", "scope": "project", "project": "e2e"},
        )
        status = client.call("git_status", {"repository": "e2e"})
        assert status["clean"] is False
        client.call("file_delete", {"path": "e2e", "recursive": True})
        assert not (workspace / "e2e").exists()
    finally:
        client.close()

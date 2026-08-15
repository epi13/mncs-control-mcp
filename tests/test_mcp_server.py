from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


class StdioClient:
    def __init__(self, config_path: Path, cwd: Path) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "mncs_control_mcp", "--config", str(config_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env={
                **os.environ,
                "PYTHONPATH": os.pathsep.join(
                    [str(cwd / "src"), str(cwd.parent / "mncs-fabric" / "src")]
                ),
            },
        )
        self.next_id = 1

    def notify(self, method: str, params: dict[str, object]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n"
        )
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        request_id = self.next_id
        self.next_id += 1
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            + "\n"
        )
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
    pytest.importorskip(
        "mcp.server.fastmcp", reason="installed MCP SDK does not include the FastMCP server API"
    )
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
home = {str(tmp_path / "sandbox-home")!r}
[terminal]
job_state_path = {str(tmp_path / "state" / "jobs.json")!r}
[server]
audit_path = {str(tmp_path / "state" / "audit.jsonl")!r}
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
            "workspace_info",
            "list_projects",
            "file_write",
            "file_read",
            "terminal_exec",
            "terminal_start",
            "git_status",
            "git_commit",
            "tool_inventory",
            "fabric_status",
            "control_capabilities",
            "developer_readiness",
            "experiment_readiness",
            "project_review",
            "control_job_status",
            "control_job_result",
            "commons_status",
            "commons_work",
            "commons_query",
            "commons_get",
            "commons_conversation",
            "commons_evidence",
            "commons_sync",
        } <= names
        assert "commons_publish" not in names
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
            {
                "command": "git init -q; git config user.email test@example.invalid; git config user.name Test",
                "scope": "project",
                "project": "e2e",
            },
        )
        status = client.call("git_status", {"repository": "e2e"})
        assert status["clean"] is False
        client.call("file_delete", {"path": "e2e", "recursive": True})
        assert not (workspace / "e2e").exists()
    finally:
        client.close()


def test_stdio_mcp_protocol_reads_persistent_fabric_without_admin_surface(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    pytest.importorskip(
        "mcp.server.fastmcp", reason="installed MCP SDK does not include the FastMCP server API"
    )
    fabric_source = Path(__file__).parents[2] / "mncs-fabric" / "src"
    if not fabric_source.is_dir():
        pytest.skip("sibling mncs-fabric source checkout is required")
    sys.path.insert(0, str(fabric_source))
    from mncs_fabric.controller_service import ControllerConfig, ControllerService

    workspace = tmp_path / "projects"
    workspace.mkdir()
    socket_path = tmp_path / "controller.sock"
    service = ControllerService(
        ControllerConfig(
            "mcp-protocol-fixture",
            tmp_path / "lifecycle.jsonl",
            service_log=tmp_path / "service.jsonl",
            socket_path=socket_path,
            admin_socket_path=tmp_path / "controller-admin.sock",
        )
    )
    thread = threading.Thread(target=service.run, kwargs={"max_seconds": 30.0}, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.is_socket():
            break
        time.sleep(0.02)
    else:
        service.request_stop()
        thread.join(timeout=3)
        pytest.fail("temporary Fabric consumer socket did not start")
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        f"""
[workspace]
root = {str(workspace)!r}
[sandbox]
backend = "none"
require_real_sandbox = false
home = {str(tmp_path / "sandbox-home")!r}
[server]
audit_path = {str(tmp_path / "state" / "audit.jsonl")!r}
[terminal]
job_state_path = {str(tmp_path / "state" / "jobs.json")!r}
[integration]
fabric_mode = "service"
fabric_socket = {str(socket_path)!r}
fabric_execution_mode = "unavailable-until-service-support"
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
                "clientInfo": {"name": "persistent-fabric-test", "version": "1"},
            },
        )
        assert initialized["serverInfo"]["name"] == "mncs-control-mcp"
        client.notify("notifications/initialized", {})
        tools = client.request("tools/list", {})["tools"]
        by_name = {item["name"]: item for item in tools}
        assert {
            "control_capabilities",
            "fabric_status",
            "laboratory_status",
            "workspace_info",
            "list_projects",
            "dispatch_fabric_job",
        } <= set(by_name)
        assert not any(
            "fabric_admin" in name
            or name.startswith("fabric_enrollment_")
            or name.startswith("fabric_worker_revoke")
            for name in by_name
        )
        assert by_name["fabric_status"]["annotations"]["readOnlyHint"] is True
        assert by_name["commons_status"]["annotations"]["readOnlyHint"] is True
        assert by_name["commons_query"]["annotations"]["readOnlyHint"] is True
        assert not any(name.startswith("commons_publish") for name in by_name)
        assert by_name["file_delete"]["annotations"]["destructiveHint"] is True
        assert by_name["git_fetch"]["annotations"]["openWorldHint"] is True
        assert by_name["dispatch_fabric_job"]["annotations"]["readOnlyHint"] is False
        assert {
            "fabric_work_status",
            "fabric_work_result",
            "fabric_work_list",
            "fabric_schedule_list",
            "fabric_schedule_tick",
        } <= set(by_name)
        assert by_name["fabric_work_status"]["inputSchema"]["required"] == ["work_id"]
        assert by_name["fabric_work_result"]["inputSchema"]["required"] == ["work_id"]
        assert "limit" in by_name["fabric_work_list"]["inputSchema"]["properties"]
        assert client.call("workspace_info", {})["root"] == str(workspace)
        assert isinstance(client.call("list_projects", {})["projects"], list)
        capabilities = client.call("control_capabilities", {})
        assert capabilities["server"]["fabric_mode"] == "service"
        assert capabilities["fabric"]["authority"].startswith("persistent-controller")
        status = client.call("fabric_status", {})
        assert status["controller_connected"] is True
        assert status["fleet_authority"] == "persistent-controller"
        assert status["execution_transport"] == "unsupported"
        laboratory = client.call("laboratory_status", {})
        assert laboratory["fabric_controller"]["connected"] is True
        dispatch = client.call("dispatch_fabric_job", {"task_type": "pytest", "project": "missing"})
        assert dispatch["error"] == "FABRIC_SERVICE_EXECUTION_UNSUPPORTED"
        smuggled = client.call(
            "control_run",
            {
                "workflow": "fabric_admin",
                "project": "missing",
                "parameters": {"operation": "enrollment.create"},
            },
        )
        assert smuggled["error"] == "INVALID_WORKFLOW"
        assert "fabric_admin" not in json.dumps(by_name["terminal_exec"], sort_keys=True)
    finally:
        client.close()
        service.request_stop()
        thread.join(timeout=3)

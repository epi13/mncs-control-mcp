from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
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

    def request(self, method: str, params: dict[str, object], timeout: float = 20) -> dict[str, object]:
        request_id = self.next_id
        self.next_id += 1
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            + "\n"
        )
        self.process.stdin.flush()
        # system_status probes Fabric/Commons/Forge integrations and can take
        # longer than lightweight calls when the suite runs on a loaded host.
        deadline = time.monotonic() + timeout + (30 if method == "tools/call" else 0)
        while True:
            ready, _, _ = select.select([self.process.stdout], [], [], max(1.0, deadline - time.monotonic()))
            if ready:
                break
            if time.monotonic() >= deadline:
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
def test_stdio_mcp_end_to_end_developer_workspace(
    tmp_path: Path, environment_rpc_socket: Path
) -> None:
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
[journal]
projects = ["e2e"]
[integration]
environment_rpc_socket = {str(environment_rpc_socket)!r}
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
            "terminal_jobs",
            "git_status",
            "git_checkout",
            "git_merge",
            "git_commit",
            "tool_inventory",
            "fabric_status",
            "control_capabilities",
            "developer_readiness",
            "experiment_readiness",
            "experiment_start",
            "experiment_status",
            "experiment_result",
            "experiment_list",
            "experiment_stop",
            "experiment_attach_reference",
            "experiment_publish",
            "experiment_rerun",
            "experiment_graph",
            "experiment_replicate",
            "replication_status",
            "replication_list",
            "journal_context_status",
            "journal_context_collect",
            "journal_context_get",
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
            "env_campaign_continuation",
            "env_campaign_task_bind",
            "env_projection_evidence",
        } <= names
        assert "commons_publish" not in names
        storage_inventory = next(
            item for item in tools if item["name"] == "workspace_storage_inventory"
        )
        assert "Btrfs allocation and device counters" in storage_inventory["description"]
        tool_by_name = {item["name"]: item for item in tools}
        for tool_name in (
            "git_worktree_add", "git_worktree_prepare", "git_create_branch",
            "git_checkout", "git_merge", "git_pull", "git_push",
        ):
            assert "short" in tool_by_name[tool_name]["description"], tool_name
        binding_tool = next(item for item in tools if item["name"] == "env_campaign_task_bind")
        assert binding_tool["inputSchema"]["required"] == [
            "repository", "campaign_id", "session_id", "task_identity",
        ]
        assert binding_tool["annotations"]["readOnlyHint"] is False
        continuation_tool = next(item for item in tools if item["name"] == "env_campaign_continuation")
        assert "repository" in continuation_tool["inputSchema"]["required"]
        assert "campaign_id" not in continuation_tool["inputSchema"].get("required", [])
        assert "task_identity" in continuation_tool["inputSchema"]["properties"]
        assert "task_identity" not in continuation_tool["inputSchema"].get("required", [])
        enter_tool = next(item for item in tools if item["name"] == "env_enter")
        assert "task_identity" in enter_tool["inputSchema"]["properties"]
        assert "task_identity" not in enter_tool["inputSchema"].get("required", [])
        projection_evidence_tool = next(
            item for item in tools if item["name"] == "env_projection_evidence"
        )
        assert projection_evidence_tool["inputSchema"]["required"] == ["session_id"]
        assert projection_evidence_tool["annotations"]["readOnlyHint"] is True
        terminal = next(item for item in tools if item["name"] == "terminal_exec")
        assert terminal["annotations"]["destructiveHint"] is True
        assert terminal["annotations"]["openWorldHint"] is True
        terminal_start = next(item for item in tools if item["name"] == "terminal_start")
        start_properties = terminal_start["inputSchema"]["properties"]
        assert "execution_scope" in start_properties
        assert "scope" not in start_properties

        system = client.call("system_status", {})
        assert system["server"]["tool_surface"]["tool_count"] == len(names)
        assert system["server"]["tool_surface"]["tool_names_sha256"].startswith("sha256:")
        assert system["server"]["tool_surface"]["registration_scope"] == "control-server"
        assert system["server"]["tool_surface"]["client_surface_observed"] is False
        assert system["server"]["tool_surface"]["experiment_tools_present"] is True
        assert system["server"]["tool_surface"]["journal_context_tools_present"] is True
        assert system["server"]["tool_surface"]["environment_continuation_tools_present"] is True
        assert system["server"]["tool_surface"][
            "environment_projection_evidence_tools_present"
        ] is True
        assert system["server"]["organization_context_configured"] is False

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
        async_job = client.call(
            "terminal_start",
            {
                "command": "printf 'async-ready\\n'",
                "execution_scope": "project",
                "project": "e2e",
                "network": False,
                "timeout": 20,
            },
        )
        job_id = async_job["job_id"]
        deadline = time.monotonic() + 5
        status = async_job
        while status["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.05)
            status = client.call("terminal_status", {"job_id": job_id})
        assert status["status"] == "completed", status
        assert status["exit_code"] == 0
        output = client.call("terminal_output", {"job_id": job_id})
        assert output["stdout"] == "async-ready\n"
        listed = client.call("terminal_jobs", {})
        assert any(job["job_id"] == job_id for job in listed["jobs"])
        status = client.call("git_status", {"repository": "e2e"})
        assert status["clean"] is False
        client.call("git_add", {"repository": "e2e", "paths": ["hello.py"]})
        client.call("git_commit", {"repository": "e2e", "message": "initial evidence fixture"})
        branches = client.call("git_branches", {"repository": "e2e"})["branches"]
        target_branch = next(item["name"] for item in branches if item["current"])
        client.call(
            "git_create_branch",
            {"repository": "e2e", "branch": "feature/evidence-transition", "checkout": True},
        )
        client.call("file_write", {"path": "e2e/hello.py", "content": "print('merged')\n"})
        client.call("git_add", {"repository": "e2e", "paths": ["hello.py"]})
        client.call("git_commit", {"repository": "e2e", "message": "evidence fixture change"})
        client.call("git_checkout", {"repository": "e2e", "branch": target_branch})
        merged = client.call(
            "git_merge",
            {"repository": "e2e", "source_branch": "feature/evidence-transition"},
        )
        assert merged["target_branch"] == target_branch
        assert merged["source_branch"] == "feature/evidence-transition"
        assert len(merged["commit"]) == 40
        client.call(
            "git_create_branch",
            {"repository": "e2e", "branch": "feature/conflicting-transition", "checkout": True},
        )
        client.call("file_write", {"path": "e2e/hello.py", "content": "print('source conflict')\n"})
        client.call("git_add", {"repository": "e2e", "paths": ["hello.py"]})
        client.call("git_commit", {"repository": "e2e", "message": "source conflict fixture"})
        client.call("git_checkout", {"repository": "e2e", "branch": target_branch})
        client.call("file_write", {"path": "e2e/hello.py", "content": "print('target conflict')\n"})
        client.call("git_add", {"repository": "e2e", "paths": ["hello.py"]})
        client.call("git_commit", {"repository": "e2e", "message": "target conflict fixture"})
        rejected = client.call(
            "git_merge",
            {"repository": "e2e", "source_branch": "feature/conflicting-transition"},
        )
        assert rejected["error"] == "GIT_MERGE_FAILED"
        assert rejected["details"]["merge_aborted"] is True
        assert rejected["details"]["working_tree_clean"] is True
        now = datetime.now(UTC)
        journal = client.call(
            "journal_context_collect",
            {
                "start": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
                "end": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                "projects": ["e2e"],
                "include_local_git": False,
                "include_uncommitted": False,
                "include_experiments": False,
                "include_commons": False,
                "include_fabric_refs": False,
                "include_forge_refs": False,
                "page_size": 50,
            },
        )
        merge_evidence = [
            item for item in journal["items"]
            if item["source_system"] == "mncs-control-redacted-audit"
            and "git_merge" in item["summary"]
        ]
        successful_merge = next(item for item in merge_evidence if "success=True" in item["summary"])
        rejected_merge = next(item for item in merge_evidence if "success=False" in item["summary"])
        assert f"target_branch={target_branch}" in successful_merge["summary"]
        assert "source_branch=feature/evidence-transition" in successful_merge["summary"]
        assert f"commit={merged['commit']}" in successful_merge["summary"]
        assert "source_branch=feature/conflicting-transition" in rejected_merge["summary"]
        assert "merge_aborted=True" in rejected_merge["summary"]
        assert "working_tree_clean=True" in rejected_merge["summary"]
        client.call("file_delete", {"path": "e2e", "recursive": True})
        assert not (workspace / "e2e").exists()
    finally:
        client.close()


def test_stdio_mcp_protocol_reads_persistent_fabric_without_admin_surface(
    tmp_path: Path, environment_rpc_socket: Path
) -> None:
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
environment_rpc_socket = {str(environment_rpc_socket)!r}
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
        assert by_name["git_checkout"]["annotations"]["readOnlyHint"] is False
        assert by_name["git_checkout"]["annotations"]["destructiveHint"] is False
        assert by_name["git_merge"]["inputSchema"]["required"] == ["repository", "source_branch"]
        assert by_name["git_merge"]["annotations"]["readOnlyHint"] is False
        assert by_name["git_merge"]["annotations"]["destructiveHint"] is False
        assert by_name["git_merge"]["annotations"]["openWorldHint"] is False
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
        dispatch = client.call("dispatch_fabric_job", {"task_type": "pytest", "project": "missing"})
        assert dispatch["error"] == "FABRIC_SERVICE_EXECUTION_UNSUPPORTED"
        # The generic workflow runner is gone, so there is no control_run-shaped
        # vector left: the admin-surface absence above plus the terminal_exec
        # description check below carry the assertion.
        assert "control_run" not in by_name
        assert "fabric_admin" not in json.dumps(by_name["terminal_exec"], sort_keys=True)
    finally:
        client.close()
        service.request_stop()
        thread.join(timeout=3)


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_environment_campaign_task_bind_tool_schema(
    tmp_path: Path, environment_rpc_socket: Path,
) -> None:
    pytest.importorskip("mcp")
    pytest.importorskip(
        "mcp.server.fastmcp",
        reason="installed MCP SDK does not include the FastMCP server API",
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
[integration]
environment_rpc_socket = {str(environment_rpc_socket)!r}
""",
        encoding="utf-8",
    )
    client = StdioClient(config_path, Path(__file__).parents[1])
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "schema-client", "version": "1"},
            },
        )
        client.notify("notifications/initialized", {})
        tools = client.request("tools/list", {})["tools"]
        binding = next(item for item in tools if item["name"] == "env_campaign_task_bind")
        assert binding["inputSchema"]["required"] == [
            "repository", "campaign_id", "session_id", "task_identity",
        ]
        assert binding["annotations"]["readOnlyHint"] is False
    finally:
        client.close()

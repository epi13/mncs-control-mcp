from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_mcp_server import StdioClient

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_mcp_client import call_environment, validate_request
from mncs_control_mcp.environment_rpc import EnvironmentRPCServer


class EnvironmentClient(StdioClient):
    def __init__(self, cwd: Path) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-B", "-m", "mncs_control_mcp.local_environment_mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cwd, env=dict(os.environ),
        )
        self.next_id = 1
        self.request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "isolated-transport-acceptance", "version": "1"},
        })
        self.notify("notifications/initialized", {})


@pytest.mark.parametrize("invocation", [
    {"project": "alpha", "operation": "context", "argv": ["sh"]},
    {"project": "alpha", "operation": "context", "principal": "another-owner"},
    {"project": "alpha"},
    {"project": "alpha", "operation": "context", "arguments": []},
])
def test_recovery_client_cannot_supply_an_alternate_execution_or_identity(invocation):
    with pytest.raises(ValueError):
        validate_request(invocation)


def test_real_mcp_provider_loss_and_fresh_connection_preserve_owner_boundary(
    tmp_path, monkeypatch, environment_rpc_socket,
):
    """Real stdio + real owner socket; no mocked dispatch or transport.

    Durable campaign continuity is separately exercised by the live acceptance.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        f'[workspace]\nroot = {json.dumps(str(workspace))}\n'
        f'[integration]\nenvironment_rpc_socket = {json.dumps(str(environment_rpc_socket))}\n'
    )
    monkeypatch.setenv("MNCS_CONTROL_CONFIG", str(config_path))
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[1] / "src"))
    owner = EnvironmentRPCServer(
        ControlConfig(workspace_root=workspace, environment_rpc_socket=environment_rpc_socket),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"), policy=object(),
    )
    owner.start()
    client = EnvironmentClient(tmp_path)
    request = {"project": "../escape", "operation": "context",
               "arguments": {"session_id": "ses_not_owned"}}
    try:
        before = client.call("mncs_environment", request)
        assert before["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
        client.process.kill()  # Only this test's private provider, never the owner.
        client.process.wait(timeout=10)
        with pytest.raises((BrokenPipeError, AssertionError)):
            client.call("mncs_environment", request)
        assert owner.status()["available"] is True
        assert owner.status()["agent_mcp"]["state"] == "unobserved"
        recovered = asyncio.run(call_environment(request))["structuredContent"]
        assert recovered["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
        assert not owner._grants  # Reconnection did not grant escaped project authority.
    finally:
        client.close()
        owner.close()

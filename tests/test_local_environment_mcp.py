from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import EnvironmentRPCServer
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.local_environment_mcp import (
    LocalEnvironmentMCP,
    _build_argv,
    _ProjectContext,
    _rpc,
)


def test_stable_tool_maps_only_named_environment_operations() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler/.worktrees/run")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "checkpoint",
        {"progress": "verified", "remaining": ["push"], "session_id": "ses_selected"},
        context, "mncs-compiler",
    )
    assert selected is True
    assert argv == [
        "checkpoint", "ses_selected", "--progress", "verified", "--remaining", "push",
    ]

    argv, selected = _build_argv(
        "complete",
        {"retry_pending": True, "session_id": "ses_selected"},
        context, "mncs-compiler",
    )
    assert selected is True
    assert argv == ["complete", "ses_selected", "--retry-pending"]

    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "enter", {"argv": ["terminal_exec", "rm -rf"]}, context,
            "mncs-compiler",
        )


def test_claim_release_mapping_is_explicit_and_bounded() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    context.selected_session_id = "ses_selected"
    argv, selected = _build_argv(
        "claims", {"mode": "release", "claim_id": "claim_123"}, context,
        "mncs-compiler",
    )
    assert selected is True
    assert argv == ["claims", "ses_selected", "--release", "claim_123",
                    "--claim-id", "claim_123"]

    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "claims",
            {"mode": "acquire", "repository": "mncs-compiler", "argv": ["raw"]},
            context, "mncs-compiler",
        )


def test_local_rpc_bootstrap_binds_capability_to_process_and_working_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-compiler"
    checkout = project / ".worktrees" / "selected"
    checkout.mkdir(parents=True)
    (project / ".git").mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "state" / "environment.sock",
            repositories={"environment": "mncs-environment"},
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "canonical"),
        policy=object(),
    )
    server.start()
    monkeypatch.setattr(server, "_peer_process_cwd", lambda _pid: checkout)
    try:
        response = _rpc(server.socket_path, {
            "action": "local-project-grant",
            "project": "mncs-compiler",
            "cwd": ".worktrees/selected",
        })
        assert response["ok"] is True
        grant = response["result"]
        assert grant["scope"] == "project"
        assert grant["sandbox_cwd"] == "/workspace/mncs-compiler/.worktrees/selected"
        record = server._grant(
            {"grant": grant["grant"]}, os.getuid(), os.getpid(),
        )
        assert record.host_root == project
        assert record.working_root == checkout
        assert record.client_pid == os.getpid()
        with pytest.raises(ControlError, match="belongs to another MCP process"):
            server._grant({"grant": grant["grant"]}, os.getuid(), os.getpid() + 1)

        with pytest.raises(ControlError, match="working directory"):
            server._dispatch_once({
                "grant": grant["grant"],
                "request_id": "req_wrong_context_test",
                "cwd": "/workspace/mncs-compiler",
                "argv": ["inspect", "ses_selected"],
            }, peer_uid=os.getuid(), peer_pid=os.getpid())
    finally:
        server.close()


def test_local_bridge_uses_owner_resolved_context_without_leaking_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-compiler"
    project.mkdir(parents=True)
    (project / ".git").mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
            repositories={"compiler": "mncs-compiler"},
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "canonical"),
        policy=object(),
    )
    server.start()
    monkeypatch.setattr(server, "_peer_process_cwd", lambda _pid: project)
    bridge = LocalEnvironmentMCP()
    monkeypatch.setattr(bridge, "socket_path", server.socket_path)
    try:
        context = bridge._context("mncs-compiler", "")
        assert context.sandbox_cwd == "/workspace/mncs-compiler"
        assert context.grant
    finally:
        server.close()

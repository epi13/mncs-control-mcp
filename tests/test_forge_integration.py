from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mncs_control_mcp.adapters import ForgeAdapter, _mcp_tool_error_diagnostic
from mncs_control_mcp.config import ControlConfig

PROJECTS = Path(__file__).parents[2]
FORGE_EXECUTABLE = PROJECTS / "mncs-forge" / "scripts" / "codex-mcp"
FORGE_CONFIG = PROJECTS / "mncs-reference-studies" / "mncs-forge.toml"


def test_mcp_tool_error_diagnostic_preserves_bounded_redacted_details() -> None:
    result = SimpleNamespace(content=[
        SimpleNamespace(text=(
            "Error executing tool: [Errno 30] Read-only file system: "
            "'/workspace/mncs-reference-studies/.mncs-native-artifact-x'"
        )),
        {"text": "provider rejected api_key=ghp_secretvalue123456"},
    ])

    diagnostic = _mcp_tool_error_diagnostic(result)

    assert "[Errno 30] Read-only file system" in diagnostic
    assert "/workspace/mncs-reference-studies/.mncs-native-artifact-x" in diagnostic
    assert "[REDACTED]" in diagnostic
    assert "ghp_secretvalue123456" not in diagnostic
    assert len(diagnostic) <= 2048


def test_mcp_tool_error_diagnostic_has_fallback_without_text() -> None:
    assert _mcp_tool_error_diagnostic(SimpleNamespace(content=[])) == (
        "MCP tool call returned an error without text details"
    )


@pytest.mark.skipif(
    not FORGE_EXECUTABLE.is_file() or not FORGE_CONFIG.is_file(),
    reason="local Forge checkout and migrated reference configuration are required",
)
def test_control_reaches_forge_through_real_mcp_path() -> None:
    config = ControlConfig(
        workspace_root=PROJECTS,
        forge_mcp_executable=FORGE_EXECUTABLE,
        forge_mcp_config=FORGE_CONFIG,
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )

    result = ForgeAdapter(config).status()

    assert result["configured"] is True
    assert result["reachable"] is True
    assert result["protocol"] == "MCP"
    assert result["server"] == "MNCS Forge"
    assert "mncs_forge_project_inspect" in result["capabilities"]
    if result["health_status"] == "capability_unavailable":
        # A Control project sandbox keeps the sibling Forge checkout
        # read-only. Forge's inspection currently creates a temporary native
        # artifact under its own project root, so report the actual denial.
        assert result["failed_capability"] == "mncs_forge_project_inspect"
        assert "Read-only file system" in result["diagnostic"]
        assert ".mncs-native-artifact-" in result["diagnostic"]
    else:
        assert result["health_status"] == "healthy"
        assert result["operation_count"] > 0


def test_control_distinguishes_missing_forge_configuration(tmp_path: Path) -> None:
    config = ControlConfig(
        workspace_root=tmp_path,
        forge_mcp_executable=Path("/bin/true"),
        forge_mcp_config=tmp_path / "missing.toml",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )

    result = ForgeAdapter(config).status()

    assert result["configured"] is False
    assert result["health_status"] == "configuration_missing"
    assert result["reachable"] is False

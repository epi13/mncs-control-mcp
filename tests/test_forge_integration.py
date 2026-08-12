from __future__ import annotations

from pathlib import Path

import pytest

from mncs_control_mcp.adapters import ForgeAdapter
from mncs_control_mcp.config import ControlConfig

PROJECTS = Path(__file__).parents[2]
FORGE_EXECUTABLE = PROJECTS / "mncs-forge-mcp" / "scripts" / "codex-mcp"
FORGE_CONFIG = PROJECTS / "mncs-reference-studies" / "mncs-forge.toml"


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
    assert result["health_status"] == "healthy"
    assert result["server"] == "MNCS Forge"
    assert "mncs_forge_project_inspect" in result["capabilities"]
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

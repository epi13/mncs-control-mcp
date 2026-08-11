from __future__ import annotations

from pathlib import Path

import pytest

from mncs_control_mcp.config import ControlConfig


@pytest.fixture
def config(tmp_path: Path) -> ControlConfig:
    return ControlConfig(
        projects_root=tmp_path,
        repositories={"fixture": "fixture-repo", "missing": "missing-repo"},
        harness_config=None,
        fabric_registry=tmp_path / "workers.json",
        fabric_state=tmp_path / "fabric.jsonl",
    )

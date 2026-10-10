from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from mncs_control_mcp.config import ControlConfig


@pytest.fixture
def environment_rpc_socket(request: pytest.FixtureRequest) -> Path:
    private_root = Path(tempfile.mkdtemp(prefix="mce-", dir="/tmp"))
    request.addfinalizer(lambda: shutil.rmtree(private_root, ignore_errors=True))
    return private_root / "environment.sock"


@pytest.fixture
def config(tmp_path: Path, environment_rpc_socket: Path) -> ControlConfig:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    return ControlConfig(
        workspace_root=workspace,
        repositories={"fixture": "fixture-repo", "missing": "missing-repo"},
        sandbox_home=tmp_path / "sandbox-home",
        job_state_path=tmp_path / "state" / "jobs.json",
        audit_path=tmp_path / "state" / "audit.jsonl",
        fabric_registry=tmp_path / "state" / "workers.json",
        fabric_state=tmp_path / "state" / "fabric.jsonl",
        environment_rpc_socket=environment_rpc_socket,
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )

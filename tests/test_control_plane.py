from __future__ import annotations

import pytest

from mncs_control_mcp.adapters import IntegrationBundle
from mncs_control_mcp.control_plane import ControlPlaneService
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.processes import ProcessManager
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.server import _register_actions
from mncs_control_mcp.tooling import ProjectService
from mncs_control_mcp.workspace import WorkspacePolicy


def _plane(config) -> ControlPlaneService:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)
    integrations = IntegrationBundle(config, _register_actions(), policy, sandbox)
    return ControlPlaneService(config, policy, sandbox, projects, git, integrations.tests, integrations, ProcessManager(config, policy, sandbox))


def test_capabilities_and_project_review_are_bounded(config) -> None:
    root = config.workspace_root / "reviewable"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='reviewable'\nversion='0.1.0'\n", encoding="utf-8")
    (root / "README.md").write_text("# reviewable\nTODO\n", encoding="utf-8")
    plane = _plane(config)
    capabilities = plane.capabilities()
    assert {"workspace", "terminal", "testing", "fabric", "forge", "models", "gpu", "network"} <= capabilities.keys()
    review = plane.review("reviewable")
    assert review["tests"]["detected_suite"] == "pytest"
    assert "README.md" in review["key_files"]
    assert review["todo_markers"]["TODO"] == 1


def test_typed_workflow_rejects_unknown_workflow(config) -> None:
    plane = _plane(config)
    with pytest.raises(ControlError):
        plane.run_workflow("unknown", "missing")

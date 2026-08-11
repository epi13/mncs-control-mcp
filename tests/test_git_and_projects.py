from __future__ import annotations

import shutil

import pytest

from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.tooling import ProjectService, ToolInventory
from mncs_control_mcp.workspace import WorkspacePolicy


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_project_discovery_creation_and_full_local_git_workflow(config) -> None:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)
    created = projects.create("demo", kind="python", git_init=True)
    assert created["created"] is True
    sandbox.run(
        "git config user.email test@example.invalid; git config user.name Test",
        scope="project",
        project="demo",
        cwd=".",
        timeout_seconds=20,
        network=False,
    )
    (config.workspace_root / "demo" / "src" / "demo.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert git.status("demo")["clean"] is False
    git.add("demo", ["pyproject.toml", "src/demo.py"])
    first = git.commit("demo", "initial")
    assert len(first["commit"]) == 40
    git.create_branch("demo", "feature/test")
    (config.workspace_root / "demo" / "src" / "demo.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert "VALUE = 2" in git.diff("demo")["diff"]
    git.add("demo", ["src/demo.py"])
    git.commit("demo", "change value")
    assert git.log("demo", limit=2)["commits"][0]["subject"] == "change value"
    assert any(item["current"] and item["name"] == "feature/test" for item in git.branches("demo")["branches"])
    listed = projects.list_projects()
    row = next(item for item in listed["projects"] if item["name"] == "demo")
    assert row["is_git"] is True
    assert "python" in row["project_types"]


def test_tool_inventory_has_no_environment_dump(config, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERY_SECRET_TOKEN", "never-return-this")
    result = ToolInventory(config).inventory()
    rendered = str(result)
    assert "never-return-this" not in rendered
    assert any(item["name"] == "git" and item["available"] for item in result["tools"])


def test_tool_inventory_reports_project_local_candidate_when_system_wrapper_is_broken(config, monkeypatch: pytest.MonkeyPatch) -> None:
    project = config.workspace_root / "fixture-repo" / ".venv" / "bin"
    project.mkdir(parents=True)
    candidate = project / "pytest"
    candidate.write_text("#!/bin/sh\nprintf 'pytest 9.9.9\\n'\n", encoding="utf-8")
    candidate.chmod(0o700)
    original_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: "/nonexistent/pytest" if name == "pytest" else original_which(name))
    item = next(row for row in ToolInventory(config).inventory()["tools"] if row["name"] == "pytest")
    assert item["available"] is True
    assert item["status"] == "healthy"
    assert item["scope"] == "project"
    assert any(row["scope"] == "project" for row in item["candidates"])

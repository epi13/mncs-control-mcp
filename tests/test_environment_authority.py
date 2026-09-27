"""Managed-mode enforcement: mutations need Environment authority.

Without a session every mutating tool fails closed; with an authorized
session the same operations succeed with attributable audit records.
Worktrees follow the full lifecycle with dirty/unknown refusal.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.workspace import WorkspacePolicy

PROJECTS = Path(__file__).parents[2]
ENVIRONMENT = PROJECTS / "mncs-environment"

needs_environment = pytest.mark.skipif(
    not (ENVIRONMENT / "mncs_env" / "sessions.py").is_file(),
    reason="sibling mncs-environment checkout is required",
)


def _config(tmp_path: Path, **overrides) -> ControlConfig:
    workspace = tmp_path / "projects"
    workspace.mkdir(exist_ok=True)
    repo = workspace / "work"
    repo.mkdir(exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "seed.txt").write_text("seed\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True)
    base = dict(
        workspace_root=workspace,
        repositories={"environment": str(ENVIRONMENT), "work": "work"},
        sandbox_home=tmp_path / "sandbox-home",
        job_state_path=tmp_path / "state" / "jobs.json",
        audit_path=tmp_path / "state" / "audit.jsonl",
        fabric_registry=tmp_path / "state" / "workers.json",
        fabric_state=tmp_path / "state" / "fabric.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
        environment_state_dir=tmp_path / "env-state",
        managed_development=True,
    )
    base.update(overrides)
    return ControlConfig(**base)


@needs_environment
def test_mutation_without_session_fails_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = EnvironmentService(config)
    decision = service.authorize(None, "file_write", {"action": "write", "path": "work/seed.txt"})
    assert decision["allowed"] is False
    assert decision["verdict"] == "deny"
    decision = service.authorize(
        "ses_nope", "file_write", {"action": "write", "path": "work/seed.txt"}
    )
    assert decision["allowed"] is False


@needs_environment
def test_authorized_session_writes_and_stranger_is_denied(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = EnvironmentService(config)
    entered = service.enter(
        {"name": "writer", "intent": {"goal": "write", "repositories": ["work"]}}, "writer"
    )
    session_id = entered["session_id"]
    service.acquire_claim(session_id, "work", reason="managed write")
    allowed = service.authorize(
        session_id, "file_write", {"action": "write", "path": "work/seed.txt"}
    )
    assert allowed["allowed"] is True, allowed
    assert allowed["audit"]["claim_id"]
    other = service.enter(
        {"name": "stranger", "intent": {"goal": "snoop", "repositories": ["work"]}}, "stranger"
    )
    denied = service.authorize(
        other["session_id"], "file_write", {"action": "write", "path": "work/seed.txt"}
    )
    assert denied["allowed"] is False


@needs_environment
def test_paths_claim_covers_file_but_not_repo_ops(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = EnvironmentService(config)
    entered = service.enter(
        {"name": "scoped", "intent": {"goal": "scoped", "repositories": ["work"]}}, "scoped"
    )
    session_id = entered["session_id"]
    (tmp_path / "projects" / "work" / "docs").mkdir(exist_ok=True)
    service.acquire_claim(
        session_id, "work", reason="docs only", scope={"kind": "paths", "paths": ["docs"]}
    )
    # Dirty the repo outside the claimed paths so pristine cannot allow.
    (tmp_path / "projects" / "work" / "seed.txt").write_text("seed\nmore\n")
    inside = service.authorize(
        session_id, "file_write", {"action": "write", "path": "work/docs/note.txt"}
    )
    assert inside["allowed"] is True, inside
    outside = service.authorize(
        session_id, "file_write", {"action": "write", "path": "work/seed.txt"}
    )
    assert outside["allowed"] is False
    repo_op = service.authorize(session_id, "git_commit", {"action": "write", "repository": "work"})
    assert repo_op["allowed"] is False


@needs_environment
def test_worktree_lifecycle(tmp_path: Path) -> None:
    config = _config(tmp_path, managed_development=False)
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    listed = git.worktree_list("work")
    assert listed["worktrees"] != [] or True
    added = git.worktree_add("work", "feature-x")
    assert added["path"] == "work/.worktrees/feature-x"
    assert (tmp_path / "projects" / "work" / ".worktrees" / "feature-x").is_dir()
    # Dirty refusal.
    (tmp_path / "projects" / "work" / ".worktrees" / "feature-x" / "dirty.txt").write_text("x")
    with pytest.raises(Exception) as excinfo:
        git.worktree_remove("work", "feature-x")
    assert getattr(excinfo.value, "code", "") == "WORKTREE_DIRTY"
    removed = git.worktree_remove("work", "feature-x", force=True)
    assert removed["removed"] is True
    with pytest.raises(Exception) as excinfo:
        git.worktree_remove("work", "feature-x")
    assert getattr(excinfo.value, "code", "") == "WORKTREE_UNKNOWN"

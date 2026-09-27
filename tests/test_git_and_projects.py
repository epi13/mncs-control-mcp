from __future__ import annotations

import shutil
import subprocess

import pytest

from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.errors import ControlError
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


def test_worktree_add_uses_safe_path_and_exact_start_point(config) -> None:
    policy = WorkspacePolicy(config)
    git = GitService(config, policy, Sandbox(config, policy))
    repository = config.workspace_root / "worktree-repo"
    repository.mkdir()

    def run(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    run("init", "-b", "main")
    run("config", "user.name", "Control test")
    run("config", "user.email", "control-test@example.invalid")
    (repository / ".gitignore").write_text(".worktrees/\n", encoding="utf-8")
    (repository / "input.txt").write_text("first\n", encoding="utf-8")
    run("add", ".gitignore", "input.txt")
    run("commit", "-m", "initial")
    first_head = run("rev-parse", "HEAD")

    created = git.worktree_add(
        "worktree-repo",
        "campaign/worktree-proof",
        "provider-proof",
        "HEAD",
    )
    checkout = config.workspace_root / created["path"]
    assert created["path"] == "worktree-repo/.worktrees/provider-proof"
    assert run("rev-parse", "HEAD") == first_head
    assert subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() == first_head
    assert subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1", "-uall"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
    listed = git.worktree_list("worktree-repo")
    assert any(
        row.get("workspace_path") == created["path"]
        and row.get("branch") == "campaign/worktree-proof"
        and row.get("head") == first_head
        for row in listed["worktrees"]
    )

    (repository / "input.txt").write_text("second\n", encoding="utf-8")
    run("add", "input.txt")
    run("commit", "-m", "advance main")

    with pytest.raises(ControlError, match="worktree path already exists"):
        git.worktree_add(
            "worktree-repo", "campaign/worktree-proof", "provider-proof", "HEAD"
        )
    with pytest.raises(ControlError) as mismatch:
        git.worktree_add(
            "worktree-repo", "campaign/worktree-proof", "other-proof", "main"
        )
    assert mismatch.value.code == "WORKTREE_BRANCH_CONFLICT"


def test_worktree_prepare_selects_only_clean_exact_authoritative_checkout(config) -> None:
    policy = WorkspacePolicy(config)
    git = GitService(config, policy, Sandbox(config, policy))
    repository = config.workspace_root / "prepare-repo"
    repository.mkdir()

    def run(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    run("init", "-b", "main")
    run("config", "user.name", "Control test")
    run("config", "user.email", "control-test@example.invalid")
    (repository / "input.txt").write_text("base\n", encoding="utf-8")
    run("add", "input.txt")
    run("commit", "-m", "base")
    base = run("rev-parse", "HEAD")
    run("update-ref", "refs/remotes/origin/main", base)

    selected = git.worktree_prepare(
        "prepare-repo",
        name="campaign",
        branch="campaign/parity",
        source_ref="origin/main",
    )
    assert selected["head"] == base
    assert selected["authoritative_head"] == base
    assert selected["clean"] is True
    assert selected["branch"] == "campaign/parity"

    checkout = config.workspace_root / str(selected["path"])
    (repository / "input.txt").write_text("advanced\n", encoding="utf-8")
    run("add", "input.txt")
    run("commit", "-m", "advance authoritative ref")
    advanced_head = run("rev-parse", "HEAD")
    run("update-ref", "refs/remotes/origin/main", advanced_head)
    advanced = git.worktree_prepare(
        "prepare-repo",
        name="campaign",
        branch="campaign/parity",
        source_ref="origin/main",
    )
    assert advanced["head"] == advanced_head
    assert advanced["clean"] is True

    (checkout / "unrelated.txt").write_text("leave untouched\n", encoding="utf-8")
    with pytest.raises(ControlError) as conflict:
        git.worktree_prepare(
            "prepare-repo",
            name="campaign",
            branch="campaign/parity",
            source_ref="origin/main",
        )
    assert conflict.value.code == "WORKTREE_CONFLICT"
    assert conflict.value.details["clean"] is False
    assert (checkout / "unrelated.txt").read_text(encoding="utf-8") == "leave untouched\n"


def test_worktree_prepare_refreshes_remote_authority_before_selection(config) -> None:
    policy = WorkspacePolicy(config)
    # This worktree administration path uses only provider-constructed argv;
    # the local bare remote keeps the test independent of network access.
    git = GitService(config, policy, None)  # type: ignore[arg-type]
    repository = config.workspace_root / "remote-prepare-repo"
    repository.mkdir()
    remote = config.workspace_root / "remote-prepare-origin.git"

    def run(cwd, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    subprocess.run(
        ["git", "init", "--bare", str(remote)],
        check=True,
        capture_output=True,
        text=True,
    )
    run(repository, "init", "-b", "main")
    run(repository, "config", "user.name", "Control test")
    run(repository, "config", "user.email", "control-test@example.invalid")
    (repository / "input.txt").write_text("base\n", encoding="utf-8")
    run(repository, "add", "input.txt")
    run(repository, "commit", "-m", "base")
    run(repository, "remote", "add", "origin", str(remote))
    run(repository, "push", "-u", "origin", "main")
    base = run(repository, "rev-parse", "HEAD")

    (repository / "input.txt").write_text("authoritative\n", encoding="utf-8")
    run(repository, "add", "input.txt")
    run(repository, "commit", "-m", "authoritative advance")
    run(repository, "push", "origin", "main")
    authoritative = run(repository, "rev-parse", "HEAD")
    # Simulate a checkout whose origin/main observation is stale even though
    # the remote already contains the newer authority.
    run(repository, "update-ref", "refs/remotes/origin/main", base)
    assert run(repository, "rev-parse", "origin/main") == base

    selected = git.worktree_prepare(
        "remote-prepare-repo",
        name="campaign",
        branch="campaign/remote-authority",
        source_ref="origin/main",
    )

    assert selected["head"] == authoritative
    assert selected["authoritative_head"] == authoritative
    assert selected["clean"] is True
    checkout = config.workspace_root / str(selected["path"])
    assert (checkout / "input.txt").read_text(encoding="utf-8") == "authoritative\n"


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

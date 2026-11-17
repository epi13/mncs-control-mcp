from __future__ import annotations

import shutil
import subprocess

import pytest

from mncs_control_mcp.errors import ControlError
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
    base_branch = next(item["name"] for item in git.branches("demo")["branches"] if item["current"])
    git.create_branch("demo", "feature/test")
    (config.workspace_root / "demo" / "src" / "demo.py").write_text("VALUE = 2\n", encoding="utf-8")
    dirty_head = git.log("demo", limit=1)["commits"][0]["hash"]
    with pytest.raises(ControlError) as dirty_merge:
        git.merge("demo", base_branch)
    assert dirty_merge.value.code == "GIT_WORKTREE_DIRTY"
    assert git.log("demo", limit=1)["commits"][0]["hash"] == dirty_head
    assert (config.workspace_root / "demo" / "src" / "demo.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert "VALUE = 2" in git.diff("demo")["diff"]
    git.add("demo", ["src/demo.py"])
    git.commit("demo", "change value")
    assert git.log("demo", limit=2)["commits"][0]["subject"] == "change value"
    assert any(item["current"] and item["name"] == "feature/test" for item in git.branches("demo")["branches"])
    git.checkout("demo", base_branch)
    merged = git.merge("demo", "feature/test")
    assert merged["target_branch"] == base_branch
    assert merged["source_branch"] == "feature/test"
    assert git.status("demo")["clean"] is True
    assert (config.workspace_root / "demo" / "src" / "demo.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    listed = projects.list_projects()
    row = next(item for item in listed["projects"] if item["name"] == "demo")
    assert row["is_git"] is True
    assert "python" in row["project_types"]


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_git_merge_conflict_aborts_and_preserves_clean_target(config) -> None:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)
    projects.create("merge-conflict", kind="empty", git_init=True)
    sandbox.run(
        "git config user.email test@example.invalid; git config user.name Test",
        scope="project",
        project="merge-conflict",
        cwd=".",
        timeout_seconds=20,
        network=False,
    )
    source = config.workspace_root / "merge-conflict" / "value.txt"
    source.write_text("base\n", encoding="utf-8")
    git.add("merge-conflict", ["value.txt"])
    git.commit("merge-conflict", "base")
    base_branch = next(
        item["name"] for item in git.branches("merge-conflict")["branches"]
        if item["current"]
    )
    git.create_branch("merge-conflict", "feature/conflict")
    source.write_text("feature value\n", encoding="utf-8")
    git.add("merge-conflict", ["value.txt"])
    git.commit("merge-conflict", "feature value")
    git.checkout("merge-conflict", base_branch)
    source.write_text("main value\n", encoding="utf-8")
    git.add("merge-conflict", ["value.txt"])
    git.commit("merge-conflict", "main value")
    target_head = git.log("merge-conflict", limit=1)["commits"][0]["hash"]

    with pytest.raises(ControlError) as failed_merge:
        git.merge("merge-conflict", "feature/conflict")

    assert failed_merge.value.code == "GIT_MERGE_FAILED"
    assert failed_merge.value.details["merge_aborted"] is True
    assert failed_merge.value.details["working_tree_clean"] is True
    assert git.log("merge-conflict", limit=1)["commits"][0]["hash"] == target_head
    assert git.status("merge-conflict")["clean"] is True
    assert source.read_text(encoding="utf-8") == "main value\n"


def test_branch_operations_reject_fully_qualified_ref_names(config, monkeypatch) -> None:
    policy = WorkspacePolicy(config)
    git = GitService(config, policy, Sandbox(config, policy))

    def unexpected_git_call(*args, **kwargs):
        pytest.fail("invalid branch name reached Git")

    monkeypatch.setattr(git, "_run", unexpected_git_call)
    attempts = {
        "create": lambda: git.create_branch("missing", "refs/heads/main"),
        "checkout": lambda: git.checkout("missing", "refs/heads/main"),
        "merge": lambda: git.merge("missing", "refs/heads/main"),
        "push": lambda: git.push("missing", branch="refs/heads/main"),
        "pull": lambda: git.pull("missing", branch="refs/heads/main"),
        "worktree-add": lambda: git.worktree_add(
            "missing", "refs/heads/main", "proof",
        ),
        "worktree-prepare": lambda: git.worktree_prepare(
            "missing", name="proof", branch="refs/heads/main",
        ),
    }

    for operation, attempt in attempts.items():
        with pytest.raises(ControlError) as rejected:
            attempt()
        assert rejected.value.code == "INVALID_GIT_REF", operation
        assert "short branch name" in rejected.value.message, operation

    assert GitService._branch("campaign/short-name") == "campaign/short-name"


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


def test_list_projects_routine_skips_git_status_and_preserves_metadata(
    config, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)

    # Create primary repo with .mncs manifest, linked worktree, and dirty file
    main_repo = config.workspace_root / "alpha"
    main_repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(main_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "-c", "user.name=T", "-c", "user.email=t@e.invalid",
         "commit", "--allow-empty", "-q", "-m", "init"],
        check=True,
    )
    (main_repo / "pyproject.toml").write_text("[project]\nname='alpha'\nversion='0.1.0'\n", encoding="utf-8")
    (main_repo / ".mncs").mkdir()
    (main_repo / ".mncs" / "project.json").write_text(json.dumps({"repository": "alpha"}), encoding="utf-8")
    (main_repo / ".mncs" / "environment.json").write_text("{}", encoding="utf-8")

    # Add linked worktree outside alpha root (at top-level workspace child alpha-wt)
    wt_dir = config.workspace_root / "alpha-wt"
    subprocess.run(["git", "-C", str(main_repo), "worktree", "add", "-q", "-b", "feat/wt", str(wt_dir)], check=True)

    # Non-git directory and symlink-escaped .git directory
    plain_dir = config.workspace_root / "plain-docs"
    plain_dir.mkdir()
    escaped_git = config.workspace_root / "symlink-git"
    escaped_git.mkdir()
    (escaped_git / ".git").symlink_to(main_repo / ".git")

    # Ensure ZERO git/sandbox subprocesses run on routine list_projects()
    status_calls: list[str] = []
    wt_calls: list[str] = []

    def fail_if_called(*_a, **_k):  # pragma: no cover
        pytest.fail("routine list_projects() should not spawn sandbox subprocesses")

    monkeypatch.setattr(sandbox, "run", fail_if_called)
    orig_status = git.status
    orig_wt = git.worktree_list
    monkeypatch.setattr(git, "status", lambda repo: (status_calls.append(repo), orig_status(repo))[1])
    monkeypatch.setattr(git, "worktree_list", lambda repo: (wt_calls.append(repo), orig_wt(repo))[1])

    listed = projects.list_projects()
    assert listed["status_observed"] is False
    assert status_calls == []
    assert wt_calls == []
    by_name = {row["name"]: row for row in listed["projects"]}

    alpha = by_name["alpha"]
    assert alpha["is_git"] is True
    assert alpha["branch"] == "main"
    assert alpha["dirty"] is None  # Never falsely claim clean when status wasn't run
    assert alpha["git_status"] == "not_requested"
    assert alpha["worktree_count"] == 2
    assert alpha["common_repository"] == "alpha"
    assert alpha["mncs_repository"] == "alpha"
    assert alpha["has_mncs_environment"] is True
    assert "python" in alpha["project_types"]

    alpha_wt = by_name["alpha-wt"]
    assert alpha_wt["is_git"] is True
    assert alpha_wt["branch"] == "feat/wt"
    assert alpha_wt["dirty"] is None
    assert alpha_wt["common_repository"] == "alpha"

    assert by_name["plain-docs"]["is_git"] is False
    assert by_name["symlink-git"]["is_git"] is False
    assert by_name["symlink-git"]["git_status"] == "inaccessible"

    # Concurrent branch switch reflects immediately with zero stale cache
    subprocess.run(["git", "-C", str(main_repo), "checkout", "-q", "-b", "feat/next"], check=True)
    listed2 = projects.list_projects(projects=["alpha"])
    assert listed2["projects"][0]["branch"] == "feat/next"


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_list_projects_explicit_status_selective_and_missing_distinction(config, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)

    for repo_name in ("clean-repo", "other-repo"):
        repo = config.workspace_root / repo_name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@e.invalid",
             "commit", "--allow-empty", "-q", "-m", "init"],
            check=True,
        )

    calls: list[str] = []
    orig_status = git.status
    monkeypatch.setattr(git, "status", lambda r: (calls.append(r), orig_status(r))[1])

    # Selective include_status inspects only requested existing repo once (even if repeated)
    res1 = projects.list_projects(
        projects=["clean-repo", "clean-repo", "missing-repo"],
        include_status=True,
    )
    assert res1["status_observed"] is True
    assert calls == ["clean-repo"]
    by_name = {row["name"]: row for row in res1["projects"]}
    assert by_name["clean-repo"]["dirty"] is False
    assert by_name["clean-repo"]["git_status"] == "observed"
    assert by_name["missing-repo"]["exists"] is False
    assert by_name["missing-repo"]["status"] == "missing"

    # Dirtying tree concurrently immediately invalidates any prior clean observation
    (config.workspace_root / "clean-repo" / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    calls.clear()
    res2 = projects.list_projects(
        projects=["clean-repo"], include_status=True, include_worktrees=True,
    )
    assert calls == ["clean-repo"]
    row = res2["projects"][0]
    assert row["dirty"] is True
    assert row["git_status"] == "observed"
    assert len(row["worktrees"]) == 1


from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mncs_control_mcp.actions import run_bounded
from mncs_control_mcp.adapters import (
    FabricAdapter,
    ForgeAdapter,
    HarnessAdapter,
    OllamaAdapter,
    SystemAdapter,
)
from mncs_control_mcp.config import load_config
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.filesystem import FileService
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.security import filtered_environment, resolve_repository, validate_environment
from mncs_control_mcp.workspace import WorkspacePolicy


def test_configuration_loads_new_model_and_legacy_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        """
[server]
name = "test-control"
[workspace]
root = "./projects"
default_scope = "project"
terminal_network_default = false
[sandbox]
backend = "bwrap"
require_real_sandbox = true
[terminal]
max_concurrent_jobs = 2
[mncs.repos]
fixture = "fixture"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MNCS_PROJECTS_ROOT", str(tmp_path / "legacy-override"))
    config = load_config(config_path)
    assert config.name == "test-control"
    assert config.workspace_root == (tmp_path / "legacy-override").resolve()
    assert config.projects_root == config.workspace_root
    assert config.repositories["fixture"] == "fixture"
    assert config.max_concurrent_jobs == 2


def test_new_workspace_environment_takes_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MNCS_PROJECTS_ROOT", str(tmp_path / "old"))
    monkeypatch.setenv("MNCS_CONTROL_WORKSPACE_ROOT", str(tmp_path / "new"))
    assert load_config(tmp_path / "missing.toml").workspace_root == (tmp_path / "new").resolve()


def test_workspace_policy_rejects_traversal_absolute_and_symlink_escape(config, tmp_path: Path) -> None:
    policy = WorkspacePolicy(config)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (config.workspace_root / "project").mkdir()
    (config.workspace_root / "escape").symlink_to(outside, target_is_directory=True)
    (config.workspace_root / "project" / "nested").symlink_to(outside, target_is_directory=True)

    for value in (
        "../outside/secret",
        "/etc/passwd",
        "project/../../outside",
        "escape/secret",
        "project/nested/secret",
        "project\\windows-style",
        "project/secret\x00suffix",
    ):
        with pytest.raises(ControlError) as error:
            policy.resolve(value, must_exist=True)
        assert error.value.code in {"PATH_ESCAPE", "INVALID_PATH"}


def test_file_service_blocks_root_deletion_and_symlink_writes(config, tmp_path: Path) -> None:
    policy = WorkspacePolicy(config)
    files = FileService(config, policy)
    outside = tmp_path / "outside.txt"
    outside.write_text("original", encoding="utf-8")
    (config.workspace_root / "link").symlink_to(outside)
    with pytest.raises(ControlError) as error:
        files.write("link", "changed")
    assert error.value.code in {"SYMLINK_MUTATION", "PATH_ESCAPE"}
    assert outside.read_text(encoding="utf-8") == "original"
    with pytest.raises(ControlError) as error:
        files.delete(".", recursive=True)
    assert error.value.code == "WORKSPACE_ROOT_PROTECTED"
    with pytest.raises(ControlError) as error:
        files.move(".", "renamed-workspace")
    assert error.value.code == "WORKSPACE_ROOT_PROTECTED"


def test_file_round_trip_search_patch_move_copy_and_delete(config) -> None:
    files = FileService(config, WorkspacePolicy(config))
    files.mkdir("demo")
    files.write("demo/hello.txt", "hello\n")
    assert files.read("demo/hello.txt")["content"] == "hello\n"
    assert files.search("hello", path="demo")["matches"][0]["line"] == 1
    files.patch("--- a/demo/hello.txt\n+++ b/demo/hello.txt\n@@ -1 +1 @@\n-hello\n+world\n")
    assert files.read("demo/hello.txt")["content"] == "world\n"
    files.copy("demo/hello.txt", "demo/copy.txt")
    files.move("demo/copy.txt", "demo/moved.txt")
    assert "demo/moved.txt" in files.glob("demo/*.txt")["matches"]
    files.delete("demo/moved.txt")
    assert not (config.workspace_root / "demo" / "moved.txt").exists()


def test_approved_mncs_alias_remains_specialization_not_general_authorization(config) -> None:
    with pytest.raises(ControlError) as unauthorized:
        resolve_repository(config, "not_approved")
    assert unauthorized.value.code == "UNAUTHORIZED_REPOSITORY"
    with pytest.raises(ControlError) as traversal:
        resolve_repository(config, "../../etc/passwd")
    assert traversal.value.code == "UNAUTHORIZED_REPOSITORY"


def test_environment_filter_and_overrides_drop_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MNCS_TEST_SECRET", "must-not-pass")
    monkeypatch.setenv("PATH", "/safe/path")
    environment = filtered_environment()
    assert environment["PATH"] == "/safe/path"
    assert "MNCS_TEST_SECRET" not in environment
    with pytest.raises(ControlError):
        validate_environment({"GITHUB_TOKEN": "nope"})
    assert validate_environment({"CFLAGS": "-O2"}) == {"CFLAGS": "-O2"}


def test_bounded_subprocess_timeout_and_output_limit() -> None:
    timeout = run_bounded((sys.executable, "-c", "import time; time.sleep(2)"), timeout_seconds=0.1, output_limit_bytes=4096)
    assert timeout.timed_out is True
    output = run_bounded((sys.executable, "-c", "print('x' * 20000)"), timeout_seconds=5, output_limit_bytes=512)
    assert len(output.stdout.encode()) <= 512
    assert output.output_truncated is True


def test_optional_integrations_fail_gracefully(config) -> None:
    actions = __import__("mncs_control_mcp.server", fromlist=["_register_actions"])._register_actions()
    system = SystemAdapter(config, actions, OllamaAdapter(config, actions)).status()
    assert "hostname" in system
    assert HarnessAdapter(config).status()["available"] in {True, False}
    assert FabricAdapter(config).status()["status"] in {"available", "empty", "unavailable"}
    assert ForgeAdapter(config).evaluate("missing", "case")["status"] == "not_supported_yet"


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_repo_status_uses_only_approved_alias(tmp_path: Path, config) -> None:
    repo = config.workspace_root / "fixture-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "MNCS Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    policy = WorkspacePolicy(config)
    result = GitService(config, policy, Sandbox(config, policy)).status("fixture-repo")
    assert result["clean"] is True
    assert result["branch_summary"]

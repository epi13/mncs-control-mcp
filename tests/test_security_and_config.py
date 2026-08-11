from __future__ import annotations

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
from mncs_control_mcp.security import filtered_environment, resolve_repository


def test_configuration_loads_and_environment_overrides_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        """
[server]
name = "test-control"
[mncs]
projects_root = "./projects"
[repos]
fixture = "fixture"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MNCS_PROJECTS_ROOT", str(tmp_path / "override"))
    config = load_config(config_path)
    assert config.name == "test-control"
    assert config.projects_root == (tmp_path / "override").resolve()
    assert config.repositories["fixture"] == "fixture"


def test_approved_repository_resolution_rejects_unauthorized_and_traversal(config) -> None:
    with pytest.raises(ControlError) as unauthorized:
        resolve_repository(config, "not_approved")
    assert unauthorized.value.code == "UNAUTHORIZED_REPOSITORY"
    with pytest.raises(ControlError) as traversal:
        resolve_repository(config, "../../etc/passwd")
    assert traversal.value.code == "UNAUTHORIZED_REPOSITORY"


def test_environment_filter_drops_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MNCS_TEST_SECRET", "must-not-pass")
    monkeypatch.setenv("PATH", "/safe/path")
    environment = filtered_environment()
    assert environment["PATH"] == "/safe/path"
    assert "MNCS_TEST_SECRET" not in environment


def test_bounded_subprocess_timeout_and_output_limit() -> None:
    timeout = run_bounded(
        (sys.executable, "-c", "import time; time.sleep(2)"),
        timeout_seconds=0.1,
        output_limit_bytes=4096,
    )
    assert timeout.timed_out is True
    assert timeout.returncode is not None
    output = run_bounded(
        (sys.executable, "-c", "print('x' * 20000)"),
        timeout_seconds=5,
        output_limit_bytes=512,
    )
    assert len(output.stdout.encode()) <= 512
    assert output.output_truncated is True


def test_optional_integrations_fail_gracefully(config) -> None:
    actions = __import__("mncs_control_mcp.server", fromlist=["_register_actions"])._register_actions()
    system = SystemAdapter(config, actions, OllamaAdapter(config, actions)).status()
    assert "hostname" in system
    assert HarnessAdapter(config).status()["available"] in {True, False}
    assert FabricAdapter(config).status()["status"] in {"available", "empty", "unavailable"}
    assert ForgeAdapter(config).evaluate("missing", "case")["status"] == "not_supported_yet"


def test_repo_status_uses_only_approved_path(tmp_path: Path, config) -> None:
    repo = tmp_path / "fixture-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "MNCS Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    from mncs_control_mcp.adapters import GitAdapter

    result = GitAdapter(config, __import__("mncs_control_mcp.server", fromlist=["_register_actions"])._register_actions()).status("fixture")
    assert result["exists"] is True
    assert result["clean"] is True
    assert result["head"]

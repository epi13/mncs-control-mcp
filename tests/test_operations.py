from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from mncs_control_mcp.actions import CommandResult
from mncs_control_mcp.deployment import (
    DeploymentPaths,
    configured_runtime_key,
    ensure_private_directory,
    ensure_private_file,
    render_user_service,
)
from mncs_control_mcp.doctor import probe_mcp_stdio, run_doctor
from mncs_control_mcp.security import safe_host_probe_environment


def test_safe_host_probe_environment_has_home_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-forward")
    environment = safe_host_probe_environment()
    assert environment["HOME"]
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["PATH"]


def test_ollama_probe_receives_safe_home(monkeypatch: pytest.MonkeyPatch, config) -> None:
    import mncs_control_mcp.adapters as adapters

    captured: dict[str, str] = {}
    monkeypatch.setattr(adapters.shutil, "which", lambda name: "/usr/bin/ollama" if name == "ollama" else None)

    def fake_run(*args: object, **kwargs: object) -> object:
        captured.update(kwargs["env"])
        return CommandResult(("ollama", "list"), 0, "NAME\n", "", False, False, 0.0)

    monkeypatch.setattr(adapters, "run_bounded", fake_run)
    adapters.OllamaAdapter(config, __import__("mncs_control_mcp.server", fromlist=["_register_actions"])._register_actions()).status()
    assert captured["HOME"]
    assert "AWS_SECRET_ACCESS_KEY" not in captured


def test_deployment_paths_and_unit_rendering(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_repository(tmp_path / "mncs-control-mcp", home=tmp_path / "home")
    assert paths.mcp_executable == tmp_path / "mncs-control-mcp" / ".venv" / "bin" / "mncs-control-mcp"
    unit = render_user_service(repository=paths.repository)
    assert "ExecStart=%h/Documents/Projects/mncs-control-mcp/scripts/run-tunnel.sh" in unit
    assert "Restart=on-failure" in unit
    assert "EnvironmentFile=-%h/.config/mncs-control-mcp/tunnel.env" in unit
    assert "ProtectHome=read-only" in unit
    assert "ReadWritePaths=%h/Documents/Projects" in unit


def test_private_runtime_files_are_idempotent_and_preserve_content(tmp_path: Path) -> None:
    directory = ensure_private_directory(tmp_path / "config")
    env_file = ensure_private_file(directory / "tunnel.env", "CONTROL_PLANE_API_KEY=first\n")
    assert directory.stat().st_mode & 0o777 == 0o700
    assert env_file.stat().st_mode & 0o777 == 0o600
    ensure_private_file(env_file, "CONTROL_PLANE_API_KEY=second\n")
    assert env_file.read_text(encoding="utf-8") == "CONTROL_PLANE_API_KEY=first\n"
    assert configured_runtime_key(env_file)
    env_file.write_text("CONTROL_PLANE_API_KEY=replace-me\n", encoding="utf-8")
    assert not configured_runtime_key(env_file)


def test_doctor_reports_missing_required_tunnel_dependencies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    config = tmp_path / "control.toml"
    config.write_text(f"[workspace]\nroot = {str(workspace)!r}\n", encoding="utf-8")
    assert run_doctor(config, json_output=True) == 1
    output = capsys.readouterr().out
    assert "Tunnel client" in output
    assert "Runtime key" in output


def test_installer_help_is_safe_and_idempotence_contract_is_documented() -> None:
    script = Path(__file__).parents[1] / "scripts" / "install-user-service.sh"
    result = subprocess.run([str(script), "--help"], capture_output=True, text=True, check=True)
    assert "--tunnel-id" in result.stdout
    assert "--no-start" in result.stdout


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_doctor_mcp_probe_performs_real_stdio_handshake(tmp_path: Path) -> None:
    repository_executable = Path(__file__).parents[1] / ".venv" / "bin" / "mncs-control-mcp"
    executable = repository_executable if repository_executable.is_file() else Path(shutil.which("mncs-control-mcp") or "")
    if not executable.is_file():
        pytest.skip("installed mncs-control-mcp executable is not on PATH")
    workspace = tmp_path / "projects"
    workspace.mkdir()
    config = tmp_path / "control.toml"
    config.write_text(f"[workspace]\nroot = {str(workspace)!r}\n", encoding="utf-8")
    result = probe_mcp_stdio(executable, config)
    assert result["tool_count"] >= 50
    assert "workspace_info" in result["required_tools"]

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from mncs_control_mcp.actions import CommandResult, run_bounded
from mncs_control_mcp.deployment import (
    DeploymentPaths,
    configured_organization_id,
    configured_runtime_key,
    ensure_private_directory,
    ensure_private_file,
    render_update_path,
    render_update_service,
    render_user_service,
    repository_revision,
    runtime_environment,
)
from mncs_control_mcp.doctor import probe_mcp_stdio, run_doctor
from mncs_control_mcp.manifest import tool_surface_manifest
from mncs_control_mcp.security import safe_host_probe_environment
from mncs_control_mcp.tooling import ToolchainResolver


def test_safe_host_probe_environment_has_home_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-forward")
    environment = safe_host_probe_environment()
    assert environment["HOME"]
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["PATH"]


def test_generic_bounded_command_gets_minimal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/host-home")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    result = run_bounded(
        ("python", "-c", "import os; print(os.getenv('HOME')); print(os.getenv('AWS_SECRET_ACCESS_KEY'))"),
        timeout_seconds=2,
    )
    assert "/host-home" not in result.stdout
    assert "secret" not in result.stdout


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


def test_toolchain_resolver_prefers_safe_project_venv_and_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    (project / ".venv" / "bin").mkdir(parents=True)
    python = project / ".venv" / "bin" / "python"
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o700)
    resolved = ToolchainResolver().resolve(project, "python")
    assert resolved.source == "project_venv"
    assert resolved.executable == str(python)
    outside = tmp_path / "outside-python"
    outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside.chmod(0o700)
    python.unlink()
    python.symlink_to(outside)
    fallback = ToolchainResolver().resolve(project, "python")
    assert fallback.source in {"system", "unavailable"}
    assert fallback.executable != str(python)


@pytest.mark.parametrize("ecosystem", ["rust", "node", "go", "cmake"])
def test_toolchain_resolution_reports_supported_ecosystems(tmp_path: Path, ecosystem: str, monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = ToolchainResolver()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    result = resolver.resolve(tmp_path, ecosystem)
    assert result.ecosystem == ecosystem
    assert result.source == "unavailable"
    assert result.diagnostic


def test_deployment_paths_and_unit_rendering(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_repository(tmp_path / "mncs-control-mcp", home=tmp_path / "home")
    assert paths.mcp_executable == tmp_path / "mncs-control-mcp" / ".venv" / "bin" / "mncs-control-mcp"
    unit = render_user_service(repository=paths.repository)
    assert "ExecStart=%h/Documents/Projects/mncs-control-mcp/scripts/run-tunnel.sh" in unit
    assert "Restart=always" in unit
    assert "EnvironmentFile=-%h/.config/mncs-control-mcp/tunnel.env" in unit
    assert "ProtectHome=read-only" in unit
    assert "ReadWritePaths=%h/Documents/Projects" in unit


def test_update_watcher_units_reload_tunnel_on_main_ref_change(tmp_path: Path) -> None:
    repository = tmp_path / "mncs-control-mcp"
    path_unit = render_update_path(repository=repository)
    service_unit = render_update_service()
    assert f"PathChanged={repository}/.git/HEAD" in path_unit
    assert f"PathChanged={repository}/.git/refs/heads/main" in path_unit
    assert f"PathChanged={repository}/.git/packed-refs" in path_unit
    assert "Unit=mncs-control-update.service" in path_unit
    assert "try-restart mncs-control-tunnel.service" in service_unit
    assert "NoNewPrivileges=true" in service_unit


def test_update_service_can_reach_user_bus_for_restart() -> None:
    """The restart oneshot must keep access to /run/user/<uid>.

    ``ProtectHome=true`` masks ``/run/user`` inside the unit namespace, which
    makes ``systemctl --user`` fail with EPERM against the user bus. That used
    to leave a stale tunnel process serving an outdated tool surface even
    though the watcher fired on every source update.
    """

    rendered = render_update_service()
    assert "ProtectHome=true" not in rendered
    assert "ProtectHome=read-only" in rendered
    deployed = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "systemd"
        / "mncs-control-update.service"
    )
    deployed_text = deployed.read_text(encoding="utf-8")
    assert "ProtectHome=true" not in deployed_text
    assert "ProtectHome=read-only" in deployed_text
    deployed_path = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "systemd"
        / "mncs-control-update.path"
    )
    deployed_path_text = deployed_path.read_text(encoding="utf-8")
    assert ".git/HEAD" in deployed_path_text


def test_repository_revision_reads_loose_and_packed_refs(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    git_dir = repository / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    loose = "a" * 40
    (git_dir / "refs" / "heads" / "main").write_text(loose + "\n", encoding="utf-8")
    assert repository_revision(repository) == loose
    (git_dir / "refs" / "heads" / "main").unlink()
    packed = "b" * 40
    (git_dir / "packed-refs").write_text(f"# pack-refs\n{packed} refs/heads/main\n", encoding="utf-8")
    assert repository_revision(repository) == packed


def test_private_runtime_files_are_idempotent_and_preserve_content(tmp_path: Path) -> None:
    directory = ensure_private_directory(tmp_path / "config")
    env_file = ensure_private_file(
        directory / "tunnel.env",
        "CONTROL_PLANE_API_KEY=secret\nCONTROL_PLANE_ORGANIZATION_ID=org-test\n",
    )
    assert directory.stat().st_mode & 0o777 == 0o700
    assert env_file.stat().st_mode & 0o777 == 0o600
    ensure_private_file(env_file, "CONTROL_PLANE_API_KEY=other\n")
    assert env_file.read_text(encoding="utf-8") == (
        "CONTROL_PLANE_API_KEY=secret\nCONTROL_PLANE_ORGANIZATION_ID=org-test\n"
    )
    assert configured_runtime_key(env_file)
    assert configured_organization_id(env_file)
    filtered = runtime_environment(env_file)
    assert filtered["CONTROL_PLANE_API_KEY"] == "secret"
    assert filtered["CONTROL_PLANE_ORGANIZATION_ID"] == "org-test"
    env_file.write_text(
        "CONTROL_PLANE_API_KEY=<runtime-key>\nCONTROL_PLANE_ORGANIZATION_ID=<organization-id>\n",
        encoding="utf-8",
    )
    assert not configured_runtime_key(env_file)
    assert not configured_organization_id(env_file)


def test_tool_surface_manifest_is_stable_and_detects_experiment_api() -> None:
    expected = tool_surface_manifest(
        [
            "experiment_status",
            "experiment_stop",
            "experiment_start",
            "experiment_result",
            "experiment_readiness",
            "experiment_list",
            "experiment_attach_reference",
            "experiment_publish",
            "experiment_rerun",
            "experiment_graph",
            "experiment_replicate",
            "replication_status",
            "replication_list",
            "system_status",
        ]
    )
    reordered = tool_surface_manifest(
        [
            "system_status",
            "replication_list",
            "experiment_list",
            "experiment_readiness",
            "replication_status",
            "experiment_result",
            "experiment_start",
            "experiment_replicate",
            "experiment_stop",
            "experiment_status",
            "experiment_graph",
            "experiment_rerun",
            "experiment_publish",
            "experiment_attach_reference",
        ]
    )
    assert expected == reordered
    assert expected["tool_count"] == 14
    assert expected["tool_names_sha256"].startswith("sha256:")
    assert expected["experiment_tools_present"] is True
    assert expected["journal_context_tools_present"] is False
    assert tool_surface_manifest(["system_status"])["experiment_tools_present"] is False
    assert tool_surface_manifest(["system_status"])["journal_context_tools_present"] is False
    with_journal = tool_surface_manifest(
        [
            "journal_context_status",
            "journal_context_collect",
            "journal_context_get",
        ]
    )
    assert with_journal["journal_context_tools_present"] is True


def test_doctor_reports_missing_required_tunnel_dependencies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    config = tmp_path / "control.toml"
    config.write_text(f"[workspace]\nroot = {str(workspace)!r}\n", encoding="utf-8")
    assert run_doctor(config, json_output=True) == 1
    output = capsys.readouterr().out
    assert "Tunnel client" in output
    assert "Runtime key" in output
    assert "Organization context" in output
    assert "Remote connector" in output


def test_installer_help_is_safe_and_idempotence_contract_is_documented() -> None:
    script = Path(__file__).parents[1] / "scripts" / "install-user-service.sh"
    result = subprocess.run([str(script), "--help"], capture_output=True, text=True, check=True)
    assert "--tunnel-id" in result.stdout
    assert "--organization-id" in result.stdout
    assert "CONTROL_PLANE_ORGANIZATION_ID" in result.stdout
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
    assert result["tool_names_sha256"].startswith("sha256:")
    assert result["experiment_tools_present"] is True
    assert "workspace_info" in result["required_tools"]

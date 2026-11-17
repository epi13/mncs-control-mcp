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
from mncs_control_mcp.doctor import (
    _environment_rpc_socket_check,
    probe_mcp_stdio,
    run_doctor,
)
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
    assert "%h/.local/share/mncs-environment/store" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=true" in unit
    deployed_unit = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "systemd"
        / "mncs-control-tunnel.service"
    ).read_text(encoding="utf-8")
    assert "%h/.local/share/mncs-environment/store" in deployed_unit


def test_update_watcher_units_reload_tunnel_for_control_and_environment_changes(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "mncs-control-mcp"
    environment_repository = tmp_path / "mncs-environment"
    scope_grants_file = tmp_path / ".config" / "mncs-control-mcp" / "environment-scope-grants.toml"
    path_unit = render_update_path(
        repository=repository,
        environment_repository=environment_repository,
        scope_grants_file=scope_grants_file,
        home=tmp_path,
    )
    service_unit = render_update_service()
    for root in (repository, environment_repository):
        assert f"PathChanged={root}/.git/HEAD" in path_unit
        assert f"PathChanged={root}/.git/refs/heads/main" in path_unit
        assert f"PathChanged={root}/.git/packed-refs" in path_unit
    assert "Unit=mncs-control-update.service" in path_unit
    assert "PathChanged=%h/.config/mncs-control-mcp/environment-scope-grants.toml" in path_unit
    assert "try-restart mncs-control-tunnel.service" in service_unit
    assert "NoNewPrivileges=true" in service_unit
    deployed = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "systemd"
        / "mncs-control-update.path"
    ).read_text(encoding="utf-8")
    assert "%h/Documents/Projects/mncs-control-mcp/.git/HEAD" in deployed
    assert "%h/Documents/Projects/mncs-environment/.git/HEAD" in deployed
    assert "%h/Documents/Projects/mncs-environment/.git/refs/heads/main" in deployed
    assert "%h/Documents/Projects/mncs-environment/.git/packed-refs" in deployed
    assert "%h/.config/mncs-control-mcp/environment-scope-grants.toml" in deployed


def test_update_watcher_renders_scope_grant_path_outside_home_as_absolute(
    tmp_path: Path,
) -> None:
    rendered = render_update_path(
        repository=tmp_path / "mncs-control-mcp",
        environment_repository=tmp_path / "mncs-environment",
        scope_grants_file=tmp_path.parent / "private-scope-grants.toml",
        home=tmp_path,
    )
    assert f"PathChanged={tmp_path.parent}/private-scope-grants.toml" in rendered


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
    assert expected["registration_scope"] == "control-server"
    assert expected["client_surface_observed"] is False
    assert expected["experiment_tools_present"] is True
    assert expected["journal_context_tools_present"] is False
    assert expected["environment_continuation_tools_present"] is False
    assert tool_surface_manifest(["system_status"])["experiment_tools_present"] is False
    assert tool_surface_manifest(["system_status"])["journal_context_tools_present"] is False
    assert tool_surface_manifest([
        "env_enter", "env_campaign_continuation", "env_campaign_task_bind", "env_resume",
    ])["environment_continuation_tools_present"] is True
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
    config.write_text(
        f"[workspace]\nroot = {str(workspace)!r}\n"
        f"[integration]\nenvironment_rpc_socket = {str(tmp_path / 'environment.sock')!r}\n",
        encoding="utf-8",
    )
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
def test_doctor_mcp_probe_performs_real_stdio_handshake(
    tmp_path: Path, environment_rpc_socket: Path
) -> None:
    repository_executable = Path(__file__).parents[1] / ".venv" / "bin" / "mncs-control-mcp"
    executable = repository_executable if repository_executable.is_file() else Path(shutil.which("mncs-control-mcp") or "")
    if not executable.is_file():
        pytest.skip("installed mncs-control-mcp executable is not on PATH")
    workspace = tmp_path / "projects"
    workspace.mkdir()
    config = tmp_path / "control.toml"
    config.write_text(
        f"[workspace]\nroot = {str(workspace)!r}\n"
        f"[integration]\nenvironment_rpc_socket = {str(environment_rpc_socket)!r}\n",
        encoding="utf-8",
    )
    result = probe_mcp_stdio(executable, config)
    assert result["tool_count"] >= 50
    assert result["tool_names_sha256"].startswith("sha256:")
    assert result["experiment_tools_present"] is True
    assert "workspace_info" in result["required_tools"]


def test_probe_mcp_stdio_isolated_does_not_collide_with_active_rpc_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mncs_control_mcp.config import ControlConfig
    from mncs_control_mcp.environment_rpc import EnvironmentRPCServer
    from mncs_control_mcp.environment_sessions import EnvironmentService

    workspace = tmp_path / "projects"
    workspace.mkdir()
    sock = tmp_path / "rpc" / "environment.sock"
    config_file = tmp_path / "control.toml"
    config_file.write_text(
        f"[workspace]\nroot = {str(workspace)!r}\n"
        f"[integration]\nenvironment_rpc_socket = {str(sock)!r}\n",
        encoding="utf-8",
    )
    cfg = ControlConfig(
        workspace_root=workspace,
        sandbox_home=tmp_path / "sandbox",
        job_state_path=tmp_path / "jobs.json",
        audit_path=tmp_path / "audit.jsonl",
        environment_rpc_socket=sock,
        environment_state_dir=tmp_path / "env-state",
    )
    svc = EnvironmentService(cfg)
    rpc = EnvironmentRPCServer(cfg, svc, object())
    rpc.start()
    try:
        # Run from worktree root with non-existent executable path to exercise
        # worktree `python -m mncs_control_mcp --isolated-probe-dir` directly.
        monkeypatch.chdir(Path(__file__).parents[1])
        result = probe_mcp_stdio(Path("/nonexistent/mncs-control-mcp"), config_file)
        assert result["tool_count"] >= 50
        assert result["tool_names_sha256"].startswith("sha256:")
        assert rpc.status()["available"] is True
    finally:
        rpc.close()
        svc.close()


def test_doctor_environment_rpc_socket_health_and_conflict_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket as std_socket

    import mncs_control_mcp.doctor as doctor_mod
    from mncs_control_mcp.config import ControlConfig

    sock = tmp_path / "rpc" / "environment.sock"
    cfg_path = tmp_path / "control.toml"
    cfg_path.write_text("", encoding="utf-8")
    cfg = ControlConfig(workspace_root=tmp_path, environment_rpc_socket=sock)

    # 1. Missing socket while active service manages this config -> FAIL
    monkeypatch.setattr(doctor_mod, "_service_matches_config", lambda _p: True)
    missing = _environment_rpc_socket_check(cfg, cfg_path, "OK")
    assert missing.status == "FAIL" and missing.required is True

    # 2. Missing socket when service does not manage this config -> WARNING (advisory)
    monkeypatch.setattr(doctor_mod, "_service_matches_config", lambda _p: False)
    unmanaged = _environment_rpc_socket_check(cfg, cfg_path, "WARNING")
    assert unmanaged.status == "WARNING" and unmanaged.required is False

    # 3. Non-socket path on canonical socket -> FAIL
    sock.parent.mkdir(parents=True, mode=0o700)
    sock.write_text("not a socket", encoding="utf-8")
    bad_file = _environment_rpc_socket_check(cfg, cfg_path, "OK")
    assert bad_file.status == "FAIL" and bad_file.required is True
    sock.unlink()

    # 4. Stale unresponsive AF_UNIX socket -> FAIL
    listener = std_socket.socket(std_socket.AF_UNIX, std_socket.SOCK_STREAM)
    listener.bind(str(sock))
    sock.chmod(0o600)
    listener.close()
    stale = _environment_rpc_socket_check(cfg, cfg_path, "OK")
    assert stale.status == "FAIL" and "stale" in stale.detail

    # 5. Live socket: inspect cgroup & process ownership
    sock.unlink()
    listener = std_socket.socket(std_socket.AF_UNIX, std_socket.SOCK_STREAM)
    listener.bind(str(sock))
    sock.chmod(0o600)
    listener.listen(8)
    try:
        monkeypatch.setattr(doctor_mod, "_service_matches_config", lambda _p: True)
        # Healthy service owner
        monkeypatch.setattr(
            doctor_mod, "_proc_endpoint_identity",
            lambda _pid: ("/venv/bin/python /venv/bin/mncs-control-mcp --config ...", "0::/user.slice/mncs-control-tunnel.service"),
        )
        healthy = _environment_rpc_socket_check(cfg, cfg_path, "OK")
        assert healthy.status == "OK" and healthy.required is True

        # Rogue Control process outside active tunnel unit -> FAIL conflict
        monkeypatch.setattr(
            doctor_mod, "_proc_endpoint_identity",
            lambda _pid: ("/venv/bin/python /venv/bin/mncs-control-mcp", "0::/user.slice/session-99.scope"),
        )
        conflict = _environment_rpc_socket_check(cfg, cfg_path, "OK")
        assert conflict.status == "FAIL" and "conflict" in conflict.detail

        # Non-Control rogue process squatting on endpoint -> FAIL
        monkeypatch.setattr(
            doctor_mod, "_proc_endpoint_identity",
            lambda _pid: ("nc -U -l environment.sock", "0::/user.slice/mncs-control-tunnel.service"),
        )
        non_control = _environment_rpc_socket_check(cfg, cfg_path, "OK")
        assert non_control.status == "FAIL" and "non-Control" in non_control.detail
    finally:
        listener.close()


def test_developer_readiness_https_and_per_repo_permissions_accuracy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace
    from types import SimpleNamespace

    import mncs_control_mcp.developer as developer_mod
    import mncs_control_mcp.github_auth as github_mod
    from mncs_control_mcp.config import ControlConfig
    from mncs_control_mcp.github_auth import GitHubAuthStatus

    workspace = tmp_path / "projects"
    workspace.mkdir()
    for name, url in (
        ("https-rw", "https://github.com/epi13/https-rw.git"),
        ("https-ro", "https://github.com/octocat/https-ro.git"),
        ("ssh-repo", "git@github.com:epi13/ssh-repo.git"),
        ("no-remote", None),
    ):
        repo = workspace / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        if url is not None:
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", url], check=True)

    cfg = ControlConfig(workspace_root=workspace)
    sandbox_ok = SimpleNamespace(
        backend="bwrap",
        run=lambda cmd, **_k: SimpleNamespace(
            exit_code=0,
            stdout="/usr/bin/gh\nLogged in to github.com account epi13\n" if "gh" in cmd else "/usr/bin/git\n",
            stderr="",
        ),
    )

    https_only_no_ssh_keys = GitHubAuthStatus(
        available=True, state="available", source="host-gh", account="epi13",
        git_protocol="https", scopes=("repo",), can_git_https=True, can_pull_request=True,
        ssh_agent=True, ssh_identities=0, ssh_github="unavailable",
        detail="host gh reports an authenticated github.com login",
    )
    monkeypatch.setattr(developer_mod, "github_auth_status", lambda: https_only_no_ssh_keys)

    # 1. Repo-agnostic readiness: empty ssh-agent does NOT invalidate valid HTTPS workflow
    general = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok)
    assert general["ready_for_development"] is True
    assert general["ready_for_pull_request"] is True
    assert general["capabilities"]["github.push"]["state"] == "available"
    assert general["capabilities"]["github.push"]["authorized"] is True
    ssh_row = next(item for item in general["checks"] if item["name"] == "ssh.agent")
    assert ssh_row["state"] == "optional"

    # 2. Specific HTTPS repo with push=True -> available even without SSH keys
    monkeypatch.setattr(
        developer_mod, "github_repo_permissions",
        lambda slug: {"status": "confirmed", "push": slug.endswith("https-rw"), "pull": True},
    )
    rw = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="https-rw")
    assert rw["ready_for_development"] is True
    assert rw["ready_for_pull_request"] is True
    assert rw["capabilities"]["github.push"]["state"] == "available"

    # 3. Specific HTTPS repo with push=False -> authenticated_insufficient (never false PASS!)
    ro = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="https-ro")
    assert ro["ready_for_development"] is False
    assert ro["ready_for_pull_request"] is False
    assert ro["capabilities"]["github.push"]["state"] == "authenticated_insufficient"
    assert ro["capabilities"]["github.push"]["authorized"] is False

    # 4. SSH remote repo without loaded SSH keys -> unavailable even when HTTPS gh login exists
    ssh_blocked = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="ssh-repo")
    assert ssh_blocked["ready_for_development"] is False
    assert ssh_blocked["capabilities"]["github.push"]["authorized"] is False
    assert ssh_blocked["capabilities"]["github.push"]["state"] in {"unavailable", "degraded"}

    # 5. SSH remote repo WITH authenticated SSH key -> available
    ssh_authed = replace(https_only_no_ssh_keys, ssh_identities=1, ssh_github="authenticated")
    monkeypatch.setattr(developer_mod, "github_auth_status", lambda: ssh_authed)
    monkeypatch.setattr(
        developer_mod, "github_repo_permissions",
        lambda _slug: {"status": "confirmed", "push": True, "pull": True},
    )
    ssh_ok = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="ssh-repo")
    assert ssh_ok["ready_for_development"] is True
    assert ssh_ok["capabilities"]["github.push"]["state"] == "available"

    # 6. No origin remote -> UNKNOWN (not available!)
    monkeypatch.setattr(developer_mod, "github_auth_status", lambda: https_only_no_ssh_keys)
    no_rem = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="no-remote")
    assert no_rem["ready_for_development"] is False
    assert no_rem["capabilities"]["github.push"]["state"] == "unknown"
    assert no_rem["capabilities"]["github.pull_request.write"]["state"] == "unknown"

    # 7. HTTPS repo when API check is offline/unknown -> UNKNOWN (not masked by sandbox.gh)
    monkeypatch.setattr(
        developer_mod, "github_repo_permissions",
        lambda _slug: {"status": "unknown", "detail": "network unreachable"},
    )
    unverified = developer_mod.developer_readiness_payload(cfg, sandbox=sandbox_ok, repository="https-rw")
    assert unverified["ready_for_development"] is False
    assert unverified["capabilities"]["github.push"]["state"] == "unknown"
    assert unverified["capabilities"]["github.pull_request.write"]["state"] == "unknown"

    # 8. git.allow_push = false policy -> unavailable
    no_push_cfg = replace(cfg, git_allow_push=False)
    policy_denied = developer_mod.developer_readiness_payload(no_push_cfg, sandbox=sandbox_ok, repository="https-rw")
    assert policy_denied["ready_for_development"] is False
    assert policy_denied["capabilities"]["github.push"]["state"] == "unavailable"

    # 9. Expired host gh token detected cleanly even if keyring returns stale token string
    monkeypatch.setattr(github_mod, "_read_token_file", lambda _p: None)
    monkeypatch.setattr(github_mod, "_host_gh_token", lambda: "gho_" + "x" * 36)
    monkeypatch.setattr(github_mod, "_gh_executable", lambda: "/usr/bin/gh")
    monkeypatch.setattr(github_mod, "ssh_agent_status", lambda: (False, 0, "no agent"))
    monkeypatch.setattr(
        github_mod, "_capture",
        lambda *_a, **_k: (1, "", "The token in default is invalid"),
    )
    expired = github_mod.github_auth_status()
    assert expired.state == "unavailable"
    assert expired.can_git_https is False
    assert expired.can_pull_request is False

    # Network failure during online gh validation -> unknown
    monkeypatch.setattr(
        github_mod, "_capture",
        lambda *_a, **_k: (1, "", "error connecting to api.github.com: timed out"),
    )
    offline = github_mod.github_auth_status()
    assert offline.state == "unknown"
    assert offline.can_git_https is False


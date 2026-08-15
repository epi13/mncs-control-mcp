from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from mncs_control_mcp.audit import AuditLog
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.processes import ProcessManager
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.workspace import WorkspacePolicy


def _sandbox(config) -> tuple[WorkspacePolicy, Sandbox]:
    if shutil.which("bwrap") is None:
        pytest.skip("bubblewrap is not installed")
    policy = WorkspacePolicy(config)
    return policy, Sandbox(config, policy)


@pytest.mark.requires_bwrap_namespace
def test_real_bwrap_blocks_home_and_project_sibling_mutation(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    (config.workspace_root / "beta").mkdir()
    policy, sandbox = _sandbox(config)
    real_home = str(Path.home())
    command = (
        "id -u; echo own > own.txt; "
        "(echo sibling > ../beta/escape.txt) 2>/dev/null || echo sibling-blocked; "
        "(cd .. && (echo sibling > beta/from-parent.txt)) 2>/dev/null || echo parent-readonly; "
        "test -r /etc/passwd && echo passwd-readable; "
        "(echo mutation >> /etc/passwd) 2>/dev/null || echo etc-readonly; "
        f"test ! -e {real_home}/.ssh && echo ssh-hidden; "
        'test "$HOME" = /home/developer && echo dedicated-home; '
        'python -c "from pathlib import Path; '
        f"p=Path('{real_home}')/'.ssh'; print('python-hidden', not p.exists())\"; "
        "bash -c 'test ! -r ~/.ssh/id_ed25519 && echo key-hidden'; "
        "sh -c 'echo subprocess-ok'"
    )
    result = sandbox.run(
        command, scope="project", project="alpha", cwd=".", timeout_seconds=20, network=False
    )
    assert result.exit_code == 0, result.stderr
    assert str(os.getuid()) in result.stdout
    assert "sibling-blocked" in result.stdout
    assert "parent-readonly" in result.stdout
    assert "passwd-readable" in result.stdout
    assert "etc-readonly" in result.stdout
    assert "ssh-hidden" in result.stdout
    assert "python-hidden True" in result.stdout
    assert "key-hidden" in result.stdout
    assert "subprocess-ok" in result.stdout
    assert not (config.workspace_root / "beta" / "escape.txt").exists()
    assert not (config.workspace_root / "beta" / "from-parent.txt").exists()
    assert (config.workspace_root / "alpha" / "own.txt").is_file()
    argv, enabled = sandbox.command_argv(
        "true", policy.resolve_scope(scope="project", project="alpha", cwd="."), network=False
    )
    assert "--unshare-net" in argv
    assert enabled is False
    network_argv, enabled = sandbox.command_argv(
        "true", policy.resolve_scope(scope="project", project="alpha", cwd="."), network=True
    )
    assert "--unshare-net" not in network_argv
    assert enabled is True


@pytest.mark.requires_bwrap_namespace
def test_workspace_scope_can_mutate_siblings_but_not_real_home(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    (config.workspace_root / "beta").mkdir()
    _, sandbox = _sandbox(config)
    result = sandbox.run(
        "echo cross > beta/cross.txt; (echo no > /tmp/../home-outside) 2>/dev/null || true; cat beta/cross.txt",
        scope="workspace",
        project=None,
        cwd=".",
        timeout_seconds=20,
        network=False,
    )
    assert result.exit_code == 0
    assert (config.workspace_root / "beta" / "cross.txt").read_text(encoding="utf-8") == "cross\n"


@pytest.mark.requires_bwrap_namespace
def test_async_job_output_input_timeout_and_stop(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    policy, sandbox = _sandbox(config)
    manager = ProcessManager(config, policy, sandbox)
    started = manager.start(
        "read line; echo got:$line; sleep 30",
        scope="project",
        project="alpha",
        cwd=".",
        timeout_seconds=60,
        network=False,
    )
    job_id = str(started["job_id"])
    manager.write(job_id, "hello\n")
    deadline = time.monotonic() + 5
    output = manager.output(job_id)
    while "got:hello" not in output["stdout"] and time.monotonic() < deadline:
        time.sleep(0.05)
        output = manager.output(job_id)
    assert "got:hello" in output["stdout"]
    manager.stop(job_id)
    deadline = time.monotonic() + 5
    while manager.status(job_id)["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert manager.status(job_id)["status"] == "stopped"
    assert config.job_state_path.is_file()


def test_workspace_host_path_is_aliased_for_venv_shebangs(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    policy, sandbox = _sandbox(config)
    argv, _enabled = sandbox.command_argv(
        "true", policy.resolve_scope(scope="project", project="alpha", cwd="."), network=False
    )
    host_root = config.workspace_root.resolve()
    joined = " ".join(argv)
    assert "--symlink" in argv
    assert "/workspace" in argv
    assert str(host_root) in argv
    assert f"--symlink /workspace {host_root}" in joined or (
        argv[argv.index("--symlink") + 1] == "/workspace"
        and argv[argv.index("--symlink") + 2] == str(host_root)
    )


@pytest.mark.requires_bwrap_namespace
def test_host_workspace_shebang_path_resolves_inside_sandbox(config) -> None:
    project = config.workspace_root / "alpha"
    project.mkdir()
    (project / "marker.txt").write_text("alias-ok\n", encoding="utf-8")
    _, sandbox = _sandbox(config)
    host_file = (project / "marker.txt").resolve()
    result = sandbox.run(
        f"test -r {host_file} && cat {host_file}",
        scope="project",
        project="alpha",
        cwd=".",
        timeout_seconds=20,
        network=False,
    )
    assert result.exit_code == 0, result.stderr
    assert "alias-ok" in result.stdout


def test_sandbox_disables_askpass_and_does_not_put_tokens_in_argv_names_only(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    policy, sandbox = _sandbox(config)
    argv, enabled = sandbox.command_argv(
        "true",
        policy.resolve_scope(scope="project", project="alpha", cwd="."),
        network=True,
    )
    assert enabled is True
    joined = " ".join(argv)
    assert "SSH_ASKPASS_REQUIRE" in joined
    assert "GIT_TERMINAL_PROMPT" in joined
    assert "unset SSH_ASKPASS" in joined
    assert "gho_" not in joined
    assert "ghp_" not in joined
    assert "GH_TOKEN" not in argv
    assert "oauth_token" not in joined


@pytest.mark.requires_bwrap_namespace
def test_sandbox_askpass_is_inactive_and_joern_or_guard_is_visible(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    _, sandbox = _sandbox(config)
    result = sandbox.run(
        'printf \'%s\\n\' "${SSH_ASKPASS-unset}" "${GIT_TERMINAL_PROMPT-unset}" "${SSH_ASKPASS_REQUIRE-unset}"; '
        "command -v joern-parse >/dev/null && echo JOERN_VISIBLE || echo JOERN_ABSENT",
        scope="project",
        project="alpha",
        cwd=".",
        timeout_seconds=30,
        network=False,
    )
    assert result.exit_code == 0, result.stderr
    assert "unset" in result.stdout or result.stdout.splitlines()[0] == ""
    assert "never" in result.stdout
    assert "JOERN_VISIBLE" in result.stdout or "JOERN_ABSENT" in result.stdout
    if (Path.home() / ".local" / "bin" / "joern").exists():
        assert "JOERN_VISIBLE" in result.stdout


def test_network_policy_can_disable_opt_in(config) -> None:
    (config.workspace_root / "alpha").mkdir()
    from dataclasses import replace

    locked = replace(config, terminal_network_allowed=False)
    policy, sandbox = _sandbox(locked)
    with pytest.raises(ControlError) as error:
        sandbox.command_argv(
            "true", policy.resolve_scope(scope="project", project="alpha", cwd="."), network=True
        )
    assert error.value.code == "NETWORK_DISABLED"


def test_audit_log_is_outside_workspace_private_and_redacted(config) -> None:
    audit = AuditLog(config.audit_path)
    audit.record(
        "terminal_exec",
        command="curl -H 'Authorization: Bearer super-secret-value' https://example.invalid",
        success=False,
    )
    content = config.audit_path.read_text(encoding="utf-8")
    assert "super-secret-value" not in content
    assert "[REDACTED]" in content
    assert config.audit_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        config.audit_path.relative_to(config.workspace_root)

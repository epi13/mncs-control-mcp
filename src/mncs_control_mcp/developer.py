from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import ControlConfig
from .github_auth import (
    GitHubAuthStatus,
    github_auth_status,
    github_repo_permissions,
    parse_github_remote,
    repository_origin_remote,
)
from .sandbox import Sandbox
from .security import redact_text
from .workspace import WorkspacePolicy

DEVELOPER_CAPABILITIES = (
    "git.read",
    "git.write",
    "github.read",
    "github.push",
    "github.pull_request.write",
    "forge.evaluate",
    "fabric.execute",
    "commons.read",
    "commons.publish",
)


@dataclass(frozen=True)
class DeveloperCheck:
    name: str
    state: str
    detail: str
    capability: str | None = None
    required: bool = False
    observed_from: str = "host"

    @property
    def blocking(self) -> bool:
        return self.required and self.state not in {
            "available",
            "optional",
            "unknown",
            "OK",
        }


def _state(value: str) -> str:
    return {
        "OK": "available",
        "FAIL": "unavailable",
        "WARNING": "degraded",
        "UNKNOWN": "unknown",
    }.get(value, value)


def _sandbox_probe(
    sandbox: Sandbox | None,
    command: str,
    *,
    network: bool = False,
    timeout: float = 30.0,
) -> tuple[int, str]:
    if sandbox is None:
        return 127, "sandbox is not available to this doctor invocation"
    try:
        result = sandbox.run(
            command,
            scope="workspace",
            project=None,
            cwd=".",
            timeout_seconds=timeout,
            network=network,
        )
    except Exception as exc:
        return 127, redact_text(str(exc))
    output = (result.stdout or result.stderr or "").strip()
    return result.exit_code if result.exit_code is not None else 127, redact_text(output)


def _evaluate_github_repo_checks(
    config: ControlConfig,
    github: GitHubAuthStatus,
    gh_state: str,
    repository: str | None,
) -> tuple[DeveloperCheck, DeveloperCheck, DeveloperCheck]:
    """Evaluate github.push, github.pull_request.write, and advisory ssh.agent.

    An optional empty SSH agent must not invalidate a working HTTPS GitHub
    workflow, while a repo configured with an SSH remote or read-only/missing
    remote permissions must not inherit a false PASS from general host login.
    """
    repo_transport: str | None = None
    owner_repo: str | None = None
    remote_url: str | None = None
    remote_error: str | None = None
    repo_invalid_detail: str | None = None

    if repository is not None:
        try:
            policy = WorkspacePolicy(config)
            repo_root = policy.resolve(repository, must_exist=True, expect="directory")
            if not ((repo_root / ".git").is_dir() or (repo_root / ".git").is_file()):
                repo_invalid_detail = f"not a Git repository: {repository}"
            else:
                remote_url, remote_error = repository_origin_remote(repo_root)
                if remote_url:
                    parsed = parse_github_remote(remote_url)
                    if parsed is not None:
                        repo_transport, owner_repo = parsed
        except Exception as exc:
            repo_invalid_detail = redact_text(str(exc))

    ssh_required = (
        repo_transport == "ssh"
        or (repository is None and not github.can_git_https and config.git_allow_push)
    )
    if github.ssh_agent and github.ssh_identities:
        ssh_state = "available" if github.ssh_github == "authenticated" else "degraded"
    elif ssh_required:
        ssh_state = "unavailable" if not github.ssh_agent else "degraded"
    else:
        ssh_state = "optional"
    ssh_detail = (
        f"{github.detail}; github_ssh={github.ssh_github}"
        if ssh_required or github.ssh_identities
        else f"SSH agent has no loaded identities (optional; GitHub HTTPS credentials via {github.source or 'none'})"
    )
    ssh_check = DeveloperCheck(
        "ssh.agent",
        ssh_state,
        ssh_detail,
        capability="github.push" if ssh_required else None,
    )

    # Determine github.push & github.pull_request.write truthfully
    perms: dict[str, Any] | None = None
    if owner_repo is not None and (github.source is not None or github.ssh_github == "authenticated"):
        perms = github_repo_permissions(owner_repo)

    push_state: str
    push_detail: str
    pr_state: str
    pr_detail: str

    if not config.git_allow_push:
        push_state = "unavailable"
        push_detail = "Git push is disabled by Control configuration (git.allow_push=false)"
    elif repo_invalid_detail is not None:
        push_state = "unavailable"
        push_detail = repo_invalid_detail
    elif repository is not None and not remote_url:
        push_state = "unknown"
        push_detail = (
            f"repository {repository} origin remote is unreadable: {remote_error}"
            if remote_error and remote_error != "missing"
            else f"repository {repository} has no 'origin' remote configured for GitHub push"
        )
    elif repository is not None and owner_repo is None:
        push_state = "unknown"
        push_detail = f"repository {repository} origin remote does not target github.com"
    elif repository is not None and owner_repo is not None and repo_transport == "ssh":
        if not config.git_use_ssh_agent:
            push_state = "unavailable"
            push_detail = f"repository {repository} uses SSH remote ({owner_repo}), but git.use_ssh_agent is disabled"
        elif github.ssh_github != "authenticated":
            push_state = (
                "authenticated_insufficient"
                if github.ssh_github == "publickey_rejected"
                else "unavailable"
            )
            push_detail = (
                f"repository {repository} uses SSH remote ({owner_repo}), "
                f"but ssh_github={github.ssh_github}; load an SSH key or switch origin to HTTPS"
            )
        elif perms is not None and perms.get("status") == "confirmed":
            if perms.get("push") is True:
                push_state = "available"
                push_detail = f"SSH authentication and push permission confirmed for {owner_repo}"
            else:
                push_state = "authenticated_insufficient"
                push_detail = f"GitHub account {github.account or 'current'} lacks push permission for {owner_repo}"
        elif perms is not None and perms.get("status") in {"unauthorized", "not_found"}:
            push_state = (
                "authenticated_insufficient"
                if perms.get("status") == "unauthorized"
                else "unavailable"
            )
            push_detail = str(perms.get("detail") or f"repository {owner_repo} is inaccessible")
        else:
            push_state = "unknown"
            push_detail = (
                f"SSH auth to github.com succeeded, but write access to {owner_repo} could not be confirmed read-only"
            )
    elif repository is not None and owner_repo is not None and repo_transport == "https":
        if github.state == "unknown":
            push_state = "unknown"
            push_detail = github.detail
        elif not github.can_git_https:
            push_state = github.state
            push_detail = github.detail
        elif gh_state != "available":
            push_state = gh_state
            push_detail = "sandbox gh is unavailable or misconfigured for HTTPS GitHub push"
        elif perms is not None and perms.get("status") == "confirmed":
            if perms.get("push") is True:
                push_state = "available"
                push_detail = f"HTTPS credentials and repository push permission confirmed for {owner_repo}"
            else:
                push_state = "authenticated_insufficient"
                push_detail = f"GitHub account {github.account or 'current'} lacks push permission for {owner_repo}"
        elif perms is not None and perms.get("status") == "unauthorized":
            push_state = "authenticated_insufficient"
            push_detail = str(perms.get("detail") or f"GitHub API denied access to {owner_repo}")
        elif perms is not None and perms.get("status") == "not_found":
            push_state = "unavailable"
            push_detail = str(perms.get("detail") or f"GitHub repository {owner_repo} was not found")
        else:
            reason = str((perms or {}).get("detail") or "read-only API check failed")
            push_state = "unknown"
            push_detail = f"HTTPS credentials exist, but push permission for {owner_repo} could not be verified read-only ({reason})"
    else:
        # Repository-agnostic check (e.g. `doctor`): report configured transport readiness cleanly.
        if github.can_git_https and gh_state == "available":
            push_state = "available"
            push_detail = (
                "HTTPS git can use host gh credentials inside networked sandboxes "
                "(target repository permission is checked when repository is supplied)"
            )
        elif config.git_use_ssh_agent and github.ssh_github == "authenticated":
            push_state = "available"
            push_detail = "SSH agent GitHub authentication is ready"
        elif github.can_git_https and gh_state != "available":
            push_state = gh_state
            push_detail = "host GitHub token exists, but sandbox gh is unavailable or misconfigured"
        elif github.state == "unknown":
            push_state = "unknown"
            push_detail = github.detail
        else:
            push_state = github.state
            push_detail = f"GitHub push is not ready ({github.ssh_github})"

    # Evaluate pull-request write readiness
    if repo_invalid_detail is not None:
        pr_state = "unavailable"
        pr_detail = repo_invalid_detail
    elif repository is not None and (not remote_url or owner_repo is None):
        pr_state = "unknown"
        pr_detail = f"repository {repository} has no github.com 'origin' remote for pull requests"
    elif not github.can_pull_request:
        pr_state = github.state if github.state != "available" else "authenticated_insufficient"
        pr_detail = github.detail
    elif gh_state != "available":
        pr_state = gh_state
        pr_detail = "sandbox gh is unavailable or misconfigured for GitHub pull requests"
    elif repository is not None and owner_repo is not None:
        if perms is not None and perms.get("status") == "confirmed":
            if perms.get("push") is True and perms.get("pull") is True:
                pr_state = "available"
                pr_detail = f"gh API token and repository access confirmed for {owner_repo} ({github.account or 'authenticated'})"
            elif perms.get("pull") is True:
                pr_state = "authenticated_insufficient"
                pr_detail = f"GitHub account {github.account or 'current'} lacks push permission for branch PRs on {owner_repo}"
            else:
                pr_state = "unavailable"
                pr_detail = f"GitHub account lacks pull/push access on {owner_repo}"
        elif perms is not None and perms.get("status") == "unauthorized":
            pr_state = "authenticated_insufficient"
            pr_detail = str(perms.get("detail") or f"GitHub API denied access to {owner_repo}")
        elif perms is not None and perms.get("status") == "not_found":
            pr_state = "unavailable"
            pr_detail = str(perms.get("detail") or f"GitHub repository {owner_repo} was not found")
        else:
            pr_state = "unknown"
            pr_detail = f"gh API token is present, but access to {owner_repo} could not be confirmed read-only"
    else:
        pr_state = "available"
        pr_detail = (
            f"gh API token is present for account {github.account}"
            if github.account
            else github.detail
        )

    return (
        DeveloperCheck("github.push", push_state, push_detail, capability="github.push", required=True),
        DeveloperCheck("github.pull_request.write", pr_state, pr_detail, capability="github.pull_request.write", required=True),
        ssh_check,
    )


def collect_developer_checks(
    config: ControlConfig,
    *,
    sandbox: Sandbox | None = None,
    integrations: Any | None = None,
    repository: str | None = None,
) -> list[DeveloperCheck]:
    checks: list[DeveloperCheck] = []
    root = config.workspace_root
    if root.is_dir() and root.exists():
        checks.append(
            DeveloperCheck(
                "project_root",
                "available",
                str(root),
                required=True,
            )
        )
    else:
        checks.append(
            DeveloperCheck(
                "project_root",
                "unavailable",
                f"workspace is missing: {root}",
                required=True,
            )
        )

    git = shutil.which("git")
    checks.append(
        DeveloperCheck(
            "git",
            "available" if git else "unavailable",
            git or "git is not installed",
            capability="git.read",
            required=True,
        )
    )
    if git:
        checks.append(
            DeveloperCheck(
                "git.write",
                "available",
                "local commits and branch operations execute inside the sandbox",
                capability="git.write",
                required=True,
            )
        )

    if sandbox is None:
        try:
            sandbox = Sandbox(config, WorkspacePolicy(config))
        except Exception:
            sandbox = None

    code, output = _sandbox_probe(
        sandbox,
        'command -v git && git --version && test -n "${GIT_TERMINAL_PROMPT:-}" && echo askpass-guarded',
    )
    sandbox_git_check = DeveloperCheck(
        "sandbox.git",
        "available" if code == 0 else "unavailable",
        output.splitlines()[0] if output else "git is not visible inside the sandbox",
        capability="git.read",
        required=True,
        observed_from="sandbox",
    )

    code, output = _sandbox_probe(
        sandbox,
        "command -v gh && gh auth status -h github.com",
        network=True,
        timeout=20,
    )
    gh_state = (
        "available"
        if code == 0 and "Logged in" in output
        else ("misconfigured" if code == 0 else "unavailable")
    )
    sandbox_gh_check = DeveloperCheck(
        "sandbox.gh",
        gh_state,
        output.splitlines()[0] if output else "gh is not authenticated inside the sandbox",
        capability="github.pull_request.write",
        required=True,
        observed_from="sandbox",
    )

    github = github_auth_status()
    checks.append(
        DeveloperCheck(
            "github.authentication",
            github.state,
            github.detail,
            capability="github.read",
            required=True,
        )
    )
    push_check, pr_check, ssh_check = _evaluate_github_repo_checks(
        config, github, gh_state, repository,
    )
    checks.extend([push_check, pr_check, ssh_check, sandbox_git_check, sandbox_gh_check])

    if integrations is not None:
        fabric = integrations.fabric.status()
        commons = integrations.commons.status()
        forge = integrations.forge.status()
        harness = integrations.harness.status()
        fabric_support = fabric.get("persistent_service_support", {})
        fabric_exec = (
            fabric.get("execution_transport") == "persistent-service"
            and isinstance(fabric_support, dict)
            and fabric_support.get("persistent_service_execution") is True
        )
        checks.append(
            DeveloperCheck(
                "fabric.execute",
                "available"
                if fabric_exec
                else ("degraded" if fabric.get("available") else "unavailable"),
                "persistent Fabric dispatch is advertised"
                if fabric_exec
                else str(
                    fabric.get("current_limitation")
                    or fabric.get("diagnostic")
                    or "Fabric execution is not advertised"
                ),
                capability="fabric.execute",
            )
        )
        checks.append(
            DeveloperCheck(
                "commons.read",
                "available" if commons.get("available") else "unavailable",
                str(commons.get("authority") or commons.get("status") or "Commons is unavailable"),
                capability="commons.read",
            )
        )
        checks.append(
            DeveloperCheck(
                "commons.publish",
                "optional",
                "Control does not expose Commons publication; operator publication remains outside this MCP",
                capability="commons.publish",
            )
        )
        checks.append(
            DeveloperCheck(
                "forge.evaluate",
                "available"
                if forge.get("available") is True
                else "unknown"
                if forge.get("available") is None and "available" in forge
                else _state(str(forge.get("health_status") or "unavailable")),
                str(forge.get("status") or forge.get("diagnostic") or "Forge probe completed"),
                capability="forge.evaluate",
                required=False,
            )
        )
        checks.append(
            DeveloperCheck(
                "harness",
                "available" if harness.get("available") else "degraded",
                str(
                    harness.get("status")
                    or harness.get("diagnostic")
                    or "Harness adapter responded"
                ),
            )
        )
        if repository:
            try:
                candidate = integrations.forge.candidate_status(repository)
                stale = bool(candidate.get("stale"))
                checks.append(
                    DeveloperCheck(
                        "forge.candidate",
                        "degraded"
                        if stale
                        else (
                            "available" if candidate.get("status") == "available" else "optional"
                        ),
                        redact_text(
                            str(
                                candidate.get("inspection")
                                or candidate.get("reason")
                                or candidate.get("status")
                            )
                        ),
                        capability="forge.evaluate",
                        observed_from="host",
                    )
                )
            except Exception as exc:
                checks.append(
                    DeveloperCheck(
                        "forge.candidate",
                        "optional",
                        redact_text(str(exc)),
                        capability="forge.evaluate",
                    )
                )
    else:
        checks.append(
            DeveloperCheck(
                "forge.evaluate",
                "available" if config.forge_path.is_dir() else "unavailable",
                str(config.forge_path),
                capability="forge.evaluate",
            )
        )
        checks.append(
            DeveloperCheck(
                "commons.read",
                "available" if config.commons_socket.expanduser().is_socket() else "unavailable",
                str(config.commons_socket),
                capability="commons.read",
            )
        )
        checks.append(
            DeveloperCheck(
                "commons.publish",
                "optional",
                "Control does not expose Commons publication",
                capability="commons.publish",
            )
        )

    elh = shutil.which("elh") or shutil.which("epi13-harness")
    checks.append(
        DeveloperCheck(
            "elh",
            "optional" if elh else "optional",
            elh
            or "elh is not on PATH; Harness remains reachable through its adapter when configured",
        )
    )
    ollama = shutil.which("ollama")
    checks.append(
        DeveloperCheck(
            "ollama",
            "available" if ollama else "optional",
            ollama or "ollama is not installed",
        )
    )
    writable = os_access_write(root)
    checks.append(
        DeveloperCheck(
            "workspace.write",
            "available" if writable else "unavailable",
            "workspace root is writable" if writable else f"workspace is not writable: {root}",
            required=True,
        )
    )
    return checks


def os_access_write(path: Path) -> bool:
    import os

    return path.is_dir() and os.access(path, os.W_OK)


def capability_map(checks: list[DeveloperCheck]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for name in DEVELOPER_CAPABILITIES:
        related = [check for check in checks if check.capability == name]
        if not related:
            result[name] = {
                "state": "unknown",
                "authorized": False,
                "detail": "not observed by this readiness probe",
            }
            continue
        states = {item.state for item in related}
        if "unavailable" in states or "misconfigured" in states:
            state = "unavailable" if "unavailable" in states else "misconfigured"
        elif "authenticated_insufficient" in states:
            state = "authenticated_insufficient"
        elif "degraded" in states:
            state = "degraded"
        elif "unknown" in states:
            state = "unknown"
        elif "available" in states:
            state = "available"
        elif "optional" in states:
            state = "optional"
        else:
            state = next(iter(states))
        result[name] = {
            "state": state,
            "authorized": state == "available",
            "detail": related[-1].detail,
            "checks": [item.name for item in related],
        }
    return result


def developer_readiness_payload(
    config: ControlConfig,
    *,
    sandbox: Sandbox | None = None,
    integrations: Any | None = None,
    repository: str | None = None,
) -> dict[str, object]:
    checks = collect_developer_checks(
        config, sandbox=sandbox, integrations=integrations, repository=repository
    )
    capabilities = capability_map(checks)
    blocking = [check.name for check in checks if check.blocking]
    push_ready = capabilities.get("github.push", {}).get("authorized") is True
    pr_ready = capabilities.get("github.pull_request.write", {}).get("authorized") is True
    return {
        "ok": not blocking,
        "ready_for_development": not blocking and push_ready,
        "ready_for_pull_request": not blocking and push_ready and pr_ready,
        "repository": repository,
        "capabilities": capabilities,
        "checks": [asdict(check) for check in checks],
        "blocking": blocking,
        "note": (
            "This report observes capabilities; it does not grant authorization. "
            "Secrets are never included."
        ),
    }

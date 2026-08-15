from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import ControlConfig
from .github_auth import github_auth_status
from .sandbox import Sandbox
from .security import redact_text
from .workspace import WorkspacePolicy

DEVELOPER_CAPABILITIES = (
    "git.read",
    "git.write",
    "github.read",
    "github.push",
    "github.pull_request.write",
    "joern.analysis",
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
    checks.append(
        DeveloperCheck(
            "github.push",
            "available"
            if github.can_git_https or github.ssh_github == "authenticated"
            else github.state,
            (
                "HTTPS git can use host gh credentials inside networked sandboxes"
                if github.can_git_https
                else f"GitHub push is not ready ({github.ssh_github})"
            ),
            capability="github.push",
            required=True,
        )
    )
    checks.append(
        DeveloperCheck(
            "github.pull_request.write",
            "available" if github.can_pull_request else github.state,
            (
                f"gh API token is present for account {github.account}"
                if github.can_pull_request and github.account
                else github.detail
            ),
            capability="github.pull_request.write",
            required=True,
        )
    )
    checks.append(
        DeveloperCheck(
            "ssh.agent",
            "available"
            if github.ssh_agent and github.ssh_identities
            else ("degraded" if github.ssh_agent else "optional"),
            f"{github.detail}; github_ssh={github.ssh_github}",
            capability="github.push",
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
    checks.append(
        DeveloperCheck(
            "sandbox.git",
            "available" if code == 0 else "unavailable",
            output.splitlines()[0] if output else "git is not visible inside the sandbox",
            capability="git.read",
            required=True,
            observed_from="sandbox",
        )
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
    checks.append(
        DeveloperCheck(
            "sandbox.gh",
            gh_state,
            output.splitlines()[0] if output else "gh is not authenticated inside the sandbox",
            capability="github.pull_request.write",
            required=True,
            observed_from="sandbox",
        )
    )

    code, output = _sandbox_probe(
        sandbox,
        'command -v joern && command -v joern-parse && test -x "$(command -v joern)" && test -x "$(command -v joern-parse)" && echo JOERN_OK',
        timeout=10,
    )
    checks.append(
        DeveloperCheck(
            "joern.installation",
            "available" if code == 0 and "JOERN_OK" in output else "unavailable",
            "joern and joern-parse are executable inside the sandbox"
            if code == 0 and "JOERN_OK" in output
            else (output.splitlines()[-1] if output else "Joern is not visible inside the sandbox"),
            capability="joern.analysis",
            required=False,
            observed_from="sandbox",
        )
    )

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
                if forge.get("available")
                else str(forge.get("health_status") or "unavailable"),
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
        elif states <= {"available", "optional", "unknown"}:
            state = "available" if "available" in states else next(iter(states))
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

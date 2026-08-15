from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Callable
from typing import Any

from . import __version__
from .actions import ActionRegistry, ActionSpec
from .adapters import IntegrationBundle
from .audit import AuditLog
from .config import ControlConfig, load_config
from .control_plane import ControlPlaneService
from .errors import ControlError
from .filesystem import FileService
from .git_adapter import GitService
from .processes import ProcessManager
from .sandbox import Sandbox
from .security import redact_text
from .tooling import ProjectService, ToolInventory
from .workspace import WorkspacePolicy

LOGGER = logging.getLogger("mncs_control_mcp")


def _logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def _register_actions() -> ActionRegistry:
    registry = ActionRegistry()
    for name, executable, description in (
        ("test.pytest", "python", "run pytest inside the developer sandbox"),
        ("test.cargo", "cargo", "run cargo test inside the developer sandbox"),
        ("model.ollama_list", "ollama", "list local Ollama models"),
        ("system.nvidia_smi", "nvidia-smi", "read local NVIDIA diagnostics"),
    ):
        registry.register(ActionSpec(name, executable, description))
    return registry


def _bounded_response(value: object, maximum: int) -> object:
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if len(encoded.encode("utf-8")) <= maximum:
        return value
    return {
        "error": "RESPONSE_LIMIT_EXCEEDED",
        "message": "MCP response exceeds the configured limit",
        "output_truncated": True,
    }


def build_server(config: ControlConfig | None = None) -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("MCP support requires the 'mcp' dependency") from exc

    selected = config or load_config()
    policy = WorkspacePolicy(selected)
    sandbox = Sandbox(selected, policy)
    audit = AuditLog(selected.audit_path)
    actions = _register_actions()
    integrations = IntegrationBundle(selected, actions, policy, sandbox)
    files = FileService(selected, policy)
    git = GitService(selected, policy, sandbox)
    processes = ProcessManager(selected, policy, sandbox)
    projects = ProjectService(selected, policy, sandbox, git)
    inventory = ToolInventory(selected)
    control_plane = ControlPlaneService(
        selected, policy, sandbox, projects, git, integrations.tests, integrations, processes
    )

    server = FastMCP(
        selected.name,
        instructions=(
            "Protected Fedora developer workspace rooted at the configured Projects directory. "
            "Prefer structured file and Git tools; terminal_exec is the general sandboxed escape "
            "hatch. Project scope is the default. Workspace scope and network access are explicit "
            "high-impact capabilities. Personal home and credential files are not mounted."
        ),
    )

    def annotation(
        *, read_only: bool, destructive: bool = False, idempotent: bool = False, open_world: bool = False
    ) -> Any:
        return ToolAnnotations(
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=idempotent,
            openWorldHint=open_world,
        )

    def invoke(
        name: str,
        function: Callable[..., object],
        *args: object,
        audit_metadata: dict[str, object] | None = None,
        **kwargs: object,
    ) -> object:
        started = time.monotonic()
        LOGGER.info("MCP call received tool=%s", name)
        try:
            result = function(*args, **kwargs)
            bounded = _bounded_response(result, selected.max_response_bytes)
            details = dict(audit_metadata or {})
            if isinstance(result, dict):
                for key in ("exit_code", "job_id", "scope", "project", "cwd", "network", "timed_out"):
                    if key in result:
                        details[key] = result[key]
            audit.record(name, success=True, duration_seconds=round(time.monotonic() - started, 3), **details)
            LOGGER.info("MCP call completed tool=%s success=true duration=%.3f", name, time.monotonic() - started)
            return bounded
        except ControlError as exc:
            audit.record(
                name,
                success=False,
                error=exc.code,
                duration_seconds=round(time.monotonic() - started, 3),
                **(audit_metadata or {}),
            )
            LOGGER.info("MCP call completed tool=%s success=false code=%s", name, exc.code)
            return exc.as_dict()
        except Exception as exc:
            audit.record(
                name,
                success=False,
                error="INTEGRATION_FAILURE",
                duration_seconds=round(time.monotonic() - started, 3),
                **(audit_metadata or {}),
            )
            LOGGER.exception("MCP call failed tool=%s", name)
            return {"error": "INTEGRATION_FAILURE", "message": redact_text(str(exc))}

    def _sync_commons_work_state(payload: dict[str, object], fabric_work_id: str) -> None:
        """Project observed Fabric state into the inert Commons lineage.

        Commons remains record-only: failures here are returned as diagnostics by
        the caller and never authorize, retry, or redirect execution.
        """
        state_raw = str(payload.get("state") or payload.get("status") or "").lower()
        mapped = {
            "submitted": "accepted",
            "accepted": "accepted",
            "queued": "queued",
            "running": "running",
            "completed": "completed",
            "failed": "failed",
            "timed_out": "failed",
            "cancelled": "cancelled",
            "canceled": "cancelled",
        }.get(state_raw)
        if mapped is None:
            return
        commons_work_id = "work:" + fabric_work_id.removeprefix("sha256:")
        try:
            current = integrations.commons.work_status(commons_work_id)
            current_record = current.get("current")
            details = current_record.get("details") if isinstance(current_record, dict) else None
            if not isinstance(details, dict) or details.get("state") == mapped:
                return
            digest = current.get("currentDigest")
            if not isinstance(digest, str):
                return
            integrations.commons.transition_work(
                commons_work_id,
                {
                    "state": mapped,
                    "actor": {"type": "service", "id": selected.fabric_consumer_identity},
                    "expectedPreviousDigest": digest,
                    "fabricJobId": fabric_work_id,
                },
            )
        except Exception:
            LOGGER.warning("could not project Fabric state into Commons", exc_info=True)

    ro = annotation(read_only=True, idempotent=True)
    mutate = annotation(read_only=False)
    destructive = annotation(read_only=False, destructive=True)
    network_mutate = annotation(read_only=False, open_world=True)

    @server.tool(name="workspace_info", description="Describe the protected workspace and active sandbox policy.", annotations=ro, structured_output=True)
    def workspace_info() -> dict[str, object]:
        return invoke("workspace_info", projects.workspace_info)  # type: ignore[return-value]

    @server.tool(name="list_projects", description="Dynamically discover immediate workspace projects and build/Git indicators.", annotations=ro, structured_output=True)
    def list_projects(limit: int = 500) -> dict[str, object]:
        return invoke("list_projects", projects.list_projects, limit=limit)  # type: ignore[return-value]

    @server.tool(name="project_info", description="Inspect one dynamically discovered workspace project.", annotations=ro, structured_output=True)
    def project_info(project: str) -> dict[str, object]:
        return invoke("project_info", projects.info, project)  # type: ignore[return-value]

    @server.tool(name="project_review", description="Aggregate bounded project, Git, test, documentation, and integration context for agent planning.", annotations=ro, structured_output=True)
    def project_review(project: str, depth: str = "standard") -> dict[str, object]:
        return invoke("project_review", control_plane.review, project, depth=depth, audit_metadata={"project": project, "depth": depth})  # type: ignore[return-value]

    @server.tool(name="project_create", description="Create an empty, Python, Rust, or Node project inside the workspace.", annotations=mutate, structured_output=True)
    def project_create(name: str, kind: str = "empty", git_init: bool = False) -> dict[str, object]:
        return invoke("project_create", projects.create, name, kind=kind, git_init=git_init, audit_metadata={"project": name})  # type: ignore[return-value]

    @server.tool(name="file_stat", description="Stat a workspace-relative path without following escapes.", annotations=ro, structured_output=True)
    def file_stat(path: str) -> dict[str, object]:
        return invoke("file_stat", files.stat, path)  # type: ignore[return-value]

    @server.tool(name="file_list", description="List a bounded workspace directory.", annotations=ro, structured_output=True)
    def file_list(path: str = ".", limit: int | None = None) -> dict[str, object]:
        return invoke("file_list", files.list, path, limit=limit)  # type: ignore[return-value]

    @server.tool(name="file_tree", description="Return a bounded recursive workspace tree without following symlinks.", annotations=ro, structured_output=True)
    def file_tree(path: str = ".", depth: int = 3, limit: int | None = None) -> dict[str, object]:
        return invoke("file_tree", files.tree, path, depth=depth, limit=limit)  # type: ignore[return-value]

    @server.tool(name="file_read", description="Read bounded UTF-8 text or base64 binary content from a workspace file.", annotations=ro, structured_output=True)
    def file_read(path: str, offset: int = 0, limit: int | None = None) -> dict[str, object]:
        return invoke("file_read", files.read, path, offset=offset, limit=limit)  # type: ignore[return-value]

    @server.tool(name="file_write", description="Write UTF-8 or base64 content to a workspace-relative regular file.", annotations=mutate, structured_output=True)
    def file_write(path: str, content: str, encoding: str = "utf-8", overwrite: bool = True, create_parents: bool = False) -> dict[str, object]:
        return invoke("file_write", files.write, path, content, encoding=encoding, overwrite=overwrite, create_parents=create_parents, audit_metadata={"path": path})  # type: ignore[return-value]

    @server.tool(name="file_patch", description="Validate and apply a unified Git-style patch to workspace files.", annotations=mutate, structured_output=True)
    def file_patch(patch: str) -> dict[str, object]:
        return invoke("file_patch", files.patch, patch, audit_metadata={"patch_bytes": len(patch.encode())})  # type: ignore[return-value]

    @server.tool(name="file_mkdir", description="Create a workspace directory.", annotations=mutate, structured_output=True)
    def file_mkdir(path: str, parents: bool = False, exist_ok: bool = False) -> dict[str, object]:
        return invoke("file_mkdir", files.mkdir, path, parents=parents, exist_ok=exist_ok, audit_metadata={"path": path})  # type: ignore[return-value]

    @server.tool(name="file_move", description="Move a workspace file or directory without crossing the workspace boundary.", annotations=destructive, structured_output=True)
    def file_move(source: str, destination: str, overwrite: bool = False) -> dict[str, object]:
        return invoke("file_move", files.move, source, destination, overwrite=overwrite, audit_metadata={"source": source, "destination": destination})  # type: ignore[return-value]

    @server.tool(name="file_copy", description="Copy a regular workspace file or directory; symbolic links are refused.", annotations=mutate, structured_output=True)
    def file_copy(source: str, destination: str, overwrite: bool = False) -> dict[str, object]:
        return invoke("file_copy", files.copy, source, destination, overwrite=overwrite, audit_metadata={"source": source, "destination": destination})  # type: ignore[return-value]

    @server.tool(name="file_delete", description="Delete a workspace path; the workspace root is always protected.", annotations=destructive, structured_output=True)
    def file_delete(path: str, recursive: bool = False) -> dict[str, object]:
        return invoke("file_delete", files.delete, path, recursive=recursive, audit_metadata={"path": path, "recursive": recursive})  # type: ignore[return-value]

    @server.tool(name="file_glob", description="Find bounded workspace paths by a relative glob.", annotations=ro, structured_output=True)
    def file_glob(pattern: str, limit: int | None = None) -> dict[str, object]:
        return invoke("file_glob", files.glob, pattern, limit=limit)  # type: ignore[return-value]

    @server.tool(name="file_search", description="Search bounded UTF-8 workspace files with literal or regular-expression matching.", annotations=ro, structured_output=True)
    def file_search(query: str, path: str = ".", glob: str = "*", regex: bool = False, case_sensitive: bool = True, limit: int | None = None) -> dict[str, object]:
        return invoke("file_search", files.search, query, path=path, glob=glob, regex=regex, case_sensitive=case_sensitive, limit=limit)  # type: ignore[return-value]

    @server.tool(name="terminal_exec", description="Run an arbitrary Bash command inside the real Fedora workspace sandbox. Project scope is default; workspace scope and network are explicit.", annotations=annotation(read_only=False, destructive=True, open_world=True), structured_output=True)
    def terminal_exec(command: str, cwd: str = ".", scope: str = "project", project: str | None = None, timeout: float | None = None, network: bool | None = None, environment: dict[str, str] | None = None) -> dict[str, object]:
        return invoke("terminal_exec", lambda: sandbox.run(command, scope=scope, project=project, cwd=cwd, timeout_seconds=timeout, network=network, environment=environment).as_dict(), audit_metadata={"command": command, "cwd": cwd, "scope": scope, "project": project, "network": network})  # type: ignore[return-value]

    @server.tool(name="terminal_start", description="Start a tracked asynchronous command in the Fedora workspace sandbox.", annotations=annotation(read_only=False, destructive=True, open_world=True), structured_output=True)
    def terminal_start(command: str, cwd: str = ".", scope: str = "project", project: str | None = None, timeout: float | None = None, network: bool | None = None, environment: dict[str, str] | None = None) -> dict[str, object]:
        return invoke("terminal_start", processes.start, command, scope=scope, project=project, cwd=cwd, timeout_seconds=timeout, network=network, environment=environment, audit_metadata={"command": command, "cwd": cwd, "scope": scope, "project": project, "network": network})  # type: ignore[return-value]

    @server.tool(name="terminal_status", description="Inspect a terminal job owned by this server.", annotations=ro, structured_output=True)
    def terminal_status(job_id: str) -> dict[str, object]:
        return invoke("terminal_status", processes.status, job_id)  # type: ignore[return-value]

    @server.tool(name="terminal_output", description="Read incremental bounded stdout/stderr from an owned terminal job.", annotations=ro, structured_output=True)
    def terminal_output(job_id: str, stdout_offset: int = 0, stderr_offset: int = 0) -> dict[str, object]:
        return invoke("terminal_output", processes.output, job_id, stdout_offset=stdout_offset, stderr_offset=stderr_offset)  # type: ignore[return-value]

    @server.tool(name="terminal_write", description="Write bounded UTF-8 input to an owned running terminal job.", annotations=mutate, structured_output=True)
    def terminal_write(job_id: str, data: str, close: bool = False) -> dict[str, object]:
        return invoke("terminal_write", processes.write, job_id, data, close=close, audit_metadata={"job_id": job_id, "bytes": len(data.encode())})  # type: ignore[return-value]

    @server.tool(name="terminal_stop", description="Terminate an owned terminal job and its process group.", annotations=destructive, structured_output=True)
    def terminal_stop(job_id: str, force: bool = False) -> dict[str, object]:
        return invoke("terminal_stop", processes.stop, job_id, force=force, audit_metadata={"job_id": job_id, "force": force})  # type: ignore[return-value]

    @server.tool(name="terminal_jobs", description="List bounded metadata for terminal jobs owned by this server.", annotations=ro, structured_output=True)
    def terminal_jobs() -> dict[str, object]:
        return invoke("terminal_jobs", processes.list)  # type: ignore[return-value]

    @server.tool(name="control_jobs", description="List terminal jobs and completed upstream Fabric, Forge, or Harness execution records.", annotations=ro, structured_output=True)
    def control_jobs() -> dict[str, object]:
        return invoke("control_jobs", processes.list)  # type: ignore[return-value]

    @server.tool(name="git_status", description="Inspect structured status for any Git repository inside the workspace.", annotations=ro, structured_output=True)
    def git_status(repository: str) -> dict[str, object]:
        return invoke("git_status", git.status, repository)  # type: ignore[return-value]

    @server.tool(name="git_diff", description="Inspect bounded working-tree or staged diffs.", annotations=ro, structured_output=True)
    def git_diff(repository: str, staged: bool = False, path: str | None = None, context_lines: int = 3) -> dict[str, object]:
        return invoke("git_diff", git.diff, repository, staged=staged, path=path, context_lines=context_lines)  # type: ignore[return-value]

    @server.tool(name="git_log", description="Inspect structured Git commit history.", annotations=ro, structured_output=True)
    def git_log(repository: str, limit: int = 20, revision: str = "HEAD") -> dict[str, object]:
        return invoke("git_log", git.log, repository, limit=limit, revision=revision)  # type: ignore[return-value]

    @server.tool(name="git_show", description="Show one bounded Git revision.", annotations=ro, structured_output=True)
    def git_show(repository: str, revision: str = "HEAD", stat_only: bool = False) -> dict[str, object]:
        return invoke("git_show", git.show, repository, revision, stat_only=stat_only)  # type: ignore[return-value]

    @server.tool(name="git_branches", description="List local and remote Git branches.", annotations=ro, structured_output=True)
    def git_branches(repository: str, all_branches: bool = True) -> dict[str, object]:
        return invoke("git_branches", git.branches, repository, all_branches=all_branches)  # type: ignore[return-value]

    @server.tool(name="git_create_branch", description="Create a non-forced Git branch, optionally checking it out.", annotations=mutate, structured_output=True)
    def git_create_branch(repository: str, branch: str, checkout: bool = True) -> dict[str, object]:
        return invoke("git_create_branch", git.create_branch, repository, branch, checkout=checkout, audit_metadata={"repository": repository, "branch": branch})  # type: ignore[return-value]

    @server.tool(name="git_checkout", description="Switch to an existing Git branch without forced reset.", annotations=destructive, structured_output=True)
    def git_checkout(repository: str, branch: str) -> dict[str, object]:
        return invoke("git_checkout", git.checkout, repository, branch, audit_metadata={"repository": repository, "branch": branch})  # type: ignore[return-value]

    @server.tool(name="git_add", description="Stage validated repository-relative paths.", annotations=mutate, structured_output=True)
    def git_add(repository: str, paths: list[str]) -> dict[str, object]:
        return invoke("git_add", git.add, repository, paths, audit_metadata={"repository": repository, "paths": paths})  # type: ignore[return-value]

    @server.tool(name="git_commit", description="Create a normal Git commit; hooks run inside the workspace sandbox.", annotations=mutate, structured_output=True)
    def git_commit(repository: str, message: str, allow_empty: bool = False) -> dict[str, object]:
        return invoke("git_commit", git.commit, repository, message, allow_empty=allow_empty, audit_metadata={"repository": repository})  # type: ignore[return-value]

    @server.tool(name="git_fetch", description="Fetch from a configured remote using sandboxed network access and optional SSH agent forwarding.", annotations=annotation(read_only=False, idempotent=True, open_world=True), structured_output=True)
    def git_fetch(repository: str, remote: str = "origin", prune: bool = False) -> dict[str, object]:
        return invoke("git_fetch", git.fetch, repository, remote, prune=prune, audit_metadata={"repository": repository, "remote": remote, "network": True})  # type: ignore[return-value]

    @server.tool(name="git_pull", description="Fetch and integrate a remote branch without forced reset.", annotations=network_mutate, structured_output=True)
    def git_pull(repository: str, remote: str = "origin", branch: str | None = None, rebase: bool = False) -> dict[str, object]:
        return invoke("git_pull", git.pull, repository, remote, branch, rebase=rebase, audit_metadata={"repository": repository, "remote": remote, "network": True})  # type: ignore[return-value]

    @server.tool(name="git_push", description="Push normally through the sandbox and SSH agent; force push is not exposed.", annotations=network_mutate, structured_output=True)
    def git_push(repository: str, remote: str = "origin", branch: str | None = None, set_upstream: bool = False) -> dict[str, object]:
        return invoke("git_push", git.push, repository, remote, branch, set_upstream=set_upstream, audit_metadata={"repository": repository, "remote": remote, "network": True})  # type: ignore[return-value]

    @server.tool(name="git_clone", description="Clone a repository into a new workspace-relative destination.", annotations=network_mutate, structured_output=True)
    def git_clone(url: str, destination: str, branch: str | None = None, depth: int | None = None) -> dict[str, object]:
        return invoke("git_clone", git.clone, url, destination, branch=branch, depth=depth, audit_metadata={"destination": destination, "network": True})  # type: ignore[return-value]

    @server.tool(name="git_remotes", description="List configured Git remotes.", annotations=ro, structured_output=True)
    def git_remotes(repository: str) -> dict[str, object]:
        return invoke("git_remotes", git.remotes, repository)  # type: ignore[return-value]

    @server.tool(name="git_restore", description="Restore selected paths without exposing hard reset.", annotations=destructive, structured_output=True)
    def git_restore(repository: str, paths: list[str], staged: bool = False) -> dict[str, object]:
        return invoke("git_restore", git.restore, repository, paths, staged=staged, audit_metadata={"repository": repository, "paths": paths})  # type: ignore[return-value]

    @server.tool(name="git_stash", description="Stash tracked changes and optionally untracked files.", annotations=destructive, structured_output=True)
    def git_stash(repository: str, message: str | None = None, include_untracked: bool = False) -> dict[str, object]:
        return invoke("git_stash", git.stash, repository, message, include_untracked=include_untracked, audit_metadata={"repository": repository})  # type: ignore[return-value]

    @server.tool(name="tool_inventory", description="Detect safe paths and versions for installed developer tools without exposing environment secrets.", annotations=ro, structured_output=True)
    def tool_inventory() -> dict[str, object]:
        return invoke("tool_inventory", inventory.inventory)  # type: ignore[return-value]

    @server.tool(name="control_capabilities", description="Report the structured capabilities, limits, security boundaries, and upstream ownership of this control plane.", annotations=ro, structured_output=True)
    def control_capabilities() -> dict[str, object]:
        return invoke("control_capabilities", control_plane.capabilities)  # type: ignore[return-value]

    @server.tool(name="developer_readiness", description="Observe whether the protected environment can carry a development task through analysis, GitHub, Joern, and Forge without granting those capabilities.", annotations=ro, structured_output=True)
    def developer_readiness(repository: str | None = None) -> dict[str, object]:
        return invoke("developer_readiness", control_plane.developer_readiness, repository, audit_metadata={"repository": repository})  # type: ignore[return-value]

    @server.tool(name="experiment_readiness", description="Inspect whether the MNCS experiment stack may start experiments. Observation only; does not repair, refresh, or publish.", annotations=ro, structured_output=True)
    def experiment_readiness(profile: str = "base-inference") -> dict[str, object]:
        return invoke("experiment_readiness", control_plane.experiment_readiness, profile, audit_metadata={"profile": profile})  # type: ignore[return-value]

    @server.tool(name="forge_candidate_status", description="Inspect whether the current Forge candidate still matches the working tree.", annotations=ro, structured_output=True)
    def forge_candidate_status(repository: str) -> dict[str, object]:
        return invoke("forge_candidate_status", integrations.forge.candidate_status, repository, audit_metadata={"repository": repository})  # type: ignore[return-value]

    @server.tool(name="forge_candidate_refresh", description="Rebind the active Forge candidate to current content and keep prior evidence attached to the previous identity.", annotations=mutate, structured_output=True)
    def forge_candidate_refresh(repository: str, hypothesis: str = "working-tree content changed after the previous candidate binding", changed_files: list[str] | None = None) -> dict[str, object]:
        return invoke("forge_candidate_refresh", integrations.forge.refresh_candidate, repository, hypothesis=hypothesis, changed_files=changed_files, audit_metadata={"repository": repository})  # type: ignore[return-value]

    @server.tool(name="laboratory_status", description="Aggregate controller resources, models, Fabric workers, MNCS integrations, and running jobs.", annotations=ro, structured_output=True)
    def laboratory_status() -> dict[str, object]:
        return invoke("laboratory_status", control_plane.laboratory_status)  # type: ignore[return-value]

    @server.tool(name="control_run", description="Run one named bounded workflow: inspect_project, check_project, test_project, evaluate_project, fabric_test_project, review_and_check_project, review_check_and_fabric_test, or the honest Harness limitation.", annotations=mutate, structured_output=True)
    def control_run(workflow: str, project: str, profile: str = "standard", task_type: str | None = None, model: str | None = None, node: str | None = None, parameters: dict[str, object] | None = None) -> dict[str, object]:
        return invoke("control_run", control_plane.run_workflow, workflow, project, profile, task_type, model, node, parameters, audit_metadata={"project": project, "workflow": workflow})  # type: ignore[return-value]

    @server.tool(name="system_status", description="Inspect Fedora host resources, sandbox, MCP jobs, and MNCS subsystem availability.", annotations=ro, structured_output=True)
    def system_status() -> dict[str, object]:
        def view() -> dict[str, object]:
            fabric = integrations.fabric.status()
            return {
                **integrations.system.status(),
                "sandbox": {"backend": sandbox.backend, "available": sandbox.available, "required": selected.require_real_sandbox},
                "workspace": projects.workspace_info(),
                "jobs": processes.list(),
                "local_harness": integrations.harness.status(),
                "commons": integrations.commons.status(),
                "fabric": fabric,
                "forge": integrations.forge.status(),
                "server": {
                    "name": selected.name,
                    "version": __version__,
                    "transport": "stdio",
                    "fabric_client_version": fabric.get("client_fabric_version"),
                    "fabric_mode": selected.fabric_mode,
                    "fabric_consumer_identity": selected.fabric_consumer_identity,
                },
            }

        return invoke(
            "system_status",
            view,
        )  # type: ignore[return-value]

    @server.tool(name="audit_summary", description="Show bounded aggregate control activity from the private audit log without exposing raw commands or secrets.", annotations=ro, structured_output=True)
    def audit_summary(limit: int = 50) -> dict[str, object]:
        return invoke("audit_summary", audit.summary, limit=limit)  # type: ignore[return-value]

    @server.tool(name="list_repositories", description="List configured MNCS aliases; aliases specialize but do not authorize general workspace access.", annotations=ro, structured_output=True)
    def list_repositories() -> dict[str, object]:
        return invoke("list_repositories", lambda: {"workspace_root": str(policy.root), "repositories": [{"alias": key, "path": value, "exists": (policy.root / value).is_dir()} for key, value in sorted(selected.repositories.items())]})  # type: ignore[return-value]

    @server.tool(name="repo_status", description="Backward-compatible Git status for one configured MNCS alias.", annotations=ro, structured_output=True)
    def repo_status(repository: str) -> dict[str, object]:
        def status_alias() -> dict[str, object]:
            if repository not in selected.repositories:
                raise ControlError("UNAUTHORIZED_REPOSITORY", f"repository alias is unknown: {repository}")
            return git.status(selected.repositories[repository])

        return invoke("repo_status", status_alias)  # type: ignore[return-value]

    @server.tool(name="commons_status", description="Inspect the controller-local Commons service through the Harness-owned MCP boundary.", annotations=ro, structured_output=True)
    def commons_status() -> dict[str, object]:
        return invoke("commons_status", integrations.commons.status)  # type: ignore[return-value]

    @server.tool(name="commons_work", description="List bounded durable Commons work records as untrusted inert data.", annotations=ro, structured_output=True)
    def commons_work(limit: int = 100) -> dict[str, object]:
        return invoke("commons_work", integrations.commons.work, limit)  # type: ignore[return-value]

    @server.tool(name="commons_work_status", description="Read one durable Commons work record and its append-only history as untrusted inert data.", annotations=ro, structured_output=True)
    def commons_work_status(work_id: str) -> dict[str, object]:
        return invoke("commons_work_status", integrations.commons.work_status, work_id)  # type: ignore[return-value]

    @server.tool(name="commons_opportunities", description="List legacy open Commons work opportunities as untrusted inert data.", annotations=ro, structured_output=True)
    def commons_opportunities(limit: int = 100) -> dict[str, object]:
        return invoke("commons_opportunities", integrations.commons.opportunities, limit)  # type: ignore[return-value]

    @server.tool(name="commons_query", description="Run a bounded read-only Commons query through the Harness-owned MCP boundary.", annotations=ro, structured_output=True)
    def commons_query(kind: str | None = None, state: str | None = None, subject: str | None = None, related: str | None = None, limit: int = 100, open_work: bool = False) -> dict[str, object]:
        return invoke("commons_query", integrations.commons.query, kind=kind, state=state, subject=subject, related=related, limit=limit, open_work=open_work)  # type: ignore[return-value]

    @server.tool(name="commons_get", description="Get one Commons record by digest as untrusted inert data.", annotations=ro, structured_output=True)
    def commons_get(digest: str) -> dict[str, object]:
        return invoke("commons_get", integrations.commons.get, digest)  # type: ignore[return-value]

    @server.tool(name="commons_conversation", description="Project a bounded Commons conversation graph rooted at one digest.", annotations=ro, structured_output=True)
    def commons_conversation(digest: str) -> dict[str, object]:
        return invoke("commons_conversation", integrations.commons.conversation, digest)  # type: ignore[return-value]

    @server.tool(name="commons_evidence", description="Trace bounded Commons evidence lineage rooted at one digest.", annotations=ro, structured_output=True)
    def commons_evidence(digest: str) -> dict[str, object]:
        return invoke("commons_evidence", integrations.commons.evidence, digest)  # type: ignore[return-value]

    @server.tool(name="commons_sync", description="Read a bounded ordered Commons ledger slice after an optional store-local cursor.", annotations=ro, structured_output=True)
    def commons_sync(cursor: dict[str, object] | None = None, limit: int = 1000) -> dict[str, object]:
        return invoke("commons_sync", integrations.commons.sync, cursor, limit)  # type: ignore[return-value]

    @server.tool(name="fabric_status", description="Inspect Fabric workers through FabricClient's public API.", annotations=ro, structured_output=True)
    def fabric_status() -> dict[str, object]:
        return invoke("fabric_status", integrations.fabric.status)  # type: ignore[return-value]

    @server.tool(name="model_status", description="Report local Ollama and Fabric model observations.", annotations=ro, structured_output=True)
    def model_status() -> dict[str, object]:
        return invoke("model_status", integrations.models.status)  # type: ignore[return-value]

    @server.tool(name="test_discover", description="Detect a bounded test workflow for a workspace project without executing it.", annotations=ro, structured_output=True)
    def test_discover(project: str) -> dict[str, object]:
        return invoke("test_discover", integrations.tests.discover, project, audit_metadata={"project": project})  # type: ignore[return-value]

    @server.tool(name="test_run", description="Run a detected pytest, Cargo, Node, Go, or CTest workflow inside the project sandbox.", annotations=mutate, structured_output=True)
    def test_run(project: str, test_suite: str = "repository", component: str | None = None, timeout: float | None = None) -> dict[str, object]:
        return invoke("test_run", integrations.tests.run, project, test_suite, component, timeout, audit_metadata={"project": project})  # type: ignore[return-value]

    @server.tool(name="project_check", description="Run a bounded quick, standard, or full project verification profile using detected tooling.", annotations=mutate, structured_output=True)
    def project_check(project: str, profile: str = "standard", timeout: float | None = None) -> dict[str, object]:
        return invoke("project_check", integrations.tests.check, project, profile, timeout, audit_metadata={"project": project, "profile": profile})  # type: ignore[return-value]

    @server.tool(name="run_tests", description="Backward-compatible test workflow for any workspace project inside the sandbox.", annotations=mutate, structured_output=True)
    def run_tests(repository: str, test_suite: str = "repository", component: str | None = None, timeout: float | None = None) -> dict[str, object]:
        return invoke("run_tests", integrations.tests.run, repository, test_suite, component, timeout, audit_metadata={"project": repository})  # type: ignore[return-value]

    @server.tool(name="run_mncs_evaluation", description="Invoke a configured Forge development workflow through Forge's public operation registry.", annotations=mutate, structured_output=True)
    def run_mncs_evaluation(repository: str, case_study: str, model: str | None = None, evaluation_profile: str | None = None) -> dict[str, object]:
        return invoke("run_mncs_evaluation", integrations.forge.evaluate, repository, case_study, model, evaluation_profile, audit_metadata={"project": repository})  # type: ignore[return-value]

    @server.tool(name="dispatch_fabric_job", description="Build validated Fabric plans/manifests/bundles and dispatch bounded pytest, Python, or cargo-test work through FabricClient.", annotations=network_mutate, structured_output=True)
    def dispatch_fabric_job(task_type: str, project: str, model: str | None = None, node: str | None = None, parameters: dict[str, object] | None = None, wait: bool = True) -> dict[str, object]:
        def dispatch() -> dict[str, object]:
            def operation() -> dict[str, object]:
                return integrations.fabric.dispatch(task_type, project, model, node, parameters)
            if not wait:
                if selected.fabric_mode == "service":
                    result = integrations.fabric.dispatch(
                        task_type,
                        project,
                        model,
                        node,
                        parameters,
                        detached=True,
                    )
                    commons_lifecycle: dict[str, object] | None = None
                    accepted_payload = result.get("accepted")
                    if isinstance(accepted_payload, dict) and isinstance(
                        accepted_payload.get("work_id"), str
                    ):
                        fabric_work_id = str(accepted_payload["work_id"])
                        commons_work_id = "work:" + fabric_work_id.removeprefix("sha256:")
                        try:
                            submitted = integrations.commons.submit_work(
                                {
                                    "workId": commons_work_id,
                                    "submittingConsumer": {
                                        "type": "service",
                                        "id": selected.fabric_consumer_identity,
                                    },
                                    "project": {"id": project},
                                    "repository": project,
                                    "task": f"MNCS Control detached {task_type} workload",
                                    "constraints": [
                                        "record is inert and untrusted; execution authority remains external",
                                    ],
                                    "fabricJobId": fabric_work_id,
                                    "workerId": node,
                                    "modelId": model,
                                }
                            )
                            commons_lifecycle = {"submitted": submitted}
                            if submitted.get("currentDigest"):
                                commons_lifecycle["accepted"] = integrations.commons.transition_work(
                                    commons_work_id,
                                    {
                                        "state": "accepted",
                                        "actor": {
                                            "type": "service",
                                            "id": selected.fabric_consumer_identity,
                                        },
                                        "expectedPreviousDigest": submitted["currentDigest"],
                                        "fabricJobId": fabric_work_id,
                                        "workerId": node,
                                        "modelId": model,
                                    },
                                )
                        except Exception as exc:
                            # Fabric remains the execution authority; expose the
                            # durable-record failure explicitly instead of hiding it.
                            commons_lifecycle = {
                                "error": type(exc).__name__ + ": " + str(exc),
                                "contentTrust": "UNTRUSTED",
                                "executionAuthority": "none",
                            }
                    result["control_job"] = processes.record_external(
                        "fabric_" + task_type,
                        project=project,
                        node=node,
                        model=model,
                        result_summary={
                            "status": result.get("status"),
                            "fabric_work_id": (
                                result.get("accepted", {}).get("work_id")
                                if isinstance(result.get("accepted"), dict)
                                else None
                            ),
                        },
                    )
                    if commons_lifecycle is not None:
                        result["commons_lifecycle"] = commons_lifecycle
                    return result
                return {"status": "running", "control_job": processes.submit_external(
                    "fabric_" + task_type,
                    operation,
                    project=project,
                    node=node,
                    model=model,
                    timeout_seconds=(
                        float(parameters["timeout_seconds"])
                        if isinstance(parameters, dict) and parameters.get("timeout_seconds") is not None
                        else None
                    ),
                )}
            result = operation()
            result["control_job"] = processes.record_external(
                "fabric_" + task_type,
                project=project,
                node=node,
                model=model,
                result_summary={"status": result.get("status"), "task_type": task_type, "node": node},
            )
            return result

        return invoke("dispatch_fabric_job", dispatch, audit_metadata={"project": project, "task_type": task_type, "node": node})  # type: ignore[return-value]

    @server.tool(name="fabric_work_status", description="Read one detached persistent Fabric workload state.", annotations=ro, structured_output=True)
    def fabric_work_status(work_id: str) -> dict[str, object]:
        def read() -> dict[str, object]:
            payload = dict(integrations.fabric.work_status(work_id))
            _sync_commons_work_state(payload, work_id)
            return payload

        return invoke("fabric_work_status", read)  # type: ignore[return-value]

    @server.tool(name="fabric_work_result", description="Read one detached persistent Fabric workload result.", annotations=ro, structured_output=True)
    def fabric_work_result(work_id: str) -> dict[str, object]:
        def read() -> dict[str, object]:
            payload = dict(integrations.fabric.work_result(work_id))
            _sync_commons_work_state(payload, work_id)
            return payload

        return invoke("fabric_work_result", read)  # type: ignore[return-value]

    @server.tool(name="fabric_work_list", description="List detached persistent Fabric workloads.", annotations=ro, structured_output=True)
    def fabric_work_list(limit: int = 100) -> dict[str, object]:
        return invoke("fabric_work_list", integrations.fabric.work_list, limit)  # type: ignore[return-value]

    @server.tool(name="fabric_schedule_list", description="List Fabric scheduled work. Commons has no execution authority.", annotations=ro, structured_output=True)
    def fabric_schedule_list() -> dict[str, object]:
        return invoke("fabric_schedule_list", integrations.fabric.schedule_list)  # type: ignore[return-value]

    @server.tool(name="fabric_schedule_tick", description="Evaluate availability windows and dispatch eligible queued Fabric work.", annotations=destructive, structured_output=True)
    def fabric_schedule_tick(now: str | None = None) -> dict[str, object]:
        return invoke("fabric_schedule_tick", integrations.fabric.schedule_tick, now)  # type: ignore[return-value]

    @server.tool(name="control_job_status", description="Inspect a local terminal or upstream control-plane job by stable control ID.", annotations=ro, structured_output=True)
    def control_job_status(job_id: str) -> dict[str, object]:
        return invoke("control_job_status", processes.status, job_id)  # type: ignore[return-value]

    @server.tool(name="control_job_result", description="Retrieve a completed upstream result or bounded terminal output for a control job.", annotations=ro, structured_output=True)
    def control_job_result(job_id: str) -> dict[str, object]:
        return invoke("control_job_result", processes.result, job_id)  # type: ignore[return-value]

    @server.tool(name="control_job_stop", description="Stop a local process or request cancellation of an upstream control job; Fabric-owned work cannot be force-killed by this MCP.", annotations=destructive, structured_output=True)
    def control_job_stop(job_id: str) -> dict[str, object]:
        return invoke("control_job_stop", processes.stop_control, job_id)  # type: ignore[return-value]

    @server.tool(name="job_status", description="Backward-compatible alias for terminal_status.", annotations=ro, structured_output=True)
    def job_status(job_id: str) -> dict[str, object]:
        return invoke("job_status", processes.status, job_id)  # type: ignore[return-value]

    @server.tool(name="job_result", description="Backward-compatible bounded terminal job status and output retrieval.", annotations=ro, structured_output=True)
    def job_result(job_id: str) -> dict[str, object]:
        return invoke("job_result", processes.output, job_id)  # type: ignore[return-value]

    server._control_processes = processes
    return server


def main(argv: list[str] | None = None) -> int:
    selected_argv = list(sys.argv[1:] if argv is None else argv)
    if selected_argv and selected_argv[0] == "doctor":
        from .doctor import doctor_main

        return doctor_main(selected_argv[1:])
    parser = argparse.ArgumentParser(prog="mncs-control-mcp")
    parser.add_argument("--config", help="path to a control TOML configuration")
    args = parser.parse_args(argv)
    _logging()
    config = load_config(args.config)
    build_server(config).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import re
import shlex
import shutil
from collections.abc import Sequence
from pathlib import Path

from .adapters import IntegrationBundle, TestAdapter
from .config import ControlConfig
from .developer import developer_readiness_payload
from .errors import ControlError
from .experiment_readiness import evaluate_experiment_readiness
from .git_adapter import GitService
from .github_auth import github_auth_status
from .processes import ProcessManager
from .sandbox import Sandbox
from .security import redact_text
from .specialist_router import (
    ProviderRun,
    invoke_control_specialist_shadow,
    prepare_request,
)
from .tooling import ProjectService
from .workspace import WorkspacePolicy


class ControlPlaneService:
    """Bounded, read-oriented planning views over the lower-level adapters."""

    def __init__(
        self,
        config: ControlConfig,
        policy: WorkspacePolicy,
        sandbox: Sandbox,
        projects: ProjectService,
        git: GitService,
        tests: TestAdapter,
        integrations: IntegrationBundle,
        processes: ProcessManager,
        journal_context: object | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox
        self.projects = projects
        self.git = git
        self.tests = tests
        self.integrations = integrations
        self.processes = processes
        self.journal_context = journal_context

    def capabilities(self) -> dict[str, object]:
        fabric = self.integrations.fabric.status()
        harness = self.integrations.harness.status()
        forge = self.integrations.forge.status()
        commons = self.integrations.commons.status()
        github = github_auth_status()
        fabric_support = fabric.get("persistent_service_support", {})
        service_execution = (
            fabric.get("execution_transport") == "persistent-service"
            and isinstance(fabric_support, dict)
            and fabric_support.get("persistent_service_execution") is True
        )
        fabric_operations = ["persistent fleet read"]
        fabric_limitations: list[str] = []
        if service_execution:
            fabric_operations.append("validated persistent-service dispatch")
        else:
            fabric_operations.append("validated dispatch in explicit compatibility mode")
            fabric_limitations.append(
                "persistent service execution is not advertised by the connected Fabric controller"
            )
        rendezvous_supported = (
            isinstance(fabric_support, dict) and fabric_support.get("worker_rendezvous") is True
        )
        if rendezvous_supported:
            fabric_operations.append("authenticated worker-initiated rendezvous")
        else:
            fabric_limitations.append(
                "worker-initiated rendezvous is not advertised by the connected Fabric controller"
            )
        return {
            "server": {
                "name": self.config.name,
                "package_version": __import__(
                    "mncs_control_mcp", fromlist=["__version__"]
                ).__version__,
                "transport": "stdio",
                "fabric_client_version": fabric.get("client_fabric_version")
                or fabric.get("version"),
                "fabric_mode": self.config.fabric_mode,
                "fabric_consumer_identity": self.config.fabric_consumer_identity,
            },
            "workspace": {
                "available": self.policy.root.is_dir(),
                "version": None,
                "supported_operations": [
                    "inspect",
                    "read",
                    "write",
                    "patch",
                    "move",
                    "copy",
                    "delete",
                    "create_project",
                ],
                "limitations": [
                    "workspace-relative paths",
                    "symlink escapes rejected",
                    "root deletion protected",
                ],
                "security_boundary": str(self.policy.root),
                "mutation": True,
                "network_required": False,
                "local": True,
            },
            "terminal": {
                "available": self.sandbox.available,
                "version": self.sandbox.backend,
                "supported_operations": [
                    "exec",
                    "start",
                    "status",
                    "output",
                    "stdin",
                    "stop",
                    "bounded upstream jobs",
                ],
                "limitations": [
                    "Bubblewrap required",
                    "project scope is default",
                    "bounded jobs and output",
                ],
                "security_boundary": "Bubblewrap namespace with /workspace and dedicated HOME",
                "mutation": True,
                "network_required": self.config.terminal_network_allowed,
                "local": True,
            },
            "git": {
                "available": shutil.which("git") is not None,
                "version": None,
                "supported_operations": [
                    "status",
                    "diff",
                    "log",
                    "branch",
                    "stage",
                    "commit",
                    "fetch",
                    "pull",
                    "push",
                    "clone",
                ],
                "limitations": ["force push unavailable", "interactive askpass is disabled"],
                "security_boundary": "Git executes inside the workspace sandbox",
                "mutation": True,
                "network_required": True,
                "local": True,
            },
            "github": self._github_capability(github),
            "testing": {
                "available": True,
                "version": None,
                "supported_operations": ["discover", "run", "check"],
                "limitations": [
                    "common ecosystems are detected; project-specific runners may need terminal_exec"
                ],
                "security_boundary": "project-scoped Bubblewrap",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "harness": self._integration_capability(
                harness,
                ["status", "models", "bounded analysis"],
                "local model execution remains upstream-owned",
            ),
            "fabric": self._integration_capability(
                fabric,
                fabric_operations,
                "; ".join(fabric_limitations)
                if fabric_limitations
                else "controller-managed persistent execution is available",
                authority="persistent-controller owns membership, presence, trust, and lifecycle",
            ),
            "forge": self._integration_capability(
                forge,
                ["capability inventory", "configured evaluation"],
                "Forge remains authoritative for scoring and evidence",
            ),
            "commons": self._integration_capability(
                commons,
                [
                    "status",
                    "work discovery",
                    "query",
                    "record read",
                    "conversation graph",
                    "evidence trace",
                    "ledger sync",
                    "terminal Concept Experiment publish/sync",
                ],
                "reads use the consumer socket; only bounded terminal Concept Experiment publication uses the operator socket",
                authority="controller-local Commons owns records and its separate operator surface",
            ),
            "journal_context": {
                "available": self.journal_context is not None,
                "status": "CONFIGURED" if self.journal_context is not None else "UNAVAILABLE",
                "supported_operations": [
                    "status",
                    "bounded interval collection",
                    "immutable bundle pagination",
                ],
                "limitations": [
                    "projection only; Atlas owns journal semantics",
                    "local-only and uncommitted work is provisional evidence",
                    "configured project allow-list and byte/item limits apply",
                ],
                "security_boundary": "authorized workspace plus private mode-0600 bundle state",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "models": {
                "available": True,
                "version": None,
                "supported_operations": ["inventory", "runtime and worker visibility"],
                "limitations": ["routing remains Harness/Fabric-owned"],
                "security_boundary": "read-only metadata",
                "mutation": False,
                "network_required": False,
                "local": False,
            },
            "specialist_routing": {
                "available": True,
                "version": "mncs-control-specialist-routing-shadow/0.1",
                "supported_operations": ["bounded external proposal", "shadow comparison"],
                "limitations": [
                    "existing policy decision remains authoritative",
                    "provider output cannot authorize or execute a tool",
                ],
                "security_boundary": "workspace sandbox with bounded stdin/stdout and timeout",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "gpu": {
                "available": shutil.which("nvidia-smi") is not None,
                "version": None,
                "supported_operations": ["host inventory"],
                "limitations": ["GPU device access is not enabled for general sandbox jobs"],
                "security_boundary": "host probe only",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "network": {
                "available": self.config.terminal_network_allowed,
                "version": None,
                "supported_operations": ["explicit networked Git and terminal jobs"],
                "limitations": ["disabled by default for terminal jobs", "no domain allowlist"],
                "security_boundary": "Bubblewrap network namespace",
                "mutation": True,
                "network_required": True,
                "local": True,
            },
            "resources": {
                "available": True,
                "version": None,
                "supported_operations": [
                    "wall-clock timeout",
                    "output quota",
                    "concurrency quota",
                    "process-group cleanup",
                    "stable control job IDs",
                ],
                "limitations": ["per-job CPU, memory, and disk cgroup quotas are not yet enforced"],
                "security_boundary": "Bubblewrap plus service-level bounded jobs",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "developer": {
                "available": True,
                "supported_operations": [
                    "git.read",
                    "git.write",
                    "github.read",
                    "github.push",
                    "github.pull_request.write",
                    "forge.evaluate",
                    "fabric.execute",
                    "commons.read",
                    "commons.publish",
                ],
                "limitations": [
                    "developer_readiness observes capabilities and does not grant them",
                    "generic Commons publication is not exposed; Control publishes only durable terminal Concept Experiment revisions",
                ],
                "security_boundary": "same sandbox and consumer sockets as the rest of Control",
                "mutation": False,
                "network_required": False,
                "local": True,
                "github": github.public(),
            },
        }

    @staticmethod
    def _integration_capability(
        status: dict[str, object],
        operations: list[str],
        limitation: str,
        *,
        authority: str | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "configured": status.get("configured", bool(status.get("available"))),
            "reachable": status.get("reachable", status.get("controller_connected", False)),
            "supported": bool(status.get("available")),
            "available": bool(status.get("available")),
            "version": status.get("version") or status.get("package_version"),
            "supported_operations": operations,
            "limitations": [limitation]
            + ([str(status["diagnostic"])] if status.get("diagnostic") else []),
            "security_boundary": "upstream adapter plus workspace authorization",
            "mutation": "dispatch" in operations or "configured evaluation" in operations,
            "network_required": "dispatch" in operations,
            "local": True,
            "authority": authority or "upstream adapter owns its declared semantics",
            "current_limitation": limitation,
        }
        for key in (
            "configured",
            "reachable",
            "protocol",
            "health_status",
            "executable",
            "config",
            "capabilities",
            "missing_capabilities",
        ):
            if key in status:
                result[key] = status[key]
        return result

    @staticmethod
    def _github_capability(status: object) -> dict[str, object]:
        public = status.public() if hasattr(status, "public") else {}
        return {
            "available": bool(getattr(status, "available", False)),
            "version": None,
            "supported_operations": ["status", "fetch", "pull", "push", "pull_request"],
            "limitations": [
                str(getattr(status, "detail", "GitHub authentication is observed, not granted"))
            ],
            "security_boundary": "networked sandbox receives gh credentials or SSH agent, never the host keyring or private keys",
            "mutation": True,
            "network_required": True,
            "local": True,
            "state": getattr(status, "state", "unknown"),
            "account": getattr(status, "account", None),
            "can_git_https": getattr(status, "can_git_https", False),
            "can_pull_request": getattr(status, "can_pull_request", False),
            "ssh_github": getattr(status, "ssh_github", "unavailable"),
            "source": getattr(status, "source", None),
            **({"detail": public.get("detail")} if isinstance(public, dict) else {}),
        }

    def developer_readiness(self, repository: str | None = None) -> dict[str, object]:
        result = developer_readiness_payload(
            self.config,
            sandbox=self.sandbox,
            integrations=self.integrations,
            repository=repository,
        )
        if self.journal_context is not None:
            try:
                result["journal_context"] = self.journal_context.status()  # type: ignore[union-attr]
            except Exception as exc:
                result["journal_context"] = {
                    "overall": "UNKNOWN",
                    "diagnostic": redact_text(str(exc))[:300],
                }
        return result

    def experiment_readiness(self, profile: str = "base-inference") -> dict[str, object]:
        return evaluate_experiment_readiness(
            self.config,
            integrations=self.integrations,
            sandbox=self.sandbox,
            profile=profile,
        )

    def specialist_route_shadow(
        self,
        artifact: dict[str, object],
        request_features: list[int],
        catalog: list[dict[str, object]],
        *,
        existing_decision: dict[str, object] | None = None,
        provider_command: list[str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, object]:
        """Measure an MNEL routing proposal without changing policy or execution."""

        if not provider_command:
            _request, _encoded, request_identity, checked_catalog, checked_decision = (
                prepare_request(
                    artifact,
                    request_features,
                    catalog,
                    existing_decision=existing_decision,
                )
            )
            catalog_bytes = sum(int(item.get("source_bytes", 0)) for item in checked_catalog)
            return {
                "schema": "mncs-control-specialist-routing-shadow/0.1",
                "status": "UNKNOWN",
                "request_identity": request_identity,
                "model_identity": artifact.get("model_identity"),
                "generation_identity": artifact.get("generation_identity"),
                "calibration_identity": artifact.get("calibration_identity"),
                "existing_decision": checked_decision,
                "abstained": True,
                "escalation_reason": "specialist-provider-not-configured",
                "fallback_family": checked_decision.get("selected_family"),
                "candidate_tool_ids": [],
                "schema_valid": False,
                "execution_authorized": False,
                "policy_authoritative": True,
                "measurements": {
                    "catalog_bytes_available": catalog_bytes,
                    "catalog_bytes_selected": 0,
                    "catalog_bytes_avoided": 0,
                    "provider_elapsed_ns": 0,
                    "p50_provider_latency_ns": 0,
                    "p95_provider_latency_ns": 0,
                    "larger_model_calls_avoided": 0,
                    "abstention_rate": 1.0,
                    "schema_validity": 0.0,
                },
                "authority": "policy-authoritative-existing-decision",
            }

        def run_provider(command: Sequence[str], payload: bytes, timeout: float) -> ProviderRun:
            argv = list(command)
            result = self.sandbox.run(
                shlex.join(argv),
                scope="workspace",
                project=None,
                cwd=".",
                timeout_seconds=timeout,
                network=False,
                input_bytes=payload,
            )
            return ProviderRun(
                result.exit_code,
                result.stdout.encode("utf-8"),
                result.timed_out,
                result.output_truncated,
                int(result.duration_seconds * 1_000_000_000),
            )

        return invoke_control_specialist_shadow(
            provider_command,
            artifact,
            request_features,
            catalog,
            existing_decision=existing_decision,
            timeout_seconds=timeout_seconds,
            runner=run_provider,
        )

    def review(self, project: str, depth: str = "standard") -> dict[str, object]:
        if depth not in {"summary", "standard", "deep"}:
            raise ControlError("INVALID_INPUT", "depth must be summary, standard, or deep")
        root = self.policy.project_path(project)
        info = self.projects.info(project)
        review: dict[str, object] = {"project": project, "path": project, "depth": depth, **info}
        try:
            review["git"] = self.git.status(project)
            review["recent_commits"] = self.git.log(project, limit=5).get("commits", [])
        except Exception as exc:
            review["git_diagnostic"] = str(exc)[:500]
        names = [
            "README.md",
            "README.rst",
            "README",
            "CONTRIBUTING.md",
            "pyproject.toml",
            "Cargo.toml",
            "package.json",
            "go.mod",
            "CMakeLists.txt",
            "Makefile",
            "Dockerfile",
        ]
        review["key_files"] = [name for name in names if (root / name).is_file()]
        review["documentation"] = [
            path.name
            for path in root.iterdir()
            if path.is_dir() and path.name.lower() in {"docs", "doc", "documentation"}
        ][:10]
        review["ci"] = (
            [
                str(path.relative_to(root))
                for path in (root / ".github" / "workflows").glob("*")
                if path.is_file()
            ][:50]
            if (root / ".github" / "workflows").is_dir()
            else []
        )
        review["tests"] = self.tests.discover(project)
        review["integrations"] = {
            "forge_configured": (root / self.config.forge_config_name).is_file(),
            "fabric_configured": any(
                (root / name).is_file() for name in ("fabric.toml", "mncs-fabric.toml")
            ),
            "harness_project": any((root / name).exists() for name in ("harness.toml", ".harness")),
            "commons_project": project == self.config.repositories.get("commons"),
        }
        if depth != "summary":
            review["entry_points"] = [
                str(path.relative_to(root))
                for path in root.iterdir()
                if path.is_file() and path.suffix in {".py", ".rs", ".go", ".js", ".ts"}
            ][:50]
            review["todo_markers"] = self._todo_markers(root, deep=depth == "deep")
            review["package_metadata"] = self._package_metadata(root)
        return review

    @staticmethod
    def _todo_markers(root: Path, *, deep: bool) -> dict[str, int]:
        counts = {"TODO": 0, "FIXME": 0}
        candidates = root.rglob("*") if deep else root.iterdir()
        seen = 0
        for path in candidates:
            if (
                seen >= 500
                or not path.is_file()
                or path.is_symlink()
                or path.stat().st_size > 512 * 1024
            ):
                continue
            if any(
                part in {".git", ".venv", "node_modules", "target", "build"} for part in path.parts
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            counts["TODO"] += len(re.findall(r"\bTODO\b", text))
            counts["FIXME"] += len(re.findall(r"\bFIXME\b", text))
            seen += 1
        return counts

    @staticmethod
    def _package_metadata(root: Path) -> dict[str, object]:
        result: dict[str, object] = {}
        for filename in ("package.json", "pyproject.toml"):
            path = root / filename
            if not path.is_file() or path.stat().st_size > 256 * 1024:
                continue
            try:
                if filename == "package.json":
                    value = json.loads(path.read_text(encoding="utf-8"))
                    result[filename] = {
                        key: value.get(key)
                        for key in ("name", "version", "private")
                        if key in value
                    }
                else:
                    import tomllib

                    value = tomllib.loads(path.read_text(encoding="utf-8"))
                    result[filename] = value.get("project", {})
            except (OSError, ValueError, TypeError):
                result[filename] = {"parse_error": True}
        return result

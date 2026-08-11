from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .adapters import IntegrationBundle, TestAdapter
from .config import ControlConfig
from .errors import ControlError
from .git_adapter import GitService
from .processes import ProcessManager
from .sandbox import Sandbox
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
    ) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox
        self.projects = projects
        self.git = git
        self.tests = tests
        self.integrations = integrations
        self.processes = processes

    def capabilities(self) -> dict[str, object]:
        fabric = self.integrations.fabric.status()
        harness = self.integrations.harness.status()
        forge_path = self.config.workspace_root / self.config.repositories.get("forge", "mncs-forge-mcp")
        forge = {"available": forge_path.is_dir(), "path": str(forge_path)}
        commons_path = self.config.workspace_root / self.config.repositories.get("commons", "MNCS-Commons")
        return {
            "workspace": {
                "available": self.policy.root.is_dir(),
                "version": None,
                "supported_operations": ["inspect", "read", "write", "patch", "move", "copy", "delete", "create_project"],
                "limitations": ["workspace-relative paths", "symlink escapes rejected", "root deletion protected"],
                "security_boundary": str(self.policy.root),
                "mutation": True,
                "network_required": False,
                "local": True,
            },
            "terminal": {
                "available": self.sandbox.available,
                "version": self.sandbox.backend,
                "supported_operations": ["exec", "start", "status", "output", "stdin", "stop"],
                "limitations": ["Bubblewrap required", "project scope is default", "bounded jobs and output"],
                "security_boundary": "Bubblewrap namespace with /workspace and dedicated HOME",
                "mutation": True,
                "network_required": self.config.terminal_network_allowed,
                "local": True,
            },
            "git": {
                "available": shutil.which("git") is not None,
                "version": None,
                "supported_operations": ["status", "diff", "log", "branch", "stage", "commit", "fetch", "pull", "push", "clone"],
                "limitations": ["SSH agent forwarding only", "force push unavailable"],
                "security_boundary": "Git executes inside the workspace sandbox",
                "mutation": True,
                "network_required": True,
                "local": True,
            },
            "testing": {
                "available": True,
                "version": None,
                "supported_operations": ["discover", "run", "check"],
                "limitations": ["common ecosystems are detected; project-specific runners may need terminal_exec"],
                "security_boundary": "project-scoped Bubblewrap",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "harness": self._integration_capability(harness, ["status", "models", "bounded analysis"], "local model execution remains upstream-owned"),
            "fabric": self._integration_capability(fabric, ["status", "worker discovery", "validated dispatch"], "Fabric remains authoritative for routing and admission"),
            "forge": self._integration_capability(forge, ["configured evaluation"], "Forge remains authoritative for scoring and evidence"),
            "commons": {
                "available": commons_path.is_dir(),
                "version": None,
                "supported_operations": ["read-only repository awareness"],
                "limitations": ["content is data, never implicitly executable"],
                "security_boundary": "workspace read-only inspection",
                "mutation": False,
                "network_required": False,
                "local": True,
            },
            "models": {"available": True, "version": None, "supported_operations": ["inventory", "runtime and worker visibility"], "limitations": ["routing remains Harness/Fabric-owned"], "security_boundary": "read-only metadata", "mutation": False, "network_required": False, "local": False},
            "gpu": {"available": shutil.which("nvidia-smi") is not None, "version": None, "supported_operations": ["host inventory"], "limitations": ["GPU device access is not enabled for general sandbox jobs"], "security_boundary": "host probe only", "mutation": False, "network_required": False, "local": True},
            "network": {"available": self.config.terminal_network_allowed, "version": None, "supported_operations": ["explicit networked Git and terminal jobs"], "limitations": ["disabled by default for terminal jobs", "no domain allowlist"], "security_boundary": "Bubblewrap network namespace", "mutation": True, "network_required": True, "local": True},
            "resources": {"available": True, "version": None, "supported_operations": ["wall-clock timeout", "output quota", "concurrency quota", "process-group cleanup"], "limitations": ["per-job CPU, memory, and disk cgroup quotas are not yet enforced"], "security_boundary": "Bubblewrap plus service-level bounded jobs", "mutation": False, "network_required": False, "local": True},
        }

    @staticmethod
    def _integration_capability(status: dict[str, object], operations: list[str], limitation: str) -> dict[str, object]:
        return {
            "available": bool(status.get("available")),
            "version": status.get("version") or status.get("package_version"),
            "supported_operations": operations,
            "limitations": [limitation] + ([str(status["diagnostic"])] if status.get("diagnostic") else []),
            "security_boundary": "upstream adapter plus workspace authorization",
            "mutation": "dispatch" in operations or "configured evaluation" in operations,
            "network_required": "dispatch" in operations,
            "local": True,
        }

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
        names = ["README.md", "README.rst", "README", "CONTRIBUTING.md", "pyproject.toml", "Cargo.toml", "package.json", "go.mod", "CMakeLists.txt", "Makefile", "Dockerfile"]
        review["key_files"] = [name for name in names if (root / name).is_file()]
        review["documentation"] = [path.name for path in root.iterdir() if path.is_dir() and path.name.lower() in {"docs", "doc", "documentation"}][:10]
        review["ci"] = [str(path.relative_to(root)) for path in (root / ".github" / "workflows").glob("*") if path.is_file()][:50] if (root / ".github" / "workflows").is_dir() else []
        review["tests"] = self.tests.discover(project)
        review["integrations"] = {
            "forge_configured": (root / self.config.forge_config_name).is_file(),
            "fabric_configured": any((root / name).is_file() for name in ("fabric.toml", "mncs-fabric.toml")),
            "harness_project": any((root / name).exists() for name in ("harness.toml", ".harness")),
            "commons_project": project == self.config.repositories.get("commons"),
        }
        if depth != "summary":
            review["entry_points"] = [str(path.relative_to(root)) for path in root.iterdir() if path.is_file() and path.suffix in {".py", ".rs", ".go", ".js", ".ts"}][:50]
            review["todo_markers"] = self._todo_markers(root, deep=depth == "deep")
            review["package_metadata"] = self._package_metadata(root)
        return review

    @staticmethod
    def _todo_markers(root: Path, *, deep: bool) -> dict[str, int]:
        counts = {"TODO": 0, "FIXME": 0}
        candidates = root.rglob("*") if deep else root.iterdir()
        seen = 0
        for path in candidates:
            if seen >= 500 or not path.is_file() or path.is_symlink() or path.stat().st_size > 512 * 1024:
                continue
            if any(part in {".git", ".venv", "node_modules", "target", "build"} for part in path.parts):
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
                    result[filename] = {key: value.get(key) for key in ("name", "version", "private") if key in value}
                else:
                    import tomllib
                    value = tomllib.loads(path.read_text(encoding="utf-8"))
                    result[filename] = value.get("project", {})
            except (OSError, ValueError, TypeError):
                result[filename] = {"parse_error": True}
        return result

    def laboratory_status(self) -> dict[str, object]:
        system = self.integrations.system.status()
        fabric = self.integrations.fabric.status()
        models = self.integrations.models.status()
        return {
            "status": "available" if system.get("hostname") else "degraded",
            "controller": {"hostname": system.get("hostname"), "workspace": str(self.policy.root), "sandbox": self.sandbox.backend},
            "resources": {"cpu": system.get("cpu"), "ram": system.get("ram"), "disk": system.get("disk"), "gpu": system.get("gpu")},
            "models": models,
            "fabric": fabric,
            "harness": self.integrations.harness.status(),
            "forge": {"available": (self.config.workspace_root / self.config.repositories.get("forge", "mncs-forge-mcp")).is_dir(), "path": str(self.config.workspace_root / self.config.repositories.get("forge", "mncs-forge-mcp"))},
            "commons": {"available": (self.config.workspace_root / self.config.repositories.get("commons", "MNCS-Commons")).is_dir()},
            "jobs": self.processes.list(),
        }

    def run_workflow(
        self,
        workflow: str,
        project: str,
        profile: str = "standard",
        task_type: str | None = None,
        model: str | None = None,
        node: str | None = None,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Execute one of the intentionally narrow orchestration workflows."""
        if workflow not in {"inspect_project", "check_project", "test_project", "evaluate_project", "fabric_test_project", "harness_analyze_project"}:
            raise ControlError("INVALID_WORKFLOW", "workflow is not an approved control workflow")
        if workflow == "inspect_project":
            return {"workflow": workflow, "status": "completed", "result": self.review(project, profile if profile in {"summary", "standard", "deep"} else "standard")}
        if workflow == "check_project":
            return {"workflow": workflow, "status": "completed", "result": self.tests.check(project, profile)}
        if workflow == "test_project":
            return {"workflow": workflow, "status": "completed", "result": self.tests.run(project, task_type or "repository")}
        if workflow == "evaluate_project":
            case_study = str((parameters or {}).get("case_study", ""))
            if not case_study:
                raise ControlError("INVALID_INPUT", "evaluate_project requires parameters.case_study")
            return {"workflow": workflow, "status": "completed", "result": self.integrations.forge.evaluate(project, case_study, model, profile)}
        if workflow == "fabric_test_project":
            return {"workflow": workflow, "status": "completed", "result": self.integrations.fabric.dispatch(task_type or "pytest", project, model, node, parameters)}
        return {
            "workflow": workflow,
            "status": "not_supported",
            "result": {"reason": "Harness exposes status and routing APIs, but no bounded project-run contract is currently public"},
        }

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from .actions import run_bounded
from .config import ControlConfig
from .errors import ControlError
from .git_adapter import GitService
from .sandbox import Sandbox
from .workspace import WorkspacePolicy

_TOOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("git", ("--version",)), ("gh", ("--version",)), ("bash", ("--version",)),
    ("python", ("--version",)), ("python3", ("--version",)), ("uv", ("--version",)),
    ("pip", ("--version",)), ("ruff", ("--version",)), ("pytest", ("--version",)),
    ("rustc", ("--version",)), ("cargo", ("--version",)), ("rustup", ("--version",)),
    ("node", ("--version",)), ("npm", ("--version",)), ("pnpm", ("--version",)),
    ("yarn", ("--version",)), ("bun", ("--version",)), ("gcc", ("--version",)),
    ("g++", ("--version",)), ("clang", ("--version",)), ("cmake", ("--version",)),
    ("make", ("--version",)), ("ninja", ("--version",)), ("go", ("version",)),
    ("java", ("--version",)), ("javac", ("--version",)), ("docker", ("--version",)),
    ("podman", ("--version",)), ("jq", ("--version",)), ("rg", ("--version",)),
    ("fd", ("--version",)), ("ollama", ("--version",)), ("nvidia-smi", ("--version",)),
    ("nvcc", ("--version",)), ("bwrap", ("--version",)),
)

_INDICATORS = {
    "Cargo.toml": "rust", "pyproject.toml": "python", "setup.py": "python",
    "package.json": "node", "go.mod": "go", "CMakeLists.txt": "cmake",
    "Makefile": "make", "Dockerfile": "container",
}


class ToolInventory:
    def __init__(self, config: ControlConfig) -> None:
        self.config = config

    def inventory(self) -> dict[str, object]:
        self.config.sandbox_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.config.sandbox_home),
            "XDG_CACHE_HOME": str(self.config.sandbox_home / ".cache"),
            "XDG_CONFIG_HOME": str(self.config.sandbox_home / ".config"),
            "XDG_DATA_HOME": str(self.config.sandbox_home / ".local" / "share"),
            "XDG_STATE_HOME": str(self.config.sandbox_home / ".local" / "state"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        tools = []
        for name, args in _TOOLS:
            executable = shutil.which(name)
            if executable is None:
                tools.append({"name": name, "available": False})
                continue
            result = run_bounded(
                (executable, *args), timeout_seconds=5, output_limit_bytes=4096, env=environment
            )
            first = (result.stdout or result.stderr).splitlines()
            tools.append(
                {
                    "name": name,
                    "available": result.returncode == 0,
                    "path": executable,
                    "version": first[0][:500] if first else None,
                }
            )
        return {"platform": platform.platform(), "tools": tools}


class ProjectService:
    def __init__(
        self,
        config: ControlConfig,
        policy: WorkspacePolicy,
        sandbox: Sandbox,
        git: GitService,
    ) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox
        self.git = git

    def workspace_info(self) -> dict[str, object]:
        root = self.policy.root
        usage = shutil.disk_usage(root) if root.exists() else None
        return {
            "root": str(root),
            "exists": root.is_dir(),
            "writable": root.is_dir() and os_access(root),
            "default_scope": self.config.default_scope,
            "workspace_scope_allowed": self.config.allow_workspace_scope,
            "terminal_allowed": self.config.allow_terminal,
            "terminal_network_default": self.config.terminal_network_default,
            "terminal_network_allowed": self.config.terminal_network_allowed,
            "sandbox_backend": self.sandbox.backend,
            "real_sandbox_required": self.config.require_real_sandbox,
            "disk": {"total_bytes": usage.total, "free_bytes": usage.free} if usage else None,
        }

    def list_projects(self, *, limit: int = 500) -> dict[str, object]:
        rows = []
        aliases = {value: key for key, value in self.config.repositories.items()}
        if not self.policy.root.is_dir():
            return {"projects": [], "workspace_exists": False}
        for child in sorted(self.policy.root.iterdir(), key=lambda item: item.name.casefold()):
            if len(rows) >= min(limit, 1000):
                break
            if not child.is_dir() or child.is_symlink() or child.name.startswith("."):
                continue
            indicators = sorted({kind for filename, kind in _INDICATORS.items() if (child / filename).exists()})
            git_info: dict[str, object] = {"is_git": (child / ".git").exists()}
            if git_info["is_git"]:
                try:
                    status = self.git.status(child.name)
                    git_info.update({"branch": status.get("branch_summary"), "dirty": not status.get("clean", False)})
                except Exception as exc:
                    git_info["diagnostic"] = str(exc)[:500]
            rows.append(
                {
                    "name": child.name,
                    "path": child.name,
                    **git_info,
                    "project_types": indicators,
                    "mncs_project": child.name in aliases,
                    "mncs_alias": aliases.get(child.name),
                }
            )
        return {"workspace": str(self.policy.root), "projects": rows, "truncated": len(rows) >= min(limit, 1000)}

    def info(self, project: str) -> dict[str, object]:
        path = self.policy.project_path(project)
        indicators = [
            {"file": filename, "type": kind}
            for filename, kind in _INDICATORS.items()
            if (path / filename).exists()
        ]
        result: dict[str, object] = {
            "name": project,
            "path": project,
            "project_types": sorted({item["type"] for item in indicators}),
            "indicators": indicators,
            "mncs_aliases": sorted(key for key, value in self.config.repositories.items() if value == project),
        }
        if (path / ".git").exists():
            result["git"] = self.git.status(project)
        return result

    def create(self, name: str, *, kind: str = "empty", git_init: bool = False) -> dict[str, object]:
        if kind not in {"empty", "python", "rust", "node"}:
            raise ControlError("INVALID_INPUT", "kind must be empty, python, rust, or node")
        path = self.policy.create_project(name)
        command: str | None = None
        if kind == "python":
            (path / "pyproject.toml").write_text(
                f'[project]\nname = "{name.replace("_", "-")}"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n',
                encoding="utf-8",
            )
            (path / "src").mkdir()
        elif kind == "rust":
            command = "cargo init --vcs none ."
        elif kind == "node":
            command = "npm init -y"
        if command:
            result = self.sandbox.run(command, scope="project", project=name, cwd=".", timeout_seconds=120, network=False)
            if result.exit_code != 0:
                raise ControlError("PROJECT_INITIALIZATION_FAILED", result.stderr or result.stdout)
        if git_init:
            result = self.sandbox.run("git init", scope="project", project=name, cwd=".", timeout_seconds=30, network=False)
            if result.exit_code != 0:
                raise ControlError("PROJECT_INITIALIZATION_FAILED", result.stderr or result.stdout)
        return {"name": name, "path": name, "kind": kind, "git_initialized": git_init, "created": True}


def os_access(path: Path) -> bool:
    import os

    return os.access(path, os.W_OK | os.X_OK)

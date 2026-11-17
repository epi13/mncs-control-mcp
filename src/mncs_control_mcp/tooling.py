from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .actions import run_bounded
from .config import ControlConfig
from .errors import ControlError
from .git_adapter import GitService
from .sandbox import Sandbox
from .security import redact_text, safe_host_probe_environment
from .workspace import WorkspacePolicy

_SAFE_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

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


@dataclass(frozen=True)
class Toolchain:
    ecosystem: str
    executable: str | None
    source: str
    version: str | None = None
    diagnostic: str | None = None

    def public(self) -> dict[str, object]:
        return {
            "ecosystem": self.ecosystem,
            "executable": self.executable,
            "source": self.source,
            "version": self.version,
            "diagnostic": self.diagnostic,
        }


class ToolchainResolver:
    """Resolve fixed runner identities without executing repository-provided code."""

    _SYSTEM_TOOLS = {
        "python": "python3",
        "rust": "cargo",
        "node": "npm",
        "go": "go",
        "cmake": "ctest",
        "ruff": "ruff",
    }

    def resolve(self, root: Path, ecosystem: str) -> Toolchain:
        root = root.resolve()
        configured = self._configured(root, ecosystem)
        candidates: list[tuple[Path, str]] = []
        if configured is not None:
            candidates.append((configured, "project_config"))
        if ecosystem == "python":
            candidates.extend((root / ".venv" / "bin" / name, "project_venv") for name in ("python", "python3"))
        if ecosystem == "ruff":
            candidates.append((root / ".venv" / "bin" / "ruff", "project_venv"))
        system_name = self._SYSTEM_TOOLS.get(ecosystem, ecosystem)
        approved_system = self._approved_system(system_name, root)
        if approved_system:
            candidates.append((Path(approved_system), "system"))
        rejected: list[str] = []
        for candidate, source in candidates:
            if not self._safe_executable(candidate, root, approved_system):
                if candidate.exists():
                    rejected.append(f"{candidate}: rejected path or executable")
                continue
            return Toolchain(ecosystem, str(candidate), source)
        diagnostic = f"no approved {ecosystem} toolchain is available"
        if rejected:
            diagnostic += "; " + "; ".join(rejected[:2])
        return Toolchain(ecosystem, None, "unavailable", diagnostic=diagnostic)

    @staticmethod
    def _approved_system(name: str, root: Path) -> str | None:
        """Find a system executable without mistaking the controller venv for it."""
        active_prefix = Path(sys.prefix).resolve()
        base_prefix = Path(sys.base_prefix).resolve()
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if not directory:
                continue
            candidate = Path(directory) / name
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file() or not os_access_executable(resolved):
                continue
            if resolved == root / name or root in resolved.parents:
                continue
            if active_prefix != base_prefix and (resolved == active_prefix or active_prefix in resolved.parents):
                continue
            return str(resolved)
        return None

    @staticmethod
    def _configured(root: Path, ecosystem: str) -> Path | None:
        path = root / "pyproject.toml"
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            return None
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
            value = raw.get("tool", {}).get("mncs-control", {}).get("toolchain", {}).get(ecosystem)
        except (OSError, ValueError, AttributeError):
            return None
        if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
            return None
        return root / value

    @staticmethod
    def _safe_executable(candidate: Path, root: Path, approved_system: str | None) -> bool:
        if not candidate.is_file() or not os_access_executable(candidate) or candidate.is_symlink() and not approved_system:
            return False
        try:
            resolved = candidate.resolve(strict=True)
            if resolved == Path(approved_system).resolve() if approved_system else False:
                return True
            resolved.relative_to(root)
            return True
        except (OSError, ValueError):
            return False


class ToolInventory:
    def __init__(self, config: ControlConfig) -> None:
        self.config = config

    def inventory(self) -> dict[str, object]:
        self.config.sandbox_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = safe_host_probe_environment({
            "HOME": str(self.config.sandbox_home),
            "XDG_CACHE_HOME": str(self.config.sandbox_home / ".cache"),
            "XDG_CONFIG_HOME": str(self.config.sandbox_home / ".config"),
            "XDG_DATA_HOME": str(self.config.sandbox_home / ".local" / "share"),
            "XDG_STATE_HOME": str(self.config.sandbox_home / ".local" / "state"),
        })
        project_candidates = self._project_candidates()
        tools = []
        for name, args in _TOOLS:
            candidates: list[dict[str, object]] = []
            system = shutil.which(name)
            if system:
                candidates.append(self._probe(name, Path(system), args, environment, "system"))
            for path in project_candidates.get(name, ()):
                if not system or Path(system).resolve() != path.resolve():
                    candidates.append(self._probe(name, path, args, environment, "project"))
            healthy = next((item for item in candidates if item["health"] == "healthy"), None)
            project_present = any(item["scope"] == "project" and item["exists"] for item in candidates)
            selected = healthy or next((item for item in candidates if item["exists"]), None)
            if selected is None:
                tools.append({"name": name, "available": False, "status": "absent", "candidates": []})
                continue
            tools.append(
                {
                    "name": name,
                    # A project-local executable is a usable discovery result
                    # even when an unrelated broken system wrapper exists.
                    "available": bool(healthy or project_present),
                    "status": "healthy" if healthy else "project_local" if project_present else "broken",
                    "path": selected["path"],
                    "version": selected["version"],
                    "version_status": selected["version_status"],
                    "diagnostic": selected.get("diagnostic"),
                    "scope": selected["scope"],
                    "source": "project_venv" if selected["scope"] == "project" else selected["scope"],
                    "candidates": candidates,
                }
            )
        return {"platform": platform.platform(), "tools": tools}

    def _project_candidates(self) -> dict[str, list[Path]]:
        """Find bounded per-project executables without executing them."""

        result: dict[str, list[Path]] = {}
        root = self.config.workspace_root
        if not root.is_dir():
            return result
        try:
            projects = sorted(
                (child for child in root.iterdir() if child.is_dir() and not child.is_symlink()),
                key=lambda item: item.name.casefold(),
            )[:200]
        except OSError:
            return result
        for project in projects:
            bin_dir = project / ".venv" / "bin"
            if not bin_dir.is_dir():
                continue
            for name, _args in _TOOLS:
                candidate = bin_dir / name
                system = shutil.which(name)
                if candidate.is_file() and os_access_executable(candidate) and ToolchainResolver._safe_executable(candidate, project, system):
                    result.setdefault(name, []).append(candidate)
        return result

    @staticmethod
    def _probe(
        name: str,
        executable: Path,
        args: tuple[str, ...],
        environment: dict[str, str],
        scope: str,
    ) -> dict[str, object]:
        exists = executable.is_file() and os_access_executable(executable)
        item: dict[str, object] = {
            "path": str(executable),
            "scope": scope,
            "exists": exists,
            "health": "absent",
            "version": None,
            "version_status": "unknown",
        }
        if not exists:
            return item
        result = run_bounded((str(executable), *args), timeout_seconds=5, output_limit_bytes=4096, env=environment)
        first = (result.stdout or result.stderr).splitlines()
        item["version"] = first[0][:500] if first else None
        item["health"] = "healthy" if result.returncode == 0 else "invocation_failed"
        if result.returncode != 0:
            item["diagnostic"] = (result.stderr or result.stdout or "command failed")[:500]
        elif not first or first[0].strip().endswith("0.0.0"):
            item["version_status"] = "unknown"
        else:
            item["version_status"] = "reported"
        return item


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

    @staticmethod
    def _inspect_mncs_metadata(project_dir: Path, entry_names: set[str]) -> dict[str, object]:
        """Read bounded MNCS manifest identity without executing repository code."""
        if ".mncs" not in entry_names:
            return {"mncs_repository": None, "has_mncs_environment": False}
        mncs_dir = project_dir / ".mncs"
        try:
            mncs_stat = mncs_dir.lstat()
        except OSError:
            return {"mncs_repository": None, "has_mncs_environment": False}
        if stat.S_ISLNK(mncs_stat.st_mode) or not stat.S_ISDIR(mncs_stat.st_mode):
            return {"mncs_repository": None, "has_mncs_environment": False}
        has_env = False
        for env_name in ("environment.json", "project-environment.json"):
            candidate = mncs_dir / env_name
            try:
                cstat = candidate.lstat()
                if stat.S_ISREG(cstat.st_mode) and not stat.S_ISLNK(cstat.st_mode):
                    has_env = True
                    break
            except OSError:
                continue
        manifest_path = mncs_dir / "project.json"
        mncs_repository: str | None = None
        try:
            pstat = manifest_path.lstat()
            if (
                stat.S_ISREG(pstat.st_mode)
                and not stat.S_ISLNK(pstat.st_mode)
                and pstat.st_size <= 256 * 1024
            ):
                loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
                repo = loaded.get("repository") if isinstance(loaded, dict) else None
                if isinstance(repo, str) and repo and len(repo) <= 128:
                    mncs_repository = repo
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        return {
            "mncs_repository": mncs_repository,
            "has_mncs_environment": has_env,
        }

    @staticmethod
    def _inspect_local_git_metadata(
        workspace_root: Path, project_dir: Path, entry_names: set[str],
    ) -> dict[str, object]:
        """Inspect non-symlink .git HEAD/worktree metadata without spawning Git."""
        if ".git" not in entry_names:
            return {"is_git": False}
        dot_git = project_dir / ".git"
        try:
            gstat = dot_git.lstat()
        except OSError as exc:
            return {
                "is_git": False,
                "git_status": "inaccessible",
                "diagnostic": redact_text(str(exc))[:300],
            }
        if stat.S_ISLNK(gstat.st_mode):
            return {
                "is_git": False,
                "git_status": "inaccessible",
                "diagnostic": "git marker traverses a symbolic link",
            }
        resolved_workspace = workspace_root.resolve()
        common_repo: str | None = None
        worktree_count: int | None = None
        if stat.S_ISDIR(gstat.st_mode):
            git_dir = dot_git
            common_dir = dot_git
            common_repo = project_dir.name
        elif stat.S_ISREG(gstat.st_mode) and gstat.st_size <= 4096:
            try:
                raw_gitdir = dot_git.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError as exc:
                return {
                    "is_git": True,
                    "git_status": "unavailable",
                    "diagnostic": redact_text(str(exc))[:300],
                }
            if not raw_gitdir.startswith("gitdir:"):
                return {
                    "is_git": True,
                    "git_status": "unavailable",
                    "diagnostic": "invalid .git file metadata",
                }
            target = raw_gitdir.split(":", 1)[1].strip()
            candidate_dir = Path(target)
            if not candidate_dir.is_absolute():
                candidate_dir = project_dir / candidate_dir
            try:
                git_dir = candidate_dir.resolve(strict=True)
                git_dir.relative_to(resolved_workspace)
            except (OSError, ValueError):
                return {
                    "is_git": False,
                    "git_status": "inaccessible",
                    "diagnostic": "gitdir target is unavailable or escapes the workspace",
                }
            if git_dir.parent.name == "worktrees" and git_dir.parent.parent.name == ".git":
                common_dir = git_dir.parent.parent
                if common_dir.parent.parent == resolved_workspace:
                    common_repo = common_dir.parent.name
            else:
                common_dir = git_dir
        else:
            return {
                "is_git": False,
                "git_status": "unavailable",
                "diagnostic": "unsupported .git entry type or size",
            }

        head_path = git_dir / "HEAD"
        branch: str | None = None
        head_oid: str | None = None
        try:
            hstat = head_path.lstat()
            if stat.S_ISLNK(hstat.st_mode) or not stat.S_ISREG(hstat.st_mode) or hstat.st_size > 4096:
                raise OSError("HEAD must be a small non-symlink regular file")
            head_raw = head_path.read_text(encoding="utf-8").strip()
            if head_raw.startswith("ref: "):
                ref_name = head_raw[5:].strip()
                branch = ref_name.removeprefix("refs/heads/")
                if not ref_name.startswith("/") and ".." not in Path(ref_name).parts:
                    ref_file = common_dir / ref_name
                    try:
                        rstat = ref_file.lstat()
                        if stat.S_ISREG(rstat.st_mode) and not stat.S_ISLNK(rstat.st_mode) and rstat.st_size <= 256:
                            candidate_sha = ref_file.read_text(encoding="utf-8").strip()
                            if re.fullmatch(r"[0-9a-f]{40,64}", candidate_sha):
                                head_oid = candidate_sha
                    except OSError:
                        pass
            elif re.fullmatch(r"[0-9a-f]{40,64}", head_raw):
                head_oid = head_raw
                branch = f"HEAD detached at {head_raw[:8]}"
            else:
                branch = head_raw[:120] or None
        except OSError as exc:
            return {
                "is_git": True,
                "branch": None,
                "dirty": None,
                "git_status": "unavailable",
                "diagnostic": redact_text(str(exc))[:300],
            }

        worktrees_dir = common_dir / "worktrees"
        try:
            if worktrees_dir.is_dir() and not worktrees_dir.is_symlink():
                linked = sum(
                    1 for entry in os.scandir(worktrees_dir)
                    if entry.is_dir(follow_symlinks=False)
                )
                worktree_count = 1 + linked
            elif common_repo is not None:
                worktree_count = 1
        except OSError:
            pass

        result: dict[str, object] = {
            "is_git": True,
            "branch": branch,
            "dirty": None,
            "git_status": "not_requested",
        }
        if head_oid is not None:
            result["head"] = head_oid
        if common_repo is not None:
            result["common_repository"] = common_repo
        if worktree_count is not None:
            result["worktree_count"] = worktree_count
        return result

    def list_projects(
        self,
        *,
        limit: int = 500,
        include_status: bool = False,
        include_worktrees: bool = False,
        projects: list[str] | None = None,
    ) -> dict[str, object]:
        aliases = {value: key for key, value in self.config.repositories.items()}
        if not self.policy.root.is_dir():
            return {"projects": [], "workspace_exists": False}
        bounded_limit = max(1, min(int(limit), 1000))
        candidates: list[tuple[str, Path | None, str | None]] = []
        truncated = False
        if projects is not None:
            if not isinstance(projects, list) or len(projects) > 1000:
                raise ControlError("INVALID_INPUT", "projects must be a list of at most 1000 repository names")
            unique_names = list(dict.fromkeys(projects))
            if len(unique_names) > bounded_limit:
                truncated = True
                unique_names = unique_names[:bounded_limit]
            for name in unique_names:
                if not isinstance(name, str) or not _SAFE_PROJECT_RE.fullmatch(name):
                    raise ControlError("INVALID_INPUT", f"invalid project name: {name!r}")
                child = self.policy.root / name
                try:
                    cstat = child.lstat()
                except FileNotFoundError:
                    candidates.append((name, None, "missing"))
                    continue
                except OSError as exc:
                    candidates.append((name, child, redact_text(str(exc))[:300]))
                    continue
                if stat.S_ISLNK(cstat.st_mode) or not stat.S_ISDIR(cstat.st_mode):
                    candidates.append((name, child, "path is missing, a symbolic link, or not a directory"))
                    continue
                candidates.append((name, child, None))
        else:
            try:
                dir_entries = sorted(
                    (
                        entry for entry in os.scandir(self.policy.root)
                        if not entry.name.startswith(".")
                        and not entry.is_symlink()
                        and entry.is_dir(follow_symlinks=False)
                    ),
                    key=lambda item: item.name.casefold(),
                )
            except OSError as exc:
                return {
                    "workspace": str(self.policy.root),
                    "workspace_exists": False,
                    "projects": [],
                    "diagnostic": redact_text(str(exc))[:500],
                }
            if len(dir_entries) > bounded_limit:
                truncated = True
                dir_entries = dir_entries[:bounded_limit]
            candidates = [(entry.name, Path(entry.path), None) for entry in dir_entries]

        rows = []
        status_cache: dict[str, dict[str, object]] = {}
        worktrees_cache: dict[str, dict[str, object]] = {}
        for name, child, error_kind in candidates:
            if error_kind == "missing" or child is None:
                rows.append({
                    "name": name,
                    "path": name,
                    "exists": False,
                    "status": "missing",
                    "is_git": False,
                    "git_status": "missing",
                    "project_types": [],
                    "mncs_project": name in aliases,
                    "mncs_alias": aliases.get(name),
                })
                continue
            if error_kind is not None:
                rows.append({
                    "name": name,
                    "path": name,
                    "exists": False,
                    "status": "inaccessible",
                    "is_git": False,
                    "git_status": "inaccessible",
                    "diagnostic": error_kind,
                    "project_types": [],
                    "mncs_project": name in aliases,
                    "mncs_alias": aliases.get(name),
                })
                continue
            try:
                entry_names = set(os.listdir(child))
            except OSError as exc:
                rows.append({
                    "name": name,
                    "path": name,
                    "exists": True,
                    "status": "inaccessible",
                    "is_git": (child / ".git").exists(),
                    "git_status": "inaccessible",
                    "diagnostic": redact_text(str(exc))[:500],
                    "project_types": [],
                    "mncs_project": name in aliases,
                    "mncs_alias": aliases.get(name),
                })
                continue
            indicators = sorted({kind for filename, kind in _INDICATORS.items() if filename in entry_names})
            mncs_meta = self._inspect_mncs_metadata(child, entry_names)
            git_info = self._inspect_local_git_metadata(self.policy.root, child, entry_names)
            if git_info.get("is_git") and include_status:
                try:
                    if name not in status_cache:
                        status_cache[name] = self.git.status(name)
                    status = status_cache[name]
                    git_info.update({
                        "branch": status.get("branch_summary"),
                        "dirty": not status.get("clean", False),
                        "git_status": "observed",
                    })
                except Exception as exc:
                    git_info["git_status"] = "unavailable"
                    git_info["dirty"] = None
                    git_info["diagnostic"] = redact_text(str(exc))[:500]
            if git_info.get("is_git") and include_worktrees:
                try:
                    if name not in worktrees_cache:
                        worktrees_cache[name] = self.git.worktree_list(name)
                    wt_list = worktrees_cache[name].get("worktrees", [])
                    git_info["worktrees"] = wt_list
                    if isinstance(wt_list, list):
                        git_info["worktree_count"] = len(wt_list)
                except Exception as exc:
                    git_info["worktrees_diagnostic"] = redact_text(str(exc))[:500]
            rows.append(
                {
                    "name": name,
                    "path": name,
                    **git_info,
                    "project_types": indicators,
                    "mncs_project": name in aliases,
                    "mncs_alias": aliases.get(name),
                    **mncs_meta,
                }
            )
        return {
            "workspace": str(self.policy.root),
            "projects": rows,
            "truncated": truncated,
            "status_observed": bool(include_status),
        }

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


def os_access_executable(path: Path) -> bool:
    return os.access(path, os.X_OK)

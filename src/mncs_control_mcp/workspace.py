from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import ControlConfig
from .errors import ControlError

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class ScopeResolution:
    scope: str
    project: str | None
    host_root: Path
    host_cwd: Path
    sandbox_cwd: str


class WorkspacePolicy:
    """Single authorization boundary for every caller-supplied workspace path."""

    def __init__(self, config: ControlConfig) -> None:
        self.config = config
        self.root = config.workspace_root.expanduser().resolve()

    @staticmethod
    def normalize_relative(value: str, *, allow_root: bool = True) -> PurePosixPath:
        if not isinstance(value, str) or "\x00" in value or "\\" in value:
            raise ControlError("INVALID_PATH", "path must use relative POSIX syntax")
        if value in {"", "."}:
            if allow_root:
                return PurePosixPath(".")
            raise ControlError("WORKSPACE_ROOT_PROTECTED", "the workspace root is protected")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or any(part == "" for part in path.parts):
            raise ControlError("PATH_ESCAPE", "path must remain relative to the workspace")
        return path

    def _contained(self, candidate: Path, boundary: Path | None = None) -> Path:
        resolved_boundary = (boundary or self.root).resolve()
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(resolved_boundary)
        except ValueError as exc:
            raise ControlError("PATH_ESCAPE", "resolved path escapes its authorized workspace boundary") from exc
        return resolved

    def resolve(
        self,
        value: str,
        *,
        must_exist: bool = False,
        allow_root: bool = True,
        mutation: bool = False,
        expect: str | None = None,
    ) -> Path:
        relative = self.normalize_relative(value, allow_root=allow_root)
        candidate = self.root.joinpath(*relative.parts)
        parent = candidate.parent.resolve(strict=False)
        self._contained(parent)
        if candidate.is_symlink() and mutation:
            raise ControlError("SYMLINK_MUTATION", "mutating a symbolic-link path is not allowed")
        resolved = self._contained(candidate)
        if must_exist and not candidate.exists():
            raise ControlError("PATH_NOT_FOUND", f"workspace path does not exist: {value}")
        if expect == "file" and (not candidate.is_file() or candidate.is_symlink()):
            raise ControlError("NOT_A_FILE", f"workspace path is not a regular file: {value}")
        if expect == "directory" and (not candidate.is_dir() or candidate.is_symlink()):
            raise ControlError("NOT_A_DIRECTORY", f"workspace path is not a directory: {value}")
        return resolved if candidate.exists() else candidate

    def relative(self, path: Path) -> str:
        return self._contained(path).relative_to(self.root).as_posix() or "."

    def project_path(self, project: str, *, must_exist: bool = True) -> Path:
        if not isinstance(project, str) or not _PROJECT_NAME.fullmatch(project):
            raise ControlError("INVALID_PROJECT", "project must name one immediate workspace child")
        path = self.resolve(project, must_exist=must_exist)
        if must_exist and (not path.is_dir() or path.is_symlink()):
            raise ControlError("INVALID_PROJECT", "project must be a real directory, not a symbolic link")
        return path

    def resolve_scope(
        self,
        *,
        scope: str | None,
        project: str | None,
        cwd: str,
    ) -> ScopeResolution:
        selected = scope or self.config.default_scope
        if selected not in {"project", "workspace"}:
            raise ControlError("INVALID_SCOPE", "scope must be project or workspace")
        relative_cwd = self.normalize_relative(cwd)
        if selected == "workspace":
            if not self.config.allow_workspace_scope:
                raise ControlError("WORKSPACE_SCOPE_DISABLED", "workspace-scoped terminal access is disabled")
            host_cwd = self._contained(self.root.joinpath(*relative_cwd.parts))
            if not host_cwd.is_dir():
                raise ControlError("INVALID_CWD", "cwd must identify an existing workspace directory")
            return ScopeResolution(selected, None, self.root, host_cwd, "/workspace/" + relative_cwd.as_posix())
        if project is None:
            raise ControlError("PROJECT_REQUIRED", "project scope requires a project")
        project_root = self.project_path(project)
        host_cwd = self._contained(project_root.joinpath(*relative_cwd.parts), project_root)
        if not host_cwd.is_dir():
            raise ControlError("INVALID_CWD", "cwd must identify an existing project directory")
        suffix = relative_cwd.as_posix()
        sandbox_cwd = f"/workspace/{project}" + ("" if suffix == "." else f"/{suffix}")
        return ScopeResolution(selected, project, project_root, host_cwd, sandbox_cwd)

    def create_project(self, name: str) -> Path:
        path = self.project_path(name, must_exist=False)
        if path.exists():
            raise ControlError("PROJECT_EXISTS", f"project already exists: {name}")
        path.mkdir(mode=0o755)
        return path

    def refuse_root_operation(self, path: Path, operation: str) -> None:
        if path.resolve(strict=False) == self.root:
            raise ControlError("WORKSPACE_ROOT_PROTECTED", f"cannot {operation} the workspace root")

    def open_write_fd(self, path: Path, *, overwrite: bool) -> int:
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        flags |= os.O_TRUNC if overwrite else os.O_EXCL
        try:
            return os.open(path, flags, 0o644)
        except FileExistsError as exc:
            raise ControlError("FILE_EXISTS", "file already exists and overwrite is false") from exc
        except OSError as exc:
            raise ControlError("FILE_WRITE_FAILED", str(exc)) from exc

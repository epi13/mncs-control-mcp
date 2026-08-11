from __future__ import annotations

import base64
import fnmatch
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import ControlConfig
from .errors import ControlError
from .security import bounded_text, is_sensitive_name
from .workspace import WorkspacePolicy


class FileService:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy) -> None:
        self.config = config
        self.policy = policy

    def stat(self, path: str) -> dict[str, object]:
        target = self.policy.resolve(path, must_exist=True)
        info = target.lstat()
        kind = "symlink" if target.is_symlink() else "directory" if target.is_dir() else "file" if target.is_file() else "other"
        result: dict[str, object] = {
            "path": path or ".",
            "kind": kind,
            "size_bytes": info.st_size,
            "mode": oct(info.st_mode & 0o777),
            "modified_ns": info.st_mtime_ns,
        }
        if target.is_symlink():
            try:
                resolved = target.resolve(strict=True)
                resolved.relative_to(self.policy.root)
                result["target_within_workspace"] = True
                result["target"] = resolved.relative_to(self.policy.root).as_posix()
            except (OSError, ValueError):
                result["target_within_workspace"] = False
        return result

    def list(self, path: str = ".", *, limit: int | None = None) -> dict[str, object]:
        root = self.policy.resolve(path, must_exist=True, expect="directory")
        maximum = min(limit or self.config.max_listing_entries, self.config.max_listing_entries)
        entries = []
        truncated = False
        for index, child in enumerate(sorted(root.iterdir(), key=lambda item: item.name.casefold())):
            if index >= maximum:
                truncated = True
                break
            info = child.lstat()
            entries.append(
                {
                    "name": child.name,
                    "path": child.relative_to(self.policy.root).as_posix(),
                    "kind": "symlink" if child.is_symlink() else "directory" if child.is_dir() else "file" if child.is_file() else "other",
                    "size_bytes": info.st_size,
                    "modified_ns": info.st_mtime_ns,
                }
            )
        return {"path": path, "entries": entries, "truncated": truncated, "limit": maximum}

    def tree(self, path: str = ".", *, depth: int = 3, limit: int | None = None) -> dict[str, object]:
        if depth < 0 or depth > 20:
            raise ControlError("INVALID_INPUT", "depth must be between 0 and 20")
        root = self.policy.resolve(path, must_exist=True, expect="directory")
        maximum = min(limit or self.config.max_listing_entries, self.config.max_listing_entries)
        entries: list[dict[str, object]] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            relative_depth = len(current_path.relative_to(root).parts)
            directories[:] = sorted(
                [name for name in directories if not (current_path / name).is_symlink()], key=str.casefold
            )
            if relative_depth >= depth:
                directories[:] = []
            for name in sorted((*directories, *files), key=str.casefold):
                child = current_path / name
                entries.append(
                    {
                        "path": child.relative_to(self.policy.root).as_posix(),
                        "kind": "symlink" if child.is_symlink() else "directory" if child.is_dir() else "file" if child.is_file() else "other",
                    }
                )
                if len(entries) >= maximum:
                    return {"path": path, "entries": entries, "truncated": True, "limit": maximum}
        return {"path": path, "entries": entries, "truncated": False, "limit": maximum}

    def read(self, path: str, *, offset: int = 0, limit: int | None = None) -> dict[str, object]:
        target = self.policy.resolve(path, must_exist=True, expect="file")
        if offset < 0:
            raise ControlError("INVALID_INPUT", "offset must be non-negative")
        maximum = min(limit or self.config.max_file_bytes, self.config.max_file_bytes)
        size = target.stat().st_size
        with target.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(maximum + 1)
        truncated = len(data) > maximum or offset + len(data) < size
        data = data[:maximum]
        binary = b"\x00" in data
        if not binary:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                binary = True
        result: dict[str, object] = {
            "path": path,
            "size_bytes": size,
            "offset": offset,
            "bytes_returned": len(data),
            "truncated": truncated,
            "binary": binary,
        }
        if binary:
            result["content_base64"] = base64.b64encode(data).decode("ascii")
        else:
            result["content"] = text
        return result

    def write(
        self,
        path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        overwrite: bool = True,
        create_parents: bool = False,
    ) -> dict[str, object]:
        target = self.policy.resolve(path, allow_root=False, mutation=True)
        if encoding == "utf-8":
            data = content.encode("utf-8")
        elif encoding == "base64":
            try:
                data = base64.b64decode(content, validate=True)
            except ValueError as exc:
                raise ControlError("INVALID_CONTENT", "content is not valid base64") from exc
        else:
            raise ControlError("INVALID_INPUT", "encoding must be utf-8 or base64")
        if len(data) > self.config.max_file_bytes:
            raise ControlError("FILE_TOO_LARGE", "file content exceeds the configured limit")
        if create_parents:
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            self.policy._contained(target.parent)
        elif not target.parent.is_dir():
            raise ControlError("PARENT_NOT_FOUND", "parent directory does not exist")
        fd = self.policy.open_write_fd(target, overwrite=overwrite)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return {"path": path, "bytes_written": len(data), "created": True}

    def mkdir(self, path: str, *, parents: bool = False, exist_ok: bool = False) -> dict[str, object]:
        target = self.policy.resolve(path, allow_root=False, mutation=True)
        try:
            target.mkdir(mode=0o755, parents=parents, exist_ok=exist_ok)
        except OSError as exc:
            raise ControlError("DIRECTORY_CREATE_FAILED", str(exc)) from exc
        self.policy._contained(target)
        return {"path": path, "created": True}

    def move(self, source: str, destination: str, *, overwrite: bool = False) -> dict[str, object]:
        src = self.policy.resolve(source, must_exist=True, allow_root=False, mutation=True)
        dst = self.policy.resolve(destination, allow_root=False, mutation=True)
        if dst.exists() and not overwrite:
            raise ControlError("DESTINATION_EXISTS", "destination already exists")
        if dst.exists() and overwrite:
            self.delete(destination, recursive=True)
        dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return {"source": source, "destination": destination, "moved": True}

    def copy(self, source: str, destination: str, *, overwrite: bool = False) -> dict[str, object]:
        src = self.policy.resolve(source, must_exist=True, allow_root=False)
        dst = self.policy.resolve(destination, allow_root=False, mutation=True)
        if src.is_symlink():
            raise ControlError("SYMLINK_COPY", "copying symbolic links is not allowed")
        if dst.exists() and not overwrite:
            raise ControlError("DESTINATION_EXISTS", "destination already exists")
        if src.is_dir():
            for current, directories, filenames in os.walk(src, followlinks=False):
                current_path = Path(current)
                if any((current_path / name).is_symlink() for name in (*directories, *filenames)):
                    raise ControlError("SYMLINK_COPY", "directory copy contains a symbolic link")
            shutil.copytree(src, dst, dirs_exist_ok=overwrite, symlinks=False)
        else:
            dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        self.policy._contained(dst)
        return {"source": source, "destination": destination, "copied": True}

    def delete(self, path: str, *, recursive: bool = False) -> dict[str, object]:
        relative = self.policy.normalize_relative(path, allow_root=False)
        target = self.policy.root.joinpath(*relative.parts)
        self.policy._contained(target.parent)
        if not target.exists() and not target.is_symlink():
            raise ControlError("PATH_NOT_FOUND", f"workspace path does not exist: {path}")
        self.policy.refuse_root_operation(target, "delete")
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif recursive:
            shutil.rmtree(target)
        else:
            target.rmdir()
        return {"path": path, "deleted": True, "recursive": recursive}

    def glob(self, pattern: str, *, limit: int | None = None) -> dict[str, object]:
        if not isinstance(pattern, str) or not pattern or pattern.startswith("/") or ".." in Path(pattern).parts:
            raise ControlError("INVALID_PATTERN", "glob must be a relative workspace pattern")
        maximum = min(limit or self.config.max_search_results, self.config.max_search_results)
        matches: list[str] = []
        for candidate in self.policy.root.glob(pattern):
            try:
                contained = self.policy._contained(candidate)
            except ControlError:
                continue
            rendered = contained.relative_to(self.policy.root).as_posix()
            if not is_sensitive_name(rendered):
                matches.append(rendered)
            if len(matches) >= maximum:
                break
        return {"pattern": pattern, "matches": sorted(set(matches)), "truncated": len(matches) >= maximum}

    def search(
        self,
        query: str,
        *,
        path: str = ".",
        glob: str = "*",
        regex: bool = False,
        case_sensitive: bool = True,
        limit: int | None = None,
    ) -> dict[str, object]:
        if not query or len(query) > 4096:
            raise ControlError("INVALID_INPUT", "query must be non-empty bounded text")
        root = self.policy.resolve(path, must_exist=True, expect="directory")
        maximum = min(limit or self.config.max_search_results, self.config.max_search_results)
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            expression = re.compile(query if regex else re.escape(query), flags)
        except re.error as exc:
            raise ControlError("INVALID_REGEX", str(exc)) from exc
        matches: list[dict[str, object]] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
            for name in files:
                if not fnmatch.fnmatch(name, glob):
                    continue
                candidate = current_path / name
                if candidate.is_symlink() or candidate.stat().st_size > self.config.max_file_bytes:
                    continue
                relative = candidate.relative_to(self.policy.root).as_posix()
                if is_sensitive_name(relative):
                    continue
                try:
                    lines = candidate.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for number, line in enumerate(lines, 1):
                    if expression.search(line):
                        excerpt, _ = bounded_text(line, 1000)
                        matches.append({"path": relative, "line": number, "text": excerpt})
                        if len(matches) >= maximum:
                            return {"query": query, "matches": matches, "truncated": True}
        return {"query": query, "matches": matches, "truncated": False}

    def patch(self, patch: str) -> dict[str, object]:
        encoded = patch.encode("utf-8")
        if len(encoded) > self.config.max_file_bytes:
            raise ControlError("PATCH_TOO_LARGE", "patch exceeds the configured file limit")
        paths: set[str] = set()
        for line in patch.splitlines():
            if line.startswith(("--- ", "+++ ")):
                value = line[4:].split("\t", 1)[0]
                if value == "/dev/null":
                    continue
                if value.startswith(("a/", "b/")):
                    value = value[2:]
                self.policy.resolve(value, allow_root=False, mutation=True)
                paths.add(value)
        if not paths:
            raise ControlError("INVALID_PATCH", "unified patch has no file headers")
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.config.sandbox_home), "GIT_CONFIG_NOSYSTEM": "1"}
        for args in (("git", "apply", "--check", "--whitespace=nowarn", "-"), ("git", "apply", "--whitespace=nowarn", "-")):
            process = subprocess.run(
                args,
                cwd=self.policy.root,
                env=environment,
                input=encoded,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if process.returncode != 0:
                stderr, truncated = bounded_text(process.stderr.decode(errors="replace"), self.config.max_output_bytes)
                raise ControlError("PATCH_REJECTED", stderr, details={"output_truncated": truncated})
        return {"applied": True, "paths": sorted(paths)}

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ControlError
from .workspace import WorkspacePolicy

_CARGO_TARGET_KIND = "cargo-target"
_CACHEDIR_TAG_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55\n"
_MAX_WALK_ENTRIES = 500_000
_MAX_CANDIDATES = 500
_PLAN_TTL_SECONDS = 15 * 60
_SKIP_DIRS = {".git"}
_CATEGORIES = {
    ".mncs": "mncs-runtime-state",
    ".venv": "python-environment",
    ".venv-vision": "python-environment",
    ".venv-vision-cuda": "python-environment",
    "node_modules": "node-dependencies",
    ".npm": "package-cache-unknown",
    ".pnpm-store": "package-cache-unknown",
    ".cache": "generated-cache-unknown",
    ".pytest_cache": "python-cache-unknown",
    ".mypy_cache": "python-cache-unknown",
    ".ruff_cache": "python-cache-unknown",
    "vendor": "vendored-dependencies-unknown",
    "runs": "execution-output",
    "run": "execution-output",
    "traces": "trace-output",
    "trace": "trace-output",
    "snapshots": "snapshot-data",
    "snapshot": "snapshot-data",
    "logs": "log-data",
    "log": "log-data",
    "test-results": "test-output",
    "test-output": "test-output",
    "generated-caches": "generated-cache-unknown",
    "build": "build-output-unknown",
    "builds": "build-output-unknown",
    ".build": "build-output-unknown",
    ".bootstrap": "build-output-unknown",
}
_BUILD_TOOLS = {
    "cargo", "rustc", "rust-analyzer", "mncs", "pytest",
    "make", "cmake", "ninja", "gcc", "g++", "clang", "clang++", "node", "npm",
    "pnpm", "yarn", "tsc", "gradle", "mvn",
}


@dataclass(frozen=True)
class _TreeManifest:
    digest: str
    entries: int
    logical_bytes: int
    unsafe_reasons: tuple[str, ...]


@dataclass(frozen=True)
class _Process:
    pid: int
    argv: tuple[str, ...]
    cwd: str | None
    references: tuple[str, ...]
    build_context: bool


@dataclass(frozen=True)
class _ProcessSnapshot:
    processes: tuple[_Process, ...]
    incomplete: bool
    unreadable_processes: int


@dataclass(frozen=True)
class _RepositoryState:
    root: Path
    branch: str | None
    default_branch: str | None
    head: str | None
    clean: bool
    worktree_count: int
    complete: bool


class StorageService:
    """Conservative workspace storage inventory and Cargo-output reclamation."""

    def __init__(self, policy: WorkspacePolicy) -> None:
        self.policy = policy
        self.root = policy.root.resolve()
        self._plans: dict[str, tuple[float, tuple[dict[str, Any], ...]]] = {}
        self._lock = threading.RLock()

    def inventory(self) -> dict[str, object]:
        """Measure workspace and common generated-data classes without mutation."""
        paths, scan_complete, scan_errors = self._discover_roots()
        measured = self._measure_paths(paths)
        workspace_bytes, workspace_complete, workspace_error = self._du(self.root)
        top_level, top_level_complete, top_level_error = self._top_level_sizes()

        by_kind: dict[str, dict[str, Any]] = {}
        for item in measured:
            kind = str(item["kind"])
            row = by_kind.setdefault(
                kind,
                {
                    "kind": kind,
                    "reconstructability": "known" if kind == _CARGO_TARGET_KIND else "unknown",
                    "reclamation_supported": kind == _CARGO_TARGET_KIND,
                    "root_count": 0,
                    "bytes": 0,
                    "measured_roots": 0,
                },
            )
            row["root_count"] += 1
            if item["bytes"] is not None:
                row["bytes"] += int(item["bytes"])
                row["measured_roots"] += 1

        disk = os.statvfs(self.root)
        total_bytes = disk.f_blocks * disk.f_frsize
        available_bytes = disk.f_bavail * disk.f_frsize
        used_bytes = max(0, total_bytes - disk.f_bfree * disk.f_frsize)
        largest = sorted(top_level, key=lambda item: int(item["bytes"]), reverse=True)[:50]
        cargo = sorted(
            (item for item in measured if item["kind"] == _CARGO_TARGET_KIND),
            key=lambda item: int(item["bytes"] or 0),
            reverse=True,
        )
        errors = list(scan_errors[:20])
        if workspace_error:
            errors.append(workspace_error)
        if top_level_error:
            errors.append(top_level_error)
        complete = scan_complete and workspace_complete and top_level_complete
        return {
            "schema_version": "mncs.workspace-storage-inventory/1",
            "measured_at": datetime.now(UTC).isoformat(),
            "root": ".",
            "filesystem": {
                "total_bytes": total_bytes,
                "used_bytes": used_bytes,
                "available_bytes": available_bytes,
                "available_fraction": round(available_bytes / total_bytes, 6) if total_bytes else None,
            },
            "workspace": {
                "allocated_bytes": workspace_bytes,
                "complete": workspace_complete,
                "measurement": "GNU du allocated blocks; Btrfs shared/compressed extents may differ from freed bytes",
            },
            "scan": {"complete": complete, "classified_roots": len(paths), "errors": errors},
            "categories": sorted(by_kind.values(), key=lambda item: str(item["kind"])),
            "largest_projects": largest,
            "cargo_targets": cargo[:100],
        }

    def plan(self) -> dict[str, object]:
        """Create a short-lived plan; only idle, clean, sole-main-worktree Cargo outputs qualify."""
        paths, scan_complete, scan_errors = self._discover_roots()
        cargo_paths = [path for path in paths if path["kind"] == _CARGO_TARGET_KIND]
        processes = self._process_snapshot()
        repo_cache: dict[Path, _RepositoryState] = {}
        candidates: list[dict[str, Any]] = []
        for discovered in cargo_paths:
            candidates.append(self._assess(discovered, processes, repo_cache, scan_errors))

        eligible = [item for item in candidates if item["reasons"] == []]
        if not scan_complete or processes.incomplete:
            # A partial inventory or partial same-user process scan cannot authorize deletion.
            for item in eligible:
                item["reasons"] = ["workspace_scan_incomplete" if not scan_complete else "process_scan_incomplete"]
                item["state"] = "unknown"
            eligible = []

        plan_id = secrets.token_urlsafe(18)
        expires = time.monotonic() + _PLAN_TTL_SECONDS
        selected = tuple(
            {
                "path": item["path"],
                "bytes": item["bytes"],
                "repo_root": item["repo_root"],
                "branch": item["branch"],
                "head": item["head"],
                "manifest_sha256": item["manifest_sha256"],
                "device": item["device"],
                "inode": item["inode"],
                "mtime_ns": item["mtime_ns"],
            }
            for item in eligible[:_MAX_CANDIDATES]
        )
        if len(eligible) > _MAX_CANDIDATES:
            eligible = eligible[:_MAX_CANDIDATES]
        with self._lock:
            now = time.monotonic()
            self._plans = {key: value for key, value in self._plans.items() if value[0] > now}
            self._plans[plan_id] = (expires, selected)

        size = sum(int(item["bytes"] or 0) for item in eligible)
        return {
            "schema_version": "mncs.workspace-storage-plan/1",
            "plan_id": plan_id,
            "expires_in_seconds": _PLAN_TTL_SECONDS,
            "requires_explicit_confirmation": True,
            "eligible_bytes": size,
            "size_measurement": "GNU du allocated bytes; filesystem space freed may differ",
            "eligible_count": len(eligible),
            "process_scan": {
                "complete": not processes.incomplete,
                "unreadable_same_user_processes": processes.unreadable_processes,
            },
            "workspace_scan_complete": scan_complete,
            "candidates": candidates,
            "scan_errors": list(scan_errors[:20]),
        }

    def reclaim(self, plan_id: str, *, confirm: bool) -> dict[str, object]:
        """Execute a fresh, identity-bound plan only after an explicit confirmation."""
        if confirm is not True:
            raise ControlError("CONFIRMATION_REQUIRED", "set confirm=true to authorize the listed Cargo outputs")
        if not isinstance(plan_id, str) or not plan_id:
            raise ControlError("INVALID_PLAN", "plan_id must be a non-empty storage plan identifier")
        with self._lock:
            plan = self._plans.get(plan_id)
            if plan is None:
                raise ControlError("PLAN_NOT_FOUND", "storage plan is absent, already used, or expired")
            expires, selected = plan
            if time.monotonic() >= expires:
                self._plans.pop(plan_id, None)
                raise ControlError("PLAN_EXPIRED", "create a fresh storage plan before reclaiming")

        if not selected:
            with self._lock:
                self._plans.pop(plan_id, None)
            return {
                "plan_id": plan_id,
                "reclaimed": [],
                "allocated_bytes_removed": 0,
                "available_bytes_delta": 0,
            }

        # Validate every entry before the first deletion so a stale plan is all-or-nothing.
        processes = self._process_snapshot()
        if processes.incomplete:
            raise ControlError("PROCESS_SCAN_INCOMPLETE", "cannot prove that workspace build outputs are idle")
        repo_cache: dict[Path, _RepositoryState] = {}
        for stored in selected:
            path = self._absolute(stored["path"])
            discovered = self._cargo_root(path)
            if discovered is not None:
                discovered["relative"] = self.policy.relative(path)
            current = self._assess(discovered, processes, repo_cache, []) if discovered else None
            if current is None or current["reasons"]:
                raise ControlError(
                    "PLAN_STALE",
                    "a planned Cargo output is no longer proven safe; create a fresh plan",
                    details={"path": stored["path"], "reasons": current["reasons"] if current else ["path_missing_or_unrecognized"]},
                )
            if any(
                current[key] != stored[key]
                for key in ("bytes", "repo_root", "branch", "head", "manifest_sha256", "device", "inode", "mtime_ns")
            ):
                raise ControlError(
                    "PLAN_STALE",
                    "a planned Cargo output changed after inspection; create a fresh plan",
                    details={"path": stored["path"]},
                )

        before_free = self._available_bytes()
        removed: list[dict[str, object]] = []
        allocated_bytes = 0
        for stored in selected:
            # Recheck process references immediately before each destructive operation.
            latest_processes = self._process_snapshot()
            if latest_processes.incomplete:
                raise ControlError("PROCESS_SCAN_INCOMPLETE", "process inspection became incomplete during reclaim")
            path = self._absolute(stored["path"])
            repo_root = str(self.root / stored["repo_root"]) if stored["repo_root"] not in {".", None} else str(self.root)
            process_use = self._process_references(path, repo_root, latest_processes)
            if process_use is not False:
                raise ControlError("ARTIFACT_IN_USE_OR_UNKNOWN", "process use could not be ruled out for a planned Cargo output")
            self._cargo_clean(Path(repo_root), path)
            if path.exists():
                raise ControlError(
                    "CARGO_CLEAN_INCOMPLETE",
                    "Cargo clean returned successfully but the target directory remains; inspect it before retrying",
                    details={"path": stored["path"]},
                )
            allocated_bytes += int(stored["bytes"])
            removed.append({"path": stored["path"], "allocated_bytes_removed": stored["bytes"]})

        after_free = self._available_bytes()
        with self._lock:
            self._plans.pop(plan_id, None)
        return {
            "plan_id": plan_id,
            "reclaimed": removed,
            "allocated_bytes_removed": allocated_bytes,
            "available_bytes_delta": max(0, after_free - before_free),
            "measurement_note": "du allocated bytes can differ from freed filesystem bytes due to compression and shared extents",
        }

    def _discover_roots(self) -> tuple[list[dict[str, Any]], bool, list[str]]:
        found: list[dict[str, Any]] = []
        errors: list[str] = []
        visited = 0
        truncated = False

        def on_error(error: OSError) -> None:
            errors.append(self.policy.relative(Path(error.filename or self.root)))

        for current, directories, _files in os.walk(self.root, topdown=True, followlinks=False, onerror=on_error):
            current_path = Path(current)
            visited += 1 + len(directories)
            if visited > _MAX_WALK_ENTRIES:
                truncated = True
                break
            kept_directories = []
            for name in directories:
                child = current_path / name
                if name in _SKIP_DIRS or child.is_symlink():
                    continue
                if os.path.ismount(child):
                    errors.append(self.policy.relative(child))
                    continue
                kept_directories.append(name)
            directories[:] = sorted(kept_directories, key=str.casefold)
            candidate = self._cargo_root(current_path)
            if candidate is not None:
                found.append({"path": current_path, "kind": _CARGO_TARGET_KIND})
                directories[:] = []
                continue
            if current_path.name == "target":
                found.append({"path": current_path, "kind": "unrecognized-target"})
                directories[:] = []
                continue
            kind = _CATEGORIES.get(current_path.name)
            if kind:
                found.append({"path": current_path, "kind": kind})
                directories[:] = []
                continue
            if current_path.name == "debug":
                found.append({"path": current_path, "kind": "debug-directory-unknown"})
                directories[:] = []
        if truncated:
            errors.append("directory_entry_limit_exceeded")
        if len(found) > _MAX_CANDIDATES:
            errors.append("classified_root_limit_exceeded")
        found = found[:_MAX_CANDIDATES]
        normalized = [
            {"path": path["path"], "relative": self.policy.relative(path["path"]), "kind": path["kind"]}
            for path in found
        ]
        return normalized, not errors, errors

    def _cargo_root(self, path: Path) -> dict[str, Any] | None:
        if not path.is_dir() or path.is_symlink() or not (path / ".rustc_info.json").is_file():
            return None
        if not self._has_cargo_cache_marker(path):
            return None
        if not any((path / profile / ".fingerprint").is_dir() for profile in ("debug", "release")):
            return None
        return {"path": path, "kind": _CARGO_TARGET_KIND}

    @staticmethod
    def _has_cargo_cache_marker(path: Path) -> bool:
        marker = path / "CACHEDIR.TAG"
        descriptor = None
        try:
            descriptor = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return False
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                return stream.read(len(_CACHEDIR_TAG_SIGNATURE)) == _CACHEDIR_TAG_SIGNATURE
        except OSError:
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _cargo_clean(repo_root: Path, target: Path) -> None:
        manifest = repo_root / "Cargo.toml"
        if not manifest.is_file() or manifest.is_symlink():
            raise ControlError("CARGO_MANIFEST_UNAVAILABLE", "Cargo manifest is missing or unsafe")
        try:
            completed = subprocess.run(
                [
                    "cargo",
                    "clean",
                    "--manifest-path",
                    str(manifest),
                    "--target-dir",
                    str(target),
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=600,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ControlError("CARGO_CLEAN_FAILED", type(exc).__name__) from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[-2000:]
            raise ControlError("CARGO_CLEAN_FAILED", detail or "cargo clean failed")

    def _measure_paths(self, paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self._du, item["path"]) for item in paths]
            measured = []
            for item, future in zip(paths, futures, strict=True):
                size, complete, error = future.result()
                measured.append(
                    {
                        "path": item["relative"],
                        "kind": item["kind"],
                        "bytes": size if complete else None,
                        "complete": complete,
                        "measurement_error": error,
                    }
                )
        return measured

    def _du(self, path: Path) -> tuple[int, bool, str | None]:
        try:
            completed = subprocess.run(
                ["du", "-sx", "--block-size=1", "--", str(path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=120,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 0, False, type(exc).__name__
        output = completed.stdout.splitlines()
        try:
            size = int(output[0].split("\t", 1)[0])
        except (IndexError, ValueError):
            return 0, False, "du_output_invalid"
        if completed.returncode != 0 or completed.stderr:
            return size, False, "du_incomplete"
        return size, True, None

    def _top_level_sizes(self) -> tuple[list[dict[str, object]], bool, str | None]:
        try:
            completed = subprocess.run(
                ["du", "-x", "-B1", "--max-depth=1", "--null", str(self.root)],
                capture_output=True,
                check=False,
                timeout=180,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [], False, type(exc).__name__
        rows: list[dict[str, object]] = []
        for item in completed.stdout.split(b"\x00"):
            if not item:
                continue
            try:
                raw_size, raw_path = item.split(b"\t", 1)
                path = Path(os.fsdecode(raw_path))
                relative = "." if path == self.root else self.policy.relative(path)
                rows.append({"path": relative, "bytes": int(raw_size)})
            except (ValueError, OSError, ControlError):
                continue
        complete = completed.returncode == 0 and not completed.stderr
        return rows, complete, None if complete else "top_level_measurement_incomplete"

    def _assess(
        self,
        discovered: dict[str, Any],
        processes: _ProcessSnapshot,
        repo_cache: dict[Path, _RepositoryState],
        scan_errors: list[str],
    ) -> dict[str, Any]:
        path: Path = discovered["path"]
        relative = discovered["relative"]
        size, measured, measurement_error = self._du(path)
        reasons: list[str] = []
        if not measured:
            reasons.append(measurement_error or "measurement_incomplete")
        if any(error == "directory_entry_limit_exceeded" or relative.startswith(error.rstrip("/") + "/") or relative == error for error in scan_errors):
            reasons.append("inventory_incomplete_for_path")
        manifest = self._manifest(path)
        reasons.extend(manifest.unsafe_reasons)
        repo = self._repository_state(path.parent, repo_cache)
        if repo is None or not repo.complete:
            reasons.append("repository_state_unknown")
        else:
            manifest_path = repo.root / "Cargo.toml"
            if not manifest_path.is_file() or manifest_path.is_symlink():
                reasons.append("cargo_manifest_unavailable")
            if not repo.clean:
                reasons.append("repository_has_uncommitted_work")
            if repo.default_branch is None:
                reasons.append("default_branch_unknown")
            elif repo.branch != repo.default_branch:
                reasons.append("not_on_default_branch")
            if repo.worktree_count != 1:
                reasons.append("repository_has_multiple_worktrees")
            target_rel = path.relative_to(repo.root).as_posix()
            tracked = self._git(repo.root, "ls-files", "--", target_rel)
            if tracked is None or tracked[0] != 0:
                reasons.append("tracked_file_check_unknown")
            elif tracked[1].strip():
                reasons.append("contains_tracked_files")
        if processes.incomplete:
            reasons.append("process_scan_incomplete")
        else:
            process_use = self._process_references(path, str(repo.root) if repo else None, processes)
            if process_use is True:
                reasons.append("referenced_by_running_process")
            elif process_use is None:
                reasons.append("process_scan_incomplete")
        reasons = sorted(set(reasons))
        unknown_reasons = {
            "repository_state_unknown",
            "measurement_incomplete",
            "du_incomplete",
            "process_scan_incomplete",
            "inventory_incomplete_for_path",
            "artifact_tree_unreadable",
            "artifact_entry_limit_exceeded",
            "tracked_file_check_unknown",
            "default_branch_unknown",
            "cargo_manifest_unavailable",
            "cargo_cache_marker_missing_or_invalid",
        }
        protected_reasons = {
            "repository_has_uncommitted_work",
            "not_on_default_branch",
            "repository_has_multiple_worktrees",
            "contains_tracked_files",
            "referenced_by_running_process",
            "contains_symlink",
            "contains_special_file",
            "contains_mountpoint",
            "contains_hardlink_outside_tree",
            "target_is_mountpoint",
        }
        if not reasons:
            state = "reclaimable"
        elif protected_reasons.intersection(reasons):
            state = "protected"
        elif unknown_reasons.intersection(reasons):
            state = "unknown"
        else:
            state = "protected"
        return {
            "path": relative,
            "kind": _CARGO_TARGET_KIND,
            "reconstructability": "known",
            "bytes": size if measured else None,
            "state": state,
            "reasons": reasons,
            "repo_root": self.policy.relative(repo.root) if repo else None,
            "branch": repo.branch if repo else None,
            "head": repo.head if repo else None,
            "manifest_sha256": manifest.digest,
            "manifest_entries": manifest.entries,
            "device": path.stat().st_dev if path.exists() else None,
            "inode": path.stat().st_ino if path.exists() else None,
            "mtime_ns": path.stat().st_mtime_ns if path.exists() else None,
        }

    def _manifest(self, root: Path) -> _TreeManifest:
        digest = hashlib.sha256()
        entries = 0
        logical_bytes = 0
        reasons: set[str] = set()
        hardlinks: dict[tuple[int, int], tuple[int, int]] = {}
        if os.path.ismount(root):
            return _TreeManifest(digest.hexdigest(), entries, logical_bytes, ("target_is_mountpoint",))
        if not self._has_cargo_cache_marker(root):
            reasons.add("cargo_cache_marker_missing_or_invalid")

        def on_error(_error: OSError) -> None:
            reasons.add("artifact_tree_unreadable")

        for current, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=on_error):
            current_path = Path(current)
            directories[:] = sorted(directories, key=str.casefold)
            for name in [*directories, *sorted(files, key=str.casefold)]:
                child = current_path / name
                try:
                    info = child.lstat()
                except OSError:
                    reasons.add("artifact_tree_unreadable")
                    continue
                if stat.S_ISLNK(info.st_mode):
                    reasons.add("contains_symlink")
                    if name in directories:
                        directories.remove(name)
                elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    reasons.add("contains_special_file")
                if info.st_nlink > 1 and stat.S_ISREG(info.st_mode):
                    key = (info.st_dev, info.st_ino)
                    seen, expected = hardlinks.get(key, (0, info.st_nlink))
                    hardlinks[key] = (seen + 1, expected)
                if os.path.ismount(child):
                    reasons.add("contains_mountpoint")
                    if name in directories:
                        directories.remove(name)
                entries += 1
                logical_bytes += info.st_size
                relative = child.relative_to(root).as_posix().encode("utf-8", errors="surrogateescape")
                digest.update(relative)
                digest.update(b"\x00")
                digest.update(
                    f"{info.st_mode}:{info.st_dev}:{info.st_ino}:{info.st_nlink}:{info.st_size}:{info.st_mtime_ns}:{info.st_ctime_ns}".encode()
                )
                digest.update(b"\x00")
                if entries > _MAX_WALK_ENTRIES:
                    reasons.add("artifact_entry_limit_exceeded")
                    return _TreeManifest(digest.hexdigest(), entries, logical_bytes, tuple(sorted(reasons)))
        if any(expected > seen for seen, expected in hardlinks.values()):
            reasons.add("contains_hardlink_outside_tree")
        return _TreeManifest(digest.hexdigest(), entries, logical_bytes, tuple(sorted(reasons)))

    def _repository_state(
        self, start: Path, cache: dict[Path, _RepositoryState]
    ) -> _RepositoryState | None:
        result = self._git(start, "rev-parse", "--show-toplevel")
        if result is None or result[0] != 0:
            return None
        try:
            root = Path(result[1].strip()).resolve()
        except OSError:
            return None
        if root in cache:
            return cache[root]
        branch_result = self._git(root, "branch", "--show-current")
        head_result = self._git(root, "rev-parse", "HEAD")
        status_result = self._git(root, "status", "--porcelain=v1", "--untracked-files=normal")
        worktrees_result = self._git(root, "worktree", "list", "--porcelain")
        origin_head = self._git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
        branches = self._git(root, "branch", "--list", "main", "master")
        complete = all(
            item is not None and item[0] == 0
            for item in (branch_result, head_result, status_result, worktrees_result)
        )
        if not complete:
            state = _RepositoryState(root, None, None, None, False, 0, False)
            cache[root] = state
            return state
        branch = branch_result[1].strip() or None
        if origin_head is not None and origin_head[0] == 0:
            default_branch = origin_head[1].strip().removeprefix("origin/")
        else:
            branch_names = set(branches[1].split()) if branches and branches[0] == 0 else set()
            default_branch = "main" if "main" in branch_names else "master" if "master" in branch_names else None
        worktree_count = sum(1 for line in worktrees_result[1].splitlines() if line.startswith("worktree "))
        state = _RepositoryState(
            root=root,
            branch=branch,
            default_branch=default_branch,
            head=head_result[1].strip(),
            clean=not status_result[1].strip(),
            worktree_count=worktree_count,
            complete=True,
        )
        cache[root] = state
        return state

    def _git(self, root: Path, *args: str) -> tuple[int, str] | None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                check=False,
                text=True,
                timeout=20,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return completed.returncode, completed.stdout

    def _process_snapshot(self) -> _ProcessSnapshot:
        proc_root = Path("/proc")
        uid = os.getuid()
        processes: list[_Process] = []
        unreadable = 0
        try:
            entries = list(os.scandir(proc_root))
        except OSError:
            return _ProcessSnapshot((), True, 1)
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            process_root = proc_root / entry.name
            try:
                if entry.stat(follow_symlinks=False).st_uid != uid:
                    continue
                cmdline = (process_root / "cmdline").read_bytes()
                argv = tuple(os.fsdecode(item) for item in cmdline.split(b"\x00") if item)
                if not argv:
                    continue
            except FileNotFoundError:
                continue
            except OSError:
                unreadable += 1
                continue
            references: set[str] = set()
            cwd: str | None = None
            for name in ("cwd", "exe"):
                try:
                    value = os.readlink(process_root / name)
                    references.add(value.removesuffix(" (deleted)"))
                    if name == "cwd":
                        cwd = value.removesuffix(" (deleted)")
                except FileNotFoundError:
                    pass
                except OSError:
                    # File handles and mappings are checked with lsof per candidate below.
                    pass
            try:
                environment = (process_root / "environ").read_bytes()
                argv_text = " ".join(argv)
                env_text = os.fsdecode(environment.replace(b"\x00", b" "))
            except FileNotFoundError:
                argv_text, env_text = " ".join(argv), ""
            except OSError:
                argv_text, env_text = " ".join(argv), ""
            name = Path(argv[0]).name.lower()
            build_context = name in _BUILD_TOOLS or any(
                token in {"test", "tests", "check", "build", "compile"}
                or token.endswith(("pytest", "unittest"))
                for arg in argv[1:]
                for token in Path(arg).parts
            )
            if build_context and cwd is None:
                unreadable += 1
            # Keep the command/environment only long enough to detect a direct target reference.
            references.add("\n" + argv_text + "\n" + env_text)
            processes.append(_Process(pid, argv, cwd, tuple(references), build_context))
        return _ProcessSnapshot(tuple(processes), unreadable > 0, unreadable)

    def _process_references(
        self, target: Path, repo_root: str | None, snapshot: _ProcessSnapshot
    ) -> bool | None:
        target = target.resolve()
        target_text = str(target)
        target_workspace = "/workspace/" + target.relative_to(self.root).as_posix() if target.is_relative_to(self.root) else None
        repo = Path(repo_root).resolve() if repo_root else None
        for process in snapshot.processes:
            for reference in process.references:
                if target_text in reference or (target_workspace and target_workspace in reference):
                    return True
                clean = reference.strip().removesuffix(" (deleted)")
                if clean.startswith("/workspace/"):
                    clean = str(self.root / clean.removeprefix("/workspace/"))
                try:
                    resolved = Path(clean).resolve(strict=False)
                except OSError:
                    continue
                if resolved == target or target in resolved.parents:
                    return True
            if process.build_context and process.cwd and repo:
                cwd = process.cwd
                if cwd.startswith("/workspace/"):
                    cwd = str(self.root / cwd.removeprefix("/workspace/"))
                try:
                    if Path(cwd).resolve(strict=False).is_relative_to(repo):
                        return True
                except OSError:
                    pass
        return self._open_target_handles(target)

    @staticmethod
    def _open_target_handles(target: Path) -> bool | None:
        """Check open descriptors, mapped files, and working directories below a target."""
        try:
            completed = subprocess.run(
                ["lsof", "-nP", "-t", "+D", str(target)],
                capture_output=True,
                check=False,
                text=True,
                timeout=60,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if completed.stderr.strip():
            return None
        if completed.returncode == 0:
            return bool(completed.stdout.strip())
        if completed.returncode == 1 and not completed.stdout.strip():
            return False
        return None

    def _absolute(self, relative: str) -> Path:
        target = self.policy.resolve(relative, must_exist=True, expect="directory")
        if target.is_symlink():
            raise ControlError("UNSAFE_PATH", "Cargo output path must not be a symbolic link")
        return target

    def _available_bytes(self) -> int:
        info = os.statvfs(self.root)
        return info.f_bavail * info.f_frsize

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .config import ControlConfig
from .errors import ControlError
from .sandbox import Sandbox, SandboxResult
from .workspace import WorkspacePolicy

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class GitService:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy, sandbox: Sandbox) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox

    def _repository(self, repository: str) -> tuple[Path, str, str]:
        root = self.policy.resolve(repository, must_exist=True, expect="directory")
        if not ((root / ".git").is_dir() or (root / ".git").is_file()):
            raise ControlError("NOT_GIT_REPOSITORY", f"not a Git repository: {repository}")
        relative = root.relative_to(self.policy.root)
        if not relative.parts:
            raise ControlError("INVALID_REPOSITORY", "workspace root is not a repository target")
        project = relative.parts[0]
        cwd = Path(*relative.parts[1:]).as_posix() if len(relative.parts) > 1 else "."
        self.policy.project_path(project)
        return root, project, cwd

    def _run(
        self,
        repository: str,
        arguments: list[str],
        *,
        network: bool = False,
        allow_failure: bool = False,
    ) -> SandboxResult:
        _, project, cwd = self._repository(repository)
        command = shlex.join(["git", "--no-pager", *arguments])
        result = self.sandbox.run(
            command,
            scope="project",
            project=project,
            cwd=cwd,
            timeout_seconds=self.config.default_timeout_seconds,
            network=network,
            use_ssh_agent=network,
        )
        if result.exit_code != 0 and not allow_failure:
            raise ControlError(
                "GIT_FAILED",
                result.stderr.strip() or result.stdout.strip() or "Git command failed",
                details={"exit_code": result.exit_code, "timed_out": result.timed_out},
            )
        return result

    @staticmethod
    def _output(result: SandboxResult) -> dict[str, object]:
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "output_truncated": result.output_truncated,
            "duration_seconds": round(result.duration_seconds, 3),
            "sandbox_backend": result.sandbox_backend,
            "network": result.network,
        }

    @staticmethod
    def _ref(value: str, field: str = "revision") -> str:
        if not isinstance(value, str) or not _REF.fullmatch(value) or value.startswith("-"):
            raise ControlError("INVALID_GIT_REF", f"{field} is not a safe Git reference")
        return value

    def status(self, repository: str) -> dict[str, object]:
        result = self._run(repository, ["status", "--porcelain=v1", "--branch", "--untracked-files=all"])
        lines = result.stdout.splitlines()
        header = lines[0] if lines and lines[0].startswith("## ") else ""
        changed = [line for line in lines[1:] if len(line) >= 3]
        return {
            "repository": repository,
            "branch_summary": header[3:] if header else None,
            "clean": not changed,
            "changes": [{"status": line[:2], "path": line[3:]} for line in changed],
            **self._output(result),
        }

    def journal_snapshot(
        self,
        repository: str,
        *,
        start: str,
        end: str,
        max_commits: int = 100,
    ) -> dict[str, object]:
        """Return bounded local developmental Git state for the journal projection.

        Remote comparison is deliberately relative to each branch's configured
        upstream. A missing upstream is represented as UNKNOWN rather than
        inferred from an arbitrary remote ref.
        """
        if not 1 <= max_commits <= 500:
            raise ControlError("INVALID_INPUT", "max_commits must be between 1 and 500")
        self._repository(repository)

        def run(args: list[str], *, allow_failure: bool = False) -> SandboxResult:
            return self._run(repository, args, allow_failure=allow_failure)

        head = run(["rev-parse", "--verify", "HEAD"], allow_failure=True).stdout.strip() or None
        branch = run(["symbolic-ref", "--quiet", "--short", "HEAD"], allow_failure=True).stdout.strip() or None
        upstream = run(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], allow_failure=True).stdout.strip() or None
        remotes = run(["remote"], allow_failure=True).stdout.splitlines()
        ahead_behind: dict[str, object] = {"status": "UNKNOWN", "ahead": None, "behind": None}
        if upstream:
            comparison = run(["rev-list", "--left-right", "--count", f"{upstream}...HEAD"], allow_failure=True)
            fields = comparison.stdout.strip().split()
            if comparison.exit_code == 0 and len(fields) == 2 and all(field.isdigit() for field in fields):
                ahead_behind = {"status": "AVAILABLE", "ahead": int(fields[1]), "behind": int(fields[0]), "upstream": upstream}
        elif not remotes:
            ahead_behind["reason"] = "no configured remote or tracking branch"
        else:
            ahead_behind["reason"] = "current branch has no trusted tracking branch"

        branches_result = run(
            ["for-each-ref", "--format=%(refname:short)%x1f%(objectname)%x1f%(upstream:short)%x1f%(HEAD)", "refs/heads"],
            allow_failure=True,
        )
        branches: list[dict[str, object]] = []
        local_only: dict[str, dict[str, object]] = {}
        local_only_commits: set[str] = set()
        for line in branches_result.stdout.splitlines():
            fields = line.split("\x1f", 3)
            if len(fields) != 4:
                continue
            name, commit, tracking, current = fields
            row: dict[str, object] = {
                "name": name,
                "head": commit,
                "upstream": tracking or None,
                "current": current == "*",
                "comparison": "UNKNOWN" if not tracking else "AVAILABLE",
            }
            if tracking:
                count = run(["rev-list", "--count", f"{tracking}..{name}"], allow_failure=True)
                if count.exit_code == 0 and count.stdout.strip().isdigit():
                    count_value = int(count.stdout.strip())
                    row["local_only_commit_count"] = count_value
                    row["comparison"] = "AVAILABLE"
                    if count_value:
                        local_only[name] = row
                        local_log = run(
                            [
                                "log",
                                f"{tracking}..{name}",
                                f"--since={start}",
                                f"--until={end}",
                                f"--max-count={max_commits}",
                                "--format=%H",
                            ],
                            allow_failure=True,
                        )
                        local_only_commits.update(
                            item.strip() for item in local_log.stdout.splitlines() if re.fullmatch(r"[0-9a-f]{40}", item.strip())
                        )
            branches.append(row)

        commit_result = run(
            [
                "log",
                "--all",
                f"--since={start}",
                f"--until={end}",
                f"--max-count={max_commits}",
                "--date=iso-strict",
                "--format=%H%x1f%ad%x1f%an%x1f%s",
                "--name-status",
            ],
            allow_failure=True,
        )
        commits: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        for line in commit_result.stdout.splitlines():
            if "\x1f" in line:
                fields = line.split("\x1f", 3)
                if len(fields) == 4:
                    current = {"commit": fields[0], "occurred_at": fields[1], "author": fields[2], "subject": fields[3], "files": []}
                    commits.append(current)
            elif current is not None and line.strip():
                status, _, path = line.partition("\t")
                safe_path = path.strip()
                if safe_path and len(current["files"]) < 40:  # type: ignore[arg-type]
                    current["files"].append({"status": status[:2], "path": safe_path})  # type: ignore[union-attr]
        seen: set[str] = set()
        deduped: list[dict[str, object]] = []
        for item in commits:
            commit_id = str(item["commit"])
            if commit_id not in seen:
                seen.add(commit_id)
                item["local_only"] = commit_id in local_only_commits
                deduped.append(item)
        return {
            "repository": repository,
            "head": head,
            "branch": branch,
            "tracking_remote": upstream,
            "ahead_behind": ahead_behind,
            "branches": branches,
            "local_only_branches": list(local_only.values()),
            "commits": deduped,
            "remote_names": [name.strip() for name in remotes if name.strip()][:20],
        }

    def diff(
        self,
        repository: str,
        *,
        staged: bool = False,
        path: str | None = None,
        context_lines: int = 3,
    ) -> dict[str, object]:
        if context_lines < 0 or context_lines > 100:
            raise ControlError("INVALID_INPUT", "context_lines must be between 0 and 100")
        args = ["diff", f"--unified={context_lines}"]
        if staged:
            args.append("--cached")
        if path is not None:
            self._repo_path(repository, path, must_exist=False)
            args.extend(("--", path))
        result = self._run(repository, args)
        return {"repository": repository, "staged": staged, "diff": result.stdout, **self._output(result)}

    def log(self, repository: str, *, limit: int = 20, revision: str = "HEAD") -> dict[str, object]:
        if limit < 1 or limit > 200:
            raise ControlError("INVALID_INPUT", "limit must be between 1 and 200")
        revision = self._ref(revision)
        result = self._run(
            repository,
            ["log", f"-{limit}", "--date=iso-strict", "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%ad%x1f%s", revision],
        )
        commits = []
        for line in result.stdout.splitlines():
            fields = line.split("\x1f", 5)
            if len(fields) == 6:
                commits.append(
                    dict(
                        zip(
                            ("hash", "short_hash", "author", "email", "date", "subject"),
                            fields,
                            strict=True,
                        )
                    )
                )
        return {"repository": repository, "commits": commits, **self._output(result)}

    def show(self, repository: str, revision: str = "HEAD", *, stat_only: bool = False) -> dict[str, object]:
        revision = self._ref(revision)
        args = ["show", "--format=fuller", "--stat" if stat_only else "--patch", revision]
        result = self._run(repository, args)
        return {"repository": repository, "revision": revision, "content": result.stdout, **self._output(result)}

    def branches(self, repository: str, *, all_branches: bool = True) -> dict[str, object]:
        args = ["branch", "--format=%(refname:short)%09%(objectname:short)%09%(upstream:short)%09%(HEAD)"]
        if all_branches:
            args.append("--all")
        result = self._run(repository, args)
        branches = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) >= 4:
                branches.append({"name": fields[0], "commit": fields[1], "upstream": fields[2] or None, "current": fields[3] == "*"})
        return {"repository": repository, "branches": branches, **self._output(result)}

    def create_branch(self, repository: str, branch: str, *, checkout: bool = True) -> dict[str, object]:
        branch = self._ref(branch, "branch")
        self._run(repository, ["check-ref-format", "--branch", branch])
        result = self._run(repository, ["switch", "-c", branch] if checkout else ["branch", branch])
        return {"repository": repository, "branch": branch, "checked_out": checkout, **self._output(result)}

    def checkout(self, repository: str, branch: str) -> dict[str, object]:
        branch = self._ref(branch, "branch")
        result = self._run(repository, ["switch", branch])
        return {"repository": repository, "branch": branch, **self._output(result)}

    def _repo_path(self, repository: str, value: str, *, must_exist: bool) -> Path:
        repo, _, _ = self._repository(repository)
        relative = self.policy.normalize_relative(value)
        candidate = repo.joinpath(*relative.parts).resolve(strict=False)
        try:
            candidate.relative_to(repo.resolve())
        except ValueError as exc:
            raise ControlError("PATH_ESCAPE", "Git path escapes repository") from exc
        if must_exist and not candidate.exists():
            raise ControlError("PATH_NOT_FOUND", f"Git path does not exist: {value}")
        return candidate

    def add(self, repository: str, paths: list[str]) -> dict[str, object]:
        if not paths or len(paths) > 500:
            raise ControlError("INVALID_INPUT", "paths must contain between 1 and 500 entries")
        for path in paths:
            self._repo_path(repository, path, must_exist=False)
        result = self._run(repository, ["add", "--", *paths])
        return {"repository": repository, "paths": paths, **self._output(result)}

    def commit(self, repository: str, message: str, *, allow_empty: bool = False) -> dict[str, object]:
        if not isinstance(message, str) or not message.strip() or len(message) > 10000 or "\x00" in message:
            raise ControlError("INVALID_INPUT", "commit message must be non-empty bounded text")
        args = ["commit", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        result = self._run(repository, args)
        head = self._run(repository, ["rev-parse", "HEAD"])
        return {"repository": repository, "commit": head.stdout.strip(), **self._output(result)}

    def fetch(self, repository: str, remote: str = "origin", *, prune: bool = False) -> dict[str, object]:
        if not self.config.git_allow_fetch:
            raise ControlError("GIT_OPERATION_DISABLED", "git fetch is disabled")
        if not _REMOTE.fullmatch(remote):
            raise ControlError("INVALID_INPUT", "remote name is invalid")
        result = self._run(repository, ["fetch", *( ["--prune"] if prune else []), remote], network=True)
        return {"repository": repository, "remote": remote, **self._output(result)}

    def pull(self, repository: str, remote: str = "origin", branch: str | None = None, *, rebase: bool = False) -> dict[str, object]:
        if not self.config.git_allow_pull:
            raise ControlError("GIT_OPERATION_DISABLED", "git pull is disabled")
        if not _REMOTE.fullmatch(remote):
            raise ControlError("INVALID_INPUT", "remote name is invalid")
        args = ["pull", "--rebase" if rebase else "--no-rebase", remote]
        if branch:
            args.append(self._ref(branch, "branch"))
        result = self._run(repository, args, network=True)
        return {"repository": repository, "remote": remote, "branch": branch, **self._output(result)}

    def push(
        self,
        repository: str,
        remote: str = "origin",
        branch: str | None = None,
        *,
        set_upstream: bool = False,
    ) -> dict[str, object]:
        if not self.config.git_allow_push:
            raise ControlError("GIT_OPERATION_DISABLED", "git push is disabled")
        if not _REMOTE.fullmatch(remote):
            raise ControlError("INVALID_INPUT", "remote name is invalid")
        args = ["push"]
        if set_upstream:
            args.append("--set-upstream")
        args.append(remote)
        if branch:
            args.append(self._ref(branch, "branch"))
        result = self._run(repository, args, network=True)
        return {"repository": repository, "remote": remote, "branch": branch, "force": False, **self._output(result)}

    def clone(self, url: str, destination: str, *, branch: str | None = None, depth: int | None = None) -> dict[str, object]:
        if not self.config.git_allow_clone:
            raise ControlError("GIT_OPERATION_DISABLED", "git clone is disabled")
        if not isinstance(url, str) or not url or len(url) > 4096 or "\x00" in url or url.startswith("-"):
            raise ControlError("INVALID_INPUT", "clone URL is invalid")
        target = self.policy.resolve(destination, allow_root=False, mutation=True)
        if target.exists():
            raise ControlError("DESTINATION_EXISTS", "clone destination already exists")
        relative = target.relative_to(self.policy.root).as_posix()
        args = ["git", "clone"]
        if branch:
            args.extend(("--branch", self._ref(branch, "branch")))
        if depth is not None:
            if depth < 1 or depth > 100000:
                raise ControlError("INVALID_INPUT", "depth must be between 1 and 100000")
            args.extend(("--depth", str(depth)))
        args.extend(("--", url, f"/workspace/{relative}"))
        result = self.sandbox.run(
            shlex.join(args),
            scope="workspace",
            project=None,
            cwd=".",
            timeout_seconds=self.config.max_timeout_seconds,
            network=True,
            use_ssh_agent=True,
        )
        if result.exit_code != 0:
            raise ControlError("GIT_FAILED", result.stderr.strip() or "git clone failed")
        return {"url": url, "destination": destination, **self._output(result)}

    def remotes(self, repository: str) -> dict[str, object]:
        result = self._run(repository, ["remote", "-v"])
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3:
                rows.append({"name": fields[0], "url": fields[1], "kind": fields[2].strip("()")})
        return {"repository": repository, "remotes": rows, **self._output(result)}

    def restore(self, repository: str, paths: list[str], *, staged: bool = False) -> dict[str, object]:
        if not paths:
            raise ControlError("INVALID_INPUT", "paths must not be empty")
        for path in paths:
            self._repo_path(repository, path, must_exist=False)
        args = ["restore"]
        if staged:
            args.append("--staged")
        args.extend(("--", *paths))
        result = self._run(repository, args)
        return {"repository": repository, "paths": paths, "staged": staged, **self._output(result)}

    def stash(self, repository: str, message: str | None = None, *, include_untracked: bool = False) -> dict[str, object]:
        args = ["stash", "push"]
        if include_untracked:
            args.append("--include-untracked")
        if message:
            if len(message) > 1000 or "\x00" in message:
                raise ControlError("INVALID_INPUT", "stash message is invalid")
            args.extend(("-m", message))
        result = self._run(repository, args)
        return {"repository": repository, **self._output(result)}

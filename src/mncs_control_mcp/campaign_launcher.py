"""Assemble an isolated compiler campaign workspace.

This is a Control-owned assembly boundary.  It creates fresh repository
administration areas, asks the pinned Control provider checkout to select the
managed worktrees, and optionally delegates entry to the selected Environment
checkout.  It never adopts, resets, cleans, or overwrites an existing source
checkout or campaign root.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.workspace import WorkspacePolicy

SCHEMA = "mncs.control.compiler-campaign/1"
DEFAULT_BRANCH_PREFIX = "campaign"
DEFAULT_SHARED_ENVIRONMENT_STATE = (
    Path.home() / ".local" / "share" / "mncs-environment"
)
MAX_OUTPUT_BYTES = 1024 * 1024


class AssemblyError(ValueError):
    """Raised when a campaign cannot be assembled without ambiguity."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "campaign-assembly-failed",
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostics = diagnostics or {}


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssemblyError(
            f"command did not finish within {timeout_seconds:.1f}s: {' '.join(command)}",
            code="campaign-command-timeout",
            diagnostics={"command": command, "timeout_seconds": timeout_seconds},
        ) from error
    if len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise AssemblyError(
            f"command output exceeded {MAX_OUTPUT_BYTES} bytes: {' '.join(command)}",
            code="campaign-command-output-too-large",
            diagnostics={"command": command, "max_output_bytes": MAX_OUTPUT_BYTES},
        )
    return result


def _git(
    repository: Path,
    arguments: list[str],
    *,
    timeout_seconds: float,
    allow_failure: bool = False,
) -> str:
    result = _run(
        ["git", "--no-pager", "-C", str(repository), *arguments],
        cwd=repository,
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0 and not allow_failure:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise AssemblyError(
            detail,
            code="campaign-git-failed",
            diagnostics={
                "repository": str(repository),
                "arguments": arguments,
                "exit_code": result.returncode,
            },
        )
    return result.stdout.strip()


def _revision(repository: Path, ref: str, *, timeout_seconds: float) -> str:
    value = _git(
        repository,
        ["rev-parse", "--verify", f"{ref}^{{commit}}"],
        timeout_seconds=timeout_seconds,
    )
    if not value:
        raise AssemblyError(
            f"source revision cannot be resolved: {ref} in {repository}",
            code="campaign-source-revision-unavailable",
            diagnostics={"source": str(repository), "source_ref": ref},
        )
    return value


def _relative_ref(source_ref: str) -> str:
    if source_ref.startswith("refs/"):
        return source_ref
    if "/" in source_ref:
        remote, branch = source_ref.split("/", 1)
        return f"refs/remotes/{remote}/{branch}"
    return f"refs/heads/{source_ref}"


def _repository_name(value: object) -> str:
    name = str(value or "")
    path = Path(name)
    if not name or name in {".", ".."} or path.is_absolute() or len(path.parts) != 1:
        raise AssemblyError(
            f"repository names must be one path component: {name!r}",
            code="campaign-invalid-repository-name",
        )
    return name


def _load_definition(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssemblyError(
            f"campaign definition is unreadable: {path}",
            code="campaign-definition-unavailable",
        ) from error
    if not isinstance(payload, dict):
        raise AssemblyError(
            "campaign definition must be a JSON object",
            code="campaign-definition-invalid",
        )
    managed = payload.get("managed_checkouts")
    provider = payload.get("workspace_provider")
    session = payload.get("session_checkout")
    if not isinstance(managed, list) or not managed:
        raise AssemblyError(
            "campaign definition needs a non-empty managed_checkouts list",
            code="campaign-definition-invalid",
        )
    if not isinstance(provider, dict) or not isinstance(session, dict):
        raise AssemblyError(
            "campaign definition needs workspace_provider and session_checkout",
            code="campaign-definition-invalid",
        )
    if not isinstance(provider.get("revision"), str) or not provider["revision"]:
        raise AssemblyError(
            "campaign workspace_provider must declare a pinned revision",
            code="campaign-definition-invalid",
        )
    return payload


def _required_sources(definition: dict[str, Any]) -> list[str]:
    required: list[str] = []
    for item in definition["managed_checkouts"]:
        if not isinstance(item, dict):
            raise AssemblyError(
                "managed_checkouts entries must be objects",
                code="campaign-definition-invalid",
            )
        name = _repository_name(item.get("repository"))
        if name not in required:
            required.append(name)
    for section in (definition["workspace_provider"], definition["session_checkout"]):
        name = _repository_name(section.get("repository"))
        if name not in required:
            required.append(name)
    return required


def _parse_sources(raw_sources: list[str]) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for raw in raw_sources:
        if "=" not in raw:
            raise AssemblyError(
                f"--source must use REPOSITORY=PATH: {raw!r}",
                code="campaign-source-invalid",
            )
        name_raw, path_raw = raw.split("=", 1)
        name = _repository_name(name_raw)
        if name in sources:
            raise AssemblyError(
                f"source supplied more than once for {name}",
                code="campaign-source-duplicate",
            )
        path = Path(path_raw).expanduser()
        if path.is_symlink() or not path.is_dir():
            raise AssemblyError(
                f"source checkout is not a real directory: {path}",
                code="campaign-source-invalid",
                diagnostics={"repository": name, "source": str(path)},
            )
        resolved = path.resolve()
        if not (resolved / ".git").is_dir() and not (resolved / ".git").is_file():
            raise AssemblyError(
                f"source is not a Git checkout: {resolved}",
                code="campaign-source-not-git",
                diagnostics={"repository": name, "source": str(resolved)},
            )
        sources[name] = resolved
    return sources


def _validate_boundaries(
    workspace_root: Path,
    state_dir: Path,
    sources: dict[str, Path],
) -> tuple[Path, Path]:
    root = workspace_root.expanduser()
    if root.is_symlink():
        raise AssemblyError(
            f"campaign workspace root must not be a symbolic link: {root}",
            code="campaign-workspace-invalid",
        )
    root = root.resolve()
    if root.exists() and not root.is_dir():
        raise AssemblyError(
            f"campaign workspace root is not a directory: {root}",
            code="campaign-workspace-invalid",
        )
    if root.exists() and any(root.iterdir()):
        raise AssemblyError(
            f"campaign workspace root must be new or empty: {root}",
            code="campaign-workspace-not-empty",
            diagnostics={"next": "choose a fresh isolated campaign root"},
        )
    for repository, source in sources.items():
        if root == source or root.is_relative_to(source) or source.is_relative_to(root):
            raise AssemblyError(
                f"campaign root and source checkout overlap for {repository}; refusing collision",
                code="campaign-boundary-overlap",
                diagnostics={"repository": repository, "source": str(source), "root": str(root)},
            )

    state = state_dir.expanduser()
    if state.is_symlink():
        raise AssemblyError(
            f"campaign state directory must not be a symbolic link: {state}",
            code="campaign-state-invalid",
        )
    state = state.resolve()
    shared = DEFAULT_SHARED_ENVIRONMENT_STATE.expanduser().resolve()
    if state == shared or state.is_relative_to(shared):
        raise AssemblyError(
            f"shared Environment state is not allowed for campaign assembly: {state}",
            code="campaign-shared-state-forbidden",
            diagnostics={"next": "pass a unique temporary --state-dir"},
        )
    if state == root or state.is_relative_to(root):
        raise AssemblyError(
            "campaign state must be outside the assembled workspace root",
            code="campaign-state-overlap",
        )
    for repository, source in sources.items():
        if state == source or state.is_relative_to(source):
            raise AssemblyError(
                f"campaign state overlaps source checkout for {repository}",
                code="campaign-boundary-overlap",
            )
    if state.exists() and not state.is_dir():
        raise AssemblyError(
            f"campaign state path is not a directory: {state}",
            code="campaign-state-invalid",
        )
    if state.exists() and any(state.iterdir()):
        raise AssemblyError(
            f"campaign state directory must be new or empty: {state}",
            code="campaign-state-not-empty",
            diagnostics={"next": "choose a fresh isolated state directory"},
        )
    return root, state


def _initialize_repository(
    destination: Path,
    source: Path,
    refs: list[tuple[str, str]],
    *,
    timeout_seconds: float,
) -> dict[str, str]:
    """Create a no-branch local repository containing only requested objects."""
    destination.mkdir(parents=True, exist_ok=False)
    _git(destination, ["init", "-q", "-b", "main"], timeout_seconds=timeout_seconds)
    _git(destination, ["remote", "add", "source", str(source)], timeout_seconds=timeout_seconds)
    source_heads: dict[str, str] = {}
    for target_ref, source_ref in refs:
        source_head = _revision(source, source_ref, timeout_seconds=timeout_seconds)
        _git(
            destination,
            ["fetch", "-q", "--no-tags", "source", source_head],
            timeout_seconds=timeout_seconds,
        )
        _git(
            destination,
            ["update-ref", target_ref, source_head],
            timeout_seconds=timeout_seconds,
        )
        source_heads[target_ref] = source_head
    _git(destination, ["remote", "remove", "source"], timeout_seconds=timeout_seconds)
    return source_heads


def _checkout_facts(
    root: Path,
    repository: str,
    checkout: Path,
    *,
    source_ref: str,
    authoritative_head: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    head = _revision(checkout, "HEAD", timeout_seconds=timeout_seconds)
    branch = _git(
        checkout,
        ["branch", "--show-current"],
        timeout_seconds=timeout_seconds,
        allow_failure=True,
    ) or None
    status = _git(
        checkout,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        timeout_seconds=timeout_seconds,
    )
    relative = checkout.resolve().relative_to(root.resolve()).as_posix()
    return {
        "repository": repository,
        "path": relative,
        "branch": branch,
        "head": head,
        "clean": not bool(status),
        "source_ref": source_ref,
        "authoritative_head": authoritative_head,
    }


def _slug(checkout: object, *, field: str) -> str:
    raw = str(checkout or "")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise AssemblyError(
            f"{field} must be a repository-relative checkout path",
            code="campaign-definition-invalid",
        )
    if len(path.parts) < 2 or path.parts[-2] != ".worktrees":
        raise AssemblyError(
            f"{field} must be nested under .worktrees",
            code="campaign-definition-invalid",
        )
    return path.parts[-1]


def _provider_prepare(
    *,
    provider_checkout: Path,
    workspace_root: Path,
    requests: list[dict[str, Any]],
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    script = provider_checkout / "src" / "mncs_control_mcp" / "worktree_cli.py"
    if not script.is_file():
        raise AssemblyError(
            f"pinned Control checkout does not contain its worktree provider: {script}",
            code="campaign-provider-unavailable",
        )
    result = _run(
        [
            sys.executable,
            str(script),
            "prepare",
            "--workspace-root",
            str(workspace_root),
            "--requests-json",
            json.dumps(requests, separators=(",", ":")),
        ],
        cwd=provider_checkout,
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        raise AssemblyError(
            "pinned Control provider could not prepare campaign worktrees",
            code="campaign-provider-failed",
            diagnostics={
                "exit_code": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            },
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssemblyError(
            "pinned Control provider returned invalid JSON",
            code="campaign-provider-invalid-response",
            diagnostics={"stdout": result.stdout[-4000:]},
        ) from error
    selected = payload.get("selected_checkouts") if isinstance(payload, dict) else None
    if not isinstance(selected, list):
        raise AssemblyError(
            "pinned Control provider response has no selected_checkouts array",
            code="campaign-provider-invalid-response",
        )
    return [item for item in selected if isinstance(item, dict)]


def assemble(
    *,
    definition_path: Path,
    workspace_root: Path,
    state_dir: Path,
    sources: dict[str, Path],
    enter: bool = False,
    consumer: str = "compiler-campaign-agent",
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    definition = _load_definition(definition_path.expanduser().resolve())
    required = _required_sources(definition)
    missing = sorted(set(required) - set(sources))
    extra = sorted(set(sources) - set(required))
    if missing or extra:
        raise AssemblyError(
            "explicit source checkouts must match the campaign closure",
            code="campaign-source-closure-invalid",
            diagnostics={"missing": missing, "extra": extra, "required": required},
        )
    root, state = _validate_boundaries(workspace_root, state_dir, sources)
    root.mkdir(parents=True, exist_ok=True)

    provider = definition["workspace_provider"]
    provider_repository = _repository_name(provider.get("repository"))
    provider_revision = str(provider["revision"])
    provider_slug = _slug(provider.get("checkout"), field="workspace_provider.checkout")
    session = definition["session_checkout"]
    session_repository = _repository_name(session.get("repository"))
    session_slug = _slug(session.get("checkout"), field="session_checkout.checkout")

    managed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in definition["managed_checkouts"]:
        name = _repository_name(item.get("repository"))
        if name in seen:
            raise AssemblyError(
                f"managed checkout repeats repository {name}",
                code="campaign-definition-invalid",
            )
        seen.add(name)
        source_ref = str(item.get("source_ref", "origin/main"))
        managed.append({**item, "repository": name, "source_ref": source_ref})

    # Resolve all source revisions before creating the target. This makes a
    # typo or stale source fail without leaving a partial campaign root.
    source_revisions: dict[str, dict[str, str]] = {}
    for item in managed:
        name = item["repository"]
        source_revisions.setdefault(name, {})[item["source_ref"]] = _revision(
            sources[name], item["source_ref"], timeout_seconds=timeout_seconds
        )
    source_revisions.setdefault(provider_repository, {})[provider_revision] = _revision(
        sources[provider_repository], provider_revision, timeout_seconds=timeout_seconds
    )
    source_revisions.setdefault(session_repository, {})["HEAD"] = _revision(
        sources[session_repository], "HEAD", timeout_seconds=timeout_seconds
    )

    bases: dict[str, Path] = {}
    for repository in required:
        refs: list[tuple[str, str]] = []
        for source_ref, source_head in source_revisions.get(repository, {}).items():
            target_ref = _relative_ref(source_ref) if source_ref != "HEAD" else "refs/heads/source-head"
            refs.append((target_ref, source_ref if source_ref != "HEAD" else source_head))
        # A pinned provider revision is fetched by hash, and the session HEAD
        # is fetched by the already-resolved hash. _initialize_repository
        # accepts refs to keep source resolution explicit and bounded.
        if repository == provider_repository:
            refs = [("refs/heads/pinned-provider", provider_revision)]
        if repository == session_repository:
            refs = [("refs/heads/source-head", "HEAD")]
        bases[repository] = root / repository
        _initialize_repository(
            bases[repository], sources[repository], refs, timeout_seconds=timeout_seconds
        )

    config = ControlConfig(
        workspace_root=root,
        require_real_sandbox=False,
        git_allow_fetch=False,
        default_timeout_seconds=timeout_seconds,
    )
    policy = WorkspacePolicy(config)
    git = GitService(config, policy, sandbox=None)  # type: ignore[arg-type]

    provider_head = provider_revision
    provider_branch = str(provider.get("branch") or f"{DEFAULT_BRANCH_PREFIX}/{provider_slug}")
    provider_added = git.worktree_add(
        provider_repository,
        provider_branch,
        provider_slug,
        provider_head,
    )
    provider_checkout = root / str(provider_added["path"])
    provider_fact = _checkout_facts(
        root,
        provider_repository,
        provider_checkout,
        source_ref="session-pinned-provider",
        authoritative_head=provider_revision,
        timeout_seconds=timeout_seconds,
    )
    if provider_fact["head"] != provider_revision or not provider_fact["clean"]:
        raise AssemblyError(
            "pinned Control provider checkout is not the requested clean revision",
            code="campaign-provider-conflict",
            diagnostics={"observed": provider_fact, "expected_revision": provider_revision},
        )

    requests = [
        {
            "repository": item["repository"],
            "name": str(item["name"]),
            "branch": str(item["branch"]),
            "source_ref": item["source_ref"],
        }
        for item in managed
    ]
    selected = _provider_prepare(
        provider_checkout=provider_checkout,
        workspace_root=root,
        requests=requests,
        timeout_seconds=timeout_seconds,
    )
    expected_by_repository = {item["repository"]: item for item in managed}
    selected_checkouts: dict[str, dict[str, Any]] = {}
    for record in selected:
        repository = _repository_name(record.get("repository"))
        expected = expected_by_repository.get(repository)
        if expected is None:
            raise AssemblyError(
                f"Control provider returned an undeclared checkout: {repository}",
                code="campaign-provider-invalid-response",
            )
        expected_path = root / repository / ".worktrees" / str(expected["name"])
        observed_path = (root / str(record.get("path", ""))).resolve()
        if observed_path != expected_path.resolve():
            raise AssemblyError(
                f"Control provider selected an unexpected path for {repository}",
                code="campaign-provider-conflict",
                diagnostics={"expected": str(expected_path), "observed": str(observed_path)},
            )
        expected_head = source_revisions[repository][expected["source_ref"]]
        if record.get("branch") != expected["branch"] or record.get("head") != expected_head:
            raise AssemblyError(
                f"Control provider selected the wrong revision for {repository}",
                code="campaign-provider-conflict",
                diagnostics={"record": record, "expected_head": expected_head},
            )
        if record.get("clean") is not True:
            raise AssemblyError(
                f"Control provider selected a dirty checkout for {repository}",
                code="campaign-provider-conflict",
                diagnostics={"record": record},
            )
        selected_checkouts[repository] = dict(record)

    if set(selected_checkouts) != set(expected_by_repository):
        raise AssemblyError(
            "Control provider did not return every declared managed checkout",
            code="campaign-provider-invalid-response",
            diagnostics={
                "expected": sorted(expected_by_repository),
                "observed": sorted(selected_checkouts),
            },
        )

    session_head = source_revisions[session_repository]["HEAD"]
    session_branch = str(session.get("branch") or f"{DEFAULT_BRANCH_PREFIX}/{session_slug}")
    session_added = git.worktree_add(
        session_repository,
        session_branch,
        session_slug,
        session_head,
    )
    session_checkout = root / str(session_added["path"])
    selected_checkouts[session_repository] = _checkout_facts(
        root,
        session_repository,
        session_checkout,
        source_ref="source:HEAD",
        authoritative_head=session_head,
        timeout_seconds=timeout_seconds,
    )
    selected_checkouts[provider_repository] = provider_fact

    result: dict[str, Any] = {
        "schema_version": SCHEMA,
        "workspace_root": str(root),
        "state_dir": str(state),
        "definition": str(definition_path.expanduser().resolve()),
        "provider": {
            "repository": provider_repository,
            "checkout": provider_fact["path"],
            "revision": provider_revision,
            "branch": provider_fact["branch"],
            "clean": provider_fact["clean"],
        },
        "selected_checkouts": {
            name: selected_checkouts[name] for name in sorted(selected_checkouts)
        },
        "source_revisions": {
            name: dict(revisions) for name, revisions in sorted(source_revisions.items())
        },
        "entry_context": None,
    }

    if enter:
        if state.exists() and any(state.iterdir()):
            raise AssemblyError(
                f"campaign state became non-empty before entry: {state}",
                code="campaign-state-not-empty",
            )
        definition_in_checkout = session_checkout / "examples" / "compiler-campaign" / "environment.json"
        entrypoint = session_checkout / "scripts" / "mncs-env"
        if not definition_in_checkout.is_file() or not entrypoint.is_file():
            raise AssemblyError(
                "selected Environment checkout cannot provide the campaign entrypoint",
                code="campaign-environment-unavailable",
                diagnostics={"definition": str(definition_in_checkout), "entrypoint": str(entrypoint)},
            )
        entered = _run(
            [
                sys.executable,
                str(entrypoint),
                "--persistence",
                "store",
                "--state-dir",
                str(state),
                "enter",
                "--definition",
                str(definition_in_checkout),
                "--workspace",
                str(root),
                "--consumer",
                consumer,
            ],
            cwd=session_checkout,
            timeout_seconds=timeout_seconds,
            env=dict(os.environ),
        )
        if entered.returncode != 0:
            raise AssemblyError(
                "assembled workspace could not enter through mncs-environment",
                code="campaign-environment-entry-failed",
                diagnostics={
                    "exit_code": entered.returncode,
                    "stdout": entered.stdout[-4000:],
                    "stderr": entered.stderr[-4000:],
                },
            )
        try:
            result["entry_context"] = json.loads(entered.stdout)
        except json.JSONDecodeError as error:
            raise AssemblyError(
                "mncs-environment returned invalid entry context JSON",
                code="campaign-environment-invalid-response",
                diagnostics={"stdout": entered.stdout[-4000:]},
            ) from error
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mncs-compiler-campaign",
        description="Assemble an isolated compiler campaign from explicit source checkouts.",
    )
    parser.add_argument("--definition", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument(
        "--state-dir",
        type=Path,
        required=True,
        help="unique campaign state directory; shared Environment state is rejected",
    )
    parser.add_argument(
        "--source",
        action="append",
        required=True,
        metavar="REPOSITORY=PATH",
        help="explicit source checkout; repeat once for every repository in the campaign closure",
    )
    parser.add_argument("--enter", action="store_true", help="enter through the selected Environment checkout")
    parser.add_argument("--consumer", default="compiler-campaign-agent")
    parser.add_argument("--timeout", type=float, default=120.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        print(json.dumps({"error": "--timeout must be positive"}), file=sys.stderr)
        return 2
    try:
        result = assemble(
            definition_path=args.definition,
            workspace_root=args.workspace_root,
            state_dir=args.state_dir,
            sources=_parse_sources(args.source),
            enter=args.enter,
            consumer=args.consumer,
            timeout_seconds=args.timeout,
        )
    except AssemblyError as error:
        payload: dict[str, Any] = {"error": str(error), "code": error.code}
        if error.diagnostics:
            payload["diagnostics"] = error.diagnostics
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

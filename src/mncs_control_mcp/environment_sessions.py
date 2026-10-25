"""MNCS Environment sessions as first-class control-plane tools.

This service composes the canonical ``mncs_env`` package from the
sibling ``mncs-environment`` checkout instead of reimplementing
sessions, claims, or rights. The package is an optional sibling: when
the checkout (or its Store backend) is unavailable every method
reports ``ENVIRONMENT_UNAVAILABLE`` rather than inventing state.

All session semantics -- tri-state authority, rights gating, claim
ownership, lifecycle -- live in ``mncs-environment``. This module only
adapts them to the control boundary (structured errors, bounded
workspace paths, isolated state directories for tests).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .config import ControlConfig
from .errors import ControlError

PACKAGE = "mncs_env"
ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"
_CAMPAIGN_ID_MAX = 160
_CAMPAIGN_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CAMPAIGN_CHARTER_SCHEMA = "mncs.environment.campaign-charter/1"
_CAMPAIGN_CHARTER_MAX_BYTES = 64 * 1024
_CAMPAIGN_CAPSULE_EVIDENCE_MAX = 32
_CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX = 16
_GIT_OBJECT_ID = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CONTEXT_RESPONSE_SUMMARY_SCHEMA = "mncs.environment.context-response-summary/1"
_CONTEXT_RESPONSE_SCHEMA_VERSION = "mncs.environment.entry-context/1"
_CONTEXT_RESPONSE_UNAVAILABLE_REASONS = frozenset({
    "operation-failed", "stdout-unavailable", "response-too-large",
    "invalid-json", "invalid-context-schema",
})
_CONTEXT_RESPONSE_PARTIAL_REASONS = frozenset({
    "capability-summary-unavailable", "capability-summary-invalid",
})
_CONTINUABLE_LIFECYCLES = frozenset({
    "active", "blocked", "waiting", "checkpointed", "abandoned",
})
_TERMINAL_LIFECYCLES = frozenset({"completed", "failed"})
_FOREIGN_CAMPAIGN_NEXT = (
    "Request an explicit handoff from the recorded owner to resume this campaign. "
    "For independent work, enter with a new campaign_id and task_identity, then "
    "include both selectors on later session-scoped operations."
)
_PACKAGE_LOAD_LOCK = threading.RLock()
_PACKAGE_SOURCE_IDENTITIES: dict[str, tuple[str, str]] = {}


def _valid_context_response_summary(value: Any) -> bool:
    """Validate the bounded Control summary before forwarding it to Environment."""
    expected = {
        "schema_version", "capture_status", "capture_reason",
        "context_schema_version", "available_count", "listed_available_count",
        "unavailable_count", "unknown_count", "capabilities_truncated",
        "available_identity_digest", "identity_digest_status",
    }
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("schema_version") != _CONTEXT_RESPONSE_SUMMARY_SCHEMA):
        return False
    status = value.get("capture_status")
    reason = value.get("capture_reason")
    context_version = value.get("context_schema_version")
    counts = (
        value.get("available_count"), value.get("listed_available_count"),
        value.get("unavailable_count"), value.get("unknown_count"),
    )
    truncated = value.get("capabilities_truncated")
    identity_digest = value.get("available_identity_digest")
    digest_status = value.get("identity_digest_status")
    if status == "unavailable":
        return (
            isinstance(reason, str)
            and reason in _CONTEXT_RESPONSE_UNAVAILABLE_REASONS
            and context_version is None and all(item is None for item in counts)
            and truncated is None and identity_digest is None
            and digest_status == "unavailable"
        )
    if status == "partial":
        return (
            isinstance(reason, str)
            and reason in _CONTEXT_RESPONSE_PARTIAL_REASONS
            and context_version == _CONTEXT_RESPONSE_SCHEMA_VERSION
            and all(item is None for item in counts) and truncated is None
            and identity_digest is None and digest_status == "unavailable"
        )
    if (status != "captured" or reason is not None
            or context_version != _CONTEXT_RESPONSE_SCHEMA_VERSION
            or any(type(item) is not int or not 0 <= item <= 1_000_000
                   for item in counts)
            or type(truncated) is not bool or counts[1] > 20
            or counts[0] < counts[1]
            or (not truncated and counts[0] != counts[1])):
        return False
    if digest_status == "complete":
        return (
            not truncated
            and counts[0] == counts[1]
            and isinstance(identity_digest, str)
            and _SHA256.fullmatch(identity_digest) is not None
        )
    return digest_status == "partial" and identity_digest is None


def _resolve_environment_source_checkout(
    configured_root: Path, authorized_workspace: Path,
) -> Path:
    """Select a clean registered checkout at the repository's local main revision.

    Control commonly runs from a stable workspace path while an agent advances
    Environment in a linked worktree. Loading the stable path unconditionally
    can keep an older branch in service after the fix is already merged. Use
    Git's registered worktree inventory and common-directory identity to find
    the committed ``main`` source without trusting path shape or lookalike
    repositories.
    """
    requested = Path(configured_root).expanduser()
    if not requested.exists():
        return requested
    if requested.is_symlink():
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            "configured mncs-environment checkout must not be a symbolic link",
            details={"path": str(requested)},
        )

    try:
        root = requested.resolve(strict=True)
        workspace = Path(authorized_workspace).expanduser().resolve(strict=True)
    except OSError:
        return requested

    # Some tests and explicitly configured development installs point at a
    # sibling outside their temporary workspace. Preserve that direct source
    # when it is not part of this Control workspace; production repository
    # mappings are direct children and take the verified path below.
    try:
        root.relative_to(workspace)
    except ValueError:
        return root

    if not ((root / ".git").is_dir() or (root / ".git").is_file()):
        return root
    if root.parent != workspace:
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            "configured mncs-environment checkout is not a direct repository in the authorized workspace",
            details={"path": str(root), "workspace": str(workspace)},
        )

    def git(path: Path, *arguments: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(path), *arguments],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ControlError(
                ENVIRONMENT_UNAVAILABLE,
                f"mncs-environment Git identity could not be verified: {exc}",
                details={"path": str(path)},
            ) from exc
        return completed.stdout.strip()

    top_level = Path(git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    common_directory = Path(
        git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    ).resolve(strict=True)
    if top_level != root:
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            "configured mncs-environment path is not its Git repository root",
            details={"path": str(root), "git_top_level": str(top_level)},
        )
    try:
        main_revision = git(root, "rev-parse", "--verify", "refs/heads/main")
    except ControlError as exc:
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            "mncs-environment has no verified local main revision",
            details={"path": str(root)},
        ) from exc

    worktree_output = git(root, "worktree", "list", "--porcelain")
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in (*worktree_output.splitlines(), ""):
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key in {"worktree", "HEAD", "branch"}:
            current[key] = value

    valid: list[tuple[bool, str, Path]] = []
    for entry in entries:
        raw_path = entry.get("worktree")
        if not raw_path or entry.get("HEAD") != main_revision:
            continue
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(workspace)
        except (OSError, ValueError):
            continue
        if candidate.is_symlink() or resolved != candidate or not resolved.is_dir():
            continue
        try:
            candidate_top = Path(
                git(resolved, "rev-parse", "--show-toplevel")
            ).resolve(strict=True)
            candidate_common = Path(
                git(resolved, "rev-parse", "--path-format=absolute", "--git-common-dir")
            ).resolve(strict=True)
            dirty = git(resolved, "status", "--porcelain=v1", "--untracked-files=all")
        except ControlError:
            continue
        if (
            candidate_top != resolved
            or candidate_common != common_directory
            or dirty
            or any(
                package.is_symlink()
                for package in (resolved / "mncs_env", resolved / "src" / "mncs_env")
                if package.exists()
            )
            or not any(
                (resolved / suffix / "__init__.py").is_file()
                for suffix in ("mncs_env", "src/mncs_env")
            )
        ):
            continue
        valid.append((entry.get("branch") == "refs/heads/main", str(resolved), resolved))

    if not valid:
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            "mncs-environment's configured checkout is stale and no clean registered checkout matches local main",
            details={
                "configured_path": str(root),
                "configured_head": git(root, "rev-parse", "HEAD"),
                "main_revision": main_revision,
            },
        )
    valid.sort(key=lambda item: (not item[0], item[1]))
    return valid[0][2]


def _claim_matches_working_checkout(
    claim: dict[str, Any], working_checkout: dict[str, Any], repository: str,
    *, session_id: str | None = None,
) -> bool:
    """Check whether one held worktree claim identifies the exact checkout."""
    scope = claim.get("scope")
    checkout_path = working_checkout.get("path")
    scope_path = scope.get("checkout") if isinstance(scope, dict) else None
    branch = working_checkout.get("branch")
    if (
        claim.get("status") != "held"
        or (session_id is not None
            and isinstance(claim.get("session_id"), str)
            and claim.get("session_id") != session_id)
        or claim.get("repository") != repository
        or not isinstance(scope, dict)
        or scope.get("kind") != "worktree"
        or scope.get("repository", repository) != repository
        or not isinstance(checkout_path, str)
        or not isinstance(scope_path, str)
    ):
        return False

    identity_fields = (
        "checkout_identity", "git_common_directory_identity", "manifest_identity",
    )
    current_identities = {field: working_checkout.get(field) for field in identity_fields}
    recorded_identities = {field: scope.get(field) for field in identity_fields}
    if any(
        isinstance(current_identities[field], str)
        and isinstance(recorded_identities[field], str)
        and current_identities[field] != recorded_identities[field]
        for field in identity_fields
    ):
        return False
    branch_matches = scope.get("branch") == branch
    same_stable_checkout = all(
        isinstance(current_identities[field], str)
        and isinstance(recorded_identities[field], str)
        and current_identities[field] == recorded_identities[field]
        for field in identity_fields
    )
    if not branch_matches and not same_stable_checkout:
        return False
    try:
        current_path = Path(checkout_path)
        claimed_path = Path(scope_path)
        return (
            current_path.is_absolute()
            and claimed_path.is_absolute()
            and current_path.resolve(strict=True) == current_path
            and claimed_path.resolve(strict=True) == claimed_path
            and current_path == claimed_path
        )
    except (OSError, RuntimeError):
        return False


def _package_source_identity(package_root: Path) -> str:
    """Fingerprint Python sources so long-lived Control can see sibling updates."""
    digest = hashlib.sha256()
    try:
        sources = sorted(package_root.rglob("*.py"))
        for path in sources:
            if path.is_symlink():
                raise ControlError(
                    ENVIRONMENT_UNAVAILABLE,
                    "mncs_env source tree cannot contain symbolic links",
                    details={"path": str(path)},
                )
            if not path.is_file():
                continue
            relative = path.relative_to(package_root).as_posix().encode("utf-8")
            source = path.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(source).to_bytes(8, "big"))
            digest.update(source)
    except ControlError:
        raise
    except OSError as exc:
        raise ControlError(
            ENVIRONMENT_UNAVAILABLE,
            f"mncs_env source tree could not be inspected: {exc}",
            details={"path": str(package_root)},
        ) from exc
    return digest.hexdigest()


def _load_flat_package(package: str, root: Path, submodules: tuple[str, ...] = ()) -> Any:
    """Import a sibling package with a flat (repo-root) layout.

    Mirrors ``adapters._load_sibling_package`` for checkouts that keep
    the importable package at the repository root instead of ``src/``.
    Submodules are imported while the checkout is on ``sys.path`` so
    attribute access (``pkg.sessions``) works afterwards.
    """
    candidate = next(
        (path for path in (root / "src", root) if (path / package).is_dir()),
        None,
    )
    if candidate is not None:
        package_root = candidate / package
        source_identity = _package_source_identity(package_root)
        source_key = (str(package_root.resolve()), source_identity)
        with _PACKAGE_LOAD_LOCK:
            if _PACKAGE_SOURCE_IDENTITIES.get(package) != source_key:
                for module_name in tuple(sys.modules):
                    if module_name == package or module_name.startswith(f"{package}."):
                        sys.modules.pop(module_name, None)
                _PACKAGE_SOURCE_IDENTITIES.pop(package, None)

            sys.path.insert(0, str(candidate))
            try:
                importlib.invalidate_caches()
                module = importlib.import_module(package)
                for submodule in submodules:
                    submodule_module = importlib.import_module(f"{package}.{submodule}")
                    setattr(module, submodule, submodule_module)
                if _package_source_identity(package_root) != source_identity:
                    for module_name in tuple(sys.modules):
                        if module_name == package or module_name.startswith(f"{package}."):
                            sys.modules.pop(module_name, None)
                    raise ControlError(
                        ENVIRONMENT_UNAVAILABLE,
                        "mncs_env source changed while loading; retry the operation",
                        details={"path": str(package_root)},
                    )
                _PACKAGE_SOURCE_IDENTITIES[package] = source_key
                return module
            except ImportError as exc:
                for module_name in tuple(sys.modules):
                    if module_name == package or module_name.startswith(f"{package}."):
                        sys.modules.pop(module_name, None)
                raise ControlError(
                    ENVIRONMENT_UNAVAILABLE,
                    f"mncs_env failed to load from {root}: {exc}",
                    details={"path": str(root)},
                ) from exc
            finally:
                try:
                    sys.path.remove(str(candidate))
                except ValueError:
                    pass
    raise ControlError(
        ENVIRONMENT_UNAVAILABLE,
        f"mncs-environment checkout unavailable at {root}",
        details={"path": str(root)},
    )


class EnvironmentService:
    """Thin control boundary over ``mncs_env.sessions`` and claims."""

    def __init__(self, config: ControlConfig) -> None:
        self._config = config
        self.authenticated_principal_id: str | None = None
        self._environment_path_cache: Path | None = None

    @property
    def environment_path(self) -> Path:
        # Environment normally advances in a linked worktree while this
        # Control process stays alive. A one-time path choice can therefore
        # keep old authorization logic active after main has been updated.
        # Resolve against the current local main revision for each operation;
        # the resolver verifies the registered, clean checkout before it is
        # used and this field remains only the last resolved path.
        self._environment_path_cache = _resolve_environment_source_checkout(
            self._config.environment_path, self._config.workspace_root,
        )
        return self._environment_path_cache

    @property
    def rights_provenance_path(self) -> Path:
        return self._config.rights_provenance_path

    @property
    def state_dir(self) -> Path:
        if self._config.environment_state_dir is not None:
            return self._config.environment_state_dir
        return Path.home() / ".local" / "share" / "mncs-environment"

    def _pkg(self) -> Any:
        try:
            return _load_flat_package(PACKAGE, self.environment_path,
                                      ("sessions", "session_store", "entry", "claims",
                                       "campaign_selector", "selection"))
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError(ENVIRONMENT_UNAVAILABLE, f"mncs_env failed to load: {exc}") from exc

    def _sessions(self) -> Any:
        return self._pkg().sessions

    def _store(self, pkg: Any) -> Any:
        return pkg.session_store.open_store(self.state_dir, "store")

    def _resolve_workspace(self, workspace: str | None) -> Path:
        if workspace is None:
            return self._config.workspace_root
        candidate = (self._config.workspace_root / workspace).resolve()
        root = self._config.workspace_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                f"workspace {workspace!r} escapes the protected root",
            )
        if not candidate.is_dir():
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING",
                f"workspace {workspace!r} is not a directory",
            )
        return candidate

    def status(self) -> dict[str, Any]:
        try:
            pkg = self._pkg()
        except ControlError as exc:
            try:
                path = self.environment_path
            except ControlError:
                path = self._config.environment_path
            return {
                "available": False,
                "error": exc.code,
                "message": exc.message,
                "path": str(path),
            }
        try:
            store_pkg = importlib.import_module("mncs_store")
            store_version = getattr(store_pkg, "__version__", "unknown")
        except ImportError:
            store_version = "unavailable"
        sessions = pkg.sessions
        return {
            "available": True,
            "path": str(self.environment_path),
            "state_dir": str(self.state_dir),
            "session_schema": getattr(sessions, "SESSION_SCHEMA", "unknown"),
            "store": store_version,
        }

    def enter(
        self,
        definition: dict[str, Any],
        consumer: str,
        workspace: str | None = None,
        consumer_kind: str = "agent",
        campaign_id: str | None = None,
        task_identity: str | None = None,
    ) -> dict[str, Any]:
        pkg = self._pkg()
        workspace_root = self._resolve_workspace(workspace)
        try:
            return pkg.entry.enter(
                definition=definition,
                definition_path=None,
                workspace_root=str(workspace_root),
                state_dir=self.state_dir,
                backend="store",
                consumer_id=consumer,
                consumer_kind=consumer_kind,
                authenticated_principal_id=self.authenticated_principal_id,
                campaign_id=campaign_id,
                task_identity=task_identity,
            )
        except ControlError:
            raise
        except Exception as exc:
            if type(exc).__name__ == "RightsBlocked":
                raise ControlError("ENVIRONMENT_ENTER_DENIED", str(exc)) from exc
            if type(exc).__name__ == "AuthorityDenied":
                raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", str(exc)) from exc
            diagnostics = getattr(exc, "diagnostics", None)
            raise ControlError(
                "ENVIRONMENT_ENTER_FAILED",
                str(exc),
                details=diagnostics if isinstance(diagnostics, dict) else None,
            ) from exc

    def bind_task_identity(
        self,
        repository: str,
        campaign_id: str,
        session_id: str,
        task_identity: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Bind one stable task key to an exact authenticated project session.

        This owner operation publishes a lookup index only. It neither resumes
        the session nor transfers claims; ordinary Environment admission still
        governs every continuation and mutation.
        """
        if self.authenticated_principal_id is None:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign task binding requires a Control-authenticated principal",
            )
        if (not isinstance(campaign_id, str) or not campaign_id.strip()
                or len(campaign_id) > _CAMPAIGN_ID_MAX or "\x00" in campaign_id):
            raise ControlError(
                "ENVIRONMENT_CAMPAIGN_ID_INVALID",
                "campaign identity must be bounded nonempty text",
            )
        if (not isinstance(session_id, str)
                or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", session_id)):
            raise ControlError(
                "ENVIRONMENT_SESSION_INVALID",
                "session identity is malformed",
            )
        if (not isinstance(task_identity, str) or not task_identity.strip()
                or len(task_identity) > 256 or "\x00" in task_identity):
            raise ControlError(
                "ENVIRONMENT_TASK_IDENTITY_INVALID",
                "task identity must be bounded nonempty text",
            )
        repository = self._validate_repository_selector(repository)
        pkg = self._pkg()
        store = self._store(pkg)
        try:
            snapshot = store.load_snapshot(session_id)
            if not isinstance(snapshot, dict):
                raise ControlError(
                    "ENVIRONMENT_SESSION_MISSING",
                    "selected session is not present in canonical Store",
                    details={"session_id": session_id},
                )
            if snapshot.get("authenticated_principal_id") != self.authenticated_principal_id:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "selected session belongs to a different authenticated principal",
                    details={"session_id": session_id,
                             "next": _FOREIGN_CAMPAIGN_NEXT},
                )
            campaign = snapshot.get("campaign")
            campaign = campaign if isinstance(campaign, dict) else {}
            if campaign.get("identity") != campaign_id:
                raise ControlError(
                    "ENVIRONMENT_CAMPAIGN_SESSION_CONFLICT",
                    "selected session does not belong to the explicitly selected campaign",
                    details={"campaign_id": campaign_id, "session_id": session_id},
                )
            if snapshot.get("lifecycle") not in _CONTINUABLE_LIFECYCLES:
                raise ControlError(
                    "ENVIRONMENT_SESSION_TERMINAL",
                    "task identity can bind only a continuable session",
                    details={"session_id": session_id,
                             "lifecycle": snapshot.get("lifecycle")},
                )

            all_claims = store.read_claims()
            active_claims = pkg.claims.active_claims(all_claims)
            session_claims = [
                claim for claim in active_claims.values()
                if isinstance(claim, dict) and claim.get("session_id") == session_id
            ]
            basis = self._snapshot_repository_reference_basis(
                snapshot, repository, session_claims,
            )
            if not basis:
                raise ControlError(
                    "ENVIRONMENT_PROJECT_SCOPE_REQUIRED",
                    "the selected session has no durable link to this project",
                    details={"repository": repository, "session_id": session_id},
                )

            provenance = snapshot.get("provenance")
            provenance = provenance if isinstance(provenance, dict) else {}
            workspace = snapshot.get("workspace")
            workspace = workspace if isinstance(workspace, dict) else {}
            definition_id = provenance.get("definition_id")
            workspace_root = workspace.get("root")
            if (not isinstance(definition_id, str)
                    or not isinstance(workspace_root, str)):
                raise ControlError(
                    "ENVIRONMENT_SESSION_CORRUPT",
                    "selected session lacks its persisted Environment definition or workspace",
                )
            if request_id is None:
                request_material = {
                    "operation": "mncs.environment.task-binding-request/1",
                    "principal_id": self.authenticated_principal_id,
                    "repository": repository,
                    "campaign_id": campaign_id,
                    "session_id": session_id,
                    "task_identity": task_identity,
                }
                request_id = "req_" + hashlib.sha256(
                    json.dumps(
                        request_material, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:48]
            elif (not isinstance(request_id, str) or not request_id.startswith("req_")
                    or len(request_id) > 160 or "\x00" in request_id):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "stable task-binding request identity is invalid",
                )

            session = pkg.sessions.Session(store, session_id)
            try:
                binding = session.bind_task_identity(
                    task_identity,
                    campaign_id=campaign_id,
                    authenticated_principal_id=self.authenticated_principal_id,
                    request_id=request_id,
                )
            except Exception as exc:
                if type(exc).__name__ == "AuthorityDenied":
                    raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", str(exc)) from exc
                if type(exc).__name__ == "LifecycleError":
                    raise ControlError("ENVIRONMENT_SESSION_TERMINAL", str(exc)) from exc
                if type(exc).__name__ == "TaskSelectorError":
                    code = getattr(exc, "code", None)
                    if code == "store-corruption":
                        raise ControlError("ENVIRONMENT_STORE_CORRUPTION", str(exc)) from exc
                    if code == "persistence-service-unavailable":
                        raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(exc)) from exc
                    if code == "ambiguous-publication":
                        raise ControlError(
                            "ENVIRONMENT_PUBLICATION_AMBIGUOUS",
                            str(exc),
                            details={"request_id": request_id,
                                     "next": "retry the same task identity and request ID to reconcile Store readback"},
                        ) from exc
                    raise ControlError(
                        "ENVIRONMENT_CAMPAIGN_TASK_CONFLICT", str(exc),
                    ) from exc
                raise
            return {
                "schema_version": "mncs.control.campaign-task-binding/1",
                "status": "bound",
                "selector_identity": binding["selector_identity"],
                "campaign_id": binding["campaign_id"],
                "session_id": binding["session_id"],
                "definition_id": binding["definition_id"],
                "workspace_root": binding["workspace_root"],
                "request_id": binding["request_id"],
                "bound_at": binding["bound_at"],
                "project_scope_basis": list(basis),
                "authority_effect": "lookup-only",
            }
        except ControlError:
            raise
        except Exception as exc:
            if type(exc).__name__ in {"StoreIntegrityFailure", "StoreCorruption"}:
                raise ControlError("ENVIRONMENT_STORE_CORRUPTION", str(exc)) from exc
            if type(exc).__name__ == "StoreUnavailable":
                raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(exc)) from exc
            raise ControlError("ENVIRONMENT_TASK_BIND_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def campaign_continuation(
        self, repository: str, campaign_id: str | None = None,
        task_identity: str | None = None,
        *, session_id: str | None = None,
        working_checkout: dict[str, str] | None = None,
        definition_id: str | None = None,
        workspace_root: str | None = None,
    ) -> dict[str, Any]:
        """Return an authenticated, repository-scoped continuation capsule.

        Environment remains the authority for session and campaign semantics:
        this adapter enumerates canonical Store snapshots, asks Environment's
        Session object for its compact context, and returns only sessions that
        share Control's authenticated principal. Without a campaign identity,
        it discovers same-principal campaigns from the requested repository.
        When a task identity is supplied, the Environment-owned selector
        validator resolves only an existing binding for the exact principal,
        definition, and workspace. The repository selector must already occur
        in a campaign's intent, checkout facts, repository references, live
        claim, or exact authenticated scope grant; a selector never grants
        ownership or adopts a campaign.
        """
        if (campaign_id is not None
                and (not isinstance(campaign_id, str) or not campaign_id.strip()
                     or len(campaign_id) > _CAMPAIGN_ID_MAX or "\x00" in campaign_id)):
            raise ControlError("ENVIRONMENT_CAMPAIGN_ID_INVALID",
                               "campaign identity must be bounded nonempty text when supplied")
        if (task_identity is not None
                and (not isinstance(task_identity, str) or not task_identity.strip()
                     or len(task_identity) > 256 or "\x00" in task_identity)):
            raise ControlError(
                "ENVIRONMENT_TASK_IDENTITY_INVALID",
                "task identity must be bounded nonempty text when supplied",
            )
        if (session_id is not None
                and (not isinstance(session_id, str)
                     or re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", session_id) is None)):
            raise ControlError(
                "ENVIRONMENT_SESSION_INVALID",
                "session identity must be a valid Environment session id",
            )
        if self.authenticated_principal_id is None:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "campaign lookup requires a Control-authenticated principal")
        repository = self._validate_repository_selector(repository)
        requested_campaign_id = campaign_id
        exact_session_id = session_id
        pkg = self._pkg()
        checkout_matcher = getattr(
            getattr(pkg, "entry", None), "_working_checkout_matches_snapshot", None,
        )
        claims_by_session: dict[str, list[dict[str, Any]]] = {}

        def scope_grant_context_matches(
            snapshot: dict[str, Any], session_id: str | None = None,
        ) -> bool:
            campaign = snapshot.get("campaign")
            campaign_identity = campaign.get("identity") \
                if isinstance(campaign, dict) else None
            if requested_campaign_id is not None:
                if campaign_identity != requested_campaign_id:
                    return False
            elif not (isinstance(definition_id, str) and definition_id
                      and isinstance(workspace_root, str) and workspace_root):
                # Discovery from a repository name alone is too weak to
                # consult project-scope grants across unrelated campaigns.
                return False
            provenance = snapshot.get("provenance")
            provenance = provenance if isinstance(provenance, dict) else {}
            workspace = snapshot.get("workspace")
            workspace = workspace if isinstance(workspace, dict) else {}
            same_project_context = bool(
                (not definition_id or provenance.get("definition_id") == definition_id)
                and (not workspace_root or workspace.get("root") == workspace_root)
            )
            if same_project_context:
                return True
            principal_id = snapshot.get("authenticated_principal_id")
            # A project-specific Environment definition may select an exact
            # worktree belonging to a different campaign workspace (for
            # example, a compiler campaign's explicitly admitted Language or
            # Environment checkout). In that case the same campaign/project
            # definition check cannot match. Its authenticated scope grant is
            # the durable cross-repository link, and only the complete
            # current checkout identity may bridge the context boundary.
            return bool(
                isinstance(session_id, str)
                and principal_id == self.authenticated_principal_id
                and working_checkout is not None
                and self._scope_grant_matches_checkout(
                    snapshot,
                    repository,
                    scope_grants_for_session(session_id),
                    working_checkout,
                )
            )

        def matches_working_checkout(
            snapshot: dict[str, Any], session_id: str | None = None,
        ) -> bool:
            if working_checkout is None:
                return True
            if (callable(checkout_matcher)
                    and checkout_matcher(snapshot, working_checkout)):
                return True
            return bool(
                isinstance(session_id, str)
                and any(
                    _claim_matches_working_checkout(
                        claim, working_checkout, repository, session_id=session_id,
                    )
                    for claim in claims_by_session.get(session_id, [])
                )
            ) or bool(
                isinstance(session_id, str)
                and scope_grant_context_matches(snapshot, session_id)
                and self._scope_grant_matches_checkout(
                    snapshot, repository,
                    scope_grants_for_session(session_id), working_checkout,
                )
            )

        def claim_overlaps_working_checkout(claim: dict[str, Any]) -> bool:
            if working_checkout is None:
                return True
            checker = getattr(getattr(pkg, "claims", None), "scopes_conflict", None)
            scope = claim.get("scope")
            path_value = working_checkout.get("path")
            if (not callable(checker) or not isinstance(scope, dict)
                    or not isinstance(path_value, str)):
                return True
            selected_scope = {
                "kind": "worktree",
                "repository": repository,
                "checkout": path_value,
                "branch": working_checkout.get("branch"),
                "paths": None,
                "exclusive": False,
            }
            try:
                return checker(scope, selected_scope) is not None
            except (TypeError, ValueError):
                return True

        store = self._store(pkg)
        try:
            if exact_session_id is not None:
                selected_snapshot = store.load_snapshot(exact_session_id)
                if not isinstance(selected_snapshot, dict):
                    raise ControlError(
                        "ENVIRONMENT_SESSION_MISSING",
                        "selected Environment session snapshot is unavailable",
                    )
                if selected_snapshot.get("authenticated_principal_id") != self.authenticated_principal_id:
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "selected Environment session belongs to a different authenticated principal",
                        details={"next": _FOREIGN_CAMPAIGN_NEXT},
                    )
                selected_campaign = selected_snapshot.get("campaign")
                selected_campaign_id = (
                    selected_campaign.get("identity")
                    if isinstance(selected_campaign, dict) else None
                )
                if not isinstance(selected_campaign_id, str) or not selected_campaign_id:
                    raise ControlError(
                        "ENVIRONMENT_SESSION_MISSING",
                        "selected Environment session has no durable campaign identity",
                    )
                if campaign_id is not None and campaign_id != selected_campaign_id:
                    raise ControlError(
                        "ENVIRONMENT_CAMPAIGN_SESSION_CONFLICT",
                        "selected Environment session does not belong to the requested campaign",
                        details={"campaign_id": campaign_id},
                    )
                campaign_id = selected_campaign_id
                requested_campaign_id = selected_campaign_id

            scope_grants_cache: dict[str, list[dict[str, Any]]] = {}
            scope_grants_lookup_count = 0

            def scope_grants_for_session(session_id: str) -> list[dict[str, Any]]:
                nonlocal scope_grants_lookup_count
                if session_id in scope_grants_cache:
                    return scope_grants_cache[session_id]
                scope_grants_lookup_count += 1
                if scope_grants_lookup_count > 128:
                    raise ControlError(
                        "ENVIRONMENT_LOOKUP_LIMIT",
                        "scope-grant continuation search exceeds the bounded same-context session limit",
                        details={"session_count": scope_grants_lookup_count, "limit": 128},
                    )
                session_type = getattr(pkg.sessions, "Session", None)
                opener = getattr(session_type, "open", None)
                if not callable(opener):
                    records = []
                else:
                    session = opener(
                        state_dir=Path("."), session_id=session_id,
                        backend="store", store=store,
                    )
                    authority_reader = getattr(session, "effective_authority", None)
                    if callable(authority_reader):
                        authority = authority_reader()
                        if (not isinstance(authority, dict)
                                or repository not in authority.get("writable", [])):
                            records = []
                        else:
                            records = authority.get("scope_grants", [])
                    else:
                        grant_reader = getattr(session, "authority_scope_grants", None)
                        if callable(grant_reader):
                            records = grant_reader()
                        else:
                            context = session.context()
                            authority = context.get("authority", {})
                            if (isinstance(authority, dict)
                                    and repository in authority.get("writable", [])):
                                records = authority.get("scope_grants", [])
                            else:
                                records = []
                valid = [record for record in records
                         if isinstance(record, dict)] if isinstance(records, list) else []
                scope_grants_cache[session_id] = valid
                return valid

            def references_repository(
                snapshot: dict[str, Any], session_id: str,
            ) -> bool:
                session_claims = claims_by_session.get(session_id, [])
                if self._snapshot_references_repository(
                    snapshot, repository, session_claims,
                ):
                    return True
                grants = (
                    scope_grants_for_session(session_id)
                    if scope_grant_context_matches(snapshot, session_id)
                    and snapshot.get("authenticated_principal_id")
                    == self.authenticated_principal_id
                    and working_checkout is not None
                    else []
                )
                return self._snapshot_references_repository(
                    snapshot, repository, session_claims,
                    scope_grants=grants,
                    working_checkout=working_checkout,
                )

            # A fresh project entry may begin at the repository root even
            # though its authenticated campaign selected a registered nested
            # worktree. Recover that checkout only from the exact campaign,
            # principal, Environment definition, and workspace already bound
            # to this request. Environment verifies the recorded Git
            # registration and manifest before the checkout is used below.
            checkout_resolver = getattr(
                getattr(pkg, "entry", None), "_campaign_checkout_from_store", None,
            )
            if (
                campaign_id is not None
                and callable(checkout_resolver)
                and isinstance(definition_id, str)
                and definition_id
                and isinstance(workspace_root, str)
                and workspace_root
                and isinstance(working_checkout, dict)
                and working_checkout.get("repository") == repository
            ):
                try:
                    configured_root = self._config.workspace_root.resolve(strict=True)
                    requested_root = Path(workspace_root).resolve(strict=True)
                    current_path = Path(str(working_checkout.get("path", ""))).resolve(
                        strict=True
                    )
                    repository_root = Path(
                        str(working_checkout.get("repository_root", ""))
                    ).resolve(strict=True)
                except (OSError, RuntimeError):
                    configured_root = requested_root = current_path = repository_root = None
                if (
                    configured_root is not None
                    and requested_root == configured_root
                    and working_checkout.get("workspace_root") == str(configured_root)
                    and current_path == repository_root
                ):
                    try:
                        recovered_checkout = checkout_resolver(
                            store,
                            campaign_id=campaign_id,
                            authenticated_principal_id=self.authenticated_principal_id,
                            definition_id=definition_id,
                            workspace_root=configured_root,
                            working_checkout=working_checkout,
                        )
                    except Exception as error:
                        diagnostics = getattr(error, "diagnostics", None)
                        diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
                        if diagnostics.get("code") == "campaign-checkout-ambiguous":
                            raise ControlError(
                                "ENVIRONMENT_SESSION_SELECTION_REQUIRED",
                                str(error),
                                details=diagnostics,
                            ) from error
                        if diagnostics.get("code") == "campaign-checkout-invalid":
                            raise ControlError(
                                "ENVIRONMENT_WORKSPACE_UNKNOWN",
                                str(error),
                                details=diagnostics,
                            ) from error
                        raise
                    if isinstance(recovered_checkout, dict):
                        working_checkout = recovered_checkout

            # An explicit campaign identity is already known before the
            # continuation scan. Reuse Environment's recoverable selection
            # projection to enumerate only that campaign's nonterminal
            # snapshots. The projection is only an index: each returned
            # snapshot is still loaded and checked against canonical Store
            # state below, including principal, checkout, project-link, and
            # claim ownership. This keeps exact continuation from reopening
            # every historical session on each request. A task selector with
            # no exact session retains the full scan because it must detect
            # conflicting bindings across project-linked campaign contexts.
            session_selection = getattr(pkg, "selection", None)
            select_sessions = getattr(session_selection, "select", None)
            if (campaign_id is not None
                    and (task_identity is None or exact_session_id is not None)
                    and callable(select_sessions)):
                campaign_selector = {
                    "control_campaign_continuation": 1,
                    "campaign_identity": campaign_id,
                    "lifecycle": "nonterminal",
                }

                def is_campaign_continuation(snapshot: dict[str, Any]) -> bool:
                    campaign = snapshot.get("campaign")
                    return bool(
                        isinstance(campaign, dict)
                        and campaign.get("identity") == campaign_id
                        and snapshot.get("lifecycle") not in _TERMINAL_LIFECYCLES
                    )

                try:
                    session_ids = select_sessions(
                        store, campaign_selector, is_campaign_continuation,
                    )
                except ValueError as error:
                    # The shared selection index has a bounded workspace
                    # inventory. Preserve the existing continuation bound
                    # and behavior when a larger workspace cannot use it.
                    if str(error) != "session selection exceeds bounded index":
                        raise
                    session_ids = store.list_sessions()
            else:
                session_ids = store.list_sessions()
            if len(session_ids) > 10000:
                raise ControlError(
                    "ENVIRONMENT_LOOKUP_LIMIT",
                    "canonical Environment session inventory exceeds the bounded lookup limit",
                    details={"session_count": len(session_ids), "limit": 10000},
                )
            if exact_session_id is not None and exact_session_id not in session_ids:
                raise ControlError(
                    "ENVIRONMENT_SESSION_MISSING",
                    "selected Environment session is not present in canonical Store",
                )
            all_claims = store.read_claims()
            active_claims = pkg.claims.active_claims(all_claims)
            for claim in active_claims.values():
                if isinstance(claim, dict):
                    owner = claim.get("session_id")
                    if isinstance(owner, str):
                        claims_by_session.setdefault(owner, []).append(claim)

            owned_by_campaign: dict[str, list[tuple[str, dict[str, Any]]]] = {}
            project_campaigns: set[str] = set()
            foreign_campaigns: set[str] = set()
            foreign_owner = False
            for session_id in session_ids:
                snapshot = store.load_snapshot(session_id)
                if not isinstance(snapshot, dict):
                    continue
                campaign = snapshot.get("campaign")
                identity = campaign.get("identity") if isinstance(campaign, dict) else None
                if not isinstance(identity, str) or not identity:
                    continue
                if campaign_id is not None and identity != campaign_id:
                    continue
                lifecycle = snapshot.get("lifecycle")
                if lifecycle in _TERMINAL_LIFECYCLES:
                    continue
                references_project = references_repository(snapshot, session_id)
                checkout_matches = matches_working_checkout(snapshot, session_id)
                if snapshot.get("authenticated_principal_id") != self.authenticated_principal_id:
                    # Explicit campaign identities are globally unique and
                    # always preserve foreign-owner refusal. Project discovery
                    # may coexist with another principal on an independent
                    # registered checkout when no active claim overlaps this
                    # exact checkout.
                    foreign_campaigns.add(identity)
                    overlapping_claim = any(
                        claim.get("repository") == repository
                        and claim_overlaps_working_checkout(claim)
                        for claim in claims_by_session.get(session_id, [])
                    )
                    foreign_owner = (
                        foreign_owner or campaign_id is not None
                        or (references_project and checkout_matches)
                        or overlapping_claim
                    )
                    continue
                owned_by_campaign.setdefault(identity, []).append((session_id, snapshot))
                if references_project and checkout_matches:
                    project_campaigns.add(identity)

            foreign_owner = foreign_owner or bool(project_campaigns & foreign_campaigns)
            if foreign_owner:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "campaign or project work is owned by a different authenticated principal",
                    details={**({"campaign_id": campaign_id} if campaign_id is not None else {}),
                             "next": _FOREIGN_CAMPAIGN_NEXT},
                )

            task_selector_projection: dict[str, Any] | None = None
            if task_identity is not None:
                selector_api = getattr(pkg, "campaign_selector", None)
                selector_identity = getattr(selector_api, "selector_identity", None)
                read_binding = getattr(selector_api, "read_binding", None)
                if not callable(selector_identity) or not callable(read_binding):
                    raise ControlError(
                        "ENVIRONMENT_PERSISTENCE_UNAVAILABLE",
                        "Environment task-selector lookup is unavailable",
                    )

                # Task selectors are scoped by Environment to principal,
                # definition, and workspace. Recompute those exact scoped
                # keys from same-principal campaign snapshots and ask the
                # Environment-owned validator to read each immutable binding.
                # The selector never grants ownership; the ordinary campaign,
                # lifecycle, and claim checks below still apply.
                contexts: dict[tuple[str, str], dict[str, Any] | None] = {}
                bindings: list[dict[str, Any]] = []
                relevant_campaigns = set(project_campaigns)
                # An explicit campaign argument narrows the result projection,
                # but it must not hide a conflicting selector binding in a
                # different campaign that is already linked to this project.
                for candidate_session_id in session_ids:
                    candidate_snapshot = store.load_snapshot(candidate_session_id)
                    if (not isinstance(candidate_snapshot, dict)
                            or candidate_snapshot.get("authenticated_principal_id")
                            != self.authenticated_principal_id):
                        continue
                    candidate_campaign = candidate_snapshot.get("campaign")
                    candidate_identity = (
                        candidate_campaign.get("identity")
                        if isinstance(candidate_campaign, dict) else None
                    )
                    if (isinstance(candidate_identity, str)
                            and matches_working_checkout(
                                candidate_snapshot, candidate_session_id,
                            )
                            and references_repository(
                                candidate_snapshot, candidate_session_id,
                            )):
                        relevant_campaigns.add(candidate_identity)
                if campaign_id is not None:
                    relevant_campaigns.add(campaign_id)
                for session_id in session_ids:
                    snapshot = store.load_snapshot(session_id)
                    if not isinstance(snapshot, dict):
                        continue
                    campaign = snapshot.get("campaign")
                    identity = campaign.get("identity") if isinstance(campaign, dict) else None
                    if identity not in relevant_campaigns:
                        continue
                    if (snapshot.get("authenticated_principal_id")
                            != self.authenticated_principal_id
                            or not matches_working_checkout(snapshot, session_id)):
                        continue
                    provenance = snapshot.get("provenance")
                    workspace = snapshot.get("workspace")
                    definition_id = (
                        provenance.get("definition_id") if isinstance(provenance, dict) else None
                    )
                    workspace_root = workspace.get("root") if isinstance(workspace, dict) else None
                    if (not isinstance(definition_id, str)
                            or not isinstance(workspace_root, str)):
                        continue
                    context_key = (definition_id, workspace_root)
                    if context_key not in contexts:
                        try:
                            selector = selector_identity(
                                task_identity,
                                authenticated_principal_id=self.authenticated_principal_id,
                                definition_id=definition_id,
                                workspace_root=workspace_root,
                            )
                            contexts[context_key] = read_binding(store, selector)
                        except Exception as error:
                            code = getattr(error, "code", None)
                            code_name = getattr(code, "name", code)
                            if code_name == "store-corruption":
                                raise ControlError(
                                    "ENVIRONMENT_STORE_CORRUPTION", str(error)
                                ) from error
                            if code_name == "persistence-service-unavailable":
                                raise ControlError(
                                    "ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(error)
                                ) from error
                            raise ControlError(
                                "ENVIRONMENT_TASK_SELECTOR_LOOKUP_FAILED", str(error)
                            ) from error
                    binding = contexts[context_key]
                    if binding is None:
                        continue
                    if (binding.get("authenticated_principal_id")
                            != self.authenticated_principal_id
                            or binding.get("definition_id") != definition_id
                            or binding.get("workspace_root") != workspace_root):
                        raise ControlError(
                            "ENVIRONMENT_STORE_CORRUPTION",
                            "task-selector binding does not match its authenticated Environment scope",
                        )
                    bound_session_id = binding.get("session_id")
                    bound_snapshot = (
                        store.load_snapshot(bound_session_id)
                        if isinstance(bound_session_id, str) else None
                    )
                    bound_campaign = (
                        bound_snapshot.get("campaign")
                        if isinstance(bound_snapshot, dict) else None
                    )
                    bound_provenance = (
                        bound_snapshot.get("provenance")
                        if isinstance(bound_snapshot, dict) else None
                    )
                    bound_workspace = (
                        bound_snapshot.get("workspace")
                        if isinstance(bound_snapshot, dict) else None
                    )
                    if (
                        not isinstance(bound_snapshot, dict)
                        or bound_snapshot.get("authenticated_principal_id")
                        != self.authenticated_principal_id
                        or not matches_working_checkout(
                            bound_snapshot, bound_session_id,
                        )
                        or not isinstance(bound_campaign, dict)
                        or bound_campaign.get("identity") != binding.get("campaign_id")
                        or not isinstance(bound_provenance, dict)
                        or bound_provenance.get("definition_id") != definition_id
                        or not isinstance(bound_workspace, dict)
                        or bound_workspace.get("root") != workspace_root
                    ):
                        raise ControlError(
                            "ENVIRONMENT_TASK_SELECTOR_TARGET_UNAVAILABLE",
                            "task-selector target no longer matches its recorded Environment owner and context",
                        )
                    bindings.append({
                        "campaign_id": binding["campaign_id"],
                        "session_id": bound_session_id,
                        "definition_id": definition_id,
                        "workspace_root": workspace_root,
                        "lifecycle": bound_snapshot.get("lifecycle"),
                        "references_repository": references_repository(
                            bound_snapshot, str(bound_session_id),
                        ),
                    })

                distinct_bindings = {
                    (item["campaign_id"], item["session_id"],
                     item["definition_id"], item["workspace_root"]): item
                    for item in bindings
                }
                binding_rows = list(distinct_bindings.values())
                if campaign_id is not None and binding_rows:
                    matching_campaign = [
                        item for item in binding_rows
                        if item["campaign_id"] == campaign_id
                    ]
                    if not matching_campaign:
                        raise ControlError(
                            "ENVIRONMENT_TASK_SELECTOR_CONFLICT",
                            "explicit campaign identity conflicts with its durable task selector",
                        )
                    binding_rows = matching_campaign

                project_bindings = [
                    item for item in binding_rows
                    if item["campaign_id"] in project_campaigns
                    or item["references_repository"]
                ]
                if len(project_bindings) > 1:
                    duplicate_selector = getattr(
                        getattr(pkg, "entry", None),
                        "_authoritative_duplicate_session",
                        None,
                    )
                    authoritative_session = None
                    if callable(duplicate_selector):
                        candidate_session_ids = sorted({
                            item["session_id"] for item in project_bindings
                            if isinstance(item.get("session_id"), str)
                        })
                        authoritative_session, _selection_evidence = duplicate_selector(
                            store, candidate_session_ids, working_checkout,
                        )
                        if (authoritative_session is None
                                and working_checkout is not None):
                            # A task selector can legitimately retain bindings
                            # from two Environment definitions after a worktree
                            # moves. If current checkout evidence is insufficient,
                            # a unique canonical checkpoint can still identify the
                            # prior continuation; duplicate checkpoints stay
                            # ambiguous in Environment's selector.
                            authoritative_session, _selection_evidence = (
                                duplicate_selector(store, candidate_session_ids, None)
                            )
                    if isinstance(authoritative_session, str):
                        selected_rows = [
                            item for item in project_bindings
                            if item.get("session_id") == authoritative_session
                        ]
                        if len(selected_rows) == 1:
                            project_bindings = selected_rows
                if len(project_bindings) > 1:
                    contexts_out = [{
                        "campaign_id": item["campaign_id"],
                        "session_id": item["session_id"],
                        "definition_id": item["definition_id"],
                        "workspace_root": item["workspace_root"],
                    } for item in sorted(
                        project_bindings,
                        key=lambda row: (row["campaign_id"], row["definition_id"],
                                         row["workspace_root"], row["session_id"]),
                    )[:16]]
                    return {
                        "schema_version": "mncs.control.campaign-continuation/1",
                        "repository": repository,
                        "status": "ambiguous-task-selector-contexts",
                        "task_selector": {"status": "ambiguous", "contexts": contexts_out,
                                          "contexts_count": len(project_bindings),
                                          "contexts_truncated": len(project_bindings) > 16},
                        "next": "select the exact Environment campaign context; Control will not choose between task-selector bindings",
                    }
                if not project_bindings:
                    if binding_rows:
                        return {
                            "schema_version": "mncs.control.campaign-continuation/1",
                            "repository": repository,
                            "status": "task-selector-not-linked-to-project",
                            "task_selector": {"status": "not-linked"},
                            "next": "inspect this project's continuation capsule; the task selector does not authorize another repository",
                        }
                    return {
                        "schema_version": "mncs.control.campaign-continuation/1",
                        "repository": repository,
                        "status": "task-selector-unbound",
                        "campaigns": sorted(project_campaigns)[:16],
                        "campaigns_count": len(project_campaigns),
                        "campaigns_truncated": len(project_campaigns) > 16,
                        "next": (
                            "no campaign was adopted; inspect the project capsule, then enter once with the selected campaign ID and this task identity, or start a new task with this identity"
                        ),
                    }

                selected_binding = project_bindings[0]
                campaign_id = selected_binding["campaign_id"]
                if selected_binding["lifecycle"] in _TERMINAL_LIFECYCLES:
                    return {
                        "schema_version": "mncs.control.campaign-continuation/1",
                        "campaign_id": campaign_id,
                        "repository": repository,
                        "status": "task-selector-target-terminal",
                        "task_selector": {
                            "status": "terminal",
                            "session_id": selected_binding["session_id"],
                            "definition_id": selected_binding["definition_id"],
                            "workspace_root": selected_binding["workspace_root"],
                        },
                        "next": "the task selector resolves to a terminal Environment session; do not create a replacement implicitly",
                    }
                task_selector_projection = {
                    "status": "resolved",
                    "campaign_id": campaign_id,
                    "session_id": selected_binding["session_id"],
                    "definition_id": selected_binding["definition_id"],
                    "workspace_root": selected_binding["workspace_root"],
                }

            candidate_campaigns = (
                [campaign_id] if campaign_id is not None
                else sorted(project_campaigns)
            )
            if not candidate_campaigns:
                return {
                    "schema_version": "mncs.control.campaign-continuation/1",
                    "campaign_id": campaign_id,
                    "repository": repository,
                    "status": "not-found",
                    **({"task_selector": task_selector_projection}
                       if task_selector_projection is not None else {}),
                    "continuations": [],
                    "next": "verify the campaign identity and that this repository belongs to its recorded work intent",
                }

            results: list[dict[str, Any]] = []
            for selected_campaign in candidate_campaigns:
                matching = owned_by_campaign.get(selected_campaign, [])
                if working_checkout is not None:
                    matching = [
                        (session_id, snapshot)
                        for session_id, snapshot in matching
                        if matches_working_checkout(snapshot, session_id)
                    ]
                if task_selector_projection is not None:
                    bound_session = task_selector_projection.get("session_id")
                    if isinstance(bound_session, str):
                        matching = [
                            (session_id, snapshot)
                            for session_id, snapshot in matching
                            if session_id == bound_session
                        ]
                project_sessions = [
                    (session_id, snapshot) for session_id, snapshot in matching
                    if references_repository(snapshot, session_id)
                ]
                if not project_sessions:
                    continue
                authoritative_session = None
                authoritative_selection_basis = None
                if exact_session_id is not None:
                    # An exact session selector narrows only after the normal
                    # campaign, principal, checkout, and project-link checks.
                    # It cannot turn a same-campaign session into authority
                    # for a repository that the selected session does not
                    # itself reference.
                    if not any(candidate_id == exact_session_id
                               for candidate_id, _snapshot in project_sessions):
                        continue
                    matching = [
                        (candidate_id, snapshot)
                        for candidate_id, snapshot in matching
                        if candidate_id == exact_session_id
                    ]
                    authoritative_session = exact_session_id
                    authoritative_selection_basis = "authenticated-exact-session-link"
                # The project link proves this campaign belongs in the
                # repository capsule. Keep its same-principal duplicates in
                # the selected checkout/context so claim and checkpoint
                # provenance can resolve them, even when one projection did
                # not persist the project reference itself.
                if len(matching) > 1 and working_checkout is not None:
                    candidate_session_ids = [
                        session_id for session_id, _snapshot in matching
                    ]
                    live_claims_by_owner = {
                        session_id: [
                            claim for claim in claims_by_session.get(session_id, [])
                            if _claim_matches_working_checkout(
                                claim, working_checkout, repository,
                                session_id=session_id,
                            )
                        ]
                        for session_id in candidate_session_ids
                    }
                    live_claim_owners = sorted(
                        session_id for session_id, claims in live_claims_by_owner.items()
                        if claims
                    )
                    selection_evidence: dict[str, Any] = {}
                    if len(live_claim_owners) == 1:
                        # A verified active claim can preserve the owner of a
                        # registered checkout across a branch rename. Snapshot
                        # branch/HEAD projections may be older, so prefer the
                        # unique same-principal live owner before a snapshot-
                        # only unique-checkout result selects a fresh session.
                        authoritative_session = live_claim_owners[0]
                        selection_evidence = {
                            "basis": "unique_active_checkout_claim",
                            "claim_ids": sorted({
                                str(claim.get("claim_id"))
                                for claim in live_claims_by_owner[authoritative_session]
                                if isinstance(claim.get("claim_id"), str)
                            }),
                        }
                    elif len(live_claim_owners) > 1:
                        # Multiple active owners of this exact checkout remain
                        # ambiguous, even if only one snapshot has the current
                        # branch projection.
                        selection_evidence = {
                            "basis": "overlapping_active_checkout_claims",
                            "candidate_sessions": live_claim_owners,
                            "claim_ids": sorted({
                                str(claim.get("claim_id"))
                                for owner in live_claim_owners
                                for claim in live_claims_by_owner[owner]
                                if isinstance(claim.get("claim_id"), str)
                            }),
                        }
                    else:
                        package_entry = getattr(pkg, "entry", None)
                        duplicate_selector = getattr(
                            package_entry, "_authoritative_duplicate_session", None,
                        )
                        if callable(duplicate_selector):
                            authoritative_session, selection_evidence = duplicate_selector(
                                store, candidate_session_ids, working_checkout,
                            )
                    if authoritative_session is not None:
                        matching = [
                            (session_id, snapshot)
                            for session_id, snapshot in matching
                            if session_id == authoritative_session
                        ]
                        evidence_basis = selection_evidence.get("basis")
                        authoritative_selection_basis = {
                            "unique_active_checkout_claim":
                                "authenticated-project-checkout-live-claim-owner",
                            "unique_session_checkpoint":
                                "authenticated-project-checkout-unique-checkpoint",
                            "unique_registered_checkout":
                                "authenticated-registered-checkout",
                        }.get(evidence_basis, "authenticated-project-checkout")
                contexts = {
                    (str((snapshot.get("provenance") or {}).get("definition_id", "")),
                     str((snapshot.get("workspace") or {}).get("root", "")))
                    for _, snapshot in matching
                }
                if len(contexts) > 1:
                    # This is a valid read result, not an invitation to choose
                    # the first row. Keep the conflicting owner-authorized
                    # session capsules visible so Environment can resume only
                    # after the caller selects the exact recorded context.
                    live_observation = self._observe_project_checkout(repository)
                    context_rows = [
                        {"definition_id": definition_id[:256] or None,
                         "workspace_root": workspace_root[:1000] or None}
                        for definition_id, workspace_root in sorted(contexts)
                    ]
                    ordered_matching = sorted(matching, key=lambda item: item[0])
                    continuations = [
                        self._continuation_capsule(
                            pkg, store, session_id, snapshot, repository,
                            claims_by_session.get(session_id, []), live_observation,
                            working_checkout=working_checkout,
                        )
                        for session_id, snapshot in ordered_matching[:16]
                    ]
                    results.append({
                        "schema_version": "mncs.control.campaign-continuation/1",
                        "campaign_id": selected_campaign,
                        "repository": repository,
                        "status": "context-conflict",
                        "contexts": context_rows[:16],
                        "contexts_count": len(context_rows),
                        "contexts_truncated": len(context_rows) > 16,
                        "continuations": continuations,
                        "continuations_count": len(ordered_matching),
                        "continuations_truncated": len(ordered_matching) > 16,
                        "next": (
                            "review each capsule's project_reference, then select the exact "
                            "recorded Environment definition and workspace; "
                            "Control will not choose between conflicting campaign contexts"
                        ),
                    })
                    continue
                noncontinuable = [
                    {"session_id": session_id, "lifecycle": snapshot.get("lifecycle")}
                    for session_id, snapshot in matching
                    if snapshot.get("lifecycle") not in _CONTINUABLE_LIFECYCLES
                ]
                if noncontinuable:
                    results.append({
                        "schema_version": "mncs.control.campaign-continuation/1",
                        "campaign_id": selected_campaign,
                        "repository": repository,
                        "status": "reconciliation-required",
                        "sessions": noncontinuable[:16],
                        "sessions_truncated": len(noncontinuable) > 16,
                        "next": "reconcile the recorded session lifecycle; handed-off sessions require Environment.accept",
                    })
                    continue

                live_observation = self._observe_project_checkout(repository)
                continuations = [
                    self._continuation_capsule(
                        pkg, store, session_id, snapshot, repository,
                        claims_by_session.get(session_id, []),
                        live_observation,
                        working_checkout=working_checkout,
                    )
                    # Once the campaign is proven to include this project,
                    # retain same-principal duplicates even if one projection
                    # omitted its project reference.
                    for session_id, snapshot in matching
                ]
                continuations.sort(key=lambda item: (str(item.get("lifecycle")),
                                                      str(item.get("session_id"))))
                results.append({
                    "schema_version": "mncs.control.campaign-continuation/1",
                    "campaign_id": selected_campaign,
                    "repository": repository,
                    "status": "ready" if len(continuations) == 1 else "ambiguous",
                    "continuations": continuations[:16],
                    "continuations_truncated": len(continuations) > 16,
                    **({
                        "selected_session_id": authoritative_session,
                        "selection_basis": authoritative_selection_basis,
                    } if authoritative_session is not None else {}),
                    "next": (
                        "resume the listed project-linked session by its exact session identity"
                        if len(continuations) == 1
                        else "review each capsule's project_reference, then select the intended listed session; Control will not choose between continuations"
                    ),
                })
            if not results:
                return {
                    "schema_version": "mncs.control.campaign-continuation/1",
                    "campaign_id": campaign_id,
                    "repository": repository,
                    "status": "not-found",
                    **({"task_selector": task_selector_projection}
                       if task_selector_projection is not None else {}),
                    "continuations": [],
                    "next": "verify the campaign identity and that this repository belongs to its recorded work intent",
                }
            if campaign_id is not None or len(results) == 1:
                result = results[0]
                if task_selector_projection is not None:
                    result["task_selector"] = task_selector_projection
                return result
            result = {
                "schema_version": "mncs.control.campaign-continuation/1",
                "repository": repository,
                "status": "ambiguous-campaigns",
                "campaigns": results[:16],
                "campaigns_truncated": len(results) > 16,
                "next": "select the intended campaign identity; Control will not choose between campaigns",
            }
            if task_selector_projection is not None:
                result["task_selector"] = task_selector_projection
            return result
        except ControlError:
            raise
        except Exception as exc:
            if type(exc).__name__ in {"StoreIntegrityFailure", "StoreCorruption"}:
                raise ControlError("ENVIRONMENT_STORE_CORRUPTION", str(exc)) from exc
            if type(exc).__name__ == "StoreUnavailable":
                raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(exc)) from exc
            raise ControlError("ENVIRONMENT_CAMPAIGN_LOOKUP_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def _validate_repository_selector(self, repository: str) -> str:
        if not isinstance(repository, str) or not _CAMPAIGN_REPOSITORY.fullmatch(repository):
            raise ControlError("ENVIRONMENT_PROJECT_INVALID",
                               "repository selector must name one immediate project")
        root = self._config.workspace_root.expanduser().resolve()
        candidate = root / repository
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ControlError("ENVIRONMENT_PROJECT_UNKNOWN",
                               "repository selector is not present in the configured workspace") from exc
        if (candidate.is_symlink() or not resolved.is_dir()
                or resolved.parent != root):
            raise ControlError("ENVIRONMENT_PROJECT_UNKNOWN",
                               "repository selector is not an immediate real project directory")
        return repository

    @staticmethod
    def _snapshot_references_repository(
        snapshot: dict[str, Any], repository: str, claims: list[dict[str, Any]],
        *, scope_grants: list[dict[str, Any]] | None = None,
        working_checkout: dict[str, Any] | None = None,
    ) -> bool:
        return bool(EnvironmentService._snapshot_repository_reference_basis(
            snapshot, repository, claims,
            scope_grants=scope_grants,
            working_checkout=working_checkout,
        ))

    @staticmethod
    def _snapshot_repository_reference_basis(
        snapshot: dict[str, Any], repository: str, claims: list[dict[str, Any]],
        *, scope_grants: list[dict[str, Any]] | None = None,
        working_checkout: dict[str, Any] | None = None,
    ) -> tuple[str, ...]:
        """Name the persisted facts that link one session to a project.

        Campaign identity can legitimately span duplicate Environment
        contexts. The continuation capsule may show those same-principal
        contexts so callers can see the conflict, while this basis makes clear
        which individual sessions have a durable project link and which are
        present only because they share the selected campaign identity.
        """
        campaign = snapshot.get("campaign")
        campaign = campaign if isinstance(campaign, dict) else {}
        basis: list[str] = []
        intent = campaign.get("work_intent")
        intent = intent if isinstance(intent, dict) else {}
        intent_repositories = intent.get("repositories")
        if isinstance(intent_repositories, list) and repository in intent_repositories:
            basis.append("campaign.work_intent.repositories")
        values = campaign.get("repository_refs")
        if isinstance(values, list) and any(
            isinstance(item, dict) and item.get("repository") == repository
            for item in values
        ):
            basis.append("campaign.repository_refs")
        for field, label in (("selected_checkouts", "snapshot.selected_checkouts"),
                             ("repo_facts", "snapshot.repo_facts")):
            values = snapshot.get(field)
            if isinstance(values, dict) and repository in values:
                basis.append(label)
        if any(claim.get("repository") == repository for claim in claims):
            basis.append("active_claim.repository")
        if EnvironmentService._scope_grant_matches_checkout(
            snapshot, repository, scope_grants or [], working_checkout,
        ):
            basis.append("authenticated-scope-grant.exact-checkout")
        return tuple(basis)

    @staticmethod
    def _scope_grant_matches_checkout(
        snapshot: dict[str, Any], repository: str,
        scope_grants: list[dict[str, Any]],
        working_checkout: dict[str, Any] | None,
    ) -> bool:
        """Match owner-admitted scope to the exact registered checkout selected now.

        A repository scope grant is both mutation authority and durable evidence
        that the campaign intentionally includes this repository. It may link a
        project continuation only when its immutable checkout identity matches
        the checkout Environment selected for this request.
        """
        if (not isinstance(working_checkout, dict)
                or working_checkout.get("repository") != repository):
            return False
        campaign = snapshot.get("campaign")
        campaign_id = campaign.get("identity") if isinstance(campaign, dict) else None
        session_id = snapshot.get("session_id")
        principal_id = snapshot.get("authenticated_principal_id")
        selected_path = working_checkout.get("path")
        selected_branch = working_checkout.get("branch")
        selected_checkout_id = working_checkout.get("checkout_identity")
        selected_common_id = working_checkout.get("git_common_directory_identity")
        if (not isinstance(campaign_id, str) or not isinstance(session_id, str)
                or not isinstance(principal_id, str)
                or not isinstance(selected_path, str) or not selected_path
                or not isinstance(selected_branch, str) or not selected_branch
                or not isinstance(selected_checkout_id, str) or not selected_checkout_id
                or not isinstance(selected_common_id, str) or not selected_common_id):
            return False
        selected_path = os.path.abspath(selected_path)
        for grant in scope_grants:
            if (not isinstance(grant, dict)
                    or grant.get("schema_version") != "mncs.environment.authority-scope-grant/1"
                    or grant.get("campaign_id") != campaign_id
                    or grant.get("session_id") != session_id
                    or grant.get("repository") != repository
                    or grant.get("authorized_by_principal_id") != principal_id):
                continue
            scope = grant.get("scope")
            identity = grant.get("repository_identity")
            if (not isinstance(scope, dict)
                    or scope.get("kind") != "repository"
                    or scope.get("repository") != repository
                    or not isinstance(identity, dict)):
                continue
            grant_path = identity.get("path")
            if (not isinstance(grant_path, str) or not grant_path
                    or os.path.abspath(grant_path) != selected_path
                    or identity.get("branch") != selected_branch
                    or identity.get("checkout_identity") != selected_checkout_id
                    or identity.get("git_common_directory_identity") != selected_common_id):
                continue
            return True
        return False

    def _observe_project_checkout(self, repository: str) -> dict[str, Any]:
        """Add a fresh, bounded Environment-owned Git observation to the capsule.

        Session snapshots are durable and may describe an earlier checkout. The
        workspace provider owns repository discovery, so use its read-only
        project-scoped scanner and keep the persisted session facts alongside
        this explicitly time-bound observation.
        """
        observed_at = datetime.now(UTC).isoformat()
        root = self._config.workspace_root.expanduser().resolve()
        project_path = root / repository
        try:
            workspace = importlib.import_module(f"{PACKAGE}.workspace")
            invalidate = getattr(workspace, "invalidate_repo_facts", None)
            if callable(invalidate):
                invalidate(project_path)
            result = workspace.discover_workspace(
                root, repositories=[repository], timeout_seconds=3.0,
            )
        except Exception as exc:
            return {
                "status": "unknown",
                "observed_at": observed_at,
                "repository": repository,
                "diagnostic": str(exc)[:500],
            }

        result = result if isinstance(result, dict) else {}
        scan = result.get("scan")
        scan = scan if isinstance(scan, dict) else {}
        rows = result.get("repositories") if isinstance(result, dict) else None
        rows = rows if isinstance(rows, list) else []
        checkout = next((row for row in rows
                         if isinstance(row, dict) and row.get("name") == repository), None)
        if result.get("error") or scan.get("status") != "complete" or checkout is None:
            return {
                "status": "unknown",
                "observed_at": observed_at,
                "repository": repository,
                "workspace_root": str(root),
                "scan_status": scan.get("status", "unknown"),
                "diagnostic": str(result.get("error") or scan.get("message")
                                  or "Environment did not observe the selected checkout")[:500],
            }

        git_error = checkout.get("git_error")
        worktrees = checkout.get("worktrees")
        worktrees = worktrees if isinstance(worktrees, list) else []
        return {
            "status": "current" if not git_error and isinstance(checkout.get("head"), str)
            else "unknown",
            "observed_at": observed_at,
            "source": "mncs-environment.workspace.discover_workspace",
            "workspace_root": str(root),
            "repository": repository,
            "scan_status": scan.get("status"),
            "checkout": {
                "path": checkout.get("path"),
                "manifest_repository": checkout.get("manifest_repository"),
                "manifest_revision": checkout.get("manifest_revision"),
                "branch": checkout.get("branch"),
                "head": checkout.get("head"),
                "clean": not bool(checkout.get("dirty")) if not git_error else None,
                "dirty_files": (checkout.get("dirty_files", [])[:16]
                                 if isinstance(checkout.get("dirty_files"), list) else []),
                "dirty_files_truncated": bool(checkout.get("dirty_truncated"))
                or len(checkout.get("dirty_files", [])) > 16
                if isinstance(checkout.get("dirty_files"), list) else False,
                "untracked_count": checkout.get("untracked_count"),
                "git_error": str(git_error)[:500] if git_error else None,
            },
            "worktree_registrations": [
                {
                    "registered_path": str(item.get("path", ""))[:1000],
                    "branch": str(item.get("branch", "")).removeprefix("refs/heads/")[:256] or None,
                    "head": str(item.get("head", ""))[:64] or None,
                    "detached": item.get("detached") == "true",
                    "physical_checkout_status": "not_checked; Git registration only",
                }
                for item in worktrees[:16] if isinstance(item, dict)
            ],
            "worktree_registrations_count": len(worktrees),
            "worktree_registrations_truncated": len(worktrees) > 16,
        }

    @staticmethod
    def _compare_recorded_checkouts(
        references: list[dict[str, Any]], live_observation: dict[str, Any],
        *, reference_workspace_root: str | None = None,
    ) -> list[dict[str, Any]]:
        """Relate persisted checkout facts to the bounded live Git observation.

        Persisted repository paths are relative to the selected Environment
        workspace. The live observation is relative to the Control caller's
        project root, which may be a different repository and worktree.
        """
        if live_observation.get("status") != "current":
            return [{"status": "unknown_live_observation"} for _ in references[:8]]

        root = (reference_workspace_root
                if isinstance(reference_workspace_root, str) and reference_workspace_root
                else str(live_observation.get("workspace_root", "")))

        def path_key(value: Any) -> str | None:
            if not isinstance(value, str) or not value:
                return None
            candidate = value if os.path.isabs(value) else os.path.join(root, value)
            return os.path.normcase(os.path.normpath(candidate))

        def branch_key(value: Any) -> str | None:
            if not isinstance(value, str) or not value:
                return None
            return value.removeprefix("refs/heads/")

        checkout = live_observation.get("checkout")
        checkout = checkout if isinstance(checkout, dict) else {}
        registrations = live_observation.get("worktree_registrations")
        registrations = registrations if isinstance(registrations, list) else []
        checkout_path_key = path_key(checkout.get("path"))
        candidates = [{
            "registered_path": checkout.get("path"),
            "branch": checkout.get("branch"),
            "head": checkout.get("head"),
            "source": "project_checkout",
        }]
        candidates.extend(
            item for item in registrations
            if path_key(item.get("registered_path")) != checkout_path_key
        )
        output: list[dict[str, Any]] = []
        for reference in references[:8]:
            recorded_path = reference.get("observed_path") or reference.get("path")
            recorded_path_key = path_key(recorded_path)
            recorded_branch = branch_key(reference.get("branch"))
            recorded_head = reference.get("head")
            path_matches = [item for item in candidates
                            if recorded_path_key is not None
                            and path_key(item.get("registered_path")) == recorded_path_key]
            matched = path_matches[0] if len(path_matches) == 1 else None
            if matched is None:
                identity_matches = [item for item in candidates
                                    if ((recorded_branch is not None
                                         and branch_key(item.get("branch")) == recorded_branch)
                                        or (isinstance(recorded_head, str)
                                            and item.get("head") == recorded_head))]
                matched = identity_matches[0] if len(identity_matches) == 1 else None
            if matched is None:
                status = ("unknown_registration_list_truncated"
                          if live_observation.get("worktree_registrations_truncated")
                          else "not_observed_in_current_registration_set")
                output.append({
                    "status": status,
                    "recorded_path": str(recorded_path)[:1000] if recorded_path else None,
                    "recorded_branch": recorded_branch,
                    "recorded_head": recorded_head,
                })
                continue

            live_branch = branch_key(matched.get("branch"))
            live_head = matched.get("head")
            branch_matches = recorded_branch is None or recorded_branch == live_branch
            head_matches = not isinstance(recorded_head, str) or recorded_head == live_head
            same_path = (recorded_path_key is not None
                         and path_key(matched.get("registered_path")) == recorded_path_key)
            if same_path and branch_matches and head_matches:
                status = "same_checkout"
            elif same_path and branch_matches:
                status = "checkout_head_changed"
            elif same_path:
                status = "checkout_branch_changed"
            elif branch_matches and head_matches:
                status = "registered_branch_head_match_path_mapping_differs"
            elif branch_matches:
                status = "registered_branch_head_changed_path_mapping_differs"
            else:
                status = "registered_checkout_differs"
            output.append({
                "status": status,
                "recorded_path": str(recorded_path)[:1000] if recorded_path else None,
                "recorded_branch": recorded_branch,
                "recorded_head": recorded_head,
                "live_registered_path": str(matched.get("registered_path", ""))[:1000],
                "live_branch": live_branch,
                "live_head": live_head,
                "path_matches": same_path,
            })
        return output

    def _continuation_capsule(
        self,
        pkg: Any, store: Any, session_id: str, snapshot: dict[str, Any],
        repository: str, claims: list[dict[str, Any]],
        live_observation: dict[str, Any],
        *, working_checkout: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = pkg.sessions.Session.open(
            state_dir=Path("."), session_id=session_id, backend="store", store=store,
        )
        context = session.context()
        authority = context.get("authority", {})
        authority = authority if isinstance(authority, dict) else {}
        scope_grants = authority.get("scope_grants", [])
        scope_grants = scope_grants if isinstance(scope_grants, list) else []
        if repository not in authority.get("writable", []):
            scope_grants = []
        continuation = context.get("continuation", {})
        continuation = continuation if isinstance(continuation, dict) else {}
        campaign = snapshot.get("campaign")
        campaign = campaign if isinstance(campaign, dict) else {}
        intent = campaign.get("work_intent")
        intent = intent if isinstance(intent, dict) else {}
        references = continuation.get("repositories", [])
        selected_references = [
            item for item in references
            if isinstance(item, dict) and item.get("repository") == repository
        ] if isinstance(references, list) else []
        fallback = campaign.get("repository_refs", [])
        if not selected_references and isinstance(fallback, list):
            selected_references = [
                {key: item.get(key) for key in
                 ("repository", "observed_path", "checkout_identity",
                  "git_common_directory_identity", "branch", "head", "clean")}
                for item in fallback
                if isinstance(item, dict) and item.get("repository") == repository
            ]
        if not selected_references:
            selected = snapshot.get("selected_checkouts", {})
            if isinstance(selected, dict) and isinstance(selected.get(repository), dict):
                selected_item = selected[repository]
                selected_references = [{
                    "repository": repository,
                    **{key: selected_item.get(key) for key in
                       ("path", "branch", "head", "clean", "checkout_identity",
                        "git_common_directory_identity") if key in selected_item},
                }]
        if not selected_references:
            workspace = snapshot.get("workspace", {})
            observed_repositories = workspace.get("repositories", []) \
                if isinstance(workspace, dict) else []
            if isinstance(observed_repositories, list):
                for observed in observed_repositories:
                    if not isinstance(observed, dict):
                        continue
                    name = observed.get("manifest_repository") or observed.get("name")
                    if name != repository:
                        continue
                    worktrees = observed.get("worktrees", [])
                    selected_references = [{
                        "repository": repository,
                        **{target: observed.get(source) for target, source in (
                            ("observed_path", "path"), ("branch", "branch"),
                            ("head", "head"), ("clean", "clean"),
                            ("dirty", "dirty"), ("worktree_of", "worktree_of"),
                        ) if source in observed},
                        "worktrees": [
                            {key: row.get(key) for key in ("path", "branch", "head") if key in row}
                            for row in worktrees[:16] if isinstance(row, dict)
                        ] if isinstance(worktrees, list) else [],
                    }]
                    break
        for reference in selected_references:
            if "observation" in reference:
                reference["recorded_observation"] = reference["observation"]
                reference["observation"] = "recorded_snapshot"
        claim_capsules = [
            {key: claim.get(key) for key in
             ("claim_id", "version", "repository", "scope", "basis", "status", "expires_at")}
            for claim in claims if claim.get("repository") == repository
        ]
        selected_checkouts = snapshot.get("selected_checkouts")
        selected_checkout = (
            selected_checkouts.get(repository)
            if isinstance(selected_checkouts, dict) else None
        )
        if isinstance(selected_checkout, dict):
            selected_checkout = {
                "repository": repository,
                **{key: selected_checkout[key] for key in
                   ("path", "checkout_identity", "git_common_directory_identity",
                    "branch", "head") if key in selected_checkout},
            }
        else:
            selected_checkout = None
        exact_scope_grants = [
            grant for grant in scope_grants
            if self._scope_grant_matches_checkout(
                snapshot, repository, [grant], working_checkout,
            )
        ]
        if len(exact_scope_grants) == 1:
            grant = exact_scope_grants[0]
            grant_identity = grant.get("repository_identity")
            if isinstance(grant_identity, dict):
                # The Environment RPC also validates the current Git worktree
                # before binding this capsule. Project selection must use the
                # exact owner-admitted checkout identity, not a stale checkout
                # projection for another repository or worktree.
                selected_checkout = {
                    "repository": repository,
                    **{key: grant_identity[key] for key in (
                        "path", "checkout_identity",
                        "git_common_directory_identity", "branch", "head",
                    ) if key in grant_identity},
                }
                selected_references = [{
                    "repository": repository,
                    "observed_path": grant_identity.get("path"),
                    "checkout_identity": grant_identity.get("checkout_identity"),
                    "git_common_directory_identity": grant_identity.get(
                        "git_common_directory_identity"
                    ),
                    "branch": grant_identity.get("branch"),
                    "head": grant_identity.get("head"),
                    "clean": grant_identity.get("clean"),
                    "observation": "authenticated_scope_grant",
                    "scope_grant_identity": grant.get("identity"),
                }]
        project_reference_basis = self._snapshot_repository_reference_basis(
            snapshot, repository, claims,
            scope_grants=scope_grants,
            working_checkout=working_checkout,
        )
        intent_repositories = intent.get("repositories", [])
        intent_project_scope = (
            [repository] if isinstance(intent_repositories, list)
            and repository in intent_repositories else []
        )
        authorized_consumers = campaign.get("authorized_consumers", [])
        if not isinstance(authorized_consumers, list):
            authorized_consumers = []
        work_intent = {
            "identity": ((snapshot.get("intent") or {}).get("identity")
                         if isinstance(snapshot.get("intent"), dict) else None),
            "goal": str(intent.get("goal", ""))[:800],
            "repositories": intent_project_scope,
        }
        campaign_evidence = continuation.get("evidence", [])
        if not isinstance(campaign_evidence, list):
            campaign_evidence = []
        evidence_limit = getattr(
            pkg.sessions, "CAMPAIGN_EVIDENCE_MAX", _CAMPAIGN_CAPSULE_EVIDENCE_MAX
        )
        if (type(evidence_limit) is not int or evidence_limit < 1
                or evidence_limit > _CAMPAIGN_CAPSULE_EVIDENCE_MAX):
            evidence_limit = _CAMPAIGN_CAPSULE_EVIDENCE_MAX
        capsule = {
            "session_id": session_id,
            "snapshot_version": int(snapshot.get("snapshot_sequence", 0)),
            "lifecycle": snapshot.get("lifecycle"),
            "consumer_id": snapshot.get("consumer_id"),
            "consumer_kind": snapshot.get("consumer_kind"),
            "current_campaign_consumer": campaign.get("current_consumer_id"),
            "authorized_consumers": [str(item)[:160] for item in authorized_consumers[-8:]
                                     if isinstance(item, str)],
            "campaign_session_ids": [str(item)[:160] for item in
                                     campaign.get("session_ids", [])[-8:]
                                     if isinstance(item, str)]
            if isinstance(campaign.get("session_ids", []), list) else [],
            "definition_id": (snapshot.get("provenance") or {}).get("definition_id"),
            "workspace_root": (snapshot.get("workspace") or {}).get("root"),
            "project_reference": {
                "status": "linked" if project_reference_basis else "same_campaign_only",
                "basis": list(project_reference_basis),
            },
            "selected_checkout": selected_checkout,
            "work_intent": work_intent,
            "repositories": selected_references,
            "repository_facts_source": "persisted Environment snapshot; may be stale",
            "live_repository_observation": live_observation,
            "recorded_checkout_comparisons": EnvironmentService._compare_recorded_checkouts(
                selected_references, live_observation,
                reference_workspace_root=(snapshot.get("workspace") or {}).get("root"),
            ),
            "claim_ids": [str(claim.get("claim_id")) for claim in claim_capsules],
            "claims": EnvironmentService._bounded_capsule_value(claim_capsules[:8]),
            "claims_truncated": len(claim_capsules) > 8,
            "checkpoint_ids": [str(item)[:160] for item in
                               continuation.get("checkpoint_ids", [])[-8:]
                               if isinstance(item, str)]
            if isinstance(continuation.get("checkpoint_ids", []), list) else [],
            "evidence": EnvironmentService._bounded_capsule_value(
                campaign_evidence[-evidence_limit:], list_limit=evidence_limit,
            ),
            "evidence_count": continuation.get("evidence_count", len(campaign_evidence)),
            "evidence_truncated": continuation.get(
                "evidence_truncated", len(campaign_evidence) > evidence_limit
            ),
            "delivery": EnvironmentService._bounded_capsule_value(
                continuation.get("delivery", campaign.get("delivery", {"status": "pending"}))
            ),
            "unresolved_pressures": EnvironmentService._bounded_capsule_value(
                continuation.get("unresolved_pressures", [])[:8]
                if isinstance(continuation.get("unresolved_pressures", []), list) else []
            ),
        }
        campaign_state_checkpoint_id = continuation.get(
            "campaign_state_checkpoint_id"
        )
        if isinstance(campaign_state_checkpoint_id, str) and campaign_state_checkpoint_id:
            # This is the CAS base for the next campaign metadata update. Keep
            # it distinct from latest_checkpoint, which is only a session
            # progress checkpoint and may have a different identity.
            capsule["campaign_state_checkpoint_id"] = campaign_state_checkpoint_id
        campaign_identity = campaign.get("identity")
        charter_evidence = campaign_evidence
        campaign_state_reader = getattr(session, "campaign_state", None)
        if isinstance(campaign_state_checkpoint_id, str) and callable(
            campaign_state_reader
        ):
            campaign_state = campaign_state_reader()
            if (
                not isinstance(campaign_state, dict)
                or campaign_state.get("campaign_identity") != campaign_identity
                or campaign_state.get("checkpoint_id")
                != campaign_state_checkpoint_id
                or not isinstance(campaign_state.get("evidence"), list)
            ):
                raise ControlError(
                    "ENVIRONMENT_CAMPAIGN_STATE_CONFLICT",
                    "campaign checkpoint changed while building the continuation capsule",
                )
            # Environment returns this small index from the validated full
            # append-only ledger; the ordinary context remains on its recent
            # evidence page. A missing, inconsistent, or truncated index is
            # fail-closed and cannot suppress ownership ambiguity.
            charter_evidence = []
            charter_index = campaign_state.get("campaign_charter_evidence")
            if isinstance(charter_index, dict):
                charter_references = charter_index.get("references")
                charter_count = charter_index.get("count")
                if (charter_index.get("truncated") is False
                        and isinstance(charter_count, int)
                        and not isinstance(charter_count, bool)
                        and 0 <= charter_count <= _CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX
                        and isinstance(charter_references, list)
                        and len(charter_references) == charter_count):
                    charter_evidence = charter_references
        verified_charter = self._verified_campaign_charter(
            campaign_identity if isinstance(campaign_identity, str) else None,
            charter_evidence,
            evidence_limit=_CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX,
        )
        if verified_charter is not None:
            capsule["campaign_charter"] = verified_charter
        latest_checkpoint = continuation.get("latest_checkpoint")
        if isinstance(latest_checkpoint, dict):
            capsule["latest_checkpoint"] = EnvironmentService._bounded_capsule_value({
                key: latest_checkpoint[key]
                for key in (
                    "identity", "sequence", "created_at", "progress",
                    "progress_truncated", "remaining", "remaining_count",
                    "remaining_truncated",
                )
                if key in latest_checkpoint
            })
        return capsule

    def _verified_campaign_charter(
        self, campaign_identity: str | None, evidence: Any,
        *, evidence_limit: int = _CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX,
    ) -> dict[str, Any] | None:
        """Project a charter only when one Environment evidence link verifies.

        The evidence reference chooses a Git object and relative path, never a
        host path. Reads are confined to the configured Environment project,
        an immediate nonsymlink child of the workspace, and to small blobs in
        the exact recorded commit. Candidate names are only hints: each blob
        must still pass schema, campaign, and digest validation before it can
        be projected.
        """
        if not isinstance(campaign_identity, str) or not campaign_identity:
            return None
        if not isinstance(evidence, list):
            return None

        configured_name = Path(str(
            self._config.repositories.get("environment", "mncs-environment")
        )).name
        if not _CAMPAIGN_REPOSITORY.fullmatch(configured_name):
            return None
        if (type(evidence_limit) is not int or evidence_limit < 1
                or evidence_limit > _CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX):
            evidence_limit = _CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX
        candidates = [
            item for item in evidence[-evidence_limit:]
            if isinstance(item, dict)
            and item.get("repository") == configured_name
            and isinstance(item.get("identity"), str)
            and "campaign_charter" in item["identity"]
        ]
        # Bound verification work, then resolve false-positive identity hints
        # from their exact blobs. Multiple valid charters remain ambiguous.
        if not candidates or len(candidates) > 8:
            return None

        try:
            workspace_root = self._config.workspace_root.expanduser().resolve(strict=True)
            project = workspace_root / configured_name
            project_root = project.resolve(strict=True)
        except OSError:
            return None
        if (project.is_symlink() or not project_root.is_dir()
                or project_root.parent != workspace_root):
            return None

        git_environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(workspace_root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        }
        verified: list[dict[str, Any]] = []
        for reference in candidates:
            path_value = reference.get("path")
            commit = reference.get("commit")
            digest = reference.get("sha256")
            evidence_identity = reference.get("identity")
            if (not isinstance(path_value, str) or not path_value or len(path_value) > 512
                    or "\\" in path_value or "\x00" in path_value
                    or path_value.startswith("/")
                    or not isinstance(commit, str) or not _GIT_OBJECT_ID.fullmatch(commit)
                    or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                    or not isinstance(evidence_identity, str) or len(evidence_identity) > 160):
                continue
            path_parts = path_value.split("/")
            if any(part in {"", ".", ".."} for part in path_parts):
                continue
            relative_path = PurePosixPath(path_value)
            if relative_path.is_absolute():
                continue

            object_spec = f"{commit}:{relative_path.as_posix()}"
            try:
                size_result = subprocess.run(
                    ["git", "cat-file", "-s", object_spec],
                    cwd=project_root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=git_environment,
                    timeout=3.0,
                    check=False,
                )
                if size_result.returncode != 0 or len(size_result.stdout) > 32:
                    continue
                blob_size = int(size_result.stdout.strip())
                if blob_size < 1 or blob_size > _CAMPAIGN_CHARTER_MAX_BYTES:
                    continue
                blob_result = subprocess.run(
                    ["git", "cat-file", "blob", object_spec],
                    cwd=project_root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=git_environment,
                    timeout=3.0,
                    check=False,
                )
                if (blob_result.returncode != 0
                        or len(blob_result.stdout) != blob_size
                        or hashlib.sha256(blob_result.stdout).hexdigest() != digest):
                    continue
                charter = json.loads(blob_result.stdout.decode("utf-8"))
            except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
                continue

            if (not isinstance(charter, dict)
                    or charter.get("schema_version") != _CAMPAIGN_CHARTER_SCHEMA
                    or charter.get("campaign_identity") != campaign_identity):
                continue
            objective = charter.get("objective")
            charter_identity = charter.get("identity")
            if (not isinstance(objective, str) or not objective.strip()
                    or not isinstance(charter_identity, str) or not charter_identity):
                continue
            verified.append({
                "status": "verified",
                "identity": charter_identity[:160],
                "evidence_identity": evidence_identity,
                "objective": objective.strip()[:1200],
                "source": {
                    "repository": configured_name,
                    "commit": commit,
                    "path": relative_path.as_posix(),
                    "sha256": digest,
                },
            })
        return verified[0] if len(verified) == 1 else None

    @staticmethod
    def _bounded_capsule_value(
        value: Any, *, depth: int = 0, list_limit: int = 8,
    ) -> Any:
        """Keep Store-originated evidence compact before returning it to MCP."""
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:1200]
        if depth >= 4:
            return "[truncated]"
        if isinstance(value, list):
            return [EnvironmentService._bounded_capsule_value(
                item, depth=depth + 1, list_limit=list_limit,
            ) for item in value[:list_limit]]
        if isinstance(value, dict):
            return {
                str(key)[:120]: EnvironmentService._bounded_capsule_value(
                    item, depth=depth + 1, list_limit=list_limit,
                )
                for key, item in list(value.items())[:24]
                if isinstance(key, str)
            }
        return str(value)[:1200]

    def _open_session(self, sessions: Any, store: Any, session_id: str) -> Any:
        try:
            self._authorize_session(store, session_id)
            return sessions.Session.resume(
                state_dir=self.state_dir, session_id=session_id, store=store
            )
        except ControlError:
            raise
        except Exception as exc:
            name = type(exc).__name__
            if name == "LifecycleError":
                raise ControlError("ENVIRONMENT_SESSION_TERMINAL", str(exc)) from exc
            raise ControlError("ENVIRONMENT_SESSION_MISSING", str(exc)) from exc

    def _authorize_session(self, store: Any, session_id: str) -> dict[str, Any]:
        snapshot = store.load_snapshot(session_id)
        if not isinstance(snapshot, dict):
            raise ControlError("ENVIRONMENT_SESSION_MISSING",
                               f"session {session_id} is not in canonical Store")
        if (self.authenticated_principal_id is not None
                and snapshot.get("authenticated_principal_id") != self.authenticated_principal_id):
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "session lacks Control-authenticated continuation provenance",
                               details={"session_id": session_id,
                                        "next": "request an explicit handoff from the recorded owner"})
        return snapshot

    def record_read_operation_activity(
        self,
        *,
        session_id: str,
        repository: str,
        operation: str,
        outcome_status: str,
        exit_code: int | None,
        failure_code: str | None,
        operation_elapsed_ms: float,
        request_id: str,
        operation_digest: str,
        control_grant_id: str,
        process_identity: str | None,
        context_response_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist a bounded read-only RPC outcome in its authenticated session."""
        if self.authenticated_principal_id is None:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "read-operation activity requires a Control-authenticated principal",
            )
        if (not isinstance(session_id, str)
                or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", session_id)
                or not isinstance(repository, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", repository)
                or not isinstance(operation, str)
                or not re.fullmatch(r"[a-z][a-z0-9.-]{0,95}", operation)
                or outcome_status not in {"succeeded", "failed"}
                or (exit_code is not None and type(exit_code) is not int)
                or (failure_code is not None and (
                    not isinstance(failure_code, str)
                    or not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", failure_code)
                ))
                or type(operation_elapsed_ms) not in {int, float}
                or not 0 <= operation_elapsed_ms <= 600_000
                or not isinstance(request_id, str)
                or not re.fullmatch(r"req_[A-Za-z0-9_-]{1,76}", request_id)
                or not isinstance(operation_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", operation_digest)
                or not isinstance(control_grant_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", control_grant_id)
                or (process_identity is not None and (
                    not isinstance(process_identity, str)
                    or not re.fullmatch(r"proc_[0-9a-f]{16,64}", process_identity)
                ))
                or (context_response_summary is not None and (
                    operation != "session.context"
                    or not _valid_context_response_summary(context_response_summary)
                    or (outcome_status == "failed" and (
                        context_response_summary.get("capture_status") != "unavailable"
                        or context_response_summary.get("capture_reason")
                        != "operation-failed"
                    ))
                    or (outcome_status == "succeeded"
                        and context_response_summary.get("capture_reason")
                        == "operation-failed")
                ))):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "read-operation activity fields are malformed",
            )

        pkg = self._pkg()
        store = self._store(pkg)
        try:
            snapshot = self._authorize_session(store, session_id)
            selected = (snapshot.get("selected_checkouts") or {}).get(repository)
            selected = selected if isinstance(selected, dict) else {}
            if not selected:
                for repo in (snapshot.get("workspace") or {}).get("repositories", []):
                    if (isinstance(repo, dict)
                            and repo.get("name") == repository):
                        selected = repo
                        break
            intent = snapshot.get("intent")
            intent = intent if isinstance(intent, dict) else {}
            campaign = snapshot.get("campaign")
            campaign = campaign if isinstance(campaign, dict) else {}
            caller = {
                "authenticated_principal_id": self.authenticated_principal_id,
                "control_grant_id": control_grant_id,
                "process_identity": process_identity,
            }
            context = {
                "repository": repository,
                "repository_branch": selected.get("branch"),
                "repository_head": selected.get("head"),
                "environment_id": snapshot.get("environment_id"),
                "campaign_id": campaign.get("identity"),
                "work_intent_id": intent.get("identity"),
            }
            payload = {
                "schema_version": (
                    "mncs.environment.rpc-read-activity/2"
                    if context_response_summary is not None
                    else "mncs.environment.rpc-read-activity/1"
                ),
                "operation": operation,
                "outcome_status": outcome_status,
                "exit_code": exit_code,
                "failure_code": failure_code,
                "request_digest": operation_digest,
                "caller": caller,
                "context": context,
                "measurement_availability": {
                    "model_identity": "unavailable",
                    "token_usage": "unavailable",
                    "control_dispatch_elapsed_ms": "measured",
                    "resource_consumption": "unavailable",
                    "cache_accounting": "unavailable",
                },
                "measurements": {
                    "control_dispatch_elapsed_ms": operation_elapsed_ms,
                },
            }
            if context_response_summary is not None:
                payload["context_response_summary"] = dict(
                    context_response_summary,
                )
            session = pkg.sessions.Session.open(
                state_dir=self.state_dir, session_id=session_id,
                backend="store", store=store,
            )
            recorder = getattr(session, "record_rpc_read_activity", None)
            if not callable(recorder):
                raise ControlError(
                    "ENVIRONMENT_OPERATION_UNAVAILABLE",
                    "Environment session does not support bounded RPC activity records",
                )
            return recorder(
                payload,
                request_id=request_id,
                operation_digest=operation_digest,
            )
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError(
                "ENVIRONMENT_RPC_ACTIVITY_RECORD_FAILED", str(exc),
            ) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def inspect(self, session_id: str) -> dict[str, Any]:
        sessions = self._sessions()
        store = self._store(self._pkg())
        try:
            self._authorize_session(store, session_id)
            session = sessions.Session.open(
                state_dir=self.state_dir, session_id=session_id, store=store
            )
            return session.inspect()
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("ENVIRONMENT_SESSION_MISSING", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def projection_evidence(self, session_id: str) -> dict[str, Any]:
        """Read stored projection evidence for one authenticated session.

        Environment owns projection meaning and Store admission. Control only
        exposes the owner's read operation for a session whose authenticated
        principal matches this connection; it does not run a projection pass
        or accept an evidence reference supplied by the caller.
        """
        if (not isinstance(session_id, str) or not session_id.strip()
                or len(session_id) > 160 or "\x00" in session_id):
            raise ControlError(
                "ENVIRONMENT_SESSION_INVALID",
                "session identity must be bounded nonempty text",
            )
        if self.authenticated_principal_id is None:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "projection evidence requires a Control-authenticated principal",
            )
        pkg = self._pkg()
        store = self._store(pkg)
        try:
            snapshot = self._authorize_session(store, session_id)
            session = pkg.sessions.Session.open(
                state_dir=self.state_dir, session_id=session_id,
                backend="store", store=store,
            )
            projection_store = getattr(pkg, "projections", None)
            if projection_store is None:
                projection_store = importlib.import_module(f"{PACKAGE}.projections")
            result = projection_store.read_evidence(session)
            epoch = snapshot.get("projection_epoch")
            epoch = epoch if isinstance(epoch, dict) else {}
            return {
                "schema_version": "mncs.control.environment-projection-evidence/1",
                "session_id": session_id,
                "snapshot_version": int(snapshot.get("snapshot_sequence", 0)),
                "projection_epoch": {
                    key: epoch.get(key)
                    for key in ("epoch", "at", "evidence_ref")
                    if key in epoch
                },
                "evidence": result.get("evidence"),
                "history": result.get("history", []),
            }
        except ControlError:
            raise
        except Exception as exc:
            if type(exc).__name__ in {"StoreIntegrityFailure", "StoreCorruption"}:
                raise ControlError("ENVIRONMENT_STORE_CORRUPTION", str(exc)) from exc
            if type(exc).__name__ == "StoreUnavailable":
                raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(exc)) from exc
            raise ControlError(
                "ENVIRONMENT_PROJECTION_EVIDENCE_FAILED", str(exc)
            ) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def resume(self, session_id: str) -> dict[str, Any]:
        sessions = self._sessions()
        store = self._store(self._pkg())
        try:
            return self._open_session(sessions, store, session_id).inspect()
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def acquire_claim(
        self,
        session_id: str,
        repository: str,
        reason: str = "",
        basis: str = "explicit-claim",
        ttl_hours: int = 24,
    ) -> dict[str, Any]:
        pkg = self._pkg()
        sessions = pkg.sessions
        store = self._store(pkg)
        try:
            session = self._open_session(sessions, store, session_id)
            try:
                return session.acquire_claim(
                    repository, basis=basis, reason=reason, ttl_hours=ttl_hours
                )
            except Exception as exc:
                if type(exc).__name__ == "ClaimConflict":
                    raise ControlError("ENVIRONMENT_CLAIM_CONFLICT", str(exc)) from exc
                raise ControlError("ENVIRONMENT_CLAIM_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def recover_claim(
        self,
        *,
        session_id: str,
        claim_id: str,
        repository: str,
        owner_session_id: str,
        expected_version: int,
        authorization: dict[str, Any],
        request_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Run Environment's exact claim recovery after Control host fencing."""
        principal = self.authenticated_principal_id
        if not isinstance(principal, str) or not principal:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "owner claim recovery requires Control's authenticated principal",
            )
        if (authorization.get("requester_principal_id") != principal
                or authorization.get("requester_session_id") != session_id
                or authorization.get("claim_id") != claim_id
                or authorization.get("repository") != repository
                or authorization.get("owner_session_id") != owner_session_id
                or authorization.get("expected_claim_version") != expected_version):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "owner claim recovery authorization does not match the selected transition",
            )
        pkg = self._pkg()
        store = self._store(pkg)
        try:
            self._authorize_session(store, session_id)
            session = pkg.sessions.Session(store, session_id)
            try:
                return session.recover_claim_controlled(
                    claim_id=claim_id,
                    repository=repository,
                    owner_session_id=owner_session_id,
                    expected_version=expected_version,
                    authorization=authorization,
                    authenticated_principal_id=principal,
                    request_id=request_id,
                    reason=reason,
                )
            except ControlError:
                raise
            except Exception as exc:
                name = type(exc).__name__
                if name == "ClaimConflict":
                    raise ControlError("ENVIRONMENT_CLAIM_CONFLICT", str(exc)) from exc
                if name == "AuthorityDenied":
                    raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", str(exc)) from exc
                if name == "SnapshotConflict":
                    raise ControlError("ENVIRONMENT_PUBLICATION_CONFLICT", str(exc)) from exc
                if name in {"StoreIntegrityFailure", "StoreCorruption"}:
                    raise ControlError("ENVIRONMENT_STORE_CORRUPTION", str(exc)) from exc
                if name == "StoreUnavailable":
                    raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE", str(exc)) from exc
                raise ControlError("ENVIRONMENT_CLAIM_RECOVERY_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def release_claim(self, session_id: str, repository: str, reason: str = "") -> dict[str, Any]:
        sessions = self._sessions()
        store = self._store(self._pkg())
        try:
            session = self._open_session(sessions, store, session_id)
            return {"released": session.release_claim(repository, reason=reason)}
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def list_claims(self) -> dict[str, Any]:
        store = self._store(self._pkg())
        try:
            return {"claims": store.read_claims()}
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

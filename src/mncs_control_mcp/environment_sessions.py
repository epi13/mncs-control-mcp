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

import importlib
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import ControlConfig
from .errors import ControlError

PACKAGE = "mncs_env"
ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"
_CAMPAIGN_ID_MAX = 160
_CAMPAIGN_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CONTINUABLE_LIFECYCLES = frozenset({
    "active", "blocked", "waiting", "checkpointed", "abandoned",
})
_TERMINAL_LIFECYCLES = frozenset({"completed", "failed"})


def _load_flat_package(package: str, root: Path, submodules: tuple[str, ...] = ()) -> Any:
    """Import a sibling package with a flat (repo-root) layout.

    Mirrors ``adapters._load_sibling_package`` for checkouts that keep
    the importable package at the repository root instead of ``src/``.
    Submodules are imported while the checkout is on ``sys.path`` so
    attribute access (``pkg.sessions``) works afterwards.
    """
    for candidate in (root / "src", root):
        if (candidate / package).is_dir():
            sys.path.insert(0, str(candidate))
            try:
                module = importlib.import_module(package)
                for submodule in submodules:
                    submodule_module = importlib.import_module(f"{package}.{submodule}")
                    setattr(module, submodule, submodule_module)
                return module
            except ImportError as exc:
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

    @property
    def environment_path(self) -> Path:
        return self._config.environment_path

    @property
    def state_dir(self) -> Path:
        if self._config.environment_state_dir is not None:
            return self._config.environment_state_dir
        return Path.home() / ".local" / "share" / "mncs-environment"

    def _pkg(self) -> Any:
        try:
            return _load_flat_package(PACKAGE, self.environment_path,
                                      ("sessions", "session_store", "entry", "claims"))
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
            return {
                "available": False,
                "error": exc.code,
                "message": exc.message,
                "path": str(self.environment_path),
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
            )
        except ControlError:
            raise
        except Exception as exc:
            if type(exc).__name__ == "RightsBlocked":
                raise ControlError("ENVIRONMENT_ENTER_DENIED", str(exc)) from exc
            if type(exc).__name__ == "AuthorityDenied":
                raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", str(exc)) from exc
            raise ControlError("ENVIRONMENT_ENTER_FAILED", str(exc)) from exc

    def campaign_continuation(
        self, repository: str, campaign_id: str | None = None,
    ) -> dict[str, Any]:
        """Return an authenticated, repository-scoped continuation capsule.

        Environment remains the authority for session and campaign semantics:
        this adapter enumerates canonical Store snapshots, asks Environment's
        Session object for its compact context, and returns only sessions that
        share Control's authenticated principal. Without a campaign identity,
        it discovers same-principal campaigns from the requested repository.
        The repository selector must already occur in a campaign's intent,
        checkout facts, repository references, or live claim.
        """
        if (campaign_id is not None
                and (not isinstance(campaign_id, str) or not campaign_id.strip()
                     or len(campaign_id) > _CAMPAIGN_ID_MAX or "\x00" in campaign_id)):
            raise ControlError("ENVIRONMENT_CAMPAIGN_ID_INVALID",
                               "campaign identity must be bounded nonempty text when supplied")
        if self.authenticated_principal_id is None:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "campaign lookup requires a Control-authenticated principal")
        repository = self._validate_repository_selector(repository)
        pkg = self._pkg()
        store = self._store(pkg)
        try:
            session_ids = store.list_sessions()
            if len(session_ids) > 10000:
                raise ControlError(
                    "ENVIRONMENT_LOOKUP_LIMIT",
                    "canonical Environment session inventory exceeds the bounded lookup limit",
                    details={"session_count": len(session_ids), "limit": 10000},
                )
            claims_by_session: dict[str, list[dict[str, Any]]] = {}
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
                references_repository = self._snapshot_references_repository(
                    snapshot, repository, claims_by_session.get(session_id, [])
                )
                if snapshot.get("authenticated_principal_id") != self.authenticated_principal_id:
                    # Environment treats campaign identity as globally unique;
                    # a foreign live owner blocks lookup even when a damaged or
                    # older projection omits a repository link. Discovery also
                    # refuses an active foreign owner for the requested project.
                    foreign_campaigns.add(identity)
                    foreign_owner = foreign_owner or campaign_id is not None or references_repository
                    continue
                owned_by_campaign.setdefault(identity, []).append((session_id, snapshot))
                if references_repository:
                    project_campaigns.add(identity)

            foreign_owner = foreign_owner or bool(project_campaigns & foreign_campaigns)
            if foreign_owner:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "campaign or project work is owned by a different authenticated principal",
                    details={**({"campaign_id": campaign_id} if campaign_id is not None else {}),
                             "next": "request an explicit handoff from the recorded owner"},
                )

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
                    "continuations": [],
                    "next": "verify the campaign identity and that this repository belongs to its recorded work intent",
                }

            results: list[dict[str, Any]] = []
            for selected_campaign in candidate_campaigns:
                matching = owned_by_campaign.get(selected_campaign, [])
                project_sessions = [
                    (session_id, snapshot) for session_id, snapshot in matching
                    if self._snapshot_references_repository(
                        snapshot, repository, claims_by_session.get(session_id, [])
                    )
                ]
                if not project_sessions:
                    continue
                contexts = {
                    (str((snapshot.get("provenance") or {}).get("definition_id", "")),
                     str((snapshot.get("workspace") or {}).get("root", "")))
                    for _, snapshot in matching
                }
                if len(contexts) > 1:
                    raise ControlError(
                        "ENVIRONMENT_CAMPAIGN_CONTEXT_CONFLICT",
                        "campaign identity is bound to more than one Environment definition or workspace",
                        details={"campaign_id": selected_campaign,
                                 "next": "inspect the recorded definition and workspace before continuing"},
                    )
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
                    "next": (
                        "resume the listed session by its exact session identity"
                        if len(continuations) == 1
                        else "select the intended listed session; Control will not choose between continuations"
                    ),
                })
            if not results:
                return {
                    "schema_version": "mncs.control.campaign-continuation/1",
                    "campaign_id": campaign_id,
                    "repository": repository,
                    "status": "not-found",
                    "continuations": [],
                    "next": "verify the campaign identity and that this repository belongs to its recorded work intent",
                }
            if campaign_id is not None or len(results) == 1:
                return results[0]
            return {
                "schema_version": "mncs.control.campaign-continuation/1",
                "repository": repository,
                "status": "ambiguous-campaigns",
                "campaigns": results[:16],
                "campaigns_truncated": len(results) > 16,
                "next": "select the intended campaign identity; Control will not choose between campaigns",
            }
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
    ) -> bool:
        campaign = snapshot.get("campaign")
        campaign = campaign if isinstance(campaign, dict) else {}
        intent = campaign.get("work_intent")
        intent = intent if isinstance(intent, dict) else {}
        intent_repositories = intent.get("repositories")
        if isinstance(intent_repositories, list) and repository in intent_repositories:
            return True
        for field in ("repository_refs",):
            values = campaign.get(field)
            if isinstance(values, list) and any(
                isinstance(item, dict) and item.get("repository") == repository
                for item in values
            ):
                return True
        for field in ("selected_checkouts", "repo_facts"):
            values = snapshot.get(field)
            if isinstance(values, dict) and repository in values:
                return True
        return any(claim.get("repository") == repository for claim in claims)

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
    ) -> list[dict[str, Any]]:
        """Relate persisted checkout facts to the bounded live Git observation."""
        if live_observation.get("status") != "current":
            return [{"status": "unknown_live_observation"} for _ in references[:8]]

        root = str(live_observation.get("workspace_root", ""))

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

    @staticmethod
    def _continuation_capsule(
        pkg: Any, store: Any, session_id: str, snapshot: dict[str, Any],
        repository: str, claims: list[dict[str, Any]],
        live_observation: dict[str, Any],
    ) -> dict[str, Any]:
        session = pkg.sessions.Session.open(
            state_dir=Path("."), session_id=session_id, backend="store", store=store,
        )
        context = session.context()
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
        return {
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
            "work_intent": work_intent,
            "repositories": selected_references,
            "repository_facts_source": "persisted Environment snapshot; may be stale",
            "live_repository_observation": live_observation,
            "recorded_checkout_comparisons": EnvironmentService._compare_recorded_checkouts(
                selected_references, live_observation,
            ),
            "claim_ids": [str(claim.get("claim_id")) for claim in claim_capsules],
            "claims": EnvironmentService._bounded_capsule_value(claim_capsules[:8]),
            "checkpoint_ids": [str(item)[:160] for item in
                               continuation.get("checkpoint_ids", [])[-8:]
                               if isinstance(item, str)]
            if isinstance(continuation.get("checkpoint_ids", []), list) else [],
            "evidence": EnvironmentService._bounded_capsule_value(
                continuation.get("evidence", [])[-8:]
                if isinstance(continuation.get("evidence", []), list) else []
            ),
            "delivery": EnvironmentService._bounded_capsule_value(
                continuation.get("delivery", campaign.get("delivery", {"status": "pending"}))
            ),
            "unresolved_pressures": EnvironmentService._bounded_capsule_value(
                continuation.get("unresolved_pressures", [])[:8]
                if isinstance(continuation.get("unresolved_pressures", []), list) else []
            ),
        }

    @staticmethod
    def _bounded_capsule_value(value: Any, *, depth: int = 0) -> Any:
        """Keep Store-originated evidence compact before returning it to MCP."""
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:1200]
        if depth >= 4:
            return "[truncated]"
        if isinstance(value, list):
            return [EnvironmentService._bounded_capsule_value(item, depth=depth + 1)
                    for item in value[:8]]
        if isinstance(value, dict):
            return {
                str(key)[:120]: EnvironmentService._bounded_capsule_value(item, depth=depth + 1)
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

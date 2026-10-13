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
_CAMPAIGN_CHARTER_EVIDENCE_SEARCH_MAX = 128
_GIT_OBJECT_ID = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
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
                                      ("sessions", "session_store", "entry", "claims",
                                       "campaign_selector"))
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
                             "next": "request an explicit handoff from the recorded owner"},
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
        in a campaign's intent, checkout facts, repository references, or live
        claim; a selector never grants ownership or adopts a campaign.
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
                            and self._snapshot_references_repository(
                                candidate_snapshot, repository,
                                claims_by_session.get(candidate_session_id, []),
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
                    if snapshot.get("authenticated_principal_id") != self.authenticated_principal_id:
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
                        "references_repository": self._snapshot_references_repository(
                            bound_snapshot, repository,
                            claims_by_session.get(str(bound_session_id), []),
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
    ) -> bool:
        return bool(EnvironmentService._snapshot_repository_reference_basis(
            snapshot, repository, claims,
        ))

    @staticmethod
    def _snapshot_repository_reference_basis(
        snapshot: dict[str, Any], repository: str, claims: list[dict[str, Any]],
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
        return tuple(basis)

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

    def _continuation_capsule(
        self,
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
        project_reference_basis = self._snapshot_repository_reference_basis(
            snapshot, repository, claims,
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
            # Search the owner-validated full ledger for the charter pointer,
            # while keeping the emitted context capsule on its bounded recent
            # evidence window.
            charter_evidence = campaign_state["evidence"]
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
        """Project a charter only when its Environment evidence link verifies.

        The evidence reference chooses a Git object and relative path, never a
        host path. Reads are confined to the configured Environment project,
        an immediate nonsymlink child of the workspace, and to small blobs in
        the exact recorded commit. The digest and charter campaign identity
        must both match before any objective text reaches the capsule.
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
        # Old and new charters can both be legitimate evidence. Do not select
        # one based on list order when the campaign projection is ambiguous.
        if len(candidates) != 1:
            return None

        reference = candidates[0]
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
            return None
        path_parts = path_value.split("/")
        if any(part in {"", ".", ".."} for part in path_parts):
            return None
        relative_path = PurePosixPath(path_value)
        if relative_path.is_absolute():
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

        object_spec = f"{commit}:{relative_path.as_posix()}"
        git_environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(workspace_root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        }
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
                return None
            blob_size = int(size_result.stdout.strip())
            if blob_size < 1 or blob_size > _CAMPAIGN_CHARTER_MAX_BYTES:
                return None
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
                return None
            charter = json.loads(blob_result.stdout.decode("utf-8"))
        except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
            return None

        if (not isinstance(charter, dict)
                or charter.get("schema_version") != _CAMPAIGN_CHARTER_SCHEMA
                or charter.get("campaign_identity") != campaign_identity):
            return None
        objective = charter.get("objective")
        charter_identity = charter.get("identity")
        if (not isinstance(objective, str) or not objective.strip()
                or not isinstance(charter_identity, str) or not charter_identity):
            return None
        return {
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
        }

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

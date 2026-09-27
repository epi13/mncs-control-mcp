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
import sys
from pathlib import Path
from typing import Any

from .config import ControlConfig
from .errors import ControlError

PACKAGE = "mncs_env"
ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"


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
        #: plan_id -> repository names resolver (set by the server wiring).
        self.plan_resolver = None
        #: job_id -> {"project", "scope"} resolver (set by the server wiring).
        self.job_resolver = None

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
            return _load_flat_package(
                PACKAGE,
                self.environment_path,
                ("sessions", "session_store", "workspace", "authority", "claims"),
            )
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError(ENVIRONMENT_UNAVAILABLE, f"mncs_env failed to load: {exc}") from exc

    def _sessions(self) -> Any:
        return self._pkg().sessions

    def _store(self, pkg: Any) -> Any:
        return pkg.session_store.open_store(self.state_dir, "store")

    def _resolve_repo(self, repository: str | None, path: str | None) -> str | None:
        """Map a tool scope to a workspace repository name (None when unmapped).

        Paths inside a managed worktree resolve to the owner repository;
        the checkout itself is recovered separately for worktree claims.
        """
        if repository:
            return repository
        if not path:
            return None
        match = self._match_record(path)
        if match is None:
            return None
        return str(match.get("worktree_of") or match.get("name", ""))

    def _match_record(self, path: str) -> dict[str, Any] | None:
        try:
            pkg = self._pkg()
            view = pkg.workspace.discover_workspace(self._config.workspace_root)
        except Exception:
            return None
        candidate = (self._config.workspace_root / path).resolve()
        best: dict[str, Any] | None = None
        best_len = -1
        for repo in view.get("repositories", []):
            if not isinstance(repo, dict):
                continue
            repo_path = Path(str(repo.get("path", ""))).resolve()
            if candidate == repo_path or repo_path in candidate.parents:
                if len(str(repo_path)) > best_len:
                    best, best_len = repo, len(str(repo_path))
        return best

    def _resolve_checkout(self, path: str | None) -> dict[str, Any] | None:
        """Worktree scope for a path inside a managed checkout (None if main)."""
        if not path:
            return None
        match = self._match_record(path)
        if match is None or not match.get("worktree_of"):
            return None
        return {
            "kind": "worktree",
            "repository": str(match["worktree_of"]),
            "checkout": str(Path(str(match["path"])).resolve()),
        }

    def authorize(
        self,
        session_id: str | None,
        tool: str,
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Decide whether an Environment session may perform a mutation.

        Pure read-only check (never appends session events): opens the
        session, evaluates live claims plus snapshot authority, and fails
        closed on any error. Control enforces; Environment decides.
        """
        scope = dict(scope or {})
        if not session_id:
            return {
                "allowed": False,
                "verdict": "deny",
                "reason": "managed mode requires env_session",
                "audit": {"tool": tool},
            }
        try:
            pkg = self._pkg()
        except ControlError as exc:
            return {
                "allowed": False,
                "verdict": "deny",
                "reason": f"environment unavailable: {exc.message}",
                "audit": {"tool": tool},
            }
        store = self._store(pkg)
        try:
            sessions = pkg.sessions
            try:
                session = sessions.Session.open(
                    state_dir=self.state_dir, session_id=session_id, store=store
                )
            except Exception as exc:
                return {
                    "allowed": False,
                    "verdict": "deny",
                    "reason": f"unknown session {session_id}: {exc}",
                    "audit": {"tool": tool, "session_id": session_id},
                }
            special = self._special_scope(session, tool, scope)
            if special is not None:
                if special.get("allowed") == "generic":
                    scope = special["scope"]
                elif special.get("allowed") == "defer-each":
                    return self._decide_each(
                        session, store, tool, special["repositories"], special.get("audit", {})
                    )
                else:
                    return special
            claim_scope = scope.get("claim_scope") or self._infer_claim_scope(scope)
            checks = self._check_targets(scope)
            if not checks:
                return {
                    "allowed": False,
                    "verdict": "deny",
                    "reason": f"tool {tool} scope maps to no workspace repository",
                    "audit": {"tool": tool, "session_id": session_id},
                }
            authority = pkg.authority
            try:
                holders = self._holder_infos(store)
            except Exception as exc:
                return {
                    "allowed": False,
                    "verdict": "deny",
                    "reason": f"claim state unreadable: {exc}",
                    "audit": {"tool": tool, "session_id": session_id},
                }
            claims_found: list[str] = []
            facts = self._fresh_repo_facts([repository for _, repository, _ in checks])
            if not facts:
                facts = session.snapshot.get("repo_facts", {})
            for action, repository, target in checks:
                try:
                    verdict = authority.evaluate(
                        session.snapshot.get("authority", {}),
                        action=action,
                        target=target,
                        session_id=session_id,
                        claims=holders,
                        repo_facts=facts,
                        scope=claim_scope,
                    )
                except Exception as exc:
                    return {
                        "allowed": False,
                        "verdict": "deny",
                        "reason": f"authority evaluation failed: {exc}",
                        "audit": {"tool": tool, "session_id": session_id},
                    }
                if verdict.get("verdict") != "allow":
                    return {
                        "allowed": False,
                        "verdict": verdict.get("verdict"),
                        "reason": verdict.get("reason"),
                        "audit": {
                            "tool": tool,
                            "session_id": session_id,
                            "consumer": session.snapshot.get("consumer_id"),
                            "action": action,
                            "target": target,
                            "verdict": verdict.get("verdict"),
                            "reason": verdict.get("reason"),
                        },
                    }
                claim = self._covering_claim(holders, session_id, repository)
                if claim:
                    claims_found.append(claim)
            first_action, _, first_target = checks[0]
            audit = {
                "tool": tool,
                "session_id": session_id,
                "consumer": session.snapshot.get("consumer_id"),
                "action": first_action,
                "target": first_target,
                "verdict": "allow",
            }
            if claims_found:
                audit["claim_id"] = claims_found[0]
            return {
                "allowed": True,
                "verdict": "allow",
                "reason": f"authority allows all {len(checks)} scope targets",
                "audit": audit,
            }
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def _special_scope(
        self, session: Any, tool: str, scope: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Decide scopes the generic repo/path model cannot express.

        Returns None when the generic path should decide. Creation of new
        checkouts is allowed only inside declared intent writable scope;
        stewardship plans require authority over every touched repo; job
        operations require a live session plus authority over the owning
        project when known.
        """
        audit_base = {
            "tool": tool,
            "session_id": session.session_id,
            "consumer": session.snapshot.get("consumer_id"),
        }
        declared = set(session.snapshot.get("intent", {}).get("repositories", []))
        if scope.get("create_name"):
            name = str(scope["create_name"])
            if name in declared:
                audit = dict(audit_base, action="write", target=name, verdict="allow")
                return {
                    "allowed": True,
                    "verdict": "allow",
                    "reason": f"{name} is declared writable scope",
                    "audit": audit,
                }
            return {
                "allowed": False,
                "verdict": "deny",
                "reason": f"{name} is not declared writable scope for this session",
                "audit": dict(audit_base, action="write", target=name),
            }
        if scope.get("stewardship_plan"):
            if self.plan_resolver is None:
                return {
                    "allowed": False,
                    "verdict": "deny",
                    "reason": "no stewardship plan resolver wired",
                    "audit": audit_base,
                }
            try:
                repos = self.plan_resolver(scope["stewardship_plan"])
            except Exception as exc:
                repos = None
                resolve_error = str(exc)
            else:
                resolve_error = ""
            if not repos:
                return {
                    "allowed": False,
                    "verdict": "deny",
                    "reason": "stewardship plan unknown or expired"
                    + (f": {resolve_error}" if resolve_error else ""),
                    "audit": audit_base,
                }
            return {"allowed": "defer-each", "repositories": repos, "audit": audit_base}
        if scope.get("job_id"):
            project = None
            if self.job_resolver is not None:
                try:
                    info = self.job_resolver(scope["job_id"]) or {}
                    project = info.get("project")
                except Exception:
                    project = None
            if not project:
                audit = dict(
                    audit_base, action="execute", target=f"job:{scope['job_id']}", verdict="allow"
                )
                return {
                    "allowed": True,
                    "verdict": "allow",
                    "reason": "live session accountability for untracked job",
                    "audit": audit,
                }
            return {"allowed": "generic", "scope": dict(scope, repository=project)}
        return None

    def _decide_each(
        self,
        session: Any,
        store: Any,
        tool: str,
        repositories: list[str],
        audit_base: dict[str, Any],
    ) -> dict[str, Any]:
        """Stewardship: allow only with authority over every touched repo."""
        pkg = self._pkg()
        holders = self._holder_infos(store)
        denied: list[str] = []
        for repository in repositories:
            verdict = pkg.authority.evaluate(
                session.snapshot.get("authority", {}),
                action="execute",
                target=repository,
                session_id=session.session_id,
                claims=holders,
                repo_facts=session.snapshot.get("repo_facts", {}),
            )
            if verdict.get("verdict") != "allow":
                denied.append(f"{repository}: {verdict.get('reason')}")
        audit = dict(audit_base, action="execute", repositories=repositories)
        if denied:
            audit["denied"] = denied
            return {
                "allowed": False,
                "verdict": "deny",
                "reason": "stewardship refused: " + "; ".join(denied),
                "audit": audit,
            }
        audit["verdict"] = "allow"
        return {
            "allowed": True,
            "verdict": "allow",
            "reason": f"authority over all {len(repositories)} plan repos",
            "audit": audit,
        }

    def _holder_infos(self, store: Any) -> dict[str, Any]:
        pkg = self._pkg()
        grouped: dict[str, Any] = {}
        try:
            live = pkg.claims.active_claims(store.read_claims())
        except Exception:
            return grouped
        for record in live.values():
            grouped.setdefault(str(record.get("repository", "")), []).append(
                {
                    "claim_id": str(record.get("claim_id", "")),
                    "session_id": str(record.get("session_id", "")),
                    "scope": record.get("scope", {"kind": "repository"}),
                }
            )
        return grouped

    def _covering_claim(
        self, holders: dict[str, Any], session_id: str, repository: str
    ) -> str | None:
        for info in holders.get(repository, []):
            if info.get("session_id") == session_id:
                return str(info.get("claim_id", "") or "held")
        return None

    def _fresh_repo_facts(self, repositories: list[str]) -> dict[str, Any]:
        """Re-observe facts for exactly the target repos (bounded).

        A mutation gate decides on current truth, not resolution-time
        snapshots. One bounded discovery covers all targets; failure
        falls back to snapshot facts at the call site.
        """
        try:
            pkg = self._pkg()
            view = pkg.workspace.discover_workspace(self._config.workspace_root)
        except Exception:
            return {}
        wanted = set(repositories)
        facts: dict[str, Any] = {}
        for repo in view.get("repositories", []):
            if not isinstance(repo, dict):
                continue
            name = str(repo.get("worktree_of") or repo.get("name", ""))
            if name not in wanted:
                continue
            facts[name] = {
                "clean": not repo.get("dirty", True) and not repo.get("git_error"),
                "main_branch": repo.get("branch") in pkg.workspace.MAIN_BRANCHES,
                "foreign_signals": pkg.workspace.foreign_work_signals(repo),
            }
        return facts

    def _infer_claim_scope(self, scope: dict[str, Any]) -> dict[str, Any] | None:
        """Derive a worktree claim scope from tool paths (None for main)."""
        for key in ("path", "also_path"):
            found = self._resolve_checkout(scope.get(key))
            if found is not None:
                return found
        patch_paths = scope.get("patch_paths")
        if isinstance(patch_paths, list):
            for sub in patch_paths[:25]:
                if isinstance(sub, str) and sub:
                    found = self._resolve_checkout(sub)
                    if found is not None:
                        return found
        return None

    def _target_for(self, path: str) -> tuple[str, str] | None:
        """Map a workspace-relative path to (repository, repo-relative target).

        Paths inside a managed worktree relativize against the checkout so
        worktree claims cover their own files.
        """
        checkout = self._resolve_checkout(path)
        candidate = (self._config.workspace_root / path).resolve()
        if checkout is not None:
            try:
                rel = candidate.relative_to(Path(checkout["checkout"]).resolve())
            except ValueError:
                return None
            repo = checkout["repository"]
            return repo, f"{repo}/{rel}" if str(rel) != "." else repo
        match = self._match_record(path)
        if match is None:
            return None
        repo = str(match.get("worktree_of") or match.get("name", ""))
        try:
            rel = candidate.relative_to(Path(str(match["path"])).resolve())
        except ValueError:
            return None
        return repo, f"{repo}/{rel}" if str(rel) != "." else repo

    def _check_targets(self, scope: dict[str, Any]) -> list[tuple[str, str, str]]:
        """Expand a tool scope to (action, repository, target) checks.

        Path-scoped operations check exactly their paths (a paths or
        worktree claim suffices); bare-repository operations check the
        whole repo (only a repository claim or pristine facts allow).
        Repo-wide Git actions therefore need repository-level authority
        even when file scopes are disjoint.
        """
        action = str(scope.get("action", "write"))
        context = scope.get("repository")
        context = context if isinstance(context, str) and context else None
        pairs: list[tuple[str, str]] = []
        paths = scope.get("paths")
        if isinstance(paths, list) and context:
            for sub in paths[:25]:
                if isinstance(sub, str) and sub:
                    pairs.append((context, f"{context}/{sub}"))
        for key in ("path", "also_path"):
            value = scope.get(key)
            if isinstance(value, str) and value not in (None, "", "."):
                if context:
                    pairs.append((context, f"{context}/{value}"))
                else:
                    mapped = self._target_for(value)
                    if mapped is None:
                        return []
                    pairs.append(mapped)
        patch_paths = scope.get("patch_paths")
        if isinstance(patch_paths, list):
            for sub in patch_paths[:25]:
                if not isinstance(sub, str) or not sub:
                    continue
                if context:
                    pairs.append((context, f"{context}/{sub}"))
                else:
                    mapped = self._target_for(sub)
                    if mapped is None:
                        return []
                    pairs.append(mapped)
        if pairs:
            return [(action, repo, target) for repo, target in pairs]
        if context:
            return [(action, context, context)]
        if scope.get("terminal_scope") == "workspace":
            return []
        return []

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
    ) -> dict[str, Any]:
        sessions = self._sessions()
        workspace_root = self._resolve_workspace(workspace)
        store = self._store(self._pkg())
        try:
            environment = sessions.resolve_environment(
                definition=definition,
                workspace_root=workspace_root,
                state_dir=self.state_dir,
                consumer_id=consumer,
                store=store,
            )
            try:
                session = sessions.Session.create(
                    state_dir=self.state_dir,
                    environment=environment,
                    consumer_id=consumer,
                    consumer_kind=consumer_kind,
                    store=store,
                )
            except Exception as exc:
                name = type(exc).__name__
                if name in ("RightsBlocked", "AuthorityDenied"):
                    raise ControlError("ENVIRONMENT_ENTER_DENIED", str(exc)) from exc
                raise
            session.transition("resolving", "control: resolving environment")
            session.transition("ready", "control: environment resolved")
            session.transition("active", f"control: consumer {consumer} entered")
            return session.inspect()
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("ENVIRONMENT_ENTER_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def _open_session(self, sessions: Any, store: Any, session_id: str) -> Any:
        try:
            return sessions.Session.resume(
                state_dir=self.state_dir, session_id=session_id, store=store
            )
        except Exception as exc:
            name = type(exc).__name__
            if name == "LifecycleError":
                raise ControlError("ENVIRONMENT_SESSION_TERMINAL", str(exc)) from exc
            raise ControlError("ENVIRONMENT_SESSION_MISSING", str(exc)) from exc

    def inspect(self, session_id: str) -> dict[str, Any]:
        sessions = self._sessions()
        store = self._store(self._pkg())
        try:
            session = sessions.Session.open(
                state_dir=self.state_dir, session_id=session_id, store=store
            )
            return session.inspect()
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
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        pkg = self._pkg()
        sessions = pkg.sessions
        store = self._store(pkg)
        try:
            session = self._open_session(sessions, store, session_id)
            try:
                return session.acquire_claim(
                    repository,
                    basis=basis,
                    reason=reason,
                    ttl_hours=ttl_hours,
                    scope=scope,
                )
            except Exception as exc:
                if type(exc).__name__ == "ClaimConflict":
                    raise ControlError("ENVIRONMENT_CLAIM_CONFLICT", str(exc)) from exc
                if type(exc).__name__ == "ClaimAdoptionRequired":
                    raise ControlError("ENVIRONMENT_CLAIM_ADOPTION", str(exc)) from exc
                raise ControlError("ENVIRONMENT_CLAIM_FAILED", str(exc)) from exc
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def release_claim(
        self, session_id: str, repository: str, reason: str = "", claim_id: str | None = None
    ) -> dict[str, Any]:
        sessions = self._sessions()
        store = self._store(self._pkg())
        try:
            session = self._open_session(sessions, store, session_id)
            return {"released": session.release_claim(repository, reason=reason, claim_id=claim_id)}
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

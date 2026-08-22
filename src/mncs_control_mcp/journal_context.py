"""Bounded local evidence projection for the Atlas Development Journal.

This module is intentionally a projection surface. Git, experiments, Commons,
Fabric, Forge, Control jobs, and the private audit log retain ownership of
their records; this service only collects bounded, provenance-rich references
for a requested interval. Every returned item is inert, untrusted data.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .audit import AuditLog
from .config import ControlConfig
from .errors import ControlError
from .git_adapter import GitService
from .security import is_sensitive_name, redact_text
from .workspace import WorkspacePolicy

STATES = {"AVAILABLE", "PARTIAL", "EMPTY", "UNAVAILABLE", "UNKNOWN", "MALFORMED"}
SOURCE_NAMES = (
    "local_repositories",
    "working_trees",
    "experiments",
    "commons",
    "fabric",
    "forge",
    "control_activity",
    "local_notes",
)
SKIP_DIRECTORIES = {".git", ".venv", "node_modules", "target", "build", "dist", "vendor", "__pycache__", ".cache"}
PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def _interval(start: str, end: str) -> tuple[str, str, datetime, datetime]:
    start_dt = _parse(start)
    end_dt = _parse(end)
    if start_dt is None or end_dt is None or end_dt < start_dt:
        raise ControlError("INVALID_INPUT", "start and end must be ordered ISO-8601 timestamps")
    return start_dt.isoformat().replace("+00:00", "Z"), end_dt.isoformat().replace("+00:00", "Z"), start_dt, end_dt


def _bounded(value: object, limit: int, *, redacted: bool = True) -> tuple[str, bool]:
    text = str(value or "")
    if redacted:
        text = redact_text(text)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _stamp(record: object) -> datetime | None:
    if not isinstance(record, dict):
        return None
    for key in (
        "occurred_at",
        "occurredAt",
        "created_at",
        "createdAt",
        "updated_at",
        "updatedAt",
        "started_at",
        "startedAt",
        "accepted_at",
        "acceptedAt",
        "submitted_at",
        "submittedAt",
        "completed_at",
        "completedAt",
        "finished_at",
        "finishedAt",
        "timestamp",
        "observed_at",
        "observedAt",
    ):
        parsed = _parse(record.get(key))
        if parsed is not None:
            return parsed
    return None


def _in_window(record: object, start: datetime, end: datetime) -> bool:
    stamp = _stamp(record)
    return stamp is not None and start <= stamp <= end


class JournalContextService:
    def __init__(
        self,
        config: ControlConfig,
        policy: WorkspacePolicy,
        git: GitService,
        experiments: Any,
        integrations: Any,
        audit: AuditLog,
        processes: Any,
    ) -> None:
        self.config = config
        self.policy = policy
        self.git = git
        self.experiments = experiments
        self.integrations = integrations
        self.audit = audit
        self.processes = processes
        self.state_root = config.journal_bundle_state_path.expanduser().resolve()
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_root, 0o700)

    def _projects(self, requested: list[str] | None) -> list[str]:
        allowed = set(self.config.journal_projects)
        aliases = self.config.repositories
        selected = requested if requested is not None else list(self.config.journal_projects)
        resolved: list[str] = []
        for value in selected:
            if not isinstance(value, str) or not PROJECT_NAME.fullmatch(value):
                raise ControlError("INVALID_PROJECT", "journal projects must be immediate workspace child names")
            project = aliases.get(value, value)
            if project not in allowed or project not in self.config.journal_projects:
                raise ControlError("JOURNAL_PROJECT_NOT_ALLOWED", f"project is outside the journal allow-list: {value}")
            self.policy.project_path(project, must_exist=False)
            if project not in resolved:
                resolved.append(project)
        return resolved

    def status(self) -> dict[str, object]:
        if not self.config.journal_enabled:
            return {"overall": "UNAVAILABLE", "enabled": False, "sources": {name: {"status": "UNAVAILABLE", "reason": "journal context is disabled"} for name in SOURCE_NAMES}}
        sources: dict[str, dict[str, object]] = {}
        projects = self._projects(None)
        existing = [project for project in projects if (self.config.workspace_root / project).is_dir()]
        git_available = bool(existing) and any((self.config.workspace_root / project / ".git").exists() for project in existing)
        sources["local_repositories"] = {"status": "AVAILABLE" if git_available else "EMPTY", "projects_configured": len(projects), "projects_present": len(existing)}
        sources["working_trees"] = {"status": "AVAILABLE" if git_available else "EMPTY"}
        sources["local_notes"] = {"status": "AVAILABLE" if existing else "EMPTY", "configured": bool(self.config.journal_include_patterns)}
        sources["experiments"] = self._integration_status("experiments", lambda: self.experiments.list())
        sources["commons"] = self._adapter_status(self.integrations.commons.status)
        sources["fabric"] = self._adapter_status(self.integrations.fabric.status)
        sources["forge"] = self._adapter_status(self.integrations.forge.status)
        audit_state = self.audit.journal_availability()
        sources["control_activity"] = {"status": audit_state["status"], "path_configured": True}
        statuses = [str(value.get("status")) for value in sources.values()]
        overall = "AVAILABLE" if statuses and all(item in {"AVAILABLE", "EMPTY"} for item in statuses) else "PARTIAL"
        if all(item == "EMPTY" for item in statuses):
            overall = "EMPTY"
        if not self.config.workspace_root.is_dir():
            overall = "UNAVAILABLE"
        return {"enabled": True, "overall": overall, "scope": {"workspace_root": str(self.policy.root), "projects": projects}, "sources": sources}

    @staticmethod
    def _adapter_status(function: Callable[[], dict[str, object]]) -> dict[str, object]:
        try:
            value = function()
        except Exception as exc:
            return {"status": "UNAVAILABLE", "diagnostic": redact_text(str(exc))[:400]}
        if not isinstance(value, dict) or value.get("available") is False:
            return {"status": "UNAVAILABLE", "diagnostic": redact_text(str(value.get("diagnostic", "adapter unavailable")))[:400] if isinstance(value, dict) else "malformed adapter response"}
        return {"status": "AVAILABLE" if value.get("status") not in {"empty", "unavailable"} else str(value.get("status")).upper(), "transport": value.get("transport"), "authority": value.get("authority")}

    @staticmethod
    def _integration_status(name: str, function: Callable[[], object]) -> dict[str, object]:
        try:
            value = function()
        except Exception as exc:
            return {"status": "UNAVAILABLE", "diagnostic": redact_text(str(exc))[:400], "source": name}
        if isinstance(value, dict) and "experiments" in value:
            return {"status": "AVAILABLE" if value.get("experiments") else "EMPTY", "source": name}
        return {"status": "AVAILABLE" if value else "EMPTY", "source": name}

    def collect(
        self,
        *,
        start: str,
        end: str,
        projects: list[str] | None = None,
        include_local_git: bool = True,
        include_uncommitted: bool = True,
        include_experiments: bool = True,
        include_commons: bool = True,
        include_control_activity: bool = True,
        include_fabric_refs: bool = True,
        include_forge_refs: bool = True,
        editor_hints: list[str] | None = None,
        page_size: int = 50,
    ) -> dict[str, object]:
        if not self.config.journal_enabled:
            raise ControlError("JOURNAL_CONTEXT_DISABLED", "journal context collection is disabled")
        start_text, end_text, start_dt, end_dt = _interval(start, end)
        selected = self._projects(projects)
        sources: list[dict[str, object]] = []
        items: list[dict[str, object]] = []
        if include_local_git:
            self._collect_git(selected, start_text, end_text, start_dt, end_dt, include_uncommitted, items, sources)
        else:
            sources.extend(self._source(name, "SKIPPED", [], "not requested") for name in ("local_repositories", "working_trees"))
        self._collect_notes(selected, start_dt, end_dt, items, sources)
        if include_experiments:
            self._collect_experiments(start_dt, end_dt, items, sources)
        else:
            sources.append(self._source("experiments", "SKIPPED", [], "not requested"))
        if include_commons:
            self._collect_commons(start_dt, end_dt, items, sources)
        else:
            sources.append(self._source("commons", "SKIPPED", [], "not requested"))
        if include_fabric_refs:
            self._collect_fabric(start_dt, end_dt, items, sources)
        else:
            sources.append(self._source("fabric", "SKIPPED", [], "not requested"))
        if include_forge_refs:
            self._collect_forge(start_dt, end_dt, items, sources)
        else:
            sources.append(self._source("forge", "SKIPPED", [], "not requested"))
        if include_control_activity:
            self._collect_activity(start_dt, end_dt, selected, items, sources)
        else:
            sources.append(self._source("control_activity", "SKIPPED", [], "not requested"))
        items = self._dedupe(items)
        sources = self._ensure_sources(sources)
        completeness = {str(source.get("source_class")): str(source.get("status")) for source in sources}
        for item in items:
            item["source_completeness"] = completeness.get(str(item.get("source_class")), "UNKNOWN")
        truncated_items = 0
        while items and len(json.dumps(items, ensure_ascii=False, sort_keys=True).encode("utf-8")) > self.config.journal_max_bytes:
            items.pop()
            truncated_items += 1
        for source in sources:
            previous_count = int(source.get("item_count") or 0)
            current_count = sum(1 for item in items if item.get("source_class") == source.get("source_class"))
            source["item_count"] = current_count
            if truncated_items or current_count < previous_count:
                source["truncated"] = True
        interval = {"start": start_text, "end": end_text}
        for item in items:
            item["covered_interval"] = interval
        canonical_items = [{key: value for key, value in item.items() if key != "collected_at"} for item in items]
        canonical = {"covered_interval": interval, "projects": selected, "sources": sources, "items": canonical_items}
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        bundle_id = "jctx-" + digest[:32]
        bundle = {
            "bundle_id": bundle_id,
            "bundle_hash": "sha256:" + digest,
            "schema": "mncs-control.journal-context.v1",
            "source_system": "mncs-control-mcp",
            "covered_interval": interval,
            "projects": selected,
            "source_statuses": sources,
            "items": items,
            "item_count": len(items),
            "truncated": truncated_items > 0,
            "truncated_items": truncated_items,
            "created_at": _now(),
            "untrusted_data": True,
            "editor_hints_persisted": False,
        }
        self._save(bundle)
        response = self._page(bundle, 0, page_size)
        if editor_hints:
            response["editor_hints"] = [
                {"text": _bounded(hint, 1000)[0], "authority": "LOW", "persisted": False, "untrusted_data": True}
                for hint in editor_hints[:8]
                if isinstance(hint, str) and hint.strip()
            ]
        return response

    def get(self, bundle_id: str, *, cursor: int = 0, page_size: int = 50) -> dict[str, object]:
        if not re.fullmatch(r"jctx-[0-9a-f]{32}", bundle_id):
            raise ControlError("INVALID_INPUT", "bundle_id is invalid")
        if cursor < 0 or page_size < 1 or page_size > 500:
            raise ControlError("INVALID_INPUT", "cursor/page_size is outside the configured bound")
        path = self.state_root / f"{bundle_id}.json"
        try:
            age = datetime.now(UTC).timestamp() - path.stat().st_mtime
            if age > self.config.journal_bundle_retention_seconds:
                raise ControlError("JOURNAL_BUNDLE_EXPIRED", "journal context bundle exceeded its retention period")
        except FileNotFoundError as exc:
            raise ControlError("JOURNAL_BUNDLE_NOT_FOUND", "journal context bundle is unavailable") from exc
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ControlError("JOURNAL_BUNDLE_NOT_FOUND", "journal context bundle is unavailable") from exc
        if not isinstance(bundle, dict) or bundle.get("bundle_id") != bundle_id:
            raise ControlError("JOURNAL_BUNDLE_INVALID", "journal context bundle is invalid")
        return self._page(bundle, cursor, page_size)

    def _page(self, bundle: dict[str, object], cursor: int, page_size: int) -> dict[str, object]:
        items = bundle.get("items") if isinstance(bundle.get("items"), list) else []
        page = items[cursor : cursor + page_size]
        next_cursor = cursor + len(page) if cursor + len(page) < len(items) else None
        return {
            "schema": bundle.get("schema"),
            "bundle_id": bundle.get("bundle_id"),
            "bundle_hash": bundle.get("bundle_hash"),
            "covered_interval": bundle.get("covered_interval"),
            "projects": bundle.get("projects"),
            "source_statuses": bundle.get("source_statuses"),
            "item_count": bundle.get("item_count"),
            "truncated": bundle.get("truncated", False),
            "truncated_items": bundle.get("truncated_items", 0),
            "items": page,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "untrusted_data": True,
        }

    def _save(self, bundle: dict[str, object]) -> None:
        path = self.state_root / f"{bundle['bundle_id']}.json"
        temporary = path.with_suffix(".json.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    def _source(self, name: str, status: str, items: list[dict[str, object]], detail: str | None = None) -> dict[str, object]:
        if status not in STATES and status != "SKIPPED":
            status = "UNKNOWN"
        return {"source_class": name, "status": status, "item_count": len(items), "detail": detail, "untrusted_data": True}

    def _ensure_sources(self, sources: list[dict[str, object]]) -> list[dict[str, object]]:
        by_name = {str(source.get("source_class")): source for source in sources}
        return [by_name.get(name, self._source(name, "UNKNOWN", [], "collector did not return a result")) for name in SOURCE_NAMES]

    def _item(
        self,
        *,
        source_class: str,
        source_system: str,
        project: str | None,
        locator: str,
        occurred_at: object,
        summary: object,
        local_only: bool = False,
        development_state: str | None = None,
        authority: str = "provisional-developmental-evidence",
        confidence: str = "MEDIUM",
        unresolved: bool = False,
        negative: bool = False,
        content_hash: str | None = None,
    ) -> dict[str, object]:
        safe_summary, truncated = _bounded(summary, self.config.journal_excerpt_bytes)
        stamp = _parse(occurred_at)
        occurred = stamp.isoformat().replace("+00:00", "Z") if stamp else None
        identity = content_hash or hashlib.sha256(f"{source_class}|{project}|{locator}|{occurred}|{safe_summary}".encode()).hexdigest()
        return {
            "evidence_id": f"control:{source_class}:{identity[:24]}",
            "source_class": source_class,
            "source_system": source_system,
            "project_id": project,
            "repository": project,
            "locator": redact_text(locator)[:512],
            "occurred_at": occurred,
            "collected_at": _now(),
            "local_only": local_only,
            "development_state": development_state or ("local-uncommitted" if local_only else "recorded"),
            "authority": authority,
            "content_hash": "sha256:" + identity,
            "summary": safe_summary,
            "truncated": truncated,
            "source_completeness": "AVAILABLE",
            "redacted": True,
            "confidence": confidence,
            "unresolved": unresolved,
            "negative": negative,
            "untrusted_data": True,
        }

    def _dedupe(self, items: list[dict[str, object]]) -> list[dict[str, object]]:
        seen: set[str] = set()
        result: list[dict[str, object]] = []
        for item in sorted(items, key=lambda value: (str(value.get("occurred_at") or ""), str(value.get("evidence_id")))):
            evidence_id = str(item.get("evidence_id"))
            if evidence_id not in seen:
                seen.add(evidence_id)
                result.append(item)
        return result[: self.config.journal_max_items]

    def _collect_git(self, projects: list[str], start: str, end: str, start_dt: datetime, end_dt: datetime, include_uncommitted: bool, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        git_items: list[dict[str, object]] = []
        tree_items: list[dict[str, object]] = []
        for project in projects:
            root = self.config.workspace_root / project
            if not root.is_dir() or not (root / ".git").exists():
                continue
            try:
                snapshot = self.git.journal_snapshot(project, start=start, end=end, max_commits=self.config.journal_max_items)
                status = self.git.status(project)
            except Exception as exc:
                sources.append(self._source("local_repositories", "PARTIAL", [], f"{project}: {redact_text(str(exc))[:300]}"))
                continue
            summary = f"branch={snapshot.get('branch') or 'detached'} head={snapshot.get('head') or 'UNKNOWN'} tracking={snapshot.get('tracking_remote') or 'UNKNOWN'} ahead_behind={snapshot.get('ahead_behind')}"
            commits = snapshot.get("commits") if isinstance(snapshot.get("commits"), list) else []
            local_branches = snapshot.get("local_only_branches") if isinstance(snapshot.get("local_only_branches"), list) else []
            changes = status.get("changes") if isinstance(status, dict) else []
            if commits or local_branches or (include_uncommitted and changes and datetime.now(UTC) <= end_dt):
                git_items.append(self._item(source_class="local_repositories", source_system="git", project=project, locator=f"{project}:HEAD", occurred_at=end, summary=summary, confidence="HIGH" if snapshot.get("head") else "UNKNOWN"))
            for commit in snapshot.get("commits", []):
                if isinstance(commit, dict):
                    commit_id = str(commit.get("commit") or "")
                    git_items.append(self._item(source_class="local_repositories", source_system="git", project=project, locator=f"{project}:commit:{commit_id}", occurred_at=commit.get("occurred_at"), summary=f"{commit.get('subject', '')}; files={commit.get('files', [])}", local_only=bool(commit.get("local_only")), development_state="local-only-commit" if commit.get("local_only") else "committed", authority="provisional-developmental-evidence", negative=any(token in str(commit.get("subject", "")).lower() for token in ("fail", "revert", "abandon", "unknown"))))
            for branch in snapshot.get("local_only_branches", []):
                if isinstance(branch, dict):
                    if not commits and datetime.now(UTC) > end_dt:
                        continue
                    git_items.append(self._item(source_class="local_repositories", source_system="git", project=project, locator=f"{project}:branch:{branch.get('name')}", occurred_at=end, summary=f"local branch has {branch.get('local_only_commit_count')} commit(s) beyond {branch.get('upstream')}", local_only=True, development_state="local-only-branch", confidence="HIGH"))
            if include_uncommitted:
                if changes and datetime.now(UTC) <= end_dt:
                    paths = [
                        {"status": str(change.get("status") or "")[:2], "path": str(change.get("path"))}
                        for change in changes
                        if isinstance(change, dict) and not is_sensitive_name(str(change.get("path") or ""))
                    ]
                    tree_items.append(self._item(source_class="working_trees", source_system="git", project=project, locator=f"{project}:working-tree", occurred_at=end, summary=f"uncommitted paths with porcelain status={paths[:100]}", local_only=True, development_state="local-uncommitted", authority="provisional-developmental-evidence", confidence="HIGH"))
        items.extend(git_items)
        items.extend(tree_items)
        sources.append(self._source("local_repositories", "AVAILABLE" if git_items else "EMPTY", git_items, None if git_items else "no bounded Git records in interval"))
        sources.append(self._source("working_trees", "AVAILABLE" if tree_items else "EMPTY", tree_items, None if tree_items else "no uncommitted changes observed"))

    def _collect_notes(self, projects: list[str], start: datetime, end: datetime, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        notes: list[dict[str, object]] = []
        total_bytes = 0
        for project in projects:
            root = self.config.workspace_root / project
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if len(notes) >= self.config.journal_max_items or total_bytes >= self.config.journal_max_bytes:
                    break
                if not path.is_file() or path.is_symlink() or any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
                    continue
                relative = path.relative_to(root).as_posix()
                if is_sensitive_name(relative) or not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in self.config.journal_include_patterns):
                    continue
                if any(fnmatch.fnmatch(relative, pattern) for pattern in self.config.journal_exclude_patterns):
                    continue
                try:
                    stat = path.stat()
                    modified = datetime.fromtimestamp(stat.st_mtime, UTC)
                    if not start <= modified <= end or stat.st_size > self.config.max_file_bytes:
                        continue
                    content = path.read_bytes()[: self.config.journal_excerpt_bytes]
                except OSError:
                    continue
                safe_content, truncated = _bounded(content.decode("utf-8", errors="replace"), self.config.journal_excerpt_bytes)
                total_bytes += len(content)
                notes.append(self._item(source_class="local_notes", source_system="workspace-filesystem", project=project, locator=f"{project}/{relative}", occurred_at=modified, summary=f"local-only note/document ({stat.st_size} bytes): {safe_content}", local_only=True, development_state="local-only-document", confidence="MEDIUM", content_hash=hashlib.sha256(content).hexdigest()))
        items.extend(notes)
        sources.append(self._source("local_notes", "AVAILABLE" if notes else "EMPTY", notes, None if notes else "no configured local notes changed in interval"))

    def _collect_experiments(self, start: datetime, end: datetime, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        try:
            payload = self.experiments.list()
            records = payload.get("experiments", []) if isinstance(payload, dict) else []
        except Exception as exc:
            sources.append(self._source("experiments", "UNAVAILABLE", [], redact_text(str(exc))[:300]))
            return
        selected: list[dict[str, object]] = []
        for record in records:
            if isinstance(record, dict) and _in_window(record, start, end):
                selected.append(record)
                experiment_id = str(record.get("experiment_id") or "unknown")
                state = str(record.get("state") or record.get("recorded_state") or "UNKNOWN")
                items.append(self._item(source_class="experiments", source_system="control-experiment-coordinator", project=None, locator=f"experiment:{experiment_id}", occurred_at=_stamp(record), summary=f"state={state} turns={record.get('turn_count')} successful_turns={record.get('successful_turns')} failed_turns={record.get('failed_turns')} spec={record.get('spec_identity')} fabric_work={((record.get('current_turn') or {}).get('work_id') if isinstance(record.get('current_turn'), dict) else None)}", development_state="durable-experiment", authority="experiment-coordinator-record", confidence="HIGH" if state not in {"UNKNOWN", "RECOVERY_PENDING"} else "UNKNOWN", unresolved=state in {"UNKNOWN", "RECOVERY_PENDING", "FINALIZING"}, negative=state in {"FAILED", "STOPPED", "TIMED_OUT"} or int(record.get("failed_turns") or 0) > 0))
        sources.append(self._source("experiments", "AVAILABLE" if selected else "EMPTY", selected, None if selected else "no durable experiments in interval"))

    def _records(self, payload: object) -> list[dict[str, object]]:
        if not isinstance(payload, dict):
            return []
        result: list[dict[str, object]] = []
        for key in ("records", "items", "results", "work", "entries", "events"):
            value = payload.get(key)
            if isinstance(value, list):
                result.extend(item for item in value if isinstance(item, dict))
        return result

    def _collect_commons(self, start: datetime, end: datetime, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        try:
            status = self.integrations.commons.status()
            if not status.get("available"):
                sources.append(self._source("commons", "UNAVAILABLE", [], str(status.get("diagnostic") or "Commons consumer unavailable")[:300]))
                return
            payload = self.integrations.commons.query(limit=1000)
            records = [record for record in self._records(payload) if _in_window(record, start, end)]
        except Exception as exc:
            sources.append(self._source("commons", "UNAVAILABLE", [], redact_text(str(exc))[:300]))
            return
        for record in records:
            locator = str(record.get("digest") or record.get("id") or record.get("workId") or "commons:record")
            summary, _ = _bounded(json.dumps(record, sort_keys=True, default=str), self.config.journal_excerpt_bytes)
            items.append(self._item(source_class="commons", source_system="MNCS-Commons-public-consumer", project=record.get("project") if isinstance(record.get("project"), str) else None, locator=locator, occurred_at=_stamp(record), summary=summary, authority="commons-record", confidence="MEDIUM", unresolved=str(record.get("state") or "").upper() in {"UNKNOWN", "OPEN"}, negative=str(record.get("state") or "").lower() in {"failed", "rejected"}))
        sources.append(self._source("commons", "AVAILABLE" if records else "EMPTY", records, None if records else "public Commons query returned no records in interval"))

    def _collect_fabric(self, start: datetime, end: datetime, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        try:
            status = self.integrations.fabric.status()
            if not status.get("available"):
                sources.append(self._source("fabric", "UNAVAILABLE", [], str(status.get("diagnostic") or "Fabric consumer unavailable")[:300]))
                return
            payload = self.integrations.fabric.work_list(limit=1000)
            records = [record for record in self._records(payload) if _in_window(record, start, end)]
        except Exception as exc:
            sources.append(self._source("fabric", "UNAVAILABLE", [], redact_text(str(exc))[:300]))
            return
        for record in records:
            work_id = str(record.get("work_id") or record.get("workId") or record.get("id") or "fabric:work")
            state = str(record.get("state") or record.get("status") or "UNKNOWN").upper()
            summary, _ = _bounded(json.dumps(record, sort_keys=True, default=str), self.config.journal_excerpt_bytes)
            items.append(self._item(source_class="fabric", source_system="mncs-fabric-public-consumer", project=record.get("project") if isinstance(record.get("project"), str) else None, locator=work_id, occurred_at=_stamp(record), summary=summary, authority="persistent-fabric-execution-record", confidence="MEDIUM", unresolved=state in {"UNKNOWN", "PENDING"}, negative=state in {"FAILED", "TIMED_OUT", "CANCELLED"}))
        sources.append(self._source("fabric", "AVAILABLE" if records else "EMPTY", records, None if records else "public Fabric execution query returned no records in interval"))

    def _collect_forge(self, start: datetime, end: datetime, items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        events = self.audit.journal_projection(start.isoformat(), end.isoformat(), projects=list(self.config.journal_projects), limit=self.config.journal_max_items).get("events", [])
        forge_events = [event for event in events if isinstance(event, dict) and str(event.get("tool", "")).startswith(("run_mncs_evaluation", "forge_"))]
        status = self.integrations.forge.status()
        if not status.get("available") and not forge_events:
            sources.append(self._source("forge", "UNAVAILABLE", [], str(status.get("diagnostic") or "Forge consumer unavailable")[:300]))
            return
        for event in forge_events:
            tool = str(event.get("tool"))
            items.append(self._item(source_class="forge", source_system="mncs-forge-public-integration", project=event.get("project") if isinstance(event.get("project"), str) else None, locator=f"control-audit:{event.get('timestamp')}:{tool}", occurred_at=event.get("timestamp"), summary=f"Forge-related Control operation {tool}; success={event.get('success')}; error={event.get('error')}", authority="forge-evidence-reference", confidence="MEDIUM", unresolved=event.get("success") is not True, negative=event.get("success") is False))
        sources.append(self._source("forge", "AVAILABLE" if forge_events else "EMPTY", forge_events, None if forge_events else "no Forge-related Control references in interval"))

    def _collect_activity(self, start: datetime, end: datetime, projects: list[str], items: list[dict[str, object]], sources: list[dict[str, object]]) -> None:
        payload = self.audit.journal_projection(start.isoformat(), end.isoformat(), projects=projects, limit=self.config.journal_max_items)
        events = payload.get("events", []) if isinstance(payload, dict) else []
        for event in events:
            if not isinstance(event, dict):
                continue
            project = event.get("project") if isinstance(event.get("project"), str) else None
            tool = str(event.get("tool") or "control")
            items.append(self._item(source_class="control_activity", source_system="mncs-control-redacted-audit", project=project, locator=f"audit:{event.get('timestamp')}:{tool}", occurred_at=event.get("timestamp"), summary=f"{tool} success={event.get('success')} duration={event.get('duration_seconds')} error={event.get('error')}", authority="control-activity-projection", confidence="HIGH", unresolved=event.get("success") is not True, negative=event.get("success") is False))
        try:
            job_payload = self.processes.list()
            jobs = job_payload.get("jobs", []) if isinstance(job_payload, dict) else []
        except Exception:
            jobs = []
        for job in jobs:
            if not isinstance(job, dict) or not _in_window(job, start, end):
                continue
            project = job.get("project") if isinstance(job.get("project"), str) else None
            if project and project not in projects:
                continue
            job_id = str(job.get("job_id") or "unknown")
            state = str(job.get("status") or "UNKNOWN")
            result_summary = job.get("result_summary") if isinstance(job.get("result_summary"), dict) else {}
            safe_result = {key: result_summary.get(key) for key in ("status", "task_type", "fabric_work_id") if key in result_summary}
            items.append(self._item(source_class="control_activity", source_system="mncs-control-persisted-jobs", project=project, locator=f"control-job:{job_id}", occurred_at=_stamp(job), summary=f"kind={job.get('kind')} status={state} upstream_id={job.get('upstream_id')} result={safe_result} artifact_count={len(job.get('artifacts') or []) if isinstance(job.get('artifacts'), list) else 0}", authority="control-job-projection", confidence="HIGH", unresolved=state in {"orphaned", "upstream_detached", "unknown"}, negative=state in {"failed", "timed_out", "stopped"}))
        activity_items = [item for item in items if item.get("source_class") == "control_activity"]
        payload_status = str(payload.get("status")) if isinstance(payload, dict) else "UNKNOWN"
        activity_status = payload_status if payload_status in {"UNAVAILABLE", "MALFORMED"} else ("AVAILABLE" if activity_items else "EMPTY")
        sources.append(self._source("control_activity", activity_status, activity_items, payload.get("detail") if isinstance(payload, dict) else None))

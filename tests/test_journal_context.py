from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from mncs_control_mcp.audit import AuditLog
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.journal_context import JournalContextService
from mncs_control_mcp.workspace import WorkspacePolicy


class FakeGit:
    def journal_snapshot(self, project: str, *, start: str, end: str, max_commits: int):
        in_interval = start <= "2026-08-20T12:00:00Z" <= end
        return {
            "head": "a" * 40,
            "branch": "feature/local-only",
            "tracking_remote": "origin/main",
            "ahead_behind": {"status": "AVAILABLE", "ahead": 1, "behind": 0},
            "commits": [
                {"commit": "b" * 40, "occurred_at": "2026-08-20T12:00:00Z", "subject": "local experiment failure", "files": [], "local_only": True}
            ] if in_interval else [],
            "local_only_branches": [{"name": "feature/local-only", "upstream": "origin/main", "local_only_commit_count": 1}] if in_interval else [],
        }

    def status(self, project: str):
        return {
            "changes": [
                {"status": " M", "path": "docs/changed.md"},
                {"status": "??", "path": "untracked.md"},
                {"status": "??", "path": ".env"},
                {"status": " D", "path": "notes/removed.md"},
            ]
        }


class FakeExperiments:
    def list(self):
        return {
            "experiments": [
                {
                    "experiment_id": "exp-1234567890abcdef1234567890abcdef",
                    "state": "FAILED",
                    "started_at": "2026-08-20T13:00:00Z",
                    "turn_count": 1,
                    "failed_turns": 1,
                    "spec_identity": "spec-deadbeef",
                    "concept_manifest": {"goal": "pressure-test backend plurality", "language_profile": "source-profile-0.4"},
                    "family_record_id": "fr-1234",
                    "producer_references": [{"kind": "forge-evaluation"}, {"kind": "fabric-execution"}],
                    "claim_boundary": "execution evidence only; not conformance",
                },
                {"experiment_id": "exp-outside", "state": "COMPLETED", "started_at": "2026-08-01T13:00:00Z"},
            ]
        }


class FakeCommons:
    def status(self):
        return {"available": True, "status": "available"}

    def query(self, **kwargs):
        return {"records": [{"digest": "sha256:commons", "created_at": "2026-08-20T14:00:00Z", "body": "untrusted text"}]}


class FakeFabric:
    def status(self):
        return {"available": True, "status": "available"}

    def work_list(self, limit: int):
        return {"work": [{"work_id": "sha256:fabric", "created_at": "2026-08-20T15:00:00Z", "state": "FAILED"}]}


class FakeForge:
    def status(self):
        return {"available": True, "status": "available"}


class FakeIntegrations:
    commons = FakeCommons()
    fabric = FakeFabric()
    forge = FakeForge()


class FakeProcesses:
    def list(self):
        return {"jobs": []}


def make_service(tmp_path: Path) -> JournalContextService:
    root = tmp_path / "projects"
    project = root / "mncs-language"
    (project / ".git").mkdir(parents=True)
    (project / "docs").mkdir(parents=True)
    (project / "docs" / "changed.md").write_text("A bounded note\n", encoding="utf-8")
    os.utime(project / "docs" / "changed.md", (1787227200, 1787227200))
    (project / "untracked.md").write_text("Untracked but not sensitive\n", encoding="utf-8")
    (project / ".env").write_text("TOKEN=must-not-appear\n", encoding="utf-8")
    (project / "outside").mkdir()
    config = ControlConfig(
        workspace_root=root,
        repositories={"language": "mncs-language"},
        journal_projects=("mncs-language",),
        journal_bundle_state_path=tmp_path / "private-bundles",
        journal_max_items=100,
        journal_max_bytes=256 * 1024,
        audit_path=tmp_path / "audit.jsonl",
    )
    audit = AuditLog(config.audit_path)
    audit.record("project_check", project="mncs-language", success=False, error="TEST_FAILURE", command="TOKEN=must-not-appear")
    audit.record("project_check", project="unrelated-project", success=True)
    return JournalContextService(config, WorkspacePolicy(config), FakeGit(), FakeExperiments(), FakeIntegrations(), audit, FakeProcesses())


def test_collect_preserves_local_only_and_failure_evidence_without_sensitive_paths(tmp_path: Path):
    service = make_service(tmp_path)
    end = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result = service.collect(start="2026-08-19T00:00:00Z", end=end, page_size=500, editor_hints=["remember worker residency"])
    rendered = json.dumps(result)
    assert "local-only-commit" in rendered
    assert "local-uncommitted" in rendered
    assert "untracked.md" in rendered
    assert ".env" not in rendered
    assert "must-not-appear" not in rendered
    assert "failed" in rendered.lower()
    assert "family_record=fr-1234" in rendered
    assert "producer_refs=fabric-execution,forge-evaluation" in rendered
    assert "language_profile=source-profile-0.4" in rendered
    assert result["editor_hints"][0]["authority"] == "LOW"
    bundle_id = result["bundle_id"]
    repeat = service.collect(start="2026-08-19T00:00:00Z", end=end, page_size=500)
    assert repeat["bundle_id"] == bundle_id
    stored = (tmp_path / "private-bundles" / f"{bundle_id}.json").read_text(encoding="utf-8")
    assert "worker residency" not in stored
    assert "untrusted_data" in stored


def test_collect_is_interval_bounded_and_paginated(tmp_path: Path):
    service = make_service(tmp_path)
    end = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    first = service.collect(start="2026-08-19T00:00:00Z", end=end, page_size=1)
    assert first["next_cursor"] == 1
    second = service.get(str(first["bundle_id"]), cursor=1, page_size=500)
    assert second["items"]
    outside = service.collect(start="2026-07-01T00:00:00Z", end="2026-07-02T23:59:59Z", page_size=500)
    assert outside["item_count"] == 0
    assert any(source["status"] == "EMPTY" for source in outside["source_statuses"] if source["source_class"] in {"experiments", "commons", "fabric"})


def test_status_distinguishes_empty_from_unavailable(tmp_path: Path):
    service = make_service(tmp_path)
    status = service.status()
    assert status["sources"]["local_repositories"]["status"] == "AVAILABLE"
    assert status["sources"]["control_activity"]["status"] == "AVAILABLE"

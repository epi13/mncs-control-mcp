"""Control reaches Environment sessions through the real sibling checkout.

Enter resolves and activates a durable session, claims enforce
single-holder ownership across sessions, and a missing checkout
reports unavailable instead of inventing state.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import (
    _PACKAGE_SOURCE_IDENTITIES,
    EnvironmentService,
    _load_flat_package,
)
from mncs_control_mcp.errors import ControlError

_CONTROL_COMMON_DIRECTORY = Path(
    subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=Path(__file__).resolve().parent,
        text=True,
    ).strip()
).resolve()
PROJECTS = _CONTROL_COMMON_DIRECTORY.parent.parent
ENVIRONMENT = PROJECTS / "mncs-environment"

needs_environment = pytest.mark.skipif(
    not (ENVIRONMENT / "mncs_env" / "sessions.py").is_file(),
    reason="sibling mncs-environment checkout is required",
)


def _config(tmp_path: Path, **overrides) -> ControlConfig:
    workspace = tmp_path / "projects"
    workspace.mkdir(exist_ok=True)
    overrides.setdefault("repositories", {"environment": str(ENVIRONMENT)})
    return ControlConfig(
        workspace_root=workspace,
        sandbox_home=tmp_path / "sandbox-home",
        job_state_path=tmp_path / "state" / "jobs.json",
        audit_path=tmp_path / "state" / "audit.jsonl",
        fabric_registry=tmp_path / "state" / "workers.json",
        fabric_state=tmp_path / "state" / "fabric.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
        environment_state_dir=tmp_path / "env-state",
        **overrides,
    )


def test_control_read_activity_binds_to_authenticated_session_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = "ctrl_" + "a" * 32
    captured: dict[str, Any] = {}

    class SessionRecorder:
        def record_rpc_read_activity(self, payload, *, request_id, operation_digest):
            captured.update({
                "payload": payload,
                "request_id": request_id,
                "operation_digest": operation_digest,
            })
            return {"status": "recorded"}

    session = SessionRecorder()
    package = SimpleNamespace(sessions=SimpleNamespace(
        Session=SimpleNamespace(open=lambda **_kwargs: session),
    ))
    snapshot = {
        "authenticated_principal_id": principal,
        "selected_checkouts": {
            "mncs-control-mcp": {
                "branch": "campaign/environment-rpc-operation-activity-20261024",
                "head": "b" * 40,
            },
        },
        "environment_id": "renv_control_activity",
        "campaign": {"identity": "cmp_control_activity"},
        "intent": {
            "identity": "int_control_activity",
            "goal": "observe authenticated read operations",
        },
    }
    store = SimpleNamespace(
        load_snapshot=lambda session_id: snapshot if session_id == "ses_activity_control" else None,
        close=lambda: None,
    )
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = principal
    monkeypatch.setattr(service, "_pkg", lambda: package)
    monkeypatch.setattr(service, "_store", lambda _package: store)

    result = service.record_read_operation_activity(
        session_id="ses_activity_control",
        repository="mncs-control-mcp",
        operation="campaign.state",
        outcome_status="failed",
        exit_code=2,
        failure_code="campaign-state-missing",
        operation_elapsed_ms=42.5,
        request_id="req_control_activity",
        operation_digest="c" * 64,
        control_grant_id="d" * 32,
        process_identity="proc_" + "e" * 32,
    )

    assert result == {"status": "recorded"}
    payload = captured["payload"]
    assert payload["caller"]["authenticated_principal_id"] == principal
    assert payload["context"] == {
        "repository": "mncs-control-mcp",
        "repository_branch": "campaign/environment-rpc-operation-activity-20261024",
        "repository_head": "b" * 40,
        "environment_id": "renv_control_activity",
        "campaign_id": "cmp_control_activity",
        "work_intent_id": "int_control_activity",
    }
    assert payload["measurement_availability"] == {
        "model_identity": "unavailable",
        "token_usage": "unavailable",
        "control_dispatch_elapsed_ms": "measured",
        "resource_consumption": "unavailable",
        "cache_accounting": "unavailable",
    }
    assert payload["measurements"] == {"control_dispatch_elapsed_ms": 42.5}
    assert "arguments" not in payload
    assert "response" not in payload

    failed = service.record_read_operation_activity(
        session_id="ses_activity_control",
        repository="mncs-control-mcp",
        operation="campaign.state",
        outcome_status="failed",
        exit_code=None,
        failure_code="ENVIRONMENT_AUTHORITY_DENIED",
        operation_elapsed_ms=51.0,
        request_id="req_control_activity_denied_read",
        operation_digest="1" * 64,
        control_grant_id="d" * 32,
        process_identity=None,
    )
    assert failed == {"status": "recorded"}
    assert captured["payload"]["outcome_status"] == "failed"
    assert captured["payload"]["exit_code"] is None
    assert captured["payload"]["failure_code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert captured["request_id"] == "req_control_activity_denied_read"

    context_summary = {
        "schema_version": "mncs.environment.context-response-summary/2",
        "capture_status": "captured",
        "capture_reason": None,
        "context_schema_version": "mncs.environment.entry-context/1",
        "available_count": 1,
        "listed_available_count": 1,
        "unavailable_count": 0,
        "unknown_count": 0,
        "capabilities_truncated": False,
        "available_identity_digest": "f" * 64,
        "identity_digest_status": "complete",
        "available_binding_ids": ["cap_" + "a" * 64],
        "binding_ids_status": "complete",
    }
    context_result = service.record_read_operation_activity(
        session_id="ses_activity_control",
        repository="mncs-control-mcp",
        operation="session.context",
        outcome_status="succeeded",
        exit_code=0,
        failure_code=None,
        operation_elapsed_ms=15.0,
        request_id="req_control_context_summary",
        operation_digest="2" * 64,
        control_grant_id="d" * 32,
        process_identity=None,
        context_response_summary=context_summary,
    )
    assert context_result == {"status": "recorded"}
    assert captured["payload"]["schema_version"] == (
        "mncs.environment.rpc-read-activity/2"
    )
    assert captured["payload"]["context_response_summary"] == context_summary
    assert "mncs-test:run" not in json.dumps(
        captured["payload"]["context_response_summary"],
    )

    with pytest.raises(ControlError, match="read-operation activity fields are malformed"):
        service.record_read_operation_activity(
            session_id="ses_activity_control",
            repository="mncs-control-mcp",
            operation="session.context",
            outcome_status="succeeded",
            exit_code=0,
            failure_code=None,
            operation_elapsed_ms=15.0,
            request_id="req_control_context_bad_summary",
            operation_digest="3" * 64,
            control_grant_id="d" * 32,
            process_identity=None,
            context_response_summary={**context_summary, "available_count": 2},
        )
    with pytest.raises(ControlError, match="read-operation activity fields are malformed"):
        service.record_read_operation_activity(
            session_id="ses_activity_control",
            repository="mncs-control-mcp",
            operation="session.context",
            outcome_status="succeeded",
            exit_code=0,
            failure_code=None,
            operation_elapsed_ms=15.0,
            request_id="req_control_context_bad_binding_id",
            operation_digest="4" * 64,
            control_grant_id="d" * 32,
            process_identity=None,
            context_response_summary={
                **context_summary, "available_binding_ids": ["bad-id"],
            },
        )
    assert captured["request_id"] == "req_control_context_summary"

    snapshot["authenticated_principal_id"] = "ctrl_" + "f" * 32
    with pytest.raises(ControlError, match="Control-authenticated continuation provenance"):
        service.record_read_operation_activity(
            session_id="ses_activity_control",
            repository="mncs-control-mcp",
            operation="campaign.state",
            outcome_status="failed",
            exit_code=2,
            failure_code="campaign-state-missing",
            operation_elapsed_ms=42.5,
            request_id="req_control_activity_denied",
            operation_digest="0" * 64,
            control_grant_id="d" * 32,
            process_identity=None,
        )
    assert captured["request_id"] == "req_control_context_summary"


def test_environment_package_loader_reloads_changed_sibling_sources(tmp_path: Path) -> None:
    package_name = "mncs_reload_fixture"
    package_root = tmp_path / package_name
    package_root.mkdir()
    (package_root / "__init__.py").write_text("from . import revision\n", encoding="utf-8")
    revision_path = package_root / "revision.py"
    revision_path.write_text("VALUE = 'first'\n", encoding="utf-8")
    try:
        first = _load_flat_package(package_name, tmp_path, ("revision",))
        assert first.revision.VALUE == "first"
        assert _load_flat_package(package_name, tmp_path, ("revision",)) is first

        revision_path.write_text("VALUE = 'second'\n", encoding="utf-8")
        second = _load_flat_package(package_name, tmp_path, ("revision",))
        assert second is not first
        assert second.revision.VALUE == "second"
    finally:
        for name in tuple(sys.modules):
            if name == package_name or name.startswith(f"{package_name}."):
                sys.modules.pop(name, None)
        _PACKAGE_SOURCE_IDENTITIES.pop(package_name, None)


def _environment_source_repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / "projects"
    root = workspace / "mncs-environment"
    root.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch", "main", str(root)],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    package = root / "mncs_env"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "sessions.py"
    source.write_text("REVISION = 'main'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "mncs_env"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "Environment main"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "checkout", "--quiet", "-b", "campaign/stale"],
        check=True,
    )
    source.write_text("REVISION = 'stale'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "mncs_env/sessions.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "Stale Environment"],
        check=True,
    )
    nested_main = workspace / ".campaigns" / "compiler" / "environment-main"
    nested_main.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "-C", str(root), "worktree", "add", "--quiet", str(nested_main), "main"],
        check=True,
    )
    return workspace, root, nested_main


def test_environment_source_uses_registered_nested_checkout_at_main(tmp_path: Path) -> None:
    workspace, configured_root, nested_main = _environment_source_repo(tmp_path)

    selected = EnvironmentService(
        _config(tmp_path, repositories={"environment": "mncs-environment"}),
    ).environment_path

    assert configured_root.parent == workspace
    assert selected == nested_main
    assert (selected / "mncs_env" / "sessions.py").read_text(encoding="utf-8") == (
        "REVISION = 'main'\n"
    )


def test_environment_source_reselects_main_after_main_advances(
    tmp_path: Path,
) -> None:
    _workspace, configured_root, nested_main = _environment_source_repo(tmp_path)
    service = EnvironmentService(
        _config(tmp_path, repositories={"environment": "mncs-environment"}),
    )

    assert service.environment_path == nested_main

    # Leave the old source checkout registered but pinned to the previous
    # revision, then advance main in the configured checkout. The same
    # long-lived service must stop using the stale Environment implementation.
    subprocess.run(
        ["git", "-C", str(nested_main), "checkout", "--quiet", "--detach"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(configured_root), "checkout", "--quiet", "main"],
        check=True,
    )
    source = configured_root / "mncs_env" / "sessions.py"
    source.write_text("REVISION = 'advanced-main'\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(configured_root), "add", "mncs_env/sessions.py"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(configured_root), "commit", "--quiet", "-m",
         "Advance Environment main"],
        check=True,
    )

    assert service.environment_path == configured_root
    assert source.read_text(encoding="utf-8") == "REVISION = 'advanced-main'\n"


def test_environment_source_rejects_unregistered_main_lookalike(tmp_path: Path) -> None:
    workspace, configured_root, nested_main = _environment_source_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(configured_root), "worktree", "remove", str(nested_main)],
        check=True,
    )
    lookalike = workspace / "lookalike-environment"
    subprocess.run(
        ["git", "clone", "--quiet", "--branch", "main", str(configured_root), str(lookalike)],
        check=True,
    )

    service = EnvironmentService(
        _config(tmp_path, repositories={"environment": "mncs-environment"}),
    )
    with pytest.raises(
        ControlError, match="no clean registered checkout matches local main",
    ):
        _ = service.environment_path


def _campaign_charter_result(
    tmp_path: Path, *, referenced_digest: str | None = None,
    charter_campaign: str = "campaign-1", evidence_prefix: int = 0,
    evidence_suffix: int = 0, selector_decoy: bool = False,
    charter_index_truncated: bool = False, second_valid_charter: bool = False,
) -> dict:
    workspace = tmp_path / "projects"
    control_project = workspace / "mncs-control-mcp"
    environment_project = workspace / "mncs-environment"
    control_project.mkdir(parents=True)
    (environment_project / "evidence").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(environment_project)], check=True)
    subprocess.run(["git", "-C", str(environment_project), "config", "user.name", "Test"],
                   check=True)
    subprocess.run(["git", "-C", str(environment_project), "config", "user.email",
                    "test@example.invalid"], check=True)
    raw_charter = json.dumps({
        "schema_version": "mncs.environment.campaign-charter/1",
        "identity": "ev_test_campaign_charter",
        "campaign_identity": charter_campaign,
        "objective": "Continue the verified long-running campaign safely.",
    }, sort_keys=True).encode("utf-8")
    charter_path = environment_project / "evidence" / "campaign-charter-test.json"
    charter_path.write_bytes(raw_charter)
    raw_selector = json.dumps({
        "schema_version": "mncs.environment.campaign-charter-task-selector/1",
        "identity": "ev_campaign_charter_task_selector_restart_20261012",
        "campaign_identity": charter_campaign,
        "objective": "This selector identity is not a charter artifact.",
    }, sort_keys=True).encode("utf-8")
    raw_secondary_charter = json.dumps({
        "schema_version": "mncs.environment.campaign-charter/1",
        "identity": "ev_test_secondary_campaign_charter",
        "campaign_identity": charter_campaign,
        "objective": "This is a conflicting second charter.",
    }, sort_keys=True).encode("utf-8")
    if selector_decoy:
        (environment_project / "evidence" / "campaign-charter-task-selector.json").write_bytes(
            raw_selector
        )
    if second_valid_charter:
        (environment_project / "evidence" / "campaign-charter-secondary.json").write_bytes(
            raw_secondary_charter
        )
    subprocess.run(["git", "-C", str(environment_project), "add", "evidence"], check=True)
    subprocess.run(["git", "-C", str(environment_project), "commit", "-q", "-m",
                    "Add test charter"], check=True)
    commit = subprocess.run(
        ["git", "-C", str(environment_project), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    digest = hashlib.sha256(raw_charter).hexdigest()
    evidence = [{
        "identity": f"ev_test_prior_{index:02d}",
        "repository": "mncs-environment",
        "commit": commit,
        "path": f"evidence/prior-{index:02d}.json",
        "sha256": digest,
    } for index in range(evidence_prefix)] + [{
        "identity": "ev_env_campaign_charter_test",
        "repository": "mncs-environment",
        "commit": commit,
        "path": "evidence/campaign-charter-test.json",
        "sha256": referenced_digest or digest,
    }] + ([{
        "identity": "ev_campaign_charter_task_selector_restart_20261012",
        "repository": "mncs-environment",
        "commit": commit,
        "path": "evidence/campaign-charter-task-selector.json",
        "sha256": hashlib.sha256(raw_selector).hexdigest(),
    }] if selector_decoy else []) + ([{
        "identity": "ev_env_campaign_charter_secondary_pointer_test",
        "repository": "mncs-environment",
        "commit": commit,
        "path": "evidence/campaign-charter-secondary.json",
        "sha256": hashlib.sha256(raw_secondary_charter).hexdigest(),
    }] if second_valid_charter else []) + [{
        "identity": f"ev_test_after_charter_{index:02d}",
        "repository": "mncs-environment",
        "commit": commit,
        "path": f"evidence/after-charter-{index:02d}.json",
        "sha256": digest,
    } for index in range(evidence_suffix)]
    snapshot = {
        "session_id": "ses_test",
        "snapshot_sequence": 3,
        "lifecycle": "active",
        "authenticated_principal_id": "principal-test",
        "provenance": {"definition_id": "env-test"},
        "workspace": {"root": str(workspace)},
        "intent": {"identity": "intent-test"},
        "campaign": {
            "identity": "campaign-1",
            "work_intent": {
                "goal": "narrow fixture goal",
                "repositories": ["mncs-control-mcp"],
            },
        },
    }

    class Store:
        def list_sessions(self):
            return ["ses_test"]

        def load_snapshot(self, _session_id: str):
            return snapshot

        def read_claims(self):
            return []

        def close(self):
            pass

    class Session:
        @staticmethod
        def open(**_kwargs):
            def campaign_state(*, evidence_offset=None, evidence_limit=128):
                total = len(evidence)
                offset = (max(0, total - evidence_limit)
                          if evidence_offset is None else evidence_offset)
                page = evidence[offset:offset + evidence_limit]
                charter_references = [
                    item for item in evidence
                    if "campaign_charter" in item.get("identity", "")
                ]
                return {
                    "campaign_identity": "campaign-1",
                    "checkpoint_id": "chk_test",
                    "evidence": page,
                    "evidence_count": total,
                    "evidence_offset": offset,
                    "evidence_limit": evidence_limit,
                    "campaign_charter_evidence": {
                        "references": charter_references[:16],
                        "count": (17 if charter_index_truncated
                                  else len(charter_references)),
                        "truncated": (charter_index_truncated
                                      or len(charter_references) > 16),
                    },
                }

            return SimpleNamespace(
                context=lambda: {"continuation": {
                    "campaign_state_checkpoint_id": "chk_test",
                    "evidence": evidence[-32:],
                    "evidence_count": len(evidence),
                    "evidence_truncated": len(evidence) > 32,
                }},
                campaign_state=campaign_state,
            )

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-test"
    service._pkg = lambda: SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda _records: {}),
        sessions=SimpleNamespace(Session=Session),
    )
    service._store = lambda _pkg: Store()
    service._observe_project_checkout = lambda repository: {
        "status": "unknown", "repository": repository,
    }
    return service.campaign_continuation("mncs-control-mcp", "campaign-1")


@needs_environment
def test_enter_inspect_claim_release_round_trip(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    assert service.status()["available"] is True

    entered = service.enter(
        {
            "name": "control-probe",
            "intent": {"goal": "probe", "repositories": ["mncs-vm"]},
        },
        "control-probe",
    )
    assert entered["lifecycle"] == "active"
    session_id = entered["session_id"]

    assert service.inspect(session_id)["session_id"] == session_id
    assert service.resume(session_id)["lifecycle"] == "active"

    claim = service.acquire_claim(session_id, "mncs-vm", reason="probe")
    assert claim["repository"] == "mncs-vm"
    assert claim["session_id"] == session_id
    assert any(c["repository"] == "mncs-vm" for c in service.list_claims()["claims"])
    assert service.release_claim(session_id, "mncs-vm") == {"released": True}


@needs_environment
def test_claim_conflict_across_sessions(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    first = service.enter(
        {"name": "a", "intent": {"goal": "a", "repositories": ["mncs-vm"]}},
        "consumer-a",
    )
    second = service.enter(
        {"name": "b", "intent": {"goal": "b", "repositories": ["mncs-vm"]}},
        "consumer-b",
    )
    service.acquire_claim(first["session_id"], "mncs-vm", reason="first")
    with pytest.raises(ControlError) as excinfo:
        service.acquire_claim(second["session_id"], "mncs-vm", reason="second")
    assert excinfo.value.code == "ENVIRONMENT_CLAIM_CONFLICT"


@needs_environment
def test_enter_denied_on_blocked_rights(tmp_path: Path) -> None:
    pytest.importorskip(
        "mncs_rights_provenance", reason="rights library required for gate enforcement"
    )
    workspace = tmp_path / "projects"
    (workspace / "demo-repo" / ".git").mkdir(parents=True)
    service = EnvironmentService(_config(tmp_path))
    with pytest.raises(ControlError) as excinfo:
        service.enter(
            {
                "name": "blocked",
                "intent": {"goal": "blocked"},
                "rights_claims": [
                    {
                        "subject": "demo-repo",
                        "claimant": "x",
                        "license": "MIT",
                        "evidence": ["LICENSE"],
                        "verified": True,
                        "revoked": True,
                    }
                ],
            },
            "consumer",
            workspace=".",
        )
    assert excinfo.value.code == "ENVIRONMENT_ENTER_DENIED"


def test_missing_checkout_reports_unavailable(tmp_path: Path) -> None:
    config = _config(tmp_path, repositories={"environment": "no-such-checkout"})
    service = EnvironmentService(config)
    status = service.status()
    assert status["available"] is False
    assert status["error"] == "ENVIRONMENT_UNAVAILABLE"
    assert status["path"] == str(config.environment_path)
    with pytest.raises(ControlError) as excinfo:
        service.enter({"name": "x"}, "consumer")
    assert excinfo.value.code == "ENVIRONMENT_UNAVAILABLE"


def test_inspection_rejects_a_foreign_authenticated_session(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-caller"

    class Store:
        def load_snapshot(self, _session_id: str):
            return {"authenticated_principal_id": "principal-owner"}

        def close(self) -> None:
            pass

    class Session:
        @staticmethod
        def open(**_kwargs):
            raise AssertionError("foreign session must be rejected before inspection")

    package = SimpleNamespace(sessions=SimpleNamespace(Session=Session))
    service._pkg = lambda: package
    service._store = lambda _pkg: Store()

    with pytest.raises(ControlError) as excinfo:
        service.inspect("ses_foreign")
    assert excinfo.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


def test_recorded_relative_checkout_uses_campaign_workspace_root(tmp_path: Path) -> None:
    caller_root = tmp_path / "projects" / "mncs-compiler"
    campaign_root = caller_root / ".worktrees" / "native-app-readiness"
    nested_checkout = campaign_root / "mncs-compiler"
    nested_checkout.mkdir(parents=True)
    branch = "campaign/native-application-readiness"
    head = "a" * 40
    references = [{
        "repository": "mncs-compiler",
        "observed_path": "mncs-compiler",
        "branch": branch,
        "head": head,
    }]
    live_observation = {
        "status": "current",
        "workspace_root": str(caller_root),
        "checkout": {
            "path": str(caller_root),
            "branch": "main",
            "head": "b" * 40,
        },
        "worktree_registrations": [{
            "registered_path": str(nested_checkout),
            "branch": branch,
            "head": head,
        }],
    }

    comparison = EnvironmentService._compare_recorded_checkouts(
        references, live_observation, reference_workspace_root=str(campaign_root),
    )[0]

    assert comparison["status"] == "same_checkout"
    assert comparison["path_matches"] is True
    assert comparison["live_registered_path"] == str(nested_checkout)


def test_campaign_continuation_returns_project_scoped_duplicate_capsules(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-caller"
    for repository in ("mncs-control-mcp", "mncs-environment"):
        (service._config.workspace_root / repository).mkdir()

    def snapshot(session_id: str, *, version: int, lifecycle: str = "active"):
        return {
            "session_id": session_id,
            "snapshot_sequence": version,
            "lifecycle": lifecycle,
            "consumer_id": f"consumer-{session_id}",
            "consumer_kind": "agent",
            "authenticated_principal_id": "principal-caller",
            "provenance": {"definition_id": "env-definition"},
            "workspace": {"root": "/projects"},
            "intent": {"identity": "intent-1"},
            "campaign": {
                "identity": "campaign-1",
                "work_intent": {"goal": "continue the campaign", "repositories": [
                    "mncs-control-mcp", "mncs-environment",
                ]},
                "repository_refs": [{
                    "repository": "mncs-control-mcp",
                    "observed_path": "/projects/mncs-control-mcp/.worktrees/campaign",
                    "branch": "campaign/continuity",
                    "head": "abc123",
                    "clean": True,
                    "observation": "current",
                }],
                "delivery": {"status": "pending"},
            },
        }

    second = snapshot("ses_second", version=12, lifecycle="checkpointed")
    second["campaign"] = {
        **second["campaign"],
        "work_intent": {"goal": "continue the campaign", "repositories": ["mncs-language"]},
        "repository_refs": [],
    }
    snapshots = {
        "ses_first": snapshot("ses_first", version=7),
        "ses_second": second,
        "ses_other_campaign": {
            **snapshot("ses_other_campaign", version=2),
            "campaign": {"identity": "campaign-2"},
        },
    }

    class Store:
        closed = False
        list_sessions_calls = 0
        loaded_sessions = []

        def list_sessions(self):
            type(self).list_sessions_calls += 1
            return list(snapshots)

        def load_snapshot(self, session_id: str):
            type(self).loaded_sessions.append(session_id)
            return snapshots.get(session_id)

        def read_claims(self):
            return [{
                "claim_id": "claim-control",
                "version": 2,
                "repository": "mncs-control-mcp",
                "scope": {"kind": "repository", "repository": "mncs-control-mcp",
                          "exclusive": True},
                "session_id": "ses_first",
                "status": "held",
                "expires_at": "2099-01-01T00:00:00+00:00",
            }]

        def close(self):
            self.closed = True

    class Session:
        def __init__(self, session_id: str):
            self.session_id = session_id

        def context(self):
            return {"continuation": {
                "repositories": ([{
                    "repository": "mncs-control-mcp",
                    "observed_path": "/projects/mncs-control-mcp/.worktrees/campaign",
                    "branch": "campaign/continuity",
                    "head": "abc123",
                    "clean": True,
                    "observation": "current",
                }] if self.session_id == "ses_first" else [{
                    "repository": "mncs-language",
                    "observed_path": "/projects/mncs-language",
                    "branch": "main",
                    "head": "def456",
                    "clean": True,
                }]),
                "checkpoint_ids": ["chk_latest"],
                "campaign_state_checkpoint_id": (
                    "chk_campaign_state" if self.session_id == "ses_first" else None
                ),
                "evidence": [
                    {"identity": f"evidence-{index}"} for index in range(12)
                ],
                "evidence_count": 12,
                "evidence_truncated": False,
                "delivery": {"status": "pending"},
                "unresolved_pressures": [{"identity": "pressure-1"}],
                "latest_checkpoint": {
                    "identity": "chk_campaign_latest",
                    "sequence": 19,
                    "created_at": "2026-10-11T09:00:00+00:00",
                    "progress": "Continuing the durable MNCS compiler campaign",
                    "progress_truncated": False,
                    "remaining": ["resume compiler execution work"],
                    "remaining_count": 1,
                    "remaining_truncated": False,
                    "private_store_path": "/home/private/store",
                },
            }}

    store = Store()
    selection_calls = []

    class Selection:
        @staticmethod
        def select(_store, selector, matches):
            selection_calls.append(selector)
            return [session_id for session_id, value in snapshots.items()
                    if matches(value)]

    pkg = SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda records: {
            record["claim_id"]: record for record in records
            if record.get("status") == "held"
        }),
        sessions=SimpleNamespace(Session=SimpleNamespace(open=lambda **kwargs: Session(kwargs["session_id"]))),
        entry=SimpleNamespace(),
        selection=Selection,
    )
    service._pkg = lambda: pkg
    service._store = lambda _pkg: store

    result = service.campaign_continuation("mncs-control-mcp", "campaign-1")

    assert result["status"] == "ambiguous"
    assert [item["session_id"] for item in result["continuations"]] == [
        "ses_first", "ses_second",
    ]
    assert result["continuations"][0]["snapshot_version"] == 7
    assert result["continuations"][0]["claim_ids"] == ["claim-control"]
    assert result["continuations"][0]["campaign_state_checkpoint_id"] == (
        "chk_campaign_state"
    )
    assert "campaign_state_checkpoint_id" not in result["continuations"][1]
    assert result["continuations"][0]["project_reference"] == {
        "status": "linked",
        "basis": [
            "campaign.work_intent.repositories",
            "campaign.repository_refs",
            "active_claim.repository",
        ],
    }
    assert result["continuations"][1]["project_reference"] == {
        "status": "same_campaign_only",
        "basis": [],
    }
    assert len(result["continuations"][0]["evidence"]) == 12
    assert result["continuations"][0]["evidence_count"] == 12
    assert result["continuations"][0]["evidence_truncated"] is False
    assert result["continuations"][0]["latest_checkpoint"] == {
        "identity": "chk_campaign_latest",
        "sequence": 19,
        "created_at": "2026-10-11T09:00:00+00:00",
        "progress": "Continuing the durable MNCS compiler campaign",
        "progress_truncated": False,
        "remaining": ["resume compiler execution work"],
        "remaining_count": 1,
        "remaining_truncated": False,
    }
    assert "private_store_path" not in repr(result["continuations"][0])
    assert result["continuations"][0]["claims"][0]["scope"]["exclusive"] is True
    assert result["continuations"][0]["repositories"] == [{
        "repository": "mncs-control-mcp",
        "observed_path": "/projects/mncs-control-mcp/.worktrees/campaign",
        "branch": "campaign/continuity",
        "head": "abc123",
        "clean": True,
        "observation": "recorded_snapshot",
        "recorded_observation": "current",
    }]
    assert result["continuations"][0]["repository_facts_source"].startswith(
        "persisted Environment"
    )
    assert result["continuations"][0]["live_repository_observation"]["status"] == "unknown"
    assert result["continuations"][0]["recorded_checkout_comparisons"] == [
        {"status": "unknown_live_observation"}
    ]
    assert "mncs-language" not in repr(result)
    assert store.closed is True

    service._store = lambda _pkg: Store()
    discovered = service.campaign_continuation("mncs-control-mcp")
    assert discovered["status"] == "ambiguous"
    assert discovered["campaign_id"] == "campaign-1"

    Store.loaded_sessions.clear()
    list_sessions_calls_before_exact = Store.list_sessions_calls
    exact = service.campaign_continuation(
        "mncs-control-mcp", session_id="ses_first",
    )
    assert exact["status"] == "ready"
    assert exact["campaign_id"] == "campaign-1"
    assert exact["selected_session_id"] == "ses_first"
    assert exact["selection_basis"] == "authenticated-exact-session-link"
    assert [item["session_id"] for item in exact["continuations"]] == ["ses_first"]
    assert Store.list_sessions_calls == list_sessions_calls_before_exact
    assert "ses_other_campaign" not in Store.loaded_sessions
    assert selection_calls[-1] == {
        "control_campaign_continuation": 1,
        "campaign_identity": "campaign-1",
        "lifecycle": "nonterminal",
    }

    foreign_duplicate = snapshot("ses_foreign_duplicate", version=1)
    foreign_duplicate["authenticated_principal_id"] = "principal-foreign"
    snapshots["ses_foreign_duplicate"] = foreign_duplicate
    with pytest.raises(ControlError) as foreign_campaign_owner:
        service.campaign_continuation(
            "mncs-control-mcp", session_id="ses_first",
        )
    assert foreign_campaign_owner.value.code == "ENVIRONMENT_AUTHORITY_DENIED"

    with pytest.raises(ControlError) as selector_conflict:
        service.campaign_continuation(
            "mncs-control-mcp", "campaign-2", session_id="ses_first",
        )
    assert selector_conflict.value.code == "ENVIRONMENT_CAMPAIGN_SESSION_CONFLICT"

    foreign_snapshot = snapshot("ses_foreign_exact", version=1)
    foreign_snapshot["authenticated_principal_id"] = "principal-foreign"
    snapshots["ses_foreign_exact"] = foreign_snapshot
    with pytest.raises(ControlError) as foreign_selector:
        service.campaign_continuation(
            "mncs-control-mcp", session_id="ses_foreign_exact",
        )
    assert foreign_selector.value.code == "ENVIRONMENT_AUTHORITY_DENIED"
    next_step = foreign_selector.value.details["next"]
    assert "explicit handoff" in next_step
    assert "new campaign_id and task_identity" in next_step


def test_owner_scope_grant_links_only_its_exact_campaign_worktree(
    tmp_path: Path,
) -> None:
    repository = "mncs-language"
    config = _config(tmp_path)
    repo_root = config.workspace_root / repository
    repo_root.mkdir(parents=True)
    service = EnvironmentService(config)
    service.authenticated_principal_id = "principal-caller"

    def checkout(name: str) -> dict[str, str]:
        path = str(repo_root / ".worktrees" / name)
        return {
            "repository": repository,
            "path": path,
            "branch": f"campaign/{name}",
            "head": (name[0] * 40),
            "checkout_identity": f"checkout-{name}",
            "git_common_directory_identity": f"common-{name}",
        }

    checkout_a = checkout("language-a")
    checkout_b = checkout("language-b")

    def grant(session_id: str, selected: dict[str, str], *, branch: str | None = None):
        return {
            "schema_version": "mncs.environment.authority-scope-grant/1",
            "identity": f"scope-{session_id}",
            "session_id": session_id,
            "campaign_id": "cmp-multi-repository",
            "repository": repository,
            "scope": {"kind": "repository", "repository": repository},
            "authorized_by_principal_id": "principal-caller",
            "repository_identity": {
                "path": selected["path"],
                "branch": branch or selected["branch"],
                "checkout_identity": selected["checkout_identity"],
                "git_common_directory_identity": selected[
                    "git_common_directory_identity"
                ],
                "head": selected["head"],
            },
        }

    grants = {
        "ses-language-a": [grant("ses-language-a", checkout_a)],
        "ses-language-b": [grant("ses-language-b", checkout_b)],
        # A same-campaign session with a branch mismatch must not become a
        # continuation for checkout B merely because its repository matches.
        "ses-language-forged": [grant(
            "ses-language-forged", checkout_b, branch="campaign/other-branch",
        )],
    }
    snapshots = {
        session_id: {
            "session_id": session_id,
            "snapshot_sequence": 1,
            "lifecycle": "active",
            "authenticated_principal_id": "principal-caller",
            "provenance": {"definition_id": "env-compiler"},
            "workspace": {"root": str(config.workspace_root)},
            "campaign": {
                "identity": "cmp-multi-repository",
                "work_intent": {
                    "goal": "continue compiler and Language work",
                    "repositories": ["mncs-compiler"],
                },
                "repository_refs": [],
            },
            "selected_checkouts": {},
        }
        for session_id in grants
    }

    class Store:
        def list_sessions(self):
            return list(snapshots)

        def load_snapshot(self, session_id: str):
            return snapshots.get(session_id)

        def read_claims(self):
            return []

        def close(self):
            pass

    class Session:
        def __init__(self, session_id: str):
            self.session_id = session_id

        def authority_scope_grants(self):
            return grants[self.session_id]

        def effective_authority(self):
            return {
                "writable": [repository],
                "scope_grants": grants[self.session_id],
            }

        def context(self):
            return {
                "authority": {
                    "writable": [repository],
                    "scope_grants": grants[self.session_id],
                },
                "continuation": {"repositories": [], "evidence": []},
            }

    pkg = SimpleNamespace(
        entry=SimpleNamespace(),
        claims=SimpleNamespace(
            active_claims=lambda _rows: {},
            scopes_conflict=lambda *_args: None,
        ),
        sessions=SimpleNamespace(
            Session=SimpleNamespace(open=lambda **kwargs: Session(kwargs["session_id"])),
        ),
    )
    service._pkg = lambda: pkg
    service._store = lambda _pkg: Store()
    service._observe_project_checkout = lambda name: {
        "status": "unknown", "repository": name,
    }

    selected_a = service.campaign_continuation(
        repository, "cmp-multi-repository", working_checkout=checkout_a,
    )
    selected_b = service.campaign_continuation(
        repository, "cmp-multi-repository", working_checkout=checkout_b,
    )
    discovered_a = service.campaign_continuation(
        repository,
        working_checkout=checkout_a,
        definition_id="env-compiler",
        workspace_root=str(config.workspace_root),
    )
    cross_project_context_a = service.campaign_continuation(
        repository,
        "cmp-multi-repository",
        working_checkout=checkout_a,
        definition_id="env-language-project",
        workspace_root=str(repo_root),
    )

    assert selected_a["status"] == "ready"
    assert selected_a["continuations"][0]["session_id"] == "ses-language-a"
    assert selected_a["continuations"][0]["project_reference"] == {
        "status": "linked",
        "basis": ["authenticated-scope-grant.exact-checkout"],
    }
    assert selected_a["continuations"][0]["selected_checkout"][
        "checkout_identity"
    ] == checkout_a["checkout_identity"]
    assert selected_a["continuations"][0]["repositories"][0][
        "scope_grant_identity"
    ] == "scope-ses-language-a"
    assert selected_b["status"] == "ready"
    assert selected_b["continuations"][0]["session_id"] == "ses-language-b"
    assert selected_b["continuations"][0]["project_reference"] == {
        "status": "linked",
        "basis": ["authenticated-scope-grant.exact-checkout"],
    }
    assert discovered_a["status"] == "ready"
    assert discovered_a["campaign_id"] == "cmp-multi-repository"
    assert discovered_a["continuations"][0]["session_id"] == "ses-language-a"
    assert cross_project_context_a["status"] == "ready"
    assert cross_project_context_a["continuations"][0]["session_id"] == "ses-language-a"
    assert cross_project_context_a["continuations"][0]["project_reference"] == {
        "status": "linked",
        "basis": ["authenticated-scope-grant.exact-checkout"],
    }


def test_campaign_continuation_recovers_one_authenticated_nested_checkout(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    workspace = config.workspace_root.resolve()
    repository_root = workspace / "mncs-compiler"
    repository_root.mkdir()
    nested_path = repository_root / ".worktrees" / "campaign" / "mncs-compiler"
    definition_id = "env_nested_compiler"
    checkout_root = {
        "repository": "mncs-compiler",
        "path": str(repository_root),
        "workspace_root": str(workspace),
        "repository_root": str(repository_root),
        "branch": "main",
        "head": "a" * 40,
        "checkout_identity": "checkout-repository-root",
        "git_common_directory_identity": "common-mncs-compiler",
    }
    recovered_checkout = {
        **checkout_root,
        "path": str(nested_path),
        "branch": "campaign/native-application-readiness-20261013",
        "head": "b" * 40,
        "checkout_identity": "checkout-native-application-readiness",
        "observed_path": "mncs-compiler/.worktrees/campaign/mncs-compiler",
    }
    nested_path.mkdir(parents=True)
    snapshots = {
        session_id: {
            "session_id": session_id,
            "lifecycle": "active",
            "authenticated_principal_id": "principal-test",
            "provenance": {"definition_id": definition_id},
            "workspace": {"root": str(workspace)},
            "campaign": {
                "identity": "cmp_native_application",
                "work_intent": {
                    "repositories": ["mncs-compiler"],
                    "goal": "continue the compiler campaign",
                },
            },
            "selected_checkouts": {
                "mncs-compiler": {
                    key: recovered_checkout[key]
                    for key in (
                        "repository", "path", "workspace_root", "repository_root",
                        "branch", "head", "checkout_identity",
                        "git_common_directory_identity", "observed_path",
                    )
                }
            },
        }
        for session_id in ("ses_uncheckpointed", "ses_checkpoint_owner")
    }

    claim_rows: list[dict[str, object]] = []

    class Store:
        closed = False

        def list_sessions(self):
            return sorted(snapshots)

        def load_snapshot(self, session_id: str):
            return snapshots.get(session_id)

        def read_claims(self):
            return claim_rows

        def close(self):
            self.closed = True

    recovery_calls: list[dict[str, object]] = []

    def recover_checkout(store, **kwargs):
        assert store is store_instance
        recovery_calls.append(kwargs)
        return recovered_checkout

    def matches(snapshot, requested):
        selected = snapshot.get("selected_checkouts", {}).get("mncs-compiler", {})
        return (
            selected.get("checkout_identity") == requested.get("checkout_identity")
            and selected.get("path") == requested.get("path")
            and selected.get("branch") == requested.get("branch")
        )

    def select_duplicate(_store, session_ids, requested):
        assert set(session_ids) == set(snapshots)
        assert requested == recovered_checkout
        if not all(matches(snapshots[session_id], requested) for session_id in session_ids):
            return None, {
                "basis": "no_unique_registered_checkout",
                "candidate_sessions": sorted(session_ids),
            }
        return "ses_checkpoint_owner", {
            "basis": "unique_session_checkpoint",
            "checkpoint_session": "ses_checkpoint_owner",
        }

    package = SimpleNamespace(
        entry=SimpleNamespace(
            _campaign_checkout_from_store=recover_checkout,
            _working_checkout_matches_snapshot=matches,
            _authoritative_duplicate_session=select_duplicate,
        ),
        claims=SimpleNamespace(
            active_claims=lambda rows: {
                str(row.get("claim_id", index)): row
                for index, row in enumerate(rows)
                if isinstance(row, dict) and row.get("status") == "held"
            },
            scopes_conflict=lambda *_args: None,
        ),
        sessions=SimpleNamespace(),
    )
    service = EnvironmentService(config)
    service.authenticated_principal_id = "principal-test"
    store_instance = Store()
    service._pkg = lambda: package
    service._store = lambda _pkg: store_instance
    service._observe_project_checkout = lambda repository: {
        "status": "unknown", "repository": repository,
    }
    def continuation_capsule(
        _pkg, _store, session_id, snapshot, repository, _claims, _live,
        *, working_checkout=None,
    ):
        return {
            "session_id": session_id,
            "definition_id": snapshot["provenance"]["definition_id"],
            "workspace_root": snapshot["workspace"]["root"],
            "lifecycle": snapshot["lifecycle"],
            "project_reference": {"status": "linked", "basis": ["work_intent"]},
            "selected_checkout": snapshot["selected_checkouts"][repository],
            "claim_ids": [],
            "claims": [],
        }

    service._continuation_capsule = continuation_capsule

    result = service.campaign_continuation(
        "mncs-compiler",
        "cmp_native_application",
        working_checkout=checkout_root,
        definition_id=definition_id,
        workspace_root=str(workspace),
    )

    assert len(recovery_calls) == 1
    assert recovery_calls[0] == {
        "campaign_id": "cmp_native_application",
        "authenticated_principal_id": "principal-test",
        "definition_id": definition_id,
        "workspace_root": workspace,
        "working_checkout": checkout_root,
    }
    assert result["status"] == "ready"
    assert result["selected_session_id"] == "ses_checkpoint_owner"
    assert result["selection_basis"] == (
        "authenticated-project-checkout-unique-checkpoint"
    )
    assert [item["session_id"] for item in result["continuations"]] == [
        "ses_checkpoint_owner",
    ]
    assert store_instance.closed is True

    # A fresh process can enter through the registered nested checkout after
    # the snapshot still describes the repository root. The exact active
    # worktree claim identifies the one session for this checkout.
    for snapshot in snapshots.values():
        snapshot["selected_checkouts"]["mncs-compiler"] = {
            key: checkout_root[key]
            for key in (
                "repository", "path", "workspace_root", "repository_root",
                "branch", "head", "checkout_identity",
                "git_common_directory_identity",
            )
        }
    claim_rows[:] = [{
        "claim_id": "claim:mncs-compiler:worktree:nested",
        "version": 1,
        "repository": "mncs-compiler",
        "session_id": "ses_checkpoint_owner",
        "status": "held",
        "scope": {
            "kind": "worktree",
            "repository": "mncs-compiler",
            "checkout": str(nested_path),
            "branch": recovered_checkout["branch"],
        },
    }]
    store_instance.closed = False
    direct_nested = service.campaign_continuation(
        "mncs-compiler",
        "cmp_native_application",
        working_checkout=recovered_checkout,
        definition_id=definition_id,
        workspace_root=str(workspace),
    )
    assert len(recovery_calls) == 1  # direct nested entry needs no root recovery
    assert direct_nested["status"] == "ready"
    assert [item["session_id"] for item in direct_nested["continuations"]] == [
        "ses_checkpoint_owner",
    ]

    # Two exact active claims on the same checkout remain ambiguous.
    claim_rows.append({
        **claim_rows[0],
        "claim_id": "claim:mncs-compiler:worktree:nested-duplicate",
        "session_id": "ses_uncheckpointed",
    })
    store_instance.closed = False
    duplicate_nested = service.campaign_continuation(
        "mncs-compiler",
        "cmp_native_application",
        working_checkout=recovered_checkout,
        definition_id=definition_id,
        workspace_root=str(workspace),
    )
    assert duplicate_nested["status"] == "ambiguous"
    assert [item["session_id"] for item in duplicate_nested["continuations"]] == [
        "ses_checkpoint_owner", "ses_uncheckpointed",
    ]


def test_campaign_continuation_preserves_distinct_worktree_conflict(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    workspace = config.workspace_root.resolve()
    repository_root = workspace / "mncs-compiler"
    repository_root.mkdir()
    checkout_root = {
        "repository": "mncs-compiler",
        "path": str(repository_root),
        "workspace_root": str(workspace),
        "repository_root": str(repository_root),
    }

    class CheckoutAmbiguous(Exception):
        diagnostics = {
            "code": "campaign-checkout-ambiguous",
            "conflicting_contexts": [
                {"path": "/projects/mncs-compiler/.worktrees/a", "sessions": ["ses_a"]},
                {"path": "/projects/mncs-compiler/.worktrees/b", "sessions": ["ses_b"]},
            ],
            "next": "enter from the intended registered worktree",
        }

    package = SimpleNamespace(
        entry=SimpleNamespace(
            _campaign_checkout_from_store=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                CheckoutAmbiguous("multiple registered worktrees")
            ),
        ),
    )
    store = SimpleNamespace(close=lambda: None)
    service = EnvironmentService(config)
    service.authenticated_principal_id = "principal-test"
    service._pkg = lambda: package
    service._store = lambda _pkg: store

    with pytest.raises(ControlError) as excinfo:
        service.campaign_continuation(
            "mncs-compiler",
            "cmp_native_application",
            working_checkout=checkout_root,
            definition_id="env_nested_compiler",
            workspace_root=str(workspace),
        )

    assert excinfo.value.code == "ENVIRONMENT_SESSION_SELECTION_REQUIRED"
    assert excinfo.value.details["conflicting_contexts"] == [
        {"path": "/projects/mncs-compiler/.worktrees/a", "sessions": ["ses_a"]},
        {"path": "/projects/mncs-compiler/.worktrees/b", "sessions": ["ses_b"]},
    ]


def test_campaign_continuation_projects_exact_git_verified_charter(tmp_path: Path) -> None:
    result = _campaign_charter_result(tmp_path)

    assert result["status"] == "ready"
    capsule = result["continuations"][0]
    assert capsule["work_intent"]["goal"] == "narrow fixture goal"
    assert capsule["campaign_charter"] == {
        "status": "verified",
        "identity": "ev_test_campaign_charter",
        "evidence_identity": "ev_env_campaign_charter_test",
        "objective": "Continue the verified long-running campaign safely.",
        "source": {
            "repository": "mncs-environment",
            "commit": capsule["campaign_charter"]["source"]["commit"],
            "path": "evidence/campaign-charter-test.json",
            "sha256": capsule["campaign_charter"]["source"]["sha256"],
        },
    }


def test_campaign_continuation_finds_original_charter_past_recent_evidence_page(
    tmp_path: Path,
) -> None:
    result = _campaign_charter_result(
        tmp_path, evidence_prefix=34, evidence_suffix=155, selector_decoy=True,
    )

    assert result["status"] == "ready"
    capsule = result["continuations"][0]
    assert capsule["evidence_count"] == 191
    assert capsule["campaign_charter"]["status"] == "verified"
    assert capsule["campaign_charter"]["evidence_identity"] == "ev_env_campaign_charter_test"
    assert capsule["campaign_charter"]["objective"] == (
        "Continue the verified long-running campaign safely."
    )


def test_campaign_continuation_verifies_charter_in_presented_evidence_window(
    tmp_path: Path,
) -> None:
    result = _campaign_charter_result(tmp_path, evidence_prefix=34)

    assert result["status"] == "ready"
    capsule = result["continuations"][0]
    assert capsule["evidence_count"] == 35
    assert len(capsule["evidence"]) == 32
    assert capsule["evidence_truncated"] is True
    assert capsule["evidence"][-1]["identity"] == "ev_env_campaign_charter_test"
    assert capsule["campaign_charter"]["status"] == "verified"
    assert capsule["campaign_charter"]["evidence_identity"] == "ev_env_campaign_charter_test"


def test_campaign_continuation_verifies_old_charter_without_emitting_old_evidence(
    tmp_path: Path,
) -> None:
    result = _campaign_charter_result(tmp_path, evidence_suffix=40)

    assert result["status"] == "ready"
    capsule = result["continuations"][0]
    assert capsule["evidence_count"] == 41
    assert len(capsule["evidence"]) == 32
    assert capsule["evidence_truncated"] is True
    assert all(
        item["identity"] != "ev_env_campaign_charter_test"
        for item in capsule["evidence"]
    )
    assert capsule["campaign_charter"]["status"] == "verified"
    assert capsule["campaign_charter"]["evidence_identity"] == "ev_env_campaign_charter_test"


def test_campaign_continuation_keeps_two_verified_charters_ambiguous(
    tmp_path: Path,
) -> None:
    result = _campaign_charter_result(tmp_path, second_valid_charter=True)

    assert result["status"] == "ready"
    assert "campaign_charter" not in result["continuations"][0]


def test_campaign_continuation_fails_closed_on_truncated_charter_index(
    tmp_path: Path,
) -> None:
    result = _campaign_charter_result(tmp_path, charter_index_truncated=True)

    assert result["status"] == "ready"
    assert "campaign_charter" not in result["continuations"][0]


@pytest.mark.parametrize("failure", ["digest", "campaign"])
def test_campaign_continuation_omits_unverified_charter(
    tmp_path: Path, failure: str,
) -> None:
    if failure == "digest":
        result = _campaign_charter_result(tmp_path, referenced_digest="0" * 64)
    else:
        result = _campaign_charter_result(tmp_path, charter_campaign="another-campaign")

    assert result["status"] == "ready"
    assert "campaign_charter" not in result["continuations"][0]


def test_campaign_continuation_surfaces_bounded_context_conflict_capsules(
    tmp_path: Path,
) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-caller"
    (service._config.workspace_root / "mncs-control-mcp").mkdir()
    snapshots = {
        f"ses_{index:02d}": {
            "snapshot_sequence": index,
            "lifecycle": "active",
            "consumer_id": f"consumer-{index}",
            "authenticated_principal_id": "principal-caller",
            "provenance": {"definition_id": f"definition-{index}"},
            "workspace": {"root": f"/projects/workspace-{index}"},
            "campaign": {
                "identity": "campaign-context-conflict",
                "work_intent": {
                    "goal": "continue the same authorized project work",
                    "repositories": ["mncs-control-mcp"],
                },
            },
        }
        for index in range(17)
    }

    class Store:
        closed = False

        def list_sessions(self):
            return list(snapshots)

        def load_snapshot(self, session_id: str):
            return snapshots.get(session_id)

        def read_claims(self):
            return []

        def close(self):
            self.closed = True

    store = Store()
    service._pkg = lambda: SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda _records: {}),
    )
    service._store = lambda _pkg: store
    service._observe_project_checkout = lambda repository: {
        "status": "unknown", "repository": repository,
    }
    def capsule(
        _pkg, _store, session_id, snapshot, _repository, _claims, _observation,
        *, working_checkout=None,
    ):
        return {
            "session_id": session_id,
            "definition_id": snapshot["provenance"]["definition_id"],
            "workspace_root": snapshot["workspace"]["root"],
            "lifecycle": snapshot["lifecycle"],
        }

    service._continuation_capsule = capsule

    result = service.campaign_continuation("mncs-control-mcp")

    assert result["status"] == "context-conflict"
    assert result["contexts_count"] == 17
    assert result["contexts_truncated"] is True
    assert len(result["contexts"]) == 16
    assert result["continuations_count"] == 17
    assert result["continuations_truncated"] is True
    assert [item["session_id"] for item in result["continuations"]] == [
        f"ses_{index:02d}" for index in range(16)
    ]
    assert result["next"].startswith("review each capsule's project_reference")
    assert store.closed is True


def test_campaign_continuation_hides_foreign_session_identity(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-caller"
    repository = service._config.workspace_root / "mncs-control-mcp"
    repository.mkdir()
    foreign = {
        "authenticated_principal_id": "principal-owner",
        "lifecycle": "active",
        "campaign": {
            "identity": "campaign-1",
            "work_intent": {"repositories": ["mncs-control-mcp"]},
        },
    }

    class Store:
        def list_sessions(self):
            return ["ses_foreign_secret"]

        def load_snapshot(self, _session_id: str):
            return foreign

        def read_claims(self):
            return []

        def close(self):
            pass

    pkg = SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda _records: {}),
        sessions=SimpleNamespace(),
    )
    service._pkg = lambda: pkg
    service._store = lambda _pkg: Store()

    with pytest.raises(ControlError) as excinfo:
        service.campaign_continuation("mncs-control-mcp", "campaign-1")

    assert excinfo.value.code == "ENVIRONMENT_AUTHORITY_DENIED"
    assert "ses_foreign_secret" not in repr(excinfo.value.details)
    next_step = excinfo.value.details["next"]
    assert "explicit handoff" in next_step
    assert "new campaign_id and task_identity" in next_step


def test_campaign_continuation_requires_authenticated_principal_and_project_scope(
    tmp_path: Path,
) -> None:
    service = EnvironmentService(_config(tmp_path))
    project = service._config.workspace_root / "mncs-control-mcp"
    project.mkdir()

    with pytest.raises(ControlError) as unauthenticated:
        service.campaign_continuation("mncs-control-mcp", "campaign-1")
    assert unauthenticated.value.code == "ENVIRONMENT_AUTHORITY_DENIED"

    service.authenticated_principal_id = "principal-caller"
    with pytest.raises(ControlError) as escaped:
        service.campaign_continuation("../mncs-control-mcp", "campaign-1")
    assert escaped.value.code == "ENVIRONMENT_PROJECT_INVALID"


def test_enter_forwards_explicit_campaign_identity(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    captured: dict[str, object] = {}
    service._pkg = lambda: SimpleNamespace(
        entry=SimpleNamespace(enter=lambda **kwargs: captured.update(kwargs) or {"ok": True})
    )

    assert service.enter(
        {"name": "continuity"}, "consumer-new", campaign_id="campaign-1",
        task_identity="Continue MNCS Store and compiler campaign",
    ) == {"ok": True}
    assert captured["campaign_id"] == "campaign-1"
    assert captured["task_identity"] == "Continue MNCS Store and compiler campaign"


def test_enter_preserves_task_selector_ambiguity_details(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))

    class EntryFailure(Exception):
        diagnostics = {
            "code": "campaign-continuation-ambiguous",
            "campaigns": ["campaign-a", "campaign-b"],
            "next": "select the intended campaign identity",
        }

    def fail_entry(**_kwargs):
        raise EntryFailure("multiple durable campaigns match this task selector")

    service._pkg = lambda: SimpleNamespace(
        entry=SimpleNamespace(enter=fail_entry)
    )

    with pytest.raises(ControlError) as raised:
        service.enter(
            {"name": "continuity"},
            "consumer-new",
            task_identity="same durable task",
        )

    assert raised.value.code == "ENVIRONMENT_ENTER_FAILED"
    assert raised.value.details["code"] == "campaign-continuation-ambiguous"
    assert raised.value.details["campaigns"] == ["campaign-a", "campaign-b"]


def test_campaign_continuation_resolves_only_an_authenticated_task_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-task-continuation"
    project = service._config.workspace_root / "mncs-control-mcp"
    project.mkdir()
    workspace_root = str(service._config.workspace_root.resolve())
    definition_id = "env_1111111111111111"
    task_identity = "durable-control-campaign-20261012"
    campaign_id = "cmp_task_continuation_fixture"
    snapshot = {
        "session_id": "ses_task_continuation_fixture",
        "snapshot_sequence": 7,
        "lifecycle": "checkpointed",
        "consumer_id": "consumer-before-restart",
        "consumer_kind": "agent",
        "authenticated_principal_id": service.authenticated_principal_id,
        "provenance": {"definition_id": definition_id},
        "workspace": {"root": workspace_root},
        "intent": {"identity": "intent-task-continuation"},
        "campaign": {
            "identity": campaign_id,
            "work_intent": {
                "goal": "continue the protected task-selector campaign",
                "repositories": ["mncs-control-mcp"],
            },
            "delivery": {"status": "partial"},
        },
    }

    class Store:
        def __init__(self) -> None:
            self.evidence: dict[str, dict[str, object]] = {}

        def list_sessions(self):
            return [snapshot["session_id"]]

        def load_snapshot(self, session_id: str):
            return snapshot if session_id == snapshot["session_id"] else None

        def read_claims(self):
            return []

        def read_evidence(self, evidence_id: str):
            return self.evidence.get(evidence_id)

        def write_evidence(self, evidence_id: str, record: dict[str, object]):
            self.evidence[evidence_id] = record
            return record

        def close(self):
            pass

    class Session:
        @staticmethod
        def open(**_kwargs):
            return SimpleNamespace(context=lambda: {"continuation": {}})

    store = Store()
    package = service._pkg()
    selector = package.campaign_selector.selector_identity(
        task_identity,
        authenticated_principal_id=service.authenticated_principal_id,
        definition_id=definition_id,
        workspace_root=workspace_root,
    )
    package.campaign_selector.bind(
        store,
        selector=selector,
        authenticated_principal_id=service.authenticated_principal_id,
        definition_id=definition_id,
        workspace_root=workspace_root,
        campaign_id=campaign_id,
        session_id=snapshot["session_id"],
        request_id="req_task_continuation_binding",
    )
    monkeypatch.setattr(package.sessions, "Session", Session)
    monkeypatch.setattr(package.claims, "active_claims", lambda _claims: {})
    service._pkg = lambda: package
    service._store = lambda _package: store

    resumed = service.campaign_continuation(
        "mncs-control-mcp", task_identity=task_identity,
    )
    assert resumed["status"] == "ready"
    assert resumed["campaign_id"] == campaign_id
    assert resumed["continuations"][0]["session_id"] == snapshot["session_id"]
    assert resumed["task_selector"] == {
        "status": "resolved",
        "campaign_id": campaign_id,
        "session_id": snapshot["session_id"],
        "definition_id": definition_id,
        "workspace_root": workspace_root,
    }

    unbound = service.campaign_continuation(
        "mncs-control-mcp", task_identity="different-unbound-task",
    )
    assert unbound["status"] == "task-selector-unbound"
    assert unbound["campaigns"] == [campaign_id]
    assert "continuations" not in unbound

    with pytest.raises(ControlError) as conflict:
        service.campaign_continuation(
            "mncs-control-mcp",
            "cmp_other_task",
            task_identity=task_identity,
        )
    assert conflict.value.code == "ENVIRONMENT_TASK_SELECTOR_CONFLICT"



def test_task_selector_uses_unique_authoritative_session_across_contexts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-context-selection"
    repository = "mncs-control-mcp"
    checkout = service._config.workspace_root / repository / ".worktrees" / "selected"
    checkout.mkdir(parents=True)
    campaign_id = "cmp_task_context_selection"
    task_identity = "same-task-after-environment-definition-change"
    contexts = [
        ("ses_checkpointed", "env_prior", str(checkout.parent)),
        ("ses_uncheckpointed", "env_current", str(service._config.workspace_root)),
    ]
    snapshots = {}
    for session_id, definition_id, workspace_root in contexts:
        snapshots[session_id] = {
            "session_id": session_id,
            "snapshot_sequence": 3,
            "lifecycle": "active",
            "authenticated_principal_id": service.authenticated_principal_id,
            "provenance": {"definition_id": definition_id},
            "workspace": {"root": workspace_root},
            "selected_checkouts": {
                repository: {
                    "repository": repository,
                    "path": str(checkout),
                    "branch": "campaign/current",
                    "head": "a" * 40,
                    "checkout_identity": "checkout-selected",
                    "git_common_directory_identity": "common-selected",
                }
            },
            "campaign": {
                "identity": campaign_id,
                "work_intent": {
                    "goal": "continue the compiler-language task",
                    "repositories": [repository],
                },
                "repository_refs": [{
                    "repository": repository,
                    "observed_path": str(checkout),
                    "branch": "campaign/current",
                    "head": "a" * 40,
                }],
                "delivery": {"status": "pending"},
            },
        }

    class Store:
        def __init__(self) -> None:
            self.evidence: dict[str, dict[str, object]] = {}

        def list_sessions(self):
            return list(snapshots)

        def load_snapshot(self, session_id: str):
            return snapshots.get(session_id)

        def read_claims(self):
            return []

        def read_evidence(self, evidence_id: str):
            return self.evidence.get(evidence_id)

        def write_evidence(self, evidence_id: str, record: dict[str, object]):
            self.evidence[evidence_id] = record
            return record

        def close(self):
            pass

    store = Store()
    package = service._pkg()
    for session_id, definition_id, workspace_root in contexts:
        selector = package.campaign_selector.selector_identity(
            task_identity,
            authenticated_principal_id=service.authenticated_principal_id,
            definition_id=definition_id,
            workspace_root=workspace_root,
        )
        package.campaign_selector.bind(
            store,
            selector=selector,
            authenticated_principal_id=service.authenticated_principal_id,
            definition_id=definition_id,
            workspace_root=workspace_root,
            campaign_id=campaign_id,
            session_id=session_id,
            request_id=f"req_{session_id}",
        )

    class Session:
        @staticmethod
        def open(**_kwargs):
            return SimpleNamespace(context=lambda: {"continuation": {}})

    selected_owner = {"session_id": "ses_checkpointed"}

    def authoritative_session(_store, session_ids, _working_checkout):
        assert set(session_ids) == {"ses_checkpointed", "ses_uncheckpointed"}
        return selected_owner["session_id"], {"basis": "unique_session_checkpoint"}

    monkeypatch.setattr(package.sessions, "Session", Session)
    monkeypatch.setattr(
        package.entry, "_authoritative_duplicate_session", authoritative_session,
    )
    monkeypatch.setattr(package.claims, "active_claims", lambda _claims: {})
    service._pkg = lambda: package
    service._store = lambda _package: store
    working_checkout = {
        "repository": repository,
        "path": str(checkout),
        "branch": "campaign/current",
        "head": "a" * 40,
        "checkout_identity": "checkout-selected",
        "git_common_directory_identity": "common-selected",
    }

    selected = service.campaign_continuation(
        repository,
        campaign_id,
        task_identity,
        working_checkout=working_checkout,
    )
    assert selected["status"] == "ready"
    assert selected["continuations"][0]["session_id"] == "ses_checkpointed"
    assert selected["task_selector"]["session_id"] == "ses_checkpointed"

    selected_owner["session_id"] = None
    ambiguous = service.campaign_continuation(
        repository,
        campaign_id,
        task_identity,
        working_checkout=working_checkout,
    )
    assert ambiguous["status"] == "ambiguous-task-selector-contexts"
    assert ambiguous["task_selector"]["status"] == "ambiguous"
    assert {item["session_id"] for item in ambiguous["task_selector"]["contexts"]} == {
        "ses_checkpointed", "ses_uncheckpointed",
    }


def test_projection_evidence_reads_authenticated_session_without_mutating_it(
    tmp_path: Path,
) -> None:
    snapshot = {
        "session_id": "ses_projection_test",
        "authenticated_principal_id": "principal-test",
        "snapshot_sequence": 17,
        "projection_epoch": {
            "epoch": "epoch-17",
            "at": "2026-10-11T12:00:00+00:00",
            "evidence_ref": "store:sha256:abc123",
            "private_field": "not part of the public capsule",
        },
    }
    before = json.dumps(snapshot, sort_keys=True)
    evidence = {"schema_version": "mncs.projection-evidence/1", "results": []}
    history = [{"at": "2026-10-11T12:00:00+00:00", "mode": "ambient"}]
    opened: list[str] = []
    reads: list[str] = []

    class Store:
        closed = False

        def load_snapshot(self, session_id: str):
            return snapshot if session_id == "ses_projection_test" else None

        def close(self):
            self.closed = True

    store = Store()

    class Session:
        @staticmethod
        def open(**kwargs):
            opened.append(kwargs["session_id"])
            return SimpleNamespace(snapshot=snapshot)

    def read_evidence(session):
        reads.append(session.snapshot["session_id"])
        return {"evidence": evidence, "history": history}

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-test"
    service._pkg = lambda: SimpleNamespace(
        sessions=SimpleNamespace(Session=Session),
        projections=SimpleNamespace(read_evidence=read_evidence),
    )
    service._store = lambda _pkg: store

    result = service.projection_evidence("ses_projection_test")

    assert result == {
        "schema_version": "mncs.control.environment-projection-evidence/1",
        "session_id": "ses_projection_test",
        "snapshot_version": 17,
        "projection_epoch": {
            "epoch": "epoch-17",
            "at": "2026-10-11T12:00:00+00:00",
            "evidence_ref": "store:sha256:abc123",
        },
        "evidence": evidence,
        "history": history,
    }
    assert opened == ["ses_projection_test"]
    assert reads == ["ses_projection_test"]
    assert store.closed is True
    assert json.dumps(snapshot, sort_keys=True) == before


def test_projection_evidence_rejects_foreign_session_before_read(tmp_path: Path) -> None:
    snapshot = {
        "session_id": "ses_foreign",
        "authenticated_principal_id": "principal-owner",
    }
    reads: list[str] = []

    class Store:
        def load_snapshot(self, _session_id: str):
            return snapshot

        def close(self):
            pass

    class Session:
        @staticmethod
        def open(**_kwargs):
            raise AssertionError("foreign session must be rejected before open")

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-caller"
    service._pkg = lambda: SimpleNamespace(
        sessions=SimpleNamespace(Session=Session),
        projections=SimpleNamespace(read_evidence=lambda _session: reads.append("read")),
    )
    service._store = lambda _pkg: Store()

    with pytest.raises(ControlError) as raised:
        service.projection_evidence("ses_foreign")

    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"
    assert reads == []


def test_projection_evidence_requires_control_principal(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    service._pkg = lambda: pytest.fail("unauthenticated reads must fail before Store access")

    with pytest.raises(ControlError) as raised:
        service.projection_evidence("ses_projection_test")

    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


@needs_environment
def test_projection_evidence_reads_owner_record_from_isolated_store(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-test"
    entered = service.enter(
        {"name": "projection-evidence-probe", "intent": {"goal": "read evidence"}},
        "projection-evidence-probe",
    )
    session_id = entered["session_id"]
    pkg = service._pkg()
    store = service._store(pkg)
    try:
        session = pkg.sessions.Session.open(
            state_dir=service.state_dir, session_id=session_id,
            backend="store", store=store,
        )
        projections = importlib.import_module("mncs_env.projections")
        evidence = {
            "schema_version": "mncs.projection-evidence/1",
            "identity": "ev_projection_read_test",
            "results": [{"projection": "workspace", "outcome": "current"}],
        }
        evidence_ref = projections.evidence_store.publish(
            session, "projections", evidence,
        )
        session.snapshot["projection_epoch"] = {
            "epoch": "epoch-test",
            "at": "2026-10-11T12:00:00+00:00",
            "evidence_ref": evidence_ref,
        }
        session.snapshot["projection_history"] = [{
            "at": "2026-10-11T12:00:00+00:00",
            "mode": "ambient",
            "evidence_ref": evidence_ref,
        }]
        session._save()
    finally:
        store.close()

    result = service.projection_evidence(session_id)

    assert result["session_id"] == session_id
    assert result["projection_epoch"]["evidence_ref"] == evidence_ref
    assert result["evidence"] == evidence
    assert result["history"] == session.snapshot["projection_history"]


@needs_environment
def test_campaign_continuation_reads_real_isolated_store(tmp_path: Path) -> None:
    repository = "mncs-control-mcp"
    checkout = tmp_path / "projects" / repository
    checkout.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "continuity-test"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email",
                    "continuity-test@example.invalid"], check=True)
    manifest = checkout / ".mncs" / "project.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({
        "schema_version": "mncs-family.repository-manifest/v0alpha1",
        "repository": repository,
        "revision": 1,
    }), encoding="utf-8")
    (checkout / "README.md").write_text("isolated campaign fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", ".mncs/project.json"], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-isolated-test"
    task_identity = "control-isolated-store-campaign-task"
    entered = service.enter(
        {
            "name": "continuity-test",
            "intent": {
                "goal": "prove authenticated campaign lookup",
                "repositories": [repository],
            },
        },
        "continuity-test-consumer",
        workspace=".",
        campaign_id="cmp_isolated_test",
        task_identity=task_identity,
    )
    recorded_head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    (checkout / "README.md").write_text("checkout advanced after session entry\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "advance after entry"], check=True)
    live_head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert live_head != recorded_head

    pkg = service._pkg()
    store = service._store(pkg)
    recorded = store.load_snapshot(entered["session_id"])
    assert isinstance(recorded, dict)
    working_checkout = pkg.workspace.verify_registered_checkout(
        checkout, repository=repository, workspace_root=service._config.workspace_root,
        expected_repository_root=checkout,
    )
    checkpoint_owner = pkg.sessions.Session.open(
        state_dir=service.state_dir, session_id=entered["session_id"],
        backend="store", store=store,
    )
    checkpoint_owner.snapshot["selected_checkouts"] = {
        repository: {
            key: working_checkout[key] for key in (
                "repository", "path", "workspace_root", "repository_root",
                "git_common_directory", "git_common_directory_identity",
                "checkout_identity", "branch", "head",
            )
        }
    }
    checkpoint_owner.snapshot["selected_checkouts"][repository]["head"] = recorded_head
    checkpoint_owner._save()
    recorded = store.load_snapshot(entered["session_id"])
    assert isinstance(recorded, dict)
    checkpoint = checkpoint_owner.checkpoint(
        progress="unique checkpoint identifies the continuing checkout session",
    )
    assert checkpoint["sequence"] == 1
    environment = {
        "identity": recorded["environment_id"],
        "intent": recorded.get("intent"),
        "authority": recorded.get("authority"),
        "rights": recorded.get("rights", {}),
        "workspace": recorded.get("workspace", {}),
        "selected_checkouts": recorded.get("selected_checkouts", {}),
        "toolchain": recorded.get("toolchain"),
        "execution_roles": recorded.get("execution_roles", {}),
        "execution_compatibility_service": recorded.get("execution_compatibility_service"),
        "execution_stack": recorded.get("execution_stack"),
        "configuration": recorded.get("configuration", {}),
        "requirements": recorded.get("requirements", {}),
        "repo_facts": recorded.get("repo_facts", {}),
        "claim_holders": recorded.get("claim_holders", {}),
        "bindings": recorded.get("bindings", []),
        "definition_id": (recorded.get("provenance") or {}).get("definition_id"),
        "resolution_inputs_digest": (recorded.get("provenance") or {}).get(
            "resolution_inputs_digest"
        ),
    }
    duplicate = pkg.sessions.Session.create(
        state_dir=service.state_dir,
        environment=environment,
        consumer_id="continuity-test-restarted-process",
        campaign_id="cmp_isolated_test",
        authenticated_principal_id=service.authenticated_principal_id,
        store=store,
    )
    duplicate.transition("resolving", "test interrupted continuation setup")
    duplicate.transition("ready", "test continuation setup complete")
    duplicate.transition("active", "test restarted consumer entered")
    duplicate_session_id = duplicate.session_id
    store.close()

    result = service.campaign_continuation(repository, "cmp_isolated_test")

    assert result["status"] == "ambiguous"
    assert {item["session_id"] for item in result["continuations"]} == {
        entered["session_id"], duplicate_session_id,
    }
    selected = next(item for item in result["continuations"]
                    if item["session_id"] == entered["session_id"])
    assert selected["work_intent"]["goal"] == "prove authenticated campaign lookup"
    checkout_ref = selected["repositories"][0]
    assert checkout_ref["repository"] == repository
    assert checkout_ref.get("observed_path", checkout_ref.get("path")) == str(checkout)
    assert checkout_ref["branch"] in {"main", "master"}
    assert len(checkout_ref["head"]) == 40
    assert checkout_ref["head"] == recorded_head
    observation = selected["live_repository_observation"]
    assert observation["status"] == "current"
    assert observation["checkout"]["path"] == str(checkout)
    assert observation["checkout"]["head"] == live_head
    assert observation["checkout"]["head"] != checkout_ref["head"]
    assert observation["checkout"]["clean"] is True
    comparison = selected["recorded_checkout_comparisons"][0]
    assert comparison["status"] == "checkout_head_changed"
    assert comparison["recorded_head"] == recorded_head
    assert comparison["live_head"] == live_head
    exact_checkout = service.campaign_continuation(
        repository, "cmp_isolated_test", working_checkout=working_checkout,
    )
    assert exact_checkout["status"] == "ready"
    assert exact_checkout["selected_session_id"] == entered["session_id"]
    assert [item["session_id"] for item in exact_checkout["continuations"]] == [
        entered["session_id"],
    ]
    task_capsule = service.campaign_continuation(
        repository, task_identity=task_identity,
    )
    assert task_capsule["status"] == "ready"
    assert [item["session_id"] for item in task_capsule["continuations"]] == [
        entered["session_id"],
    ]
    assert task_capsule["task_selector"] == {
        "status": "resolved",
        "campaign_id": "cmp_isolated_test",
        "session_id": entered["session_id"],
        "definition_id": recorded["provenance"]["definition_id"],
        "workspace_root": str(tmp_path / "projects"),
    }
    assert observation["worktree_registrations"][0]["physical_checkout_status"].startswith(
        "not_checked"
    )
    child_script = """
import json
import sys
from pathlib import Path
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import EnvironmentService

root, state, environment, session_id, duplicate_id, task_identity = sys.argv[1:]
service = EnvironmentService(ControlConfig(
    workspace_root=Path(root),
    repositories={"environment": environment},
    environment_state_dir=Path(state),
))
service.authenticated_principal_id = "principal-isolated-test"
capsule = service.campaign_continuation(
    "mncs-control-mcp", task_identity=task_identity,
)
selected = next(item for item in capsule["continuations"]
                if item["session_id"] == session_id)
resumed = service.resume(selected["session_id"])
print(json.dumps({
    "status": capsule["status"],
    "candidate_ids": sorted(item["session_id"] for item in capsule["continuations"]),
    "task_selector": capsule["task_selector"],
    "resumed_session_id": resumed["session_id"],
    "expected_ids": sorted((session_id, duplicate_id)),
}))
"""
    child = subprocess.run(
        [sys.executable, "-c", child_script,
         str(tmp_path / "projects"), str(tmp_path / "env-state"), str(ENVIRONMENT),
         entered["session_id"], duplicate_session_id, task_identity],
        cwd=Path(__file__).parents[1],
        env={**os.environ,
             "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    continued = json.loads(child.stdout)
    assert continued["status"] == "ready"
    assert continued["candidate_ids"] == [entered["session_id"]]
    assert continued["expected_ids"] == sorted((entered["session_id"], duplicate_session_id))
    assert continued["task_selector"]["status"] == "resolved"
    assert continued["task_selector"]["session_id"] == entered["session_id"]
    assert continued["resumed_session_id"] == entered["session_id"]
    resumed_capsule = service.campaign_continuation(repository, "cmp_isolated_test")
    assert resumed_capsule["status"] == "ambiguous"
    assert {item["session_id"] for item in resumed_capsule["continuations"]} == {
        entered["session_id"], duplicate_session_id,
    }
    inventory = service._store(pkg)
    try:
        assert set(inventory.list_sessions()) == {entered["session_id"], duplicate_session_id}
    finally:
        inventory.close()


@pytest.mark.parametrize(
    ("claim_owners", "expected_status", "expected_session"),
    [
        (["ses_prior_campaign"], "ready", "ses_prior_campaign"),
        (["ses_prior_campaign", "ses_current_branch"], "ambiguous", None),
    ],
)
def test_campaign_continuation_prefers_unique_active_checkout_claim_across_branch_change(
    tmp_path: Path, claim_owners: list[str], expected_status: str,
    expected_session: str | None,
) -> None:
    repository = "mncs-compiler"
    workspace = tmp_path / "projects"
    checkout_root = workspace / repository
    checkout = checkout_root / ".worktrees" / "continuation"
    checkout.mkdir(parents=True)
    checkout_identity = "checkout:stable"
    common_identity = "git-common:stable"
    manifest_identity = "manifest:stable"
    previous_branch = "campaign/previous"
    current_branch = "campaign/current"
    current_checkout = {
        "repository": repository,
        "path": str(checkout),
        "workspace_root": str(workspace),
        "repository_root": str(checkout_root),
        "git_common_directory": str(checkout_root / ".git"),
        "git_common_directory_identity": common_identity,
        "checkout_identity": checkout_identity,
        "manifest_identity": manifest_identity,
        "branch": current_branch,
        "head": "c" * 40,
        "clean": False,
    }
    session_ids = ["ses_prior_campaign", "ses_current_branch"]

    def snapshot(session_id: str) -> dict:
        prior = session_id == "ses_prior_campaign"
        branch = previous_branch if prior else current_branch
        head = "a" * 40 if prior else "c" * 40
        selected = {**current_checkout, "branch": branch, "head": head}
        return {
            "session_id": session_id,
            "snapshot_sequence": 10 if prior else 2,
            "lifecycle": "active",
            "consumer_id": "local-agent",
            "consumer_kind": "agent",
            "authenticated_principal_id": "principal-test",
            "provenance": {"definition_id": "env-campaign"},
            "workspace": {"root": str(workspace)},
            "intent": {"identity": f"intent-{session_id}"},
            "selected_checkouts": {repository: selected},
            "campaign": {
                "identity": "cmp_branch_change",
                "session_ids": session_ids,
                "authorized_consumers": ["local-agent"],
                "work_intent": {
                    "goal": "continue the existing compiler campaign",
                    "repositories": [repository],
                },
                "repository_refs": [{
                    "repository": repository,
                    "observed_path": str(checkout),
                    "checkout_identity": checkout_identity,
                    "git_common_directory_identity": common_identity,
                    "branch": branch,
                    "head": head,
                    "clean": False,
                    "observation": "current",
                }],
                "delivery": {"status": "pending"},
            },
        }

    snapshots = {session_id: snapshot(session_id) for session_id in session_ids}
    claims = []
    for owner in claim_owners:
        branch = previous_branch if owner == "ses_prior_campaign" else current_branch
        claims.append({
            "claim_id": f"claim-{owner}",
            "version": 1,
            "repository": repository,
            "session_id": owner,
            "status": "held",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "scope": {
                "kind": "worktree",
                "repository": repository,
                "checkout": str(checkout),
                "branch": branch,
                "checkout_identity": checkout_identity,
                "git_common_directory_identity": common_identity,
                "manifest_identity": manifest_identity,
                "paths": None,
                "exclusive": False,
            },
        })

    class Store:
        def list_sessions(self):
            return list(snapshots)

        def load_snapshot(self, session_id: str):
            return snapshots.get(session_id)

        def read_claims(self):
            return claims

        def close(self):
            return None

    class Session:
        @staticmethod
        def open(*, session_id: str, **_kwargs):
            selected = snapshots[session_id]["selected_checkouts"][repository]
            reference = {
                key: selected[key] for key in (
                    "repository", "path", "checkout_identity",
                    "git_common_directory_identity", "branch", "head", "clean",
                )
            }
            continuation = {
                "repositories": [{**reference, "observed_path": str(checkout)}],
                "checkpoint_ids": ["chk_prior"] if session_id == "ses_prior_campaign" else [],
            }
            if session_id == "ses_prior_campaign":
                continuation["latest_checkpoint"] = {
                    "identity": "chk_prior", "sequence": 649,
                }
            return SimpleNamespace(context=lambda: {
                "authority": {"writable": [repository], "scope_grants": []},
                "continuation": continuation,
            })

    def active_claims(records):
        return {
            str(record["claim_id"]): record for record in records
            if record.get("status") == "held"
        }

    duplicate_selector_calls = []

    def snapshot_matches(snapshot_value, working_checkout):
        selected = snapshot_value.get("selected_checkouts", {}).get(repository, {})
        return (
            selected.get("path") == working_checkout.get("path")
            and selected.get("checkout_identity") == working_checkout.get("checkout_identity")
            and selected.get("branch") == working_checkout.get("branch")
        )

    def snapshot_duplicate_selector(_store, candidate_ids, _working_checkout):
        duplicate_selector_calls.append(list(candidate_ids))
        return "ses_current_branch", {"basis": "unique_registered_checkout"}

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-test"
    service._pkg = lambda: SimpleNamespace(
        claims=SimpleNamespace(active_claims=active_claims),
        sessions=SimpleNamespace(Session=Session, CAMPAIGN_EVIDENCE_MAX=32),
        entry=SimpleNamespace(
            _working_checkout_matches_snapshot=snapshot_matches,
            _authoritative_duplicate_session=snapshot_duplicate_selector,
        ),
    )
    service._store = lambda _pkg: Store()
    service._observe_project_checkout = lambda _repository: {
        "status": "current",
        "repository": repository,
        "workspace_root": str(workspace),
        "checkout": current_checkout,
        "worktree_registrations": [{
            "registered_path": str(checkout),
            "branch": current_branch,
            "head": "c" * 40,
        }],
    }

    result = service.campaign_continuation(
        repository, "cmp_branch_change", working_checkout=current_checkout,
    )

    if expected_status == "ready":
        assert result["status"] == "ready"
        assert result["selected_session_id"] == expected_session
        assert result["selection_basis"] == (
            "authenticated-project-checkout-live-claim-owner"
        )
        assert [row["session_id"] for row in result["continuations"]] == [expected_session]
    else:
        assert result["status"] == "ambiguous"
        assert result.get("selected_session_id") is None
        assert {row["session_id"] for row in result["continuations"]} == set(session_ids)
    assert duplicate_selector_calls == []


def test_task_binding_uses_authenticated_project_link_and_stable_request(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    (workspace / "mncs-control-mcp").mkdir()
    (workspace / "mncs-environment").mkdir()
    snapshot = {
        "session_id": "ses_task_binding",
        "authenticated_principal_id": "principal-test",
        "snapshot_sequence": 7,
        "lifecycle": "active",
        "provenance": {"definition_id": "env_persisted_definition"},
        "workspace": {"root": "/persisted/workspace"},
        "campaign": {
            "identity": "cmp_task_binding",
            "principal_id": "principal-test",
            "work_intent": {
                "goal": "continue the current authorized project task",
                "repositories": ["mncs-control-mcp"],
            },
        },
    }
    calls = []

    class Store:
        def load_snapshot(self, session_id):
            return snapshot if session_id == snapshot["session_id"] else None

        def read_claims(self):
            return []

        def close(self):
            pass

    class Session:
        def __init__(self, store, session_id):
            assert store.load_snapshot(session_id) is snapshot
            self.session_id = session_id

        def bind_task_identity(self, task_identity, **kwargs):
            calls.append((task_identity, kwargs))
            return {
                "selector_identity": "tsel_fixture",
                "campaign_id": kwargs["campaign_id"],
                "session_id": self.session_id,
                "definition_id": "env_persisted_definition",
                "workspace_root": "/persisted/workspace",
                "request_id": kwargs["request_id"],
                "bound_at": "2026-10-12T00:00:00+00:00",
            }

    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "principal-test"
    service._pkg = lambda: SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda _records: {}),
        sessions=SimpleNamespace(Session=Session),
    )
    service._store = lambda _pkg: Store()

    first = service.bind_task_identity(
        "mncs-control-mcp", "cmp_task_binding", "ses_task_binding",
        "durable-task-binding-identity",
    )
    second = service.bind_task_identity(
        "mncs-control-mcp", "cmp_task_binding", "ses_task_binding",
        "durable-task-binding-identity",
    )
    assert first == second
    assert first["status"] == "bound"
    assert first["authority_effect"] == "lookup-only"
    assert len(calls) == 2
    assert calls[0][1]["request_id"] == calls[1][1]["request_id"]
    assert snapshot["snapshot_sequence"] == 7

    with pytest.raises(ControlError) as unlinked:
        service.bind_task_identity(
            "mncs-environment", "cmp_task_binding", "ses_task_binding",
            "durable-task-binding-identity",
        )
    assert unlinked.value.code == "ENVIRONMENT_PROJECT_SCOPE_REQUIRED"

    service.authenticated_principal_id = "principal-foreign"
    with pytest.raises(ControlError) as foreign:
        service.bind_task_identity(
            "mncs-control-mcp", "cmp_task_binding", "ses_task_binding",
            "durable-task-binding-identity",
        )
    assert foreign.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


@needs_environment
def test_task_binding_survives_a_fresh_environment_service(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    (workspace / "mncs-control-mcp").mkdir()
    config = _config(tmp_path)
    service = EnvironmentService(config)
    service.authenticated_principal_id = "principal-task-binding-test"
    campaign_id = "cmp_task_binding_fresh_service"
    task_identity = "fresh-service-task-binding"

    entered = service.enter(
        {
            "name": "task-binding-test",
            "intent": {
                "goal": "verify durable task selector across service instances",
                "repositories": ["mncs-control-mcp"],
            },
        },
        "task-binding-test-consumer",
        campaign_id=campaign_id,
    )
    session_id = entered["session_id"]
    bound = service.bind_task_identity(
        "mncs-control-mcp", campaign_id, session_id, task_identity,
    )
    assert bound["status"] == "bound"
    assert bound["session_id"] == session_id

    restarted_service = EnvironmentService(config)
    restarted_service.authenticated_principal_id = "principal-task-binding-test"
    capsule = restarted_service.campaign_continuation(
        "mncs-control-mcp", task_identity=task_identity,
    )
    assert capsule["task_selector"]["status"] == "resolved"
    assert capsule["task_selector"]["session_id"] == session_id
    assert capsule["task_selector"]["campaign_id"] == campaign_id

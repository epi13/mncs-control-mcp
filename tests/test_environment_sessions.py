"""Control reaches Environment sessions through the real sibling checkout.

Enter resolves and activates a durable session, claims enforce
single-holder ownership across sessions, and a missing checkout
reports unavailable instead of inventing state.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.errors import ControlError

PROJECTS = Path(__file__).parents[2]
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


@needs_environment
def test_enter_inspect_claim_release_round_trip(tmp_path: Path) -> None:
    service = EnvironmentService(_config(tmp_path))
    assert service.status()["available"] is True

    entered = service.enter({"name": "control-probe", "intent": {"goal": "probe"}}, "control-probe")
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
    first = service.enter({"name": "a", "intent": {"goal": "a"}}, "consumer-a")
    second = service.enter({"name": "b", "intent": {"goal": "b"}}, "consumer-b")
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

        def list_sessions(self):
            return list(snapshots)

        def load_snapshot(self, session_id: str):
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
                }] if self.session_id == "ses_first" else [{
                    "repository": "mncs-language",
                    "observed_path": "/projects/mncs-language",
                    "branch": "main",
                    "head": "def456",
                    "clean": True,
                }]),
                "checkpoint_ids": ["chk_latest"],
                "evidence": [{"identity": "evidence-1"}],
                "delivery": {"status": "pending"},
                "unresolved_pressures": [{"identity": "pressure-1"}],
            }}

    store = Store()
    pkg = SimpleNamespace(
        claims=SimpleNamespace(active_claims=lambda records: {
            record["claim_id"]: record for record in records
            if record.get("status") == "held"
        }),
        sessions=SimpleNamespace(Session=SimpleNamespace(open=lambda **kwargs: Session(kwargs["session_id"]))),
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
    assert result["continuations"][0]["claims"][0]["scope"]["exclusive"] is True
    assert result["continuations"][0]["repositories"] == [{
        "repository": "mncs-control-mcp",
        "observed_path": "/projects/mncs-control-mcp/.worktrees/campaign",
        "branch": "campaign/continuity",
        "head": "abc123",
        "clean": True,
    }]
    assert "mncs-language" not in repr(result)
    assert store.closed is True

    service._store = lambda _pkg: Store()
    discovered = service.campaign_continuation("mncs-control-mcp")
    assert discovered["status"] == "ambiguous"
    assert discovered["campaign_id"] == "campaign-1"


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
        {"name": "continuity"}, "consumer-new", campaign_id="campaign-1"
    ) == {"ok": True}
    assert captured["campaign_id"] == "campaign-1"


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
        campaign_id="campaign-isolated-test",
    )

    pkg = service._pkg()
    store = service._store(pkg)
    recorded = store.load_snapshot(entered["session_id"])
    assert isinstance(recorded, dict)
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
        campaign_id="campaign-isolated-test",
        authenticated_principal_id=service.authenticated_principal_id,
        store=store,
    )
    duplicate.transition("resolving", "test interrupted continuation setup")
    duplicate.transition("ready", "test continuation setup complete")
    duplicate.transition("active", "test restarted consumer entered")
    duplicate_session_id = duplicate.session_id
    store.close()

    result = service.campaign_continuation(repository, "campaign-isolated-test")

    assert result["status"] == "ambiguous"
    assert {item["session_id"] for item in result["continuations"]} == {
        entered["session_id"], duplicate_session_id,
    }
    selected = next(item for item in result["continuations"]
                    if item["session_id"] == entered["session_id"])
    assert selected["work_intent"]["goal"] == "prove authenticated campaign lookup"
    checkout_ref = selected["repositories"][0]
    assert checkout_ref["repository"] == repository
    assert checkout_ref["observed_path"] == str(checkout)
    assert checkout_ref["branch"] in {"main", "master"}
    assert len(checkout_ref["head"]) == 40
    child_script = """
import json
import sys
from pathlib import Path
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import EnvironmentService

root, state, environment, session_id, duplicate_id = sys.argv[1:]
service = EnvironmentService(ControlConfig(
    workspace_root=Path(root),
    repositories={"environment": environment},
    environment_state_dir=Path(state),
))
service.authenticated_principal_id = "principal-isolated-test"
capsule = service.campaign_continuation("mncs-control-mcp", "campaign-isolated-test")
selected = next(item for item in capsule["continuations"]
                if item["session_id"] == session_id)
resumed = service.resume(selected["session_id"])
print(json.dumps({
    "status": capsule["status"],
    "candidate_ids": sorted(item["session_id"] for item in capsule["continuations"]),
    "resumed_session_id": resumed["session_id"],
    "expected_ids": sorted((session_id, duplicate_id)),
}))
"""
    child = subprocess.run(
        [sys.executable, "-c", child_script,
         str(tmp_path / "projects"), str(tmp_path / "env-state"), str(ENVIRONMENT),
         entered["session_id"], duplicate_session_id],
        cwd=Path(__file__).parents[1],
        env={**os.environ,
             "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    continued = json.loads(child.stdout)
    assert continued["status"] == "ambiguous"
    assert continued["candidate_ids"] == continued["expected_ids"]
    assert continued["resumed_session_id"] == entered["session_id"]
    resumed_capsule = service.campaign_continuation(repository, "campaign-isolated-test")
    assert resumed_capsule["status"] == "ambiguous"
    assert {item["session_id"] for item in resumed_capsule["continuations"]} == {
        entered["session_id"], duplicate_session_id,
    }
    inventory = service._store(pkg)
    try:
        assert set(inventory.list_sessions()) == {entered["session_id"], duplicate_session_id}
    finally:
        inventory.close()

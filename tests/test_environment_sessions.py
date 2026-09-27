"""Control reaches Environment sessions through the real sibling checkout.

Enter resolves and activates a durable session, claims enforce
single-holder ownership across sessions, and a missing checkout
reports unavailable instead of inventing state.
"""

from __future__ import annotations

from pathlib import Path

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

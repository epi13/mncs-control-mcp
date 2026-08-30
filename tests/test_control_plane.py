from __future__ import annotations

import shutil
import time
from dataclasses import replace

import pytest

from mncs_control_mcp.adapters import IntegrationBundle
from mncs_control_mcp.control_plane import ControlPlaneService
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.processes import ProcessManager
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.server import _register_actions
from mncs_control_mcp.tooling import ProjectService
from mncs_control_mcp.workspace import WorkspacePolicy

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="control-plane integration requires Bubblewrap"
)


def _plane(config) -> ControlPlaneService:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    git = GitService(config, policy, sandbox)
    projects = ProjectService(config, policy, sandbox, git)
    integrations = IntegrationBundle(config, _register_actions(), policy, sandbox)
    return ControlPlaneService(
        config,
        policy,
        sandbox,
        projects,
        git,
        integrations.tests,
        integrations,
        ProcessManager(config, policy, sandbox),
    )


def test_capabilities_and_project_review_are_bounded(config) -> None:
    root = config.workspace_root / "reviewable"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname='reviewable'\nversion='0.1.0'\n", encoding="utf-8"
    )
    (root / "README.md").write_text("# reviewable\nTODO\n", encoding="utf-8")
    plane = _plane(config)
    capabilities = plane.capabilities()
    assert {
        "workspace",
        "terminal",
        "testing",
        "fabric",
        "forge",
        "models",
        "gpu",
        "network",
        "github",
        "developer",
    } <= capabilities.keys()
    assert "joern" not in capabilities
    assert "joern.analysis" not in capabilities["developer"]["supported_operations"]
    assert "github.push" in capabilities["developer"]["supported_operations"]
    readiness = plane.developer_readiness()
    assert "capabilities" in readiness
    assert "github.push" in readiness["capabilities"]
    experiment = plane.experiment_readiness()
    assert experiment["status"] in {"READY", "DEGRADED", "BLOCKED", "UNKNOWN"}
    assert experiment["claim_boundary"] == "infrastructure validation"
    assert experiment.get("schema") == "mncs.experiment-readiness.v1"
    assert "control" in experiment["layers"]
    assert experiment["layers"]["control"]["status"] in {"READY", "DEGRADED", "BLOCKED", "UNKNOWN"}
    rendered = str(readiness)
    assert "gho_" not in rendered
    assert "ghp_" not in rendered
    review = plane.review("reviewable")
    assert review["tests"]["detected_suite"] == "pytest"
    assert "README.md" in review["key_files"]
    assert review["todo_markers"]["TODO"] == 1


def test_typed_workflow_rejects_unknown_workflow(config) -> None:
    plane = _plane(config)
    with pytest.raises(ControlError):
        plane.run_workflow("unknown", "missing")


def test_named_workflow_has_bounded_auditable_steps(config) -> None:
    root = config.workspace_root / "workflow-project"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname='workflow-project'\nversion='0.1.0'\n", encoding="utf-8"
    )
    plane = _plane(config)
    result = plane.run_workflow("review_and_check_project", "workflow-project", profile="quick")
    assert result["workflow"] == "review_and_check_project"
    assert result["workflow_execution_id"].startswith("ctrl-run-")
    assert [step["operation"] for step in result["steps"]] == [
        "project_review",
        "test_discover",
        "project_check",
    ]
    assert result["control_job_id"].startswith("ctrl-")


def test_external_control_job_has_stable_lifecycle(config) -> None:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    manager = ProcessManager(config, policy, sandbox)
    job = manager.submit_external(
        "fabric_test", lambda: {"status": "completed", "receipt": "r1"}, project="fixture"
    )
    assert job["job_id"].startswith("ctrl-")
    deadline = time.monotonic() + 5
    while (
        manager.status(job["job_id"])["status"] in {"queued", "running"}
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    result = manager.result(job["job_id"])
    assert result["ready"] is True
    assert result["result"]["receipt"] == "r1"
    manager.cleanup()


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        (lambda: (_ for _ in ()).throw(RuntimeError("upstream boom")), "failed"),
        (lambda: time.sleep(1), "timed_out"),
    ],
)
def test_external_jobs_have_truthful_exception_and_deadline_states(
    config, operation, expected
) -> None:
    policy = WorkspacePolicy(config)
    manager = ProcessManager(config, policy, Sandbox(config, policy))
    job = manager.submit_external("fabric_test", operation, timeout_seconds=0.1)
    deadline = time.monotonic() + 3
    while (
        manager.status(job["job_id"])["status"] in {"queued", "running"}
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    status = manager.status(job["job_id"])
    assert status["status"] == expected
    assert status["pid"] is None
    assert manager.result(job["job_id"])["ready"] is True
    manager.cleanup()


def test_external_cancellation_before_execution_and_while_owned_are_distinct(config) -> None:
    config = replace(config, max_concurrent_jobs=1)
    policy = WorkspacePolicy(config)
    manager = ProcessManager(config, policy, Sandbox(config, policy))
    first = manager.submit_external("fabric_test", lambda: time.sleep(0.4), timeout_seconds=2)
    second = manager.submit_external(
        "fabric_test", lambda: {"status": "should-not-run"}, timeout_seconds=2
    )
    stopped = manager.stop_control(second["job_id"])
    assert stopped["status"] == "stopped"
    deadline = time.monotonic() + 2
    while (
        manager.status(first["job_id"])["status"] in {"queued", "running"}
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    owned = manager.submit_external("fabric_test", lambda: time.sleep(5), timeout_seconds=10)
    deadline = time.monotonic() + 2
    while not manager._external_processes and time.monotonic() < deadline:
        time.sleep(0.01)
    detached = manager.stop_control(owned["job_id"])
    assert detached["status"] == "upstream_detached"
    assert detached["pid"] is None
    manager.cleanup()


def test_external_capacity_recovers_after_timeout_and_restart_is_truthful(config) -> None:
    config = replace(config, max_concurrent_jobs=1)
    policy = WorkspacePolicy(config)
    manager = ProcessManager(config, policy, Sandbox(config, policy))
    timed_out = manager.submit_external("fabric_test", lambda: time.sleep(2), timeout_seconds=0.1)
    deadline = time.monotonic() + 3
    while (
        manager.status(timed_out["job_id"])["status"] in {"queued", "running"}
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    replacement = manager.submit_external(
        "fabric_test", lambda: {"status": "completed"}, timeout_seconds=1
    )
    deadline = time.monotonic() + 2
    while (
        manager.status(replacement["job_id"])["status"] in {"queued", "running"}
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert manager.status(replacement["job_id"])["status"] == "completed"
    incomplete = manager.submit_external("fabric_test", lambda: time.sleep(2), timeout_seconds=2)
    restarted = ProcessManager(config, policy, Sandbox(config, policy))
    assert restarted.status(incomplete["job_id"])["status"] == "upstream_detached"
    persisted = config.job_state_path.read_text(encoding="utf-8")
    assert '"status": "running"' not in persisted
    manager.cleanup()
    restarted.cleanup()

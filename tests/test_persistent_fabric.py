from __future__ import annotations

import inspect
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from mncs_control_mcp.adapters import FabricAdapter
from mncs_control_mcp.config import ControlConfig, load_config
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.runtime import prepare_fabric_runtime
from mncs_control_mcp.workspace import WorkspacePolicy

fabric = pytest.importorskip("mncs_fabric")


@pytest.fixture
def persistent_service(tmp_path: Path):
    from mncs_fabric.controller_service import ControllerConfig, ControllerService

    socket = tmp_path / "controller.sock"
    service = ControllerService(
        ControllerConfig(
            "persistent-fixture",
            tmp_path / "lifecycle.jsonl",
            service_log=tmp_path / "controller-service.jsonl",
            socket_path=socket,
            admin_socket_path=tmp_path / "controller-admin.sock",
        )
    )
    thread = threading.Thread(
        target=service.run,
        kwargs={"max_seconds": 30.0},
        daemon=True,
    )
    thread.start()
    for _ in range(100):
        if socket.is_socket():
            break
        time.sleep(0.02)
    else:
        service.request_stop()
        thread.join(timeout=3)
        pytest.fail("persistent Fabric consumer socket did not start")
    try:
        yield service, socket
    finally:
        service.request_stop()
        thread.join(timeout=3)


def test_service_config_uses_public_consumer_endpoint(tmp_path: Path) -> None:
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        """
[workspace]
root = "projects"

[integration]
fabric_mode = "service"
fabric_socket = "__SOCKET__"
fabric_execution_mode = "unavailable-until-service-support"
        """.strip().replace("__SOCKET__", str(tmp_path / "controller.sock")),
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.fabric_mode == "service"
    assert config.fabric_socket == (tmp_path / "controller.sock").resolve()
    assert config.fabric_execution_mode == "unavailable-until-service-support"


def test_service_status_reads_persistent_fleet_and_closes_only_consumer(
    config, persistent_service
) -> None:
    service, socket = persistent_service
    consumer_config = replace(
        config,
        fabric_mode="service",
        fabric_socket=socket,
        fabric_service_timeout_seconds=2.0,
        fabric_execution_mode="unavailable-until-service-support",
    )

    status = FabricAdapter(consumer_config).status()

    assert status["controller_connected"] is True
    assert status["fleet_authority"] == "persistent-controller"
    assert status["execution_transport"] == "unsupported"
    assert status["persistent_service_support"]["persistent_fleet_read"] is True
    assert status["fleet_count"] == 0
    assert service.status()["service_runtime"] == "RUNNING"
    assert status["controller_version"] == service.status()["fabric_version"]
    assert status["controller_contract_identity"] == service.status()["public_contract_identity"]
    assert status["compatibility"]["state"] == "compatible"
    assert status["compatibility"]["action"] == "dispatch_allowed"
    assert status["persistent_service_support"]["last_known_fleet_status"] is True
    assert status["persistent_service_support"]["persistent_fleet_refresh"] is True


def test_service_compatibility_requires_running_controller_capabilities() -> None:
    compatibility = FabricAdapter._version_compatibility(
        type("Fabric", (), {"__version__": "0.2.0a19"})(),
        {"fabric_version": "0.2.0a18", "service_features": {"persistent_fleet_read": True}},
    )
    assert compatibility["state"] == "restart_required"
    assert compatibility["action"] == "restart_persistent_controller"
    assert "last_known_fleet_status" in compatibility["missing_capabilities"]


def test_service_dispatch_fails_explicitly_without_fallback(config, persistent_service) -> None:
    _service, socket = persistent_service
    consumer_config = replace(config, fabric_mode="service", fabric_socket=socket)

    with pytest.raises(ControlError) as error:
        FabricAdapter(consumer_config).dispatch("pytest", "fixture")

    assert error.value.code == "FABRIC_SERVICE_EXECUTION_UNSUPPORTED"
    assert error.value.details["fabric_controller"] == "persistent-service"
    assert error.value.details["fleet_authority"] == "persistent-controller"
    assert error.value.details["execution_transport"] == "unsupported"
    assert error.value.details["persistent_service_support"]["persistent_service_execution"] is False


def test_live_service_projection_enables_bounded_control_dispatch(
    config, persistent_service
) -> None:
    service, socket = persistent_service

    class BackendFixture:
        archive: Path | None = None

        def refresh_workers(self) -> None:
            return

        def workers(self, *, apply_lease: bool = True):
            del apply_lease
            return [
                {
                    "worker_id": "controller-owned-worker",
                    "availability": "AVAILABLE",
                    "capabilities": ["python"],
                }
            ]

        def close(self) -> None:
            return

        def execute(self, _plan, _manifest, **kwargs):
            self.archive = Path(kwargs["execution_bundle_archive"])
            assert self.archive.is_file()
            return [
                {
                    "disposition": "EXECUTED",
                    "worker_identity": "controller-owned-worker",
                    "record": {"outcome": "PASS"},
                }
            ]

    backend = BackendFixture()
    service._worker_client = backend
    project = config.workspace_root / "fixture-repo"
    project.mkdir()
    artifact = project / "artifact"
    artifact.mkdir()
    (artifact / "task.py").write_text("print('control persistent fixture')\n", encoding="utf-8")
    consumer_config = replace(
        config,
        fabric_mode="service",
        fabric_socket=socket,
        fabric_service_timeout_seconds=2.0,
        fabric_execution_mode="unavailable-until-service-support",
    )
    adapter = FabricAdapter(consumer_config, WorkspacePolicy(consumer_config))

    status = adapter.status()
    result = adapter.dispatch(
        "python",
        "fixture-repo",
        parameters={"artifact_path": "artifact", "script": "task.py", "timeout_seconds": 5},
    )

    assert status["execution_transport"] == "persistent-service"
    assert status["persistent_service_support"]["persistent_service_execution"] is True
    assert result["execution_transport"] == "persistent-service"
    assert result["results"][0]["worker_identity"] == "controller-owned-worker"
    assert backend.archive is not None
    assert backend.archive.is_relative_to(service.config.execution_bundle_root_value)
    assert not backend.archive.is_relative_to(consumer_config.job_state_path.parent)

    detached = adapter.dispatch(
        "python",
        "fixture-repo",
        parameters={
            "artifact_path": "artifact",
            "script": "task.py",
            "timeout_seconds": 5,
            "idempotency_key": "control-detached-fixture",
        },
        detached=True,
    )
    assert detached["status"] == "accepted"
    accepted = detached["accepted"]
    assert isinstance(accepted, dict)
    work_id = str(accepted["work_id"])
    deadline = time.monotonic() + 2
    observed = adapter.work_result(work_id)
    while observed["state"] != "COMPLETED" and time.monotonic() < deadline:
        time.sleep(0.01)
        observed = adapter.work_result(work_id)
    assert observed["state"] == "COMPLETED"
    assert adapter.work_status(work_id)["persistent"] is True
    assert adapter.work_list()["work"][0]["work_id"] == work_id


def test_raw_dispatch_rejects_implicit_or_project_root_bundle(config) -> None:
    project = config.workspace_root / "fixture-repo"
    project.mkdir()
    adapter = FabricAdapter(config, WorkspacePolicy(config))

    with pytest.raises(ControlError) as missing:
        adapter.dispatch("pytest", "fixture-repo")
    assert missing.value.code == "FABRIC_ARTIFACT_ROOT_REQUIRED"

    with pytest.raises(ControlError) as broad:
        adapter.dispatch("pytest", "fixture-repo", parameters={"artifact_path": "."})
    assert broad.value.code == "FABRIC_ARTIFACT_ROOT_TOO_BROAD"


def test_control_config_direct_and_loaded_defaults_use_persistent_service(tmp_path: Path) -> None:
    direct = ControlConfig()
    loaded = load_config(tmp_path / "missing.toml")
    example = load_config(Path(__file__).parents[1] / "config" / "control.example.toml")
    assert direct.fabric_mode == loaded.fabric_mode == "service"
    assert direct.fabric_execution_mode == loaded.fabric_execution_mode == "unavailable-until-service-support"
    assert (example.fabric_mode, example.fabric_execution_mode) == (direct.fabric_mode, direct.fabric_execution_mode)


def test_fabric_adapter_has_no_admin_client_authority() -> None:
    from mncs_control_mcp.adapters import FabricAdapter

    assert "FabricAdminClient" not in inspect.getsource(FabricAdapter)


def test_service_mode_does_not_prepare_private_fabric_runtime(config) -> None:
    consumer_config = replace(config, fabric_mode="service")
    with pytest.raises(ControlError) as error:
        prepare_fabric_runtime(consumer_config)
    assert error.value.code == "FABRIC_SERVICE_NO_PRIVATE_REGISTRY"


def test_current_fabric_contract_has_no_persistent_execution_claim() -> None:
    features = fabric.FabricClient.contract()["features"]
    assert features.get("persistent_service_execution", False) is False
    assert features.get("persistent_service_capability_ingestion", False) is False

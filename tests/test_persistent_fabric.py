from __future__ import annotations

import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from mncs_control_mcp.adapters import FabricAdapter
from mncs_control_mcp.config import load_config
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.runtime import prepare_fabric_runtime

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


def test_service_dispatch_fails_explicitly_without_fallback(config, persistent_service) -> None:
    _service, socket = persistent_service
    consumer_config = replace(config, fabric_mode="service", fabric_socket=socket)

    with pytest.raises(ControlError) as error:
        FabricAdapter(consumer_config).dispatch("pytest", "fixture")

    assert error.value.code == "FABRIC_SERVICE_EXECUTION_UNSUPPORTED"
    assert error.value.details == {
        "fabric_controller": "persistent-service",
        "fleet_authority": "persistent-controller",
        "execution_transport": "unsupported",
    }


def test_service_mode_does_not_prepare_private_fabric_runtime(config) -> None:
    consumer_config = replace(config, fabric_mode="service")
    with pytest.raises(ControlError) as error:
        prepare_fabric_runtime(consumer_config)
    assert error.value.code == "FABRIC_SERVICE_NO_PRIVATE_REGISTRY"


def test_current_fabric_contract_has_no_persistent_execution_claim() -> None:
    features = fabric.FabricClient.contract()["features"]
    assert features.get("persistent_service_execution", False) is False
    assert features.get("persistent_service_capability_ingestion", False) is False

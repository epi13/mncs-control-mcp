from __future__ import annotations

import pytest

from mncs_control_mcp.experiment_readiness import evaluate_control_self


def test_control_self_readiness_is_not_unconditional(tmp_path, monkeypatch) -> None:
    class Config:
        workspace_root = tmp_path

    class Integrations:
        class _Status:
            def __init__(self, payload):
                self._payload = payload

            def status(self):
                return self._payload

        harness = _Status({"available": False})
        fabric = _Status({"available": False})
        commons = _Status({"available": False})

    result = evaluate_control_self(Config(), sandbox=None, integrations=Integrations())
    assert result["status"] != "READY"
    assert "sandbox_backend_unknown" in result["blockers"]
    assert "harness_unavailable" in result["blockers"]


def test_control_projects_the_same_core_classification_as_harness() -> None:
    harness = pytest.importorskip("epi13_local_harness.experiment_readiness")
    snapshot = {
        "control": {"available": True, "status": "READY"},
        "harness": {"available": True, "status": "READY"},
        "fabric": {
            "available": True,
            "version": "0.2.0a28",
            "commit": "4f657c4d0441073902ebcbae823c11af43c09535",
            "controller_connected": True,
            "persistent_service_support": {
                name: True
                for name in (
                    "persistent_fleet_read",
                    "persistent_fleet_refresh",
                    "classified_fleet_refresh",
                    "persistent_service_execution",
                    "persistent_detached_execution",
                    "scheduled_work_queue",
                )
            },
            "workers": [
                {
                    "worker_id": "fabric-worker-01",
                    "availability": "AVAILABLE",
                    "management_state": "READY",
                    "certification_status": "CERTIFIED",
                    "certification": {
                        "disposition": "CERTIFIED",
                        "inventory_identity": "sha256:inventory-1",
                    },
                    "inventory": {"inventory_identity": "sha256:inventory-1"},
                    "desired_state_identity": "sha256:desired-1",
                    "conformance": {
                        "disposition": "CONFORMANT",
                        "blocking_failures": [],
                        "desired_state_identity": "sha256:desired-1",
                    },
                    "capability_inventory_status": "CURRENT",
                    "worker_service_version": "0.2.0a28",
                    "schedulable": True,
                    "model_inventory": [
                        {
                            "name": "granite3.3:2b",
                            "namespace": "ollama",
                            "subject_identity": "abc",
                        }
                    ],
                }
            ],
        },
        "commons": {"available": True, "consumerReadCapable": True},
        "artifact_write": {"writable": True},
        "runtime_identities": {
            "control": {"package": "mncs-control-mcp", "version": "0.4.7", "source_commit": "c" * 40},
            "harness": {"package": "mncs-harness", "version": "0.6.9", "source_commit": "h" * 40},
            "fabric_controller": {
                "package": "mncs-fabric",
                "version": "0.2.0a28",
                "source_commit": "4f657c4d0441073902ebcbae823c11af43c09535",
            },
            "commons": {"package": "mncs-commons", "version": "0.5.0.dev1", "source_commit": "m" * 40},
            "reference_studies": {
                "package": "mncs-reference-studies",
                "version": "0",
                "source_commit": "s" * 40,
            },
        },
    }
    first = harness.evaluate_layers(**snapshot)
    second = harness.evaluate_layers(**snapshot)
    assert first["status"] == second["status"]
    assert first["layers"]["workers"]["status"] == second["layers"]["workers"]["status"]
    assert first["layers"]["models"]["status"] == second["layers"]["models"]["status"]
    assert first["profile_status"] == "READY"

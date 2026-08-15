"""Observe whether the live MNCS stack may start experiments.

Inspection only. This module does not refresh, reconcile, publish, or repair.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import ControlConfig
from .sandbox import utc_now

READY = "READY"
DEGRADED = "DEGRADED"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

PROFILES = {
    "base-inference": (
        "control",
        "harness",
        "fabric_controller",
        "fleet",
        "workers",
        "models",
        "commons_consumer",
        "artifact_write",
    ),
    "code-analysis": (
        "control",
        "harness",
        "fabric_controller",
        "fleet",
        "workers",
        "models",
        "commons_consumer",
        "artifact_write",
        "joern",
        "forge",
    ),
    "multi-agent": (
        "control",
        "harness",
        "fabric_controller",
        "fleet",
        "workers",
        "models",
        "routing",
        "commons_consumer",
        "artifact_write",
    ),
    "MNEL": (
        "control",
        "harness",
        "fabric_controller",
        "fleet",
        "workers",
        "models",
        "routing",
        "commons_consumer",
        "commons_operator",
        "reference_studies",
        "artifact_write",
    ),
    "RAVEL": (
        "control",
        "harness",
        "fabric_controller",
        "fleet",
        "workers",
        "models",
        "commons_consumer",
        "reference_studies",
        "forge",
        "artifact_write",
    ),
}


def _state(value: Any, *, available_key: str = "available") -> str:
    if isinstance(value, dict):
        if value.get("status") in {READY, DEGRADED, BLOCKED, UNKNOWN}:
            return str(value["status"])
        if value.get(available_key) is True or value.get("reachable") is True:
            return READY
        if value.get(available_key) is False or value.get("reachable") is False:
            return BLOCKED
    return UNKNOWN


def _layer(status: str, detail: Any, evidence: Any = None) -> dict[str, Any]:
    return {"status": status, "detail": detail, "evidence": evidence}


def _overall(layers: dict[str, dict[str, Any]], required: tuple[str, ...]) -> str:
    states = [layers.get(name, {}).get("status", UNKNOWN) for name in required]
    if any(state == BLOCKED for state in states):
        return BLOCKED
    if any(state == UNKNOWN for state in states):
        return UNKNOWN
    if any(state == DEGRADED for state in states):
        return DEGRADED
    return READY


def evaluate_experiment_readiness(
    config: ControlConfig,
    *,
    integrations: Any,
    sandbox: Any | None = None,
    profile: str = "base-inference",
) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(f"unknown experiment profile: {profile}")

    harness = integrations.harness.status()
    fabric = integrations.fabric.status()
    commons = integrations.commons.status()
    forge = integrations.forge.status()
    nodes = list(fabric.get("known_nodes") or fabric.get("workers") or [])
    available = [node for node in nodes if str(node.get("availability") or "").upper() == "AVAILABLE"]
    stale = [
        node
        for node in available
        if str(node.get("capability_inventory_status") or "").upper() == "STALE"
    ]
    models = list((integrations.models.status() or {}).get("models") or [])
    joern_host = any(
        (Path.home() / ".local" / "bin" / name).exists() for name in ("joern", "joern-parse")
    )
    studies = (config.workspace_root / "mncs-reference-studies").is_dir()
    artifact_root = config.workspace_root
    writable = artifact_root.is_dir()
    compatibility = fabric.get("compatibility") or {}
    fabric_ok = (
        fabric.get("available") is True
        and (compatibility.get("action") in {None, "dispatch_allowed"})
    )
    fabric_state = READY if fabric_ok else BLOCKED if fabric else UNKNOWN
    if fabric_ok and stale:
        fleet_state = DEGRADED
        worker_state = DEGRADED
    elif available:
        fleet_state = READY
        worker_state = READY
    elif nodes:
        fleet_state = BLOCKED
        worker_state = BLOCKED
    else:
        fleet_state = UNKNOWN
        worker_state = UNKNOWN

    layers = {
        "control": _layer(READY, {"sandbox": getattr(sandbox, "backend", None)}),
        "harness": _layer(_state(harness), harness, harness.get("package_version")),
        "fabric_controller": _layer(
            fabric_state,
            {
                "version": fabric.get("controller_version") or fabric.get("version"),
                "compatibility": compatibility,
                "stale_capability_inventory": fabric.get("stale_capability_inventory"),
                "stale_workers": fabric.get("stale_workers"),
            },
            fabric.get("controller_contract_identity"),
        ),
        "fleet": _layer(
            fleet_state,
            {
                "available": [node.get("worker_id") for node in available],
                "stale_capability_inventory": [node.get("worker_id") for node in stale],
                "note": "STALE capability inventory is not worker UNAVAILABLE",
            },
        ),
        "workers": _layer(
            worker_state,
            {
                "workers": [
                    {
                        "worker_id": node.get("worker_id"),
                        "availability": node.get("availability"),
                        "capability_inventory_status": node.get("capability_inventory_status"),
                        "worker_service_version": node.get("worker_service_version"),
                    }
                    for node in nodes
                ]
            },
        ),
        "models": _layer(READY if models or available else UNKNOWN, {"count": len(models)}),
        "routing": _layer(
            READY if available else UNKNOWN,
            {"available_workers": [node.get("worker_id") for node in available]},
        ),
        "commons_consumer": _layer(
            READY if commons.get("consumerReadCapable") or commons.get("available") else BLOCKED if commons else UNKNOWN,
            commons,
        ),
        "commons_operator": _layer(
            READY if commons.get("operatorPublicationCapable") else DEGRADED,
            {
                "operatorPublicationCapable": commons.get("operatorPublicationCapable"),
                "independent_of_model_publication": True,
            },
        ),
        "forge": _layer(_state(forge), forge),
        "joern": _layer(READY if joern_host else DEGRADED, {"host_visible": joern_host}),
        "reference_studies": _layer(READY if studies else DEGRADED, {"path": "mncs-reference-studies"}),
        "scheduler": _layer(DEGRADED, {"detail": "inspection only; no overnight schedule started"}),
        "artifact_write": _layer(READY if writable else BLOCKED, {"path": str(artifact_root)}),
    }
    status = _overall(layers, PROFILES[profile])
    return {
        "status": status,
        "profile": profile,
        "claim_boundary": "infrastructure validation",
        "inspected_at": utc_now(),
        "layers": layers,
        "required_layers": list(PROFILES[profile]),
        "local_fallback": False,
        "ssh_used": False,
    }

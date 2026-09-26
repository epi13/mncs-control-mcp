"""Project Harness experiment-readiness and add Control-specific evidence.

Inspection only. This module does not refresh, reconcile, publish, or repair.
Worker, model, routing, Commons, and Fabric classification are owned by Harness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__
from .config import ControlConfig
from .developer import developer_readiness_payload
from .sandbox import utc_now

READY = "READY"
DEGRADED = "DEGRADED"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"
READINESS_SCHEMA = "mncs.experiment-readiness.v1"
MappingLike = dict[str, Any]


def _probe_artifact_write(path: Path) -> dict[str, Any]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        marker = path / ".mncs-control-experiment-readiness.tmp"
        payload = b"mncs.experiment-readiness.v1\n"
        marker.write_bytes(payload)
        ok = marker.read_bytes() == payload
        marker.unlink(missing_ok=True)
        return {"writable": ok, "path": str(path), "tested_marker": marker.name}
    except OSError as exc:
        return {"writable": False, "path": str(path), "reason": str(exc)}


def evaluate_control_self(
    config: ControlConfig,
    *,
    sandbox: Any | None,
    integrations: Any,
    developer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workspace = config.workspace_root
    sandbox_backend = getattr(sandbox, "backend", None)
    harness_status = integrations.harness.status()
    fabric_status = integrations.fabric.status()
    commons_status = integrations.commons.status()
    blockers: list[str] = []
    if not workspace.is_dir():
        blockers.append("workspace_missing")
    if not sandbox_backend:
        blockers.append("sandbox_backend_unknown")
    if harness_status.get("available") is not True:
        blockers.append("harness_unavailable")
    if fabric_status.get("available") is not True and fabric_status.get("controller_connected") is not True:
        blockers.append("fabric_unavailable")
    if commons_status.get("available") is not True and not commons_status.get("consumerReadCapable"):
        blockers.append("commons_unavailable")
    status = READY if not blockers else DEGRADED if workspace.is_dir() else BLOCKED
    return {
        "status": status,
        "available": status == READY,
        "package": "mncs-control-mcp",
        "version": __version__,
        "sandbox": sandbox_backend,
        "workspace": str(workspace),
        "harness_integration": harness_status.get("status") or harness_status.get("available"),
        "fabric_integration": fabric_status.get("status") or fabric_status.get("available"),
        "commons_integration": commons_status.get("status") or commons_status.get("available"),
        "developer_ready": None if developer is None else bool(developer.get("ready_for_development")),
        "blockers": blockers,
        "evidence": __version__,
    }


def evaluate_experiment_readiness(
    config: ControlConfig,
    *,
    integrations: Any,
    sandbox: Any | None = None,
    profile: str = "base-inference",
) -> dict[str, Any]:
    """Project integration-adapter status into a readiness verdict Control owns.

    Every layer below is a fact Control can verify itself: its own
    self-check, adapter availability projections, Forge capability gating,
    and a write probe against Control's own experiment store. The overall
    verdict rule is stated, not delegated: BLOCKED when a required layer is
    BLOCKED, DEGRADED when a required layer is not READY, else READY.
    Worker, model, routing, Commons, and Fabric classification stay with
    their owning subsystems; readiness here never re-judges them.
    """
    developer = developer_readiness_payload(
        config,
        sandbox=sandbox,
        integrations=integrations,
    )
    control = evaluate_control_self(
        config,
        sandbox=sandbox,
        integrations=integrations,
        developer=developer,
    )
    harness_status = integrations.harness.status() or {}
    fabric = integrations.fabric.status() or {}
    commons = integrations.commons.status() or {}
    forge_status = integrations.forge.status() or {}
    nodes = list(fabric.get("known_nodes") or fabric.get("workers") or [])
    available_nodes = sum(
        1 for node in nodes if str(node.get("availability") or "").upper() == "AVAILABLE"
    )
    capabilities = developer.get("capabilities") if isinstance(developer, dict) else {}
    forge_cap = (capabilities or {}).get("forge.evaluate") or {}
    forge_callable = (
        forge_cap.get("state") == "available" and forge_cap.get("authorized") is True
    )
    forge = {
        "available": forge_status.get("available"),
        "sandbox_callable": forge_callable,
        "callable": forge_status.get("available") is True and forge_callable,
        "status": READY
        if forge_callable and forge_status.get("available")
        else DEGRADED if forge_status else UNKNOWN,
    }
    # Control probes only its own experiment store: the directory the
    # coordinator persists terminal experiment state under. Sibling
    # checkouts are never written to by a readiness probe.
    store = config.job_state_path.expanduser().resolve().parent / "experiments"
    probe = _probe_artifact_write(store)
    layers = {
        "control": {
            "status": control["status"],
            "detail": control,
            "evidence": control.get("evidence"),
        },
        "harness": {
            "status": READY if harness_status.get("available") is True else DEGRADED,
            "detail": harness_status,
        },
        "fabric": {
            "status": READY
            if fabric.get("available") is True
            or fabric.get("controller_connected") is True
            else DEGRADED,
            "detail": {
                "available": fabric.get("available"),
                "controller_connected": fabric.get("controller_connected"),
                "known_nodes": len(nodes),
                "available_nodes": available_nodes,
            },
        },
        "commons": {
            "status": READY
            if commons.get("available") is True or commons.get("consumerReadCapable")
            else DEGRADED,
            "detail": {
                "available": commons.get("available"),
                "consumer_read_capable": bool(commons.get("consumerReadCapable")),
            },
        },
        "forge": {"status": forge["status"], "detail": forge},
        "artifact_write": {
            "status": READY if probe.get("writable") else BLOCKED,
            "detail": probe,
        },
    }
    required = ("control", "harness")
    if any(layers[name]["status"] == BLOCKED for name in required):
        status = BLOCKED
    elif any(layers[name]["status"] != READY for name in required):
        status = DEGRADED
    else:
        status = READY
    blockers = [
        name
        for name in required
        if layers[name]["status"] != READY
    ]
    return {
        "schema": READINESS_SCHEMA,
        "status": status,
        "profile": profile,
        "profile_status": status,
        "claim_boundary": "infrastructure validation",
        "inspected_at": utc_now(),
        "layers": layers,
        "required_layers": list(required),
        "blockers": blockers,
        "local_fallback": False,
        "ssh_used": False,
    }



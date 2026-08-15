"""Project Harness experiment-readiness and add Control-specific evidence.

Inspection only. This module does not refresh, reconcile, publish, or repair.
Worker, model, routing, Commons, and Fabric classification are owned by Harness.
"""

from __future__ import annotations

import importlib
import json
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


def _load_harness_contract(config: ControlConfig) -> Any | None:
    from .adapters import _load_sibling_package

    try:
        _load_sibling_package("epi13_local_harness", config.harness_path)
        return importlib.import_module("epi13_local_harness.experiment_readiness")
    except Exception:
        try:
            return importlib.import_module("epi13_local_harness.experiment_readiness")
        except Exception:
            return None


def _probe_artifact_write(path: Path, harness: Any | None) -> dict[str, Any]:
    if harness is not None and hasattr(harness, "probe_artifact_write"):
        return harness.probe_artifact_write(path)
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


def _reference_studies(config: ControlConfig) -> dict[str, Any]:
    root = config.workspace_root / "mncs-reference-studies"
    if not root.is_dir():
        return {"available": False, "path": str(root)}
    commit = None
    try:
        import subprocess

        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        commit = (result.stdout or "").strip() or None
    except Exception:
        commit = None
    schema = (root / "schemas" / "study.schema.json").is_file()
    limitation_path = root / "case-studies" / "ravel" / "ravel-0.5-historical-limitation.json"
    limitation = None
    if limitation_path.is_file():
        try:
            limitation = json.loads(limitation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            limitation = {"disposition": "KNOWN_HISTORICAL_LIMITATION"}
    output_path = root / "evidence" / "actual"
    return {
        "available": True,
        "path": str(root),
        "commit": commit,
        "schema_available": schema,
        "output_path": str(output_path),
        "ravel_0_5_limitation": limitation,
        "current_ravel_lane_valid": False if limitation else None,
        "status": READY if commit and schema else DEGRADED,
    }


def evaluate_experiment_readiness(
    config: ControlConfig,
    *,
    integrations: Any,
    sandbox: Any | None = None,
    profile: str = "base-inference",
) -> dict[str, Any]:
    harness = _load_harness_contract(config)
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
    fabric = integrations.fabric.status()
    commons = integrations.commons.status()
    forge_status = integrations.forge.status()
    nodes = list(fabric.get("known_nodes") or fabric.get("workers") or [])
    capabilities = developer.get("capabilities") if isinstance(developer, dict) else {}
    joern_cap = (capabilities or {}).get("joern.analysis") or {}
    forge_cap = (capabilities or {}).get("forge.evaluate") or {}
    joern = {
        "sandbox_callable": joern_cap.get("state") == "available" and joern_cap.get("authorized") is True,
        "host_visible": any(
            (Path.home() / ".local" / "bin" / name).exists() for name in ("joern", "joern-parse")
        ),
        "detail": joern_cap.get("detail"),
        "status": READY if joern_cap.get("state") == "available" else DEGRADED,
    }
    forge = {
        **dict(forge_status or {}),
        "sandbox_callable": forge_cap.get("state") == "available" and forge_cap.get("authorized") is True,
        "callable": forge_status.get("available") is True and forge_cap.get("state") == "available",
        "status": READY
        if forge_cap.get("state") == "available" and forge_status.get("available")
        else DEGRADED if forge_status else UNKNOWN,
    }
    studies = _reference_studies(config)
    destinations = [
        config.workspace_root / "mncs-harness",
        config.workspace_root / "mncs-reference-studies" / "evidence" / "actual",
    ]
    artifact_paths = []
    writable = True
    for destination in destinations:
        if destination.exists() or destination == destinations[-1]:
            probe = _probe_artifact_write(destination if destination.exists() else config.workspace_root, harness)
            artifact_paths.append(probe)
            writable = writable and bool(probe.get("writable"))
    artifact_write = {
        "writable": writable,
        "path": str(config.workspace_root / "mncs-reference-studies" / "evidence" / "actual"),
        "tested": artifact_paths,
    }

    if harness is not None and hasattr(harness, "inspect_live_config"):
        try:
            from epi13_local_harness.config import load_config

            live = harness.inspect_live_config(load_config(config.harness_config_path), profile=profile)
            layers = dict(live.get("layers") or {})
            layers["control"] = {
                "name": "control",
                "status": control["status"],
                "detail": control,
                "evidence": control.get("evidence"),
            }
            layers["joern"] = {
                "name": "joern",
                "status": joern.get("status") or UNKNOWN,
                "detail": joern,
                "evidence": None,
            }
            layers["forge"] = {
                "name": "forge",
                "status": forge.get("status") or UNKNOWN,
                "detail": forge,
                "evidence": None,
            }
            layers["artifact_write"] = {
                "name": "artifact_write",
                "status": READY if artifact_write.get("writable") else BLOCKED,
                "detail": artifact_write,
                "evidence": None,
            }
            required = tuple(live.get("required_layers") or [])
            if hasattr(harness, "_overall"):
                status, warnings = harness._overall(list(layers.values()), required)
            else:
                status, warnings = live.get("status") or UNKNOWN, live.get("optional_warnings") or []
            live["layers"] = layers
            live["status"] = status
            live["profile_status"] = status
            live["optional_warnings"] = warnings
            live["inspected_at"] = utc_now()
            live["local_fallback"] = False
            live["ssh_used"] = False
            live["control_projection"] = True
            return live
        except Exception:
            pass

    if harness is None or not hasattr(harness, "evaluate_layers"):
        return {
            "schema": READINESS_SCHEMA,
            "status": UNKNOWN,
            "profile": profile,
            "profile_status": UNKNOWN,
            "claim_boundary": "infrastructure validation",
            "inspected_at": utc_now(),
            "layers": {
                "control": {"status": control["status"], "detail": control, "evidence": control.get("evidence")},
                "harness": {
                    "status": BLOCKED,
                    "detail": {"harness_contract": "unavailable"},
                    "evidence": None,
                },
            },
            "required_layers": ["control", "harness"],
            "optional_warnings": [],
            "local_fallback": False,
            "ssh_used": False,
            "note": "Control could not import the Harness readiness contract",
        }

    runtime_identities = {
        "control": {
            "package": "mncs-control-mcp",
            "version": __version__,
            "source_commit": None,
            "module": "mncs_control_mcp",
        },
        "harness": {
            "package": "mncs-harness",
            "version": (integrations.harness.status() or {}).get("package_version"),
            "source_commit": None,
        },
        "fabric_controller": {
            "package": "mncs-fabric",
            "version": fabric.get("controller_version") or fabric.get("version"),
            "source_commit": (fabric.get("runtime_identity") or {}).get("source_commit")
            if isinstance(fabric.get("runtime_identity"), dict)
            else None,
            "artifact_digest": fabric.get("controller_contract_identity"),
        },
        "commons": {
            "package": "mncs-commons",
            "version": commons.get("packageVersion"),
            "source_commit": None,
        },
        "reference_studies": {
            "package": "mncs-reference-studies",
            "version": None,
            "source_commit": studies.get("commit"),
        },
    }
    try:
        from epi13_local_harness.runtime_identity import runtime_build_identity

        runtime_identities["control"] = runtime_build_identity("mncs_control_mcp", version=__version__)
        runtime_identities["harness"] = runtime_build_identity(
            "epi13_local_harness",
            version=str((integrations.harness.status() or {}).get("package_version") or ""),
        )
        runtime_identities["commons"] = runtime_build_identity(
            "mncs_commons",
            version=str(commons.get("packageVersion") or ""),
        )
    except Exception:
        pass

    result = harness.evaluate_layers(
        control=control,
        harness=integrations.harness.status(),
        fabric={
            "available": fabric.get("available") is True,
            "version": fabric.get("controller_version") or fabric.get("version"),
            "controller_connected": fabric.get("controller_connected"),
            "persistent_service_support": (fabric.get("persistent_service_support") or {}),
            "workers": nodes,
            "commit": runtime_identities["fabric_controller"].get("source_commit"),
            "source_commit": runtime_identities["fabric_controller"].get("source_commit"),
            "artifact_digest": None,
            "contract_identity": fabric.get("controller_contract_identity"),
            "stale_capability_inventory": fabric.get("stale_capability_inventory"),
            "available_workers": [
                node for node in nodes if str(node.get("availability") or "").upper() == "AVAILABLE"
            ],
        },
        commons=commons,
        forge=forge,
        joern=joern,
        reference_studies=studies,
        routing={
            "available": any(str(node.get("availability") or "").upper() == "AVAILABLE" for node in nodes),
            "local_fallback": False,
            "fallback_explicit": True,
        },
        scheduler={"available": True, "detail": "inspection only; no overnight schedule started"},
        artifact_write=artifact_write,
        runtime_identities=runtime_identities,
        profile=profile,
    )
    result["inspected_at"] = utc_now()
    result["local_fallback"] = False
    result["ssh_used"] = False
    result["control_projection"] = True
    return result

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from mncs_control_mcp.control_plane import ControlPlaneService
from mncs_control_mcp.developer import developer_readiness_payload
from mncs_control_mcp.experiment_readiness import UNKNOWN, evaluate_experiment_readiness


def test_integration_capability_preserves_unknown_state() -> None:
    result = ControlPlaneService._integration_capability(
        {
            "configured": True,
            "reachable": None,
            "supported": None,
            "available": None,
            "health_status": "probe_timed_out",
            "diagnostic": "Forge probe timed out",
        },
        ["configured evaluation"],
        "Forge owns scoring and evidence",
    )

    assert result["configured"] is True
    assert result["reachable"] is None
    assert result["supported"] is None
    assert result["available"] is None
    assert result["health_status"] == "probe_timed_out"


def test_developer_and_experiment_readiness_report_forge_timeout_as_unknown(
    config, tmp_path
) -> None:
    config = replace(config, job_state_path=tmp_path / "state" / "jobs.json")
    statuses = {
        "fabric": {"available": False, "controller_connected": False},
        "commons": {"available": False},
        "forge": {
            "configured": True,
            "reachable": None,
            "available": None,
            "status": "probe_timed_out",
            "health_status": "probe_timed_out",
            "diagnostic": "Forge MCP health probe timed out",
        },
        "harness": {"available": True, "status": "available"},
    }
    integrations = SimpleNamespace(
        **{
            name: SimpleNamespace(status=lambda name=name: statuses[name])
            for name in statuses
        }
    )
    sandbox = SimpleNamespace(
        backend="bwrap",
        run=lambda *_args, **_kwargs: SimpleNamespace(
            exit_code=1, stdout="", stderr="probe unavailable"
        ),
    )

    developer = developer_readiness_payload(
        config,
        sandbox=sandbox,
        integrations=integrations,
    )
    experiment = evaluate_experiment_readiness(
        config,
        integrations=integrations,
        sandbox=sandbox,
    )

    assert developer["capabilities"]["forge.evaluate"]["state"] == "unknown"
    assert experiment["layers"]["forge"]["status"] == UNKNOWN
    assert experiment["layers"]["forge"]["detail"]["available"] is None

from __future__ import annotations

import hashlib
import json

from mncs_control_mcp.specialist_router import (
    ProviderRun,
    build_routing_shadow,
    invoke_control_specialist_shadow,
    prepare_request,
)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _artifact() -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "mnel-recurrent-specialist-artifact/0.1",
        "provider_id": "mnel-bounded-recurrent-specialist",
        "provider_abi": "mnel-specialist-provider-abi/0.1",
        "target_role": "control.tool-family-routing",
        "model_identity": _digest("model"),
        "generation_identity": _digest("generation"),
        "training_dataset_identity": _digest("dataset"),
        "training_spec_identity": _digest("spec"),
        "checkpoint_identity": _digest("checkpoint"),
        "calibration_identity": _digest("calibration"),
        "operating_envelope": {
            "max_iterations": 4,
            "maximum_context_observations": 32,
        },
        "class_centroids": {"git": [700, 700, 200, 300], "testing": [700, 700, 600, 700]},
        "authority": "diagnostic-only",
    }
    value["artifact_identity"] = _digest(value)
    return value


def _catalog() -> list[dict[str, object]]:
    return [
        {
            "family_id": "git",
            "tool_id": "git_status",
            "schema_identity": _digest("git-schema"),
            "destructive": False,
            "source_bytes": 400,
        },
        {
            "family_id": "testing",
            "tool_id": "test_pytest",
            "schema_identity": _digest("test-schema"),
            "destructive": False,
            "source_bytes": 600,
        },
    ]


def _response(request_identity: str, decision: str) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "mnel-recurrent-specialist-provider/0.1",
        "type": "inference_response",
        "request_id": request_identity,
        "model_identity": _artifact()["model_identity"],
        "generation_identity": _artifact()["generation_identity"],
        "target_role": "control.tool-family-routing",
        "results": [
            {
                "decision": decision,
                "abstained": decision == "ABSTAIN",
                "reasoning_iterations": 2,
                "operations": 9,
            }
        ],
        "authority": "diagnostic-only",
    }
    value["response_identity"] = _digest(value)
    return value


def test_routing_shadow_preserves_authority_and_measures_savings() -> None:
    artifact = _artifact()
    catalog = _catalog()
    request, _encoded, request_id, _checked, _decision = prepare_request(
        artifact,
        [780, 680, 240, 380],
        catalog,
        existing_decision={"selected_family": "git", "policy_identity": _digest("policy")},
    )
    result = build_routing_shadow(
        artifact=artifact,
        request_identity=request_id,
        response=_response(request["request_id"], "git"),
        catalog=catalog,
        existing_decision={"selected_family": "git", "policy_identity": _digest("policy")},
        duration_ns=123,
    )
    assert result["status"] == "OBSERVED"
    assert result["proposed_family"] == "git"
    assert result["execution_authorized"] is False
    assert result["policy_authoritative"] is True
    assert result["comparison"]["exact_family_match"] == 1
    assert result["measurements"]["catalog_bytes_avoided"] == 600


def test_invalid_or_abstaining_provider_falls_back_without_authorizing() -> None:
    artifact = _artifact()
    catalog = _catalog()
    request, _encoded, request_id, _checked, _decision = prepare_request(
        artifact,
        [500, 500, 500, 500],
        catalog,
        existing_decision={"selected_family": "testing"},
    )
    result = build_routing_shadow(
        artifact=artifact,
        request_identity=request_id,
        response=_response(request["request_id"], "ABSTAIN"),
        catalog=catalog,
        existing_decision={"selected_family": "testing"},
        duration_ns=123,
    )
    assert result["abstained"] is True
    assert result["fallback_family"] == "testing"
    assert result["candidate_tool_ids"] == []
    assert result["execution_authorized"] is False


def test_provider_exchange_is_bounded_and_bad_output_is_unknown() -> None:
    artifact = _artifact()
    catalog = _catalog()

    def bad_runner(_command, _payload, _timeout):
        return ProviderRun(0, b"not-json", False, False, 99)

    result = invoke_control_specialist_shadow(
        ["provider"],
        artifact,
        [500, 500, 500, 500],
        catalog,
        existing_decision={"selected_family": "git"},
        runner=bad_runner,
    )
    assert result["status"] == "UNKNOWN"
    assert result["fallback_family"] == "git"
    assert result["execution_authorized"] is False

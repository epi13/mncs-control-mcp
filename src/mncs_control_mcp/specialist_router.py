"""Control-side consumer for the bounded MNEL routing specialist.

This module owns only shadow comparison.  A specialist proposal may reduce
catalog and context work, but it cannot authorize a tool, replace policy, or
become the selected execution route.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple

SCHEMA = "mncs-control-specialist-routing-shadow/0.1"
PROTOCOL = "mnel-recurrent-specialist-provider/0.1"
AUTHORITY = "policy-authoritative-existing-decision"
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
MAX_CATALOG = 64
DIMENSIONS = 4


class SpecialistRoutingError(ValueError):
    """A malformed or over-budget specialist routing exchange."""


class ProviderRun(NamedTuple):
    exit_code: int | None
    stdout: bytes
    timed_out: bool
    output_limited: bool
    duration_ns: int


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise SpecialistRoutingError(f"{label} must be a sha256 identity")
    return value


def _features(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or len(value) != DIMENSIONS:
        raise SpecialistRoutingError(f"{label} must contain exactly four lanes")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or not -1000 <= item <= 1000
        for item in value
    ):
        raise SpecialistRoutingError(f"{label} contains an invalid lane")
    return list(value)


def _text(value: object, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SpecialistRoutingError(f"{label} must be bounded non-empty text")
    return value


def _reject_authority(value: object) -> None:
    forbidden = {
        "verdict",
        "evaluator_verdict",
        "promotion",
        "promotion_authorized",
        "permission",
        "credentials",
        "trust",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in forbidden:
                raise SpecialistRoutingError(f"specialist payload contains authority field: {key}")
            _reject_authority(child)
    elif isinstance(value, list):
        for child in value:
            _reject_authority(child)


def validate_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(artifact)
    _reject_authority(value)
    if value.get("schema") != "mnel-recurrent-specialist-artifact/0.1":
        raise SpecialistRoutingError("unsupported specialist artifact schema")
    if value.get("provider_abi") != "mnel-specialist-provider-abi/0.1":
        raise SpecialistRoutingError("unsupported specialist provider ABI")
    if value.get("target_role") != "control.tool-family-routing":
        raise SpecialistRoutingError("specialist artifact role does not match Control routing")
    for key in (
        "provider_id",
        "target_role",
        "model_identity",
        "generation_identity",
        "calibration_identity",
        "training_dataset_identity",
        "training_spec_identity",
        "checkpoint_identity",
    ):
        _text(value.get(key), key)
    for key in (
        "model_identity",
        "generation_identity",
        "calibration_identity",
        "training_dataset_identity",
        "training_spec_identity",
        "checkpoint_identity",
    ):
        _identity(value.get(key), key)
    supplied = value.pop("artifact_identity", None)
    _identity(supplied, "artifact_identity")
    if _digest(value) != supplied:
        raise SpecialistRoutingError("specialist artifact identity does not match content")
    envelope = value.get("operating_envelope")
    if not isinstance(envelope, Mapping):
        raise SpecialistRoutingError("specialist operating envelope is missing")
    if (
        not isinstance(envelope.get("max_iterations"), int)
        or not 1 <= envelope["max_iterations"] <= 8
    ):
        raise SpecialistRoutingError("specialist iteration envelope is invalid")
    if (
        not isinstance(envelope.get("maximum_context_observations"), int)
        or not 1 <= envelope["maximum_context_observations"] <= 32
    ):
        raise SpecialistRoutingError("specialist context envelope is invalid")
    encoded = _canonical(artifact)
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise SpecialistRoutingError("specialist artifact exceeds Control input ceiling")
    return dict(artifact)


def _validate_catalog(catalog: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    if len(catalog) > MAX_CATALOG:
        raise SpecialistRoutingError("tool catalog exceeds its bound")
    checked: list[dict[str, Any]] = []
    for item in catalog:
        value = dict(item)
        family_id = _text(value.get("family_id"), "catalog.family_id", 128)
        _text(value.get("tool_id"), "catalog.tool_id", 128)
        _identity(value.get("schema_identity"), "catalog.schema_identity")
        if not isinstance(value.get("destructive"), bool):
            raise SpecialistRoutingError("catalog.destructive must be boolean")
        source_bytes = value.get("source_bytes", 0)
        if not isinstance(source_bytes, int) or not 0 <= source_bytes <= 1_000_000:
            raise SpecialistRoutingError("catalog.source_bytes is invalid")
        value["family_id"] = family_id
        checked.append(value)
    return checked, sum(int(item.get("source_bytes", 0)) for item in checked)


def prepare_request(
    artifact: Mapping[str, Any],
    request_features: Sequence[int],
    catalog: Sequence[Mapping[str, Any]],
    *,
    existing_decision: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], bytes, str, list[dict[str, Any]], dict[str, Any]]:
    checked_artifact = validate_artifact(artifact)
    features = _features(list(request_features), "request_features")
    checked_catalog, _ = _validate_catalog(catalog)
    decision = dict(existing_decision or {})
    _reject_authority(decision)
    family = decision.get("selected_family")
    if family is not None:
        _text(family, "existing_decision.selected_family", 128)
    query = {"query_id": "control-routing-request", "features": features}
    request: dict[str, Any] = {
        "protocol_version": PROTOCOL,
        "type": "infer",
        "request_id": _digest(
            {
                "artifact": checked_artifact["artifact_identity"],
                "features": features,
                "catalog": checked_catalog,
                "existing_family": family,
            }
        ),
        "artifact": checked_artifact,
        "queries": [query],
        "context_observations": [],
    }
    encoded = _canonical(request)
    if len(encoded) > MAX_REQUEST_BYTES:
        raise SpecialistRoutingError("specialist request exceeds Control input ceiling")
    return request, encoded, str(request["request_id"]), checked_catalog, decision


def _validate_response(
    response: Mapping[str, Any], artifact: Mapping[str, Any], request_identity: str
) -> dict[str, Any]:
    value = dict(response)
    _reject_authority(value)
    if value.get("protocol_version") != PROTOCOL or value.get("type") != "inference_response":
        raise SpecialistRoutingError("unsupported specialist response")
    if value.get("request_id") != request_identity:
        raise SpecialistRoutingError("specialist response request identity mismatch")
    if value.get("model_identity") != artifact.get("model_identity"):
        raise SpecialistRoutingError("specialist response model identity mismatch")
    if value.get("generation_identity") != artifact.get("generation_identity"):
        raise SpecialistRoutingError("specialist response generation identity mismatch")
    if value.get("target_role") != artifact.get("target_role"):
        raise SpecialistRoutingError("specialist response role mismatch")
    results = value.get("results")
    if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], Mapping):
        raise SpecialistRoutingError("specialist routing response must contain one result")
    supplied = value.pop("response_identity", None)
    _identity(supplied, "response_identity")
    if _digest(value) != supplied:
        raise SpecialistRoutingError("specialist response identity does not match content")
    return dict(response)


def _unknown(
    *,
    request_identity: str,
    artifact: Mapping[str, Any],
    catalog: Sequence[Mapping[str, Any]],
    existing_decision: Mapping[str, Any],
    reason: str,
    duration_ns: int,
    catalog_bytes: int,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "UNKNOWN",
        "request_identity": request_identity,
        "model_identity": artifact.get("model_identity"),
        "generation_identity": artifact.get("generation_identity"),
        "calibration_identity": artifact.get("calibration_identity"),
        "existing_decision": dict(existing_decision),
        "proposed_family": None,
        "fallback_family": existing_decision.get("selected_family"),
        "candidate_tool_ids": [],
        "schema_valid": False,
        "abstained": True,
        "escalation_reason": reason,
        "execution_authorized": False,
        "policy_authoritative": True,
        "catalog_family_count": len(catalog),
        "measurements": {
            "catalog_bytes_available": catalog_bytes,
            "catalog_bytes_selected": 0,
            "catalog_bytes_avoided": 0,
            "provider_elapsed_ns": duration_ns,
            "p50_provider_latency_ns": duration_ns,
            "p95_provider_latency_ns": duration_ns,
            "larger_model_calls_avoided": 0,
            "abstention_rate": 1.0,
            "schema_validity": 0.0,
        },
        "authority": AUTHORITY,
        "semantics": "control-shadow-observation; proposal-only; policy-and-execution-untouched",
    }


def build_routing_shadow(
    *,
    artifact: Mapping[str, Any],
    request_identity: str,
    response: Mapping[str, Any],
    catalog: Sequence[Mapping[str, Any]],
    existing_decision: Mapping[str, Any],
    duration_ns: int,
) -> dict[str, Any]:
    checked_artifact = validate_artifact(artifact)
    checked_catalog, catalog_bytes = _validate_catalog(catalog)
    checked_response = _validate_response(response, checked_artifact, request_identity)
    result = checked_response["results"][0]
    proposed = result.get("decision")
    abstained = bool(result.get("abstained")) or proposed == "ABSTAIN"
    if proposed is not None and not isinstance(proposed, str):
        raise SpecialistRoutingError("specialist proposed family is malformed")
    matches = [item for item in checked_catalog if item["family_id"] == proposed]
    schema_valid = bool(matches) if not abstained else True
    existing_family = existing_decision.get("selected_family")
    exact = int(not abstained and schema_valid and proposed == existing_family)
    candidate_recall = int(
        not existing_family
        or any(
            item["family_id"] == existing_family
            for item in checked_catalog
            if proposed == item["family_id"]
        )
    )
    selected_bytes = sum(int(item.get("source_bytes", 0)) for item in matches)
    avoided = max(0, catalog_bytes - selected_bytes) if schema_valid and not abstained else 0
    return {
        "schema": SCHEMA,
        "status": "OBSERVED",
        "request_identity": request_identity,
        "model_identity": checked_artifact["model_identity"],
        "generation_identity": checked_artifact["generation_identity"],
        "calibration_identity": checked_artifact["calibration_identity"],
        "existing_decision": dict(existing_decision),
        "proposed_family": None if abstained else proposed,
        "fallback_family": existing_family,
        "candidate_tool_ids": [item["tool_id"] for item in matches] if schema_valid else [],
        "schema_valid": schema_valid,
        "abstained": abstained,
        "escalation_reason": "specialist-abstained-or-schema-invalid"
        if abstained or not schema_valid
        else None,
        "execution_authorized": False,
        "policy_authoritative": True,
        "comparison": {
            "exact_family_match": exact,
            "candidate_set_recall": candidate_recall,
            "false_accept": int(
                bool(
                    schema_valid
                    and not abstained
                    and existing_family
                    and proposed != existing_family
                )
            ),
            "escalation_correctness": int(
                abstained == (not existing_family or proposed != existing_family)
            ),
        },
        "measurements": {
            "catalog_family_count": len(checked_catalog),
            "catalog_bytes_available": catalog_bytes,
            "catalog_bytes_selected": selected_bytes,
            "catalog_bytes_avoided": avoided,
            "estimated_tokens_avoided": avoided // 4,
            "provider_elapsed_ns": duration_ns,
            "p50_provider_latency_ns": duration_ns,
            "p95_provider_latency_ns": duration_ns,
            "reasoning_iterations": int(result.get("reasoning_iterations", 0)),
            "provider_operations": int(result.get("operations", 0)),
            "larger_model_calls_avoided": int(exact == 1),
            "abstention_rate": int(abstained),
            "schema_validity": int(schema_valid),
            "schema_version_drift": 0,
        },
        "authority": AUTHORITY,
        "semantics": "control-shadow-observation; proposal-only; policy-and-execution-untouched",
        "limitations": [
            "the existing decision remains authoritative and is the fallback",
            "catalog membership validates shape, not authorization or tool safety",
            "shadow measurements are not correctness or promotion evidence",
        ],
    }


def invoke_control_specialist_shadow(
    command: Sequence[str],
    artifact: Mapping[str, Any],
    request_features: Sequence[int],
    catalog: Sequence[Mapping[str, Any]],
    *,
    existing_decision: Mapping[str, Any] | None = None,
    timeout_seconds: float = 5.0,
    runner: Callable[[Sequence[str], bytes, float], ProviderRun] | None = None,
) -> dict[str, Any]:
    """Run a routing specialist through a bounded argv and compare in shadow."""

    if not command or any(not isinstance(item, str) or not item for item in command):
        raise SpecialistRoutingError("provider command must be a non-empty argv")
    if not 0.1 <= timeout_seconds <= 30:
        raise SpecialistRoutingError("provider timeout is outside the Control envelope")
    request, encoded, request_identity, checked_catalog, decision = prepare_request(
        artifact,
        request_features,
        catalog,
        existing_decision=existing_decision,
    )
    started = time.perf_counter_ns()
    if runner is None:
        try:
            completed = subprocess.run(
                list(command),
                input=encoded + b"\n",
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
            run = ProviderRun(
                completed.returncode,
                completed.stdout,
                False,
                len(completed.stdout) > MAX_RESPONSE_BYTES,
                time.perf_counter_ns() - started,
            )
        except (OSError, subprocess.TimeoutExpired):
            run = ProviderRun(None, b"", True, False, time.perf_counter_ns() - started)
    else:
        run = runner(command, encoded + b"\n", timeout_seconds)
    if (
        run.timed_out
        or run.output_limited
        or run.exit_code != 0
        or len(run.stdout) > MAX_RESPONSE_BYTES
    ):
        return _unknown(
            request_identity=request_identity,
            artifact=artifact,
            catalog=checked_catalog,
            existing_decision=decision,
            reason="provider-exit-timeout-or-output-limit",
            duration_ns=run.duration_ns,
            catalog_bytes=sum(int(item.get("source_bytes", 0)) for item in checked_catalog),
        )
    try:
        response = json.loads(run.stdout)
        return build_routing_shadow(
            artifact=artifact,
            request_identity=request_identity,
            response=response,
            catalog=checked_catalog,
            existing_decision=decision,
            duration_ns=run.duration_ns,
        )
    except (json.JSONDecodeError, SpecialistRoutingError) as error:
        return _unknown(
            request_identity=request_identity,
            artifact=artifact,
            catalog=checked_catalog,
            existing_decision=decision,
            reason="provider-response-invalid-or-stale",
            duration_ns=run.duration_ns,
            catalog_bytes=sum(int(item.get("source_bytes", 0)) for item in checked_catalog),
        ) | {"error": str(error)[:256]}


__all__ = [
    "AUTHORITY",
    "PROTOCOL",
    "ProviderRun",
    "SCHEMA",
    "SpecialistRoutingError",
    "build_routing_shadow",
    "invoke_control_specialist_shadow",
    "prepare_request",
    "validate_artifact",
]

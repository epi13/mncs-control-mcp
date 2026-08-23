from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.replication import REPLICATION_SCHEMA, ReplicationManager


@pytest.fixture
def replication_config(tmp_path: Path) -> ControlConfig:
    """Control config with a placeholder language binary for bundle staging."""
    workspace = tmp_path / "projects"
    workspace.mkdir()
    fake_binary = workspace / "fake-mncs"
    fake_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_binary.chmod(0o755)
    return ControlConfig(
        workspace_root=workspace,
        sandbox_home=tmp_path / "sandbox-home",
        job_state_path=tmp_path / "state" / "jobs.json",
        audit_path=tmp_path / "state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
        language_binary=fake_binary,
    )


RESULT_ID = "mncs:language:experiment:result:" + "a" * 64
DEFINITION_ID = "mncs:language:experiment:definition:" + "b" * 64
ARTIFACT_ID = "mncs:compiler:backend-artifact:" + "c" * 64
BACKEND_ID = "mncs:compiler:backend:" + "d" * 64


def _write_fixtures(tmp_path: Path) -> dict[str, Path]:
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": "0.1",
        "contract_id": "mncs:language:experiment-result:0.1",
        "identity": RESULT_ID,
        "definition_identity": DEFINITION_ID,
        "source_artifact_identity": "mncs:source:artifact:" + "e" * 64,
        "semantic_fingerprint": "f" * 64,
        "hir_fingerprint": "0" * 64,
        "ssa_fingerprint": "1" * 64,
        "realization_request_identity": "mncs:compiler:realization-request:" + "2" * 64,
        "realization_plan_identity": "mncs:compiler:target-lowering-plan:" + "3" * 64,
        "backend_identity": BACKEND_ID,
        "backend_artifact_identity": ARTIFACT_ID,
        "backend_artifact_kind": "wasm_module",
        "status": "PASS",
    }
    result_path = baseline_dir / "result.json"
    artifact = {"identity": ARTIFACT_ID, "artifact_kind": "wasm_module", "bytes_hex": "0061736d"}
    result["artifact"] = artifact
    result_path.write_text(json.dumps(result), encoding="utf-8")
    artifact_path = baseline_dir / "backend-artifact.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    corpus_path = baseline_dir / "corpus.json"
    corpus_path.write_text(json.dumps({"cases": [], "properties": []}), encoding="utf-8")
    return {"result": result_path, "artifact": artifact_path, "corpus": corpus_path}


def _fake_inspector(valid: bool = True, *, report_overrides: dict | None = None):
    def inspector(binary, path: Path) -> dict:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if path.name == "replicated-result.json":
            return {
                "identity": data.get("identity"),
                "identity_valid": valid,
                "definition_identity": data.get("definition", {}).get("identity"),
            }
        return {
            "identity": data["identity"],
            "identity_valid": valid,
            "definition_identity": data["definition_identity"],
            "source_artifact_identity": data["source_artifact_identity"],
            "semantic_fingerprint": data["semantic_fingerprint"],
            "hir_fingerprint": data["hir_fingerprint"],
            "ssa_fingerprint": data["ssa_fingerprint"],
            "realization_request_identity": data["realization_request_identity"],
            "realization_plan_identity": data["realization_plan_identity"],
            "backend_identity": data["backend_identity"],
            "backend_artifact_identity": data["backend_artifact_identity"],
            "backend_artifact_kind": data["backend_artifact_kind"],
            **(report_overrides or {}),
        }

    return inspector


class FakeFabric:
    def __init__(self, *, stdout: str | None = None, error: ControlError | None = None) -> None:
        self.calls: list[dict] = []
        self.error = error
        if stdout is None:
            stdout = json.dumps(
                {
                    "exit_code": 0,
                    "stderr_tail": "",
                    "summary": _worker_summary(),
                    "replicated_result": _replicated_result(),
                }
            )
        self.stdout = stdout

    def execute_exact_target(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {
            "status": "executed",
            "disposition": "EXECUTED",
            "requested_worker": kwargs.get("worker_id"),
            "admitted_worker": kwargs.get("worker_id"),
            "work_evidence": {
                "record_identity": "sha256:" + "9" * 64,
                "target_admission_identity": "sha256:" + "8" * 64,
            },
            "stdout": self.stdout,
            "family_execution_reference": {
                "schema_version": "mncs-fabric.family-execution-reference.v0.1",
                "stable_id": "mncs-fabric://execution/" + "9" * 64 + "/attempt/1",
                "content_digest": "sha256:" + "7" * 64,
            },
        }


def _worker_summary(*, agrees: bool = True, status: str = "PASS") -> dict:
    return {
        "schemaVersion": "0.1",
        "baselineResultIdentity": RESULT_ID,
        "replicatedResultIdentity": RESULT_ID if agrees and status == "PASS" else REPLICA_RESULT_ID,
        "definitionIdentity": DEFINITION_ID,
        "status": status,
        "caseCount": 9,
        "propertyCount": 6,
        "casesMatchingBaseline": 9 if agrees else 3,
        "propertiesMatchingBaseline": 6 if agrees else 2,
        "boundedBehaviorAgrees": agrees,
        "earliestCaseDivergence": None if agrees else "unknown-unknown",
    }


REPLICA_RESULT_ID = "mncs:language:experiment:result:" + "5" * 64


def _replicated_result() -> dict:
    return {
        "schema_version": "0.1",
        "contract_id": "mncs:language:experiment-result:0.1",
        "identity": REPLICA_RESULT_ID,
        "definition": {"identity": DEFINITION_ID},
        "backend": {"identity": BACKEND_ID},
        "status": "PASS",
    }


class FakeForge:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record_concept_evidence(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "status": "completed",
            "baseline_experiment_id": "compiler-experiment:baseline",
            "replica_experiment_id": "compiler-experiment:replica",
            "comparison": {
                "earliest_observed_difference": None,
                "bounded_behavior_agrees": True,
                "same_backend": True,
                "interpretation": "observation_only_not_assurance_or_conformance",
            },
            "concept_evaluation_id": "concept-evaluation:" + "6" * 64,
        }


class FakeCommons:
    def __init__(self) -> None:
        self.published: list[dict] = []

    def _module(self):  # noqa: ANN001 - mirrors CommonsAdapter seam
        def make_replication_record(**kwargs):
            return {
                "kind": "Replication",
                "metadata": {"recordId": kwargs["replication_id"]},
                "details": {"outcome": kwargs["outcome"], "targetRecord": kwargs["target_record"]},
                "relationships": [],
            }

        return SimpleNamespace(make_replication_record=make_replication_record)

    def publish_record(self, record):
        self.published.append(record)
        return {
            "deliveryStatus": "INGESTED",
            "contentDigest": "sha256:" + "4" * 64,
            "logicalRecordId": record["metadata"]["recordId"],
            "acceptanceStatus": "UNCHANGED",
        }


@pytest.fixture
def manager(replication_config: ControlConfig):
    fixtures = _write_fixtures(replication_config.workspace_root)

    def build(
        *,
        fabric=None,
        forge=None,
        commons=None,
        inspector=None,
    ) -> tuple[ReplicationManager, dict[str, Path], FakeFabric, FakeForge, FakeCommons]:
        fabric = fabric or FakeFabric()
        forge = forge or FakeForge()
        commons = commons or FakeCommons()
        instance = ReplicationManager(
            replication_config,
            fabric=fabric,
            forge=forge,
            commons=commons,
            inspector=inspector or _fake_inspector(),
            resume=False,
        )
        instance._spawn = lambda replication_id: None  # tests drive stages synchronously
        return instance, fixtures, fabric, forge, commons

    return build


SPEC = {
    "baseline_result_path": "",
    "backend_artifact_path": "",
    "corpus_path": "",
    "worker_id": "fabric-worker-01",
}


def _spec(fixtures: dict[str, Path]) -> dict:
    return {
        **SPEC,
        "baseline_result_path": str(fixtures["result"]),
        "backend_artifact_path": str(fixtures["artifact"]),
        "corpus_path": str(fixtures["corpus"]),
    }


def _drive(manager: ReplicationManager, replication_id: str) -> dict:
    for _ in range(12):
        state = manager._load(replication_id)
        if state["state"] in {"COMPLETED", "FAILED"}:
            return state
        manager._run(replication_id)
    raise AssertionError("replication did not reach a terminal state")


def test_happy_path_produces_complete_durable_lineage(manager) -> None:
    instance, fixtures, fabric, forge, commons = manager()
    started = instance.start(_spec(fixtures))
    replication_id = started["replication_id"]
    state = _drive(instance, replication_id)

    assert state["state"] == "COMPLETED"
    assert state["outcome"] == "PASS"
    identities = state["identities"]
    assert identities["baseline_result_identity"] == RESULT_ID
    assert identities["definition_identity"] == DEFINITION_ID
    assert identities["backend_artifact_identity"] == ARTIFACT_ID
    assert identities["replicated_result_identity"]
    assert identities["replicated_identity_verified"] is True
    assert state["fabric"]["disposition"] == "EXECUTED"
    assert state["fabric"]["admitted_worker"] == "fabric-worker-01"
    assert state["fabric"]["family_execution_reference"]["stable_id"].startswith(
        "mncs-fabric://execution/"
    )
    assert state["forge"]["concept_evaluation_id"].startswith("concept-evaluation:")
    assert state["forge"]["comparison_reference"]["bounded_behavior_agrees"] is True
    assert state["commons"]["publication"]["deliveryStatus"] == "INGESTED"
    assert state["commons"]["publication"]["acceptanceStatus"] == "UNCHANGED"

    # The published Commons record binds the typed producer references.
    published = commons.published[0]
    assert published["kind"] == "Replication"
    # Exact target behavior: exactly one dispatch to the requested worker.
    assert len(fabric.calls) == 1
    assert fabric.calls[0]["worker_id"] == "fabric-worker-01"


def test_artifact_substitution_fails_closed_without_dispatching(manager) -> None:
    instance, fixtures, fabric, *_ = manager()
    spec = _spec(fixtures)
    # Substitute a different frozen artifact after freezing: its recorded
    # identity no longer matches the baseline result's recorded realization.
    artifact = json.loads(Path(spec["backend_artifact_path"]).read_text())
    artifact["identity"] = "mncs:compiler:backend-artifact:" + "f" * 64
    Path(spec["backend_artifact_path"]).write_text(json.dumps(artifact))
    started = instance.start(spec)
    state = _drive(instance, started["replication_id"])

    assert state["state"] == "FAILED"
    assert state["error"]["code"] == "ARTIFACT_IDENTITY_MISMATCH"
    assert fabric.calls == []


def test_requested_worker_unavailable_never_falls_back(manager) -> None:
    unavailable = ControlError(
        "FABRIC_WORKER_UNAVAILABLE",
        "requested Fabric worker is not available (UNKNOWN); exact-target replication never falls back",
    )
    instance, fixtures, fabric, _, commons = manager(fabric=FakeFabric(error=unavailable))
    started = instance.start(_spec(fixtures))
    state = _drive(instance, started["replication_id"])

    assert state["state"] == "FAILED"
    assert state["error"]["code"] == "FABRIC_TARGET_FAILED"
    assert len(fabric.calls) == 1, "no retry or worker substitution may occur"
    assert not commons.published


def test_missing_worker_output_stays_unknown_and_fails_closed(manager) -> None:
    instance, fixtures, _, forge, commons = manager(fabric=FakeFabric(stdout=""))
    started = instance.start(_spec(fixtures))
    state = _drive(instance, started["replication_id"])

    assert state["state"] == "FAILED"
    assert state["error"]["code"] == "REPLICA_OUTPUT_MISSING"
    assert state["outcome"] == "UNKNOWN"
    assert forge.calls == [] and not commons.published


def test_behavior_divergence_is_recorded_as_fail_not_laundered_to_pass(manager) -> None:
    divergence_stdout = json.dumps(
        {
            "exit_code": 1,
            "stderr_tail": "",
            "summary": _worker_summary(agrees=False),
            "replicated_result": {**_replicated_result(), "status": "FAIL"},
        }
    )

    class DivergeForge(FakeForge):
        def record_concept_evidence(self, **kwargs):
            result = super().record_concept_evidence(**kwargs)
            result["comparison"]["bounded_behavior_agrees"] = False
            result["comparison"]["earliest_observed_difference"] = "backend_artifact"
            return result

    instance, fixtures, _, forge, commons = manager(
        fabric=FakeFabric(stdout=divergence_stdout), forge=DivergeForge()
    )
    started = instance.start(_spec(fixtures))
    state = _drive(instance, started["replication_id"])

    assert state["state"] == "COMPLETED"
    assert state["outcome"] == "FAIL"
    assert state["forge"]["comparison_reference"]["bounded_behavior_agrees"] is False
    published = commons.published[0]
    assert published["details"]["outcome"] == "FAIL"


def test_definition_divergence_in_returned_result_fails_closed(manager) -> None:
    forged = _replicated_result()
    forged["definition"] = {"identity": "mncs:language:experiment:definition:" + "9" * 64}
    envelope = json.dumps(
        {
            "exit_code": 0,
            "stderr_tail": "",
            "summary": _worker_summary(),
            "replicated_result": forged,
        }
    )
    instance, fixtures, _, forge, commons = manager(fabric=FakeFabric(stdout=envelope))
    started = instance.start(_spec(fixtures))
    state = _drive(instance, started["replication_id"])

    assert state["state"] == "FAILED"
    assert state["error"]["code"] == "DEFINITION_IDENTITY_DIVERGENCE"
    assert forge.calls == [] and not commons.published


def test_repeated_identical_spec_deduplicates_to_one_replication(manager) -> None:
    instance, fixtures, fabric, _, _ = manager()
    first = instance.start(_spec(fixtures))
    second = instance.start(_spec(fixtures))
    assert second["replication_id"] == first["replication_id"]
    assert second.get("deduplicated") is True
    _drive(instance, first["replication_id"])
    third = instance.start(_spec(fixtures))
    assert third["recorded_state"] in {"COMPLETED", "FAILED"}


def test_state_schema_and_spec_identity_are_verified_on_load(manager) -> None:
    instance, fixtures, *_ = manager()
    started = instance.start(_spec(fixtures))
    state = instance._load(started["replication_id"])
    assert state["schema_version"] == REPLICATION_SCHEMA
    tampered_path = instance._state_path(started["replication_id"])
    mutated = json.loads(tampered_path.read_text())
    mutated["spec"]["worker_id"] = "other-worker"
    tampered_path.write_text(json.dumps(mutated))
    from mncs_control_mcp.errors import ControlError as _ControlError

    with pytest.raises(_ControlError, match="does not verify"):
        instance._load(started["replication_id"])

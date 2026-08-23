"""Durable Concept Experiment replication orchestration.

Control coordinates one exact replication of an already-frozen MNCS Language
Concept Experiment realization onto one explicitly requested Fabric worker:

    frozen experiment -> identity verification -> bundle preparation ->
    Fabric exact-target execution (no fallback) -> replicated result ->
    Forge record/comparison/evaluation -> Commons Replication Family Record.

Authority boundaries preserved by this module:

- MNCS Language owns semantics, realization identities, and experiment results;
  this coordinator only invokes the language CLI to verify sealed identities.
- Fabric owns worker admission, placement, execution attempts, and runtime
  facts.  A Fabric ``EXECUTED`` disposition never means the program is correct.
- Forge owns persisted comparison evidence and bounded evaluations.
- Commons stores the durable lineage; publication is not acceptance.

Every identity mismatch fails closed: the workflow records ``FAILED`` with a
diagnostic and never substitutes artifacts, corpora, workers, or backends.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
import uuid
from collections.abc import Callable
from datetime import UTC
from pathlib import Path
from typing import Any

from .config import ControlConfig
from .errors import ControlError

REPLICATION_SCHEMA = "mncs-control.replication.v0.1"

_ACTIVE_STATES = frozenset(
    {"ACCEPTED", "VERIFYING", "PREPARING", "EXECUTING", "COLLECTING", "COMPARING", "PUBLISHING"}
)
_TERMINAL_STATES = frozenset({"COMPLETED", "FAILED"})

_RUNNER_SCRIPT = '''"""Fabric bundle entry point for one frozen MNCS Concept Experiment replication."""

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    bundle = Path(__file__).resolve().parent
    executable = bundle / ("mncs.exe" if (bundle / "mncs.exe").is_file() else "mncs")
    if executable.name == "mncs":
        executable.chmod(executable.stat().st_mode | stat.S_IEXEC)
    timeout = float(sys.argv[1]) if len(sys.argv) > 1 else 120.0
    try:
        completed = subprocess.run(
            [
                str(executable),
                "experiment",
                "execute",
                "backend-artifact.json",
                "corpus.json",
                "--baseline",
                "baseline-result.json",
                "--output-dir",
                ".",
            ],
            cwd=bundle,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"error": "FROZEN_EXECUTE_TIMEOUT"}))
        return 3
    summary = None
    if completed.stdout.strip():
        try:
            summary = json.loads(completed.stdout)
        except ValueError:
            summary = None
    result = None
    result_path = bundle / "replicated-result.json"
    if result_path.is_file():
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except ValueError:
            result = None
    envelope = {
        "exit_code": completed.returncode,
        "stderr_tail": completed.stderr[-2000:] if completed.stderr else "",
        "summary": summary,
        "replicated_result": result,
    }
    print(json.dumps(envelope))
    return 0 if result is not None else max(1, completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _identity_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _canonical_identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _default_inspector(binary: Path, result_path: Path) -> dict[str, object]:
    """Verify one language experiment result through the language CLI itself."""
    if not binary.is_file():
        raise ControlError(
            "LANGUAGE_BINARY_UNAVAILABLE",
            f"MNCS language CLI binary is missing: {binary}",
        )
    completed = subprocess.run(
        [str(binary), "experiment", "inspect", str(result_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if not completed.stdout.strip():
        raise ControlError(
            "LANGUAGE_IDENTITY_INVALID",
            "language CLI produced no inspection report",
            details={"stderr_tail": completed.stderr[-1000:] if completed.stderr else ""},
        )
    try:
        report = json.loads(completed.stdout)
    except ValueError as exc:
        raise ControlError(
            "LANGUAGE_IDENTITY_INVALID",
            f"language CLI inspection output was not JSON: {exc}",
        ) from exc
    if completed.returncode != 0 or not report.get("identity_valid"):
        raise ControlError(
            "LANGUAGE_IDENTITY_INVALID",
            "language experiment result identity chain does not verify",
            details={"report": report},
        )
    return report


class ReplicationManager:
    """Durable coordinator for exact-target Concept Experiment replications."""

    def __init__(
        self,
        config: ControlConfig,
        *,
        fabric: Any = None,
        forge: Any = None,
        commons: Any = None,
        inspector: Callable[[Path, Path], dict[str, object]] | None = None,
        resume: bool = True,
    ) -> None:
        self.config = config
        self.fabric = fabric
        self.forge = forge
        self.commons = commons
        self._inspector = inspector or _default_inspector
        self.root = config.job_state_path.parent / "replications"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._locks: dict[str, threading.Lock] = {}
        self._lock_guard = threading.Lock()
        if resume:
            threading.Timer(2.0, self.resume_unfinished).start()

    # ------------------------------------------------------------------ paths

    def _directory(self, replication_id: str) -> Path:
        if (
            not isinstance(replication_id, str)
            or not replication_id.startswith("repl-")
            or len(replication_id) != 37
            or any(character not in "0123456789abcdef" for character in replication_id[5:])
        ):
            raise ControlError("INVALID_INPUT", "replication id is malformed")
        path = self.root / replication_id
        if not path.is_dir():
            raise ControlError("REPLICATION_NOT_FOUND", f"unknown replication: {replication_id}")
        return path

    def _state_path(self, replication_id: str) -> Path:
        return self._directory(replication_id) / "state.json"

    def _load(self, replication_id: str) -> dict[str, Any]:
        path = self._state_path(replication_id)
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ControlError(
                "REPLICATION_STATE_INVALID", f"unable to read replication state: {exc}"
            ) from exc
        if state.get("schema_version") != REPLICATION_SCHEMA:
            raise ControlError("REPLICATION_STATE_INVALID", "unsupported replication state schema")
        expected = state.get("spec_identity")
        if expected and expected != _canonical_identity(state.get("spec")):
            raise ControlError(
                "REPLICATION_STATE_INVALID", "replication spec identity does not verify"
            )
        manifest_identity = state.get("manifest_identity")
        if manifest_identity and manifest_identity != _canonical_identity(
            {"schema_version": REPLICATION_SCHEMA, "spec": state.get("spec")}
        ):
            raise ControlError(
                "REPLICATION_STATE_INVALID", "replication manifest identity does not verify"
            )
        return state

    def _save(self, replication_id: str, state: dict[str, Any]) -> None:
        path = self._state_path(replication_id)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)

    # ------------------------------------------------------------------- api

    def start(self, raw_spec: dict[str, object]) -> dict[str, object]:
        spec = self._validate_spec(raw_spec)
        spec_identity = _canonical_identity(spec)
        existing = self._find_by_spec(spec_identity)
        if existing is not None:
            recorded = self.status(existing["replication_id"])
            if recorded.get("recorded_state") != "FAILED":
                recorded["deduplicated"] = True
                return recorded
        replication_id = "repl-" + uuid.uuid4().hex
        directory = self.root / replication_id
        directory.mkdir(mode=0o700)
        state: dict[str, Any] = {
            "schema_version": REPLICATION_SCHEMA,
            "replication_id": replication_id,
            "spec_identity": spec_identity,
            "manifest_identity": _canonical_identity(
                {"schema_version": REPLICATION_SCHEMA, "spec": spec}
            ),
            "spec": spec,
            "state": "ACCEPTED",
            "created_at": _now(),
            "updated_at": _now(),
            "identities": _empty_identities(),
            "fabric": {},
            "forge": {},
            "commons": {},
            "status_summary": {},
            "outcome": None,
            "error": None,
        }
        self._save(replication_id, state)
        self._spawn(replication_id)
        return self.status(replication_id)

    def status(self, replication_id: str) -> dict[str, object]:
        state = self._load(replication_id)
        effective = state["state"]
        if state["state"] in _ACTIVE_STATES:
            lock_path = self._directory(replication_id) / "coordinator.lock"
            if not lock_path.exists():
                effective = "RECOVERY_PENDING"
        bounded = {
            "schema_version": REPLICATION_SCHEMA,
            "replication_id": replication_id,
            "recorded_state": state["state"],
            "state": effective,
            "created_at": state["created_at"],
            "updated_at": state["updated_at"],
            "spec": _bounded_spec(state["spec"]),
            "identities": state.get("identities"),
            "fabric": _bounded_fabric(state.get("fabric")),
            "forge": _bounded_forge(state.get("forge")),
            "commons": state.get("commons"),
            "status_summary": state.get("status_summary"),
            "outcome": state.get("outcome"),
            "error": state.get("error"),
            "claim_boundary": (
                "Coordination status only. Language owns experiment semantics; Fabric owns "
                "execution facts; Forge owns comparison evidence; Commons publication is not "
                "acceptance."
            ),
        }
        return bounded

    def list(self) -> dict[str, object]:
        items = []
        for directory in sorted(self.root.glob("repl-*")):
            try:
                state = self._load(directory.name)
            except ControlError:
                continue
            items.append(
                {
                    "replication_id": directory.name,
                    "state": state["state"],
                    "outcome": state.get("outcome"),
                    "worker": (state.get("spec") or {}).get("worker_id"),
                    "baseline_result_identity": (state.get("identities") or {}).get(
                        "baseline_result_identity"
                    ),
                    "updated_at": state.get("updated_at"),
                }
            )
        return {"replications": items, "count": len(items)}

    # ------------------------------------------------------------- validation

    @staticmethod
    def _validate_spec(raw_spec: dict[str, object]) -> dict[str, object]:
        if not isinstance(raw_spec, dict):
            raise ControlError("INVALID_INPUT", "spec must be an object")
        unknown = sorted(set(raw_spec) - _ALLOWED_SPEC_FIELDS)
        if unknown:
            raise ControlError(
                "INVALID_INPUT", f"spec has unsupported fields: {', '.join(unknown)}"
            )
        for field in ("baseline_result_path", "backend_artifact_path", "corpus_path", "worker_id"):
            value = raw_spec.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ControlError("INVALID_INPUT", f"spec.{field} is required")
        worker = str(raw_spec["worker_id"])
        if len(worker) > 128 or "\x00" in worker:
            raise ControlError("INVALID_INPUT", "spec.worker_id is malformed")
        concept = raw_spec.get("concept_experiment_id")
        if concept is not None and (not isinstance(concept, str) or len(concept) > 256):
            raise ControlError("INVALID_INPUT", "spec.concept_experiment_id must be short text")
        timeout = raw_spec.get("timeout_seconds", 300)
        if not isinstance(timeout, (int, float)) or not 30 <= float(timeout) <= 3600:
            raise ControlError("INVALID_INPUT", "spec.timeout_seconds must be between 30 and 3600")
        return {
            "baseline_result_path": str(raw_spec["baseline_result_path"]),
            "backend_artifact_path": str(raw_spec["backend_artifact_path"]),
            "corpus_path": str(raw_spec["corpus_path"]),
            "worker_id": worker,
            "concept_experiment_id": concept if isinstance(concept, str) else None,
            "timeout_seconds": float(timeout),
        }

    def _find_by_spec(self, spec_identity: str) -> dict[str, object] | None:
        for directory in sorted(self.root.glob("repl-*")):
            try:
                state = self._load(directory.name)
            except ControlError:
                continue
            if state.get("spec_identity") == spec_identity:
                return {"replication_id": directory.name}
        return None

    # ------------------------------------------------------------- durability

    def _spawn(self, replication_id: str) -> None:
        with self._lock_guard:
            self._locks.setdefault(replication_id, threading.Lock())
        thread = threading.Thread(
            target=self._thread_main,
            args=(replication_id,),
            name=f"replication-{replication_id}",
            daemon=True,
        )
        thread.start()

    def _thread_main(self, replication_id: str) -> None:
        with self._lock_guard:
            lock = self._locks.setdefault(replication_id, threading.Lock())
        if not lock.acquire(blocking=False):
            return
        try:
            self._run(replication_id)
        except Exception as exc:  # noqa: BLE001 - durable coordinator records everything
            state = self._load(replication_id)
            state["state"] = "FAILED"
            state["error"] = {
                "code": "COORDINATOR_FAILURE",
                "message": str(exc)[:500],
            }
            state["updated_at"] = _now()
            self._save(replication_id, state)
        finally:
            lock.release()

    def resume_unfinished(self) -> None:
        for directory in sorted(self.root.glob("repl-*")):
            try:
                state = self._load(directory.name)
            except ControlError:
                continue
            if state["state"] in _ACTIVE_STATES:
                self._spawn(directory.name)

    # ------------------------------------------------------------------ stages

    def _advance(self, replication_id: str, next_state: str, **updates: Any) -> dict[str, Any]:
        state = self._load(replication_id)
        state["state"] = next_state
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(state.get(key), dict):
                state[key].update(value)
            else:
                state[key] = value
        state["updated_at"] = _now()
        self._save(replication_id, state)
        return state

    def _fail(self, replication_id: str, code: str, message: str, details: Any = None) -> None:
        error: dict[str, Any] = {"code": code, "message": message[:800]}
        if details is not None:
            error["details"] = details
        state = self._load(replication_id)
        state["state"] = "FAILED"
        state["error"] = error
        if state.get("outcome") is None:
            state["outcome"] = "UNKNOWN"
        state["updated_at"] = _now()
        self._save(replication_id, state)

    def _run(self, replication_id: str) -> None:
        state = self._load(replication_id)
        current = state["state"]
        if current in _TERMINAL_STATES:
            return
        if current == "ACCEPTED":
            self._stage_verifying(replication_id)
        elif current == "VERIFYING":
            self._stage_preparing(replication_id)
        elif current == "PREPARING":
            self._stage_executing(replication_id)
        elif current == "EXECUTING":
            self._stage_collecting(replication_id)
        elif current == "COLLECTING":
            self._stage_comparing(replication_id)
        elif current == "COMPARING":
            self._stage_publishing(replication_id)
        elif current == "PUBLISHING":
            # Publication crashed mid-flight; re-run publishing idempotently.
            self._stage_publishing(replication_id)

    # VERIFYING: verify the baseline chain through the language CLI itself.
    def _stage_verifying(self, replication_id: str) -> None:
        state = self._load(replication_id)
        spec = state["spec"]
        baseline_path = Path(spec["baseline_result_path"])
        artifact_path = Path(spec["backend_artifact_path"])
        corpus_path = Path(spec["corpus_path"])
        if not baseline_path.is_file() or not artifact_path.is_file() or not corpus_path.is_file():
            self._fail(
                replication_id,
                "REPLICATION_INPUT_MISSING",
                "baseline result, backend artifact, and corpus files must all exist",
                details={
                    "baseline": str(baseline_path),
                    "artifact": str(artifact_path),
                    "corpus": str(corpus_path),
                },
            )
            return
        try:
            report = self._inspector(self.config.resolved_language_binary, baseline_path)
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except ControlError as exc:
            self._fail(
                replication_id, exc.code if hasattr(exc, "code") else "VERIFY_FAILED", str(exc)
            )
            return
        except ValueError as exc:
            self._fail(replication_id, "ARTIFACT_MALFORMED", f"backend artifact is not JSON: {exc}")
            return
        artifact_identity = artifact.get("identity")
        inspected_artifact = report.get("backend_artifact_identity")
        if artifact_identity != inspected_artifact:
            self._fail(
                replication_id,
                "ARTIFACT_IDENTITY_MISMATCH",
                "supplied backend artifact does not match the artifact recorded by the "
                "baseline result; refusing to replicate a substituted realization",
                details={
                    "artifact_identity": artifact_identity,
                    "baseline_recorded": inspected_artifact,
                },
            )
            return
        self._advance(
            replication_id,
            "VERIFYING",
            identities={
                "baseline_result_identity": report.get("identity"),
                "definition_identity": report.get("definition_identity"),
                "source_artifact_identity": report.get("source_artifact_identity"),
                "semantic_fingerprint": report.get("semantic_fingerprint"),
                "hir_fingerprint": report.get("hir_fingerprint"),
                "ssa_fingerprint": report.get("ssa_fingerprint"),
                "realization_request_identity": report.get("realization_request_identity"),
                "realization_plan_identity": report.get("realization_plan_identity"),
                "backend_identity": report.get("backend_identity"),
                "backend_artifact_identity": inspected_artifact,
                "backend_artifact_kind": report.get("backend_artifact_kind"),
                "artifact_verified": True,
            },
        )
        self._stage_preparing(replication_id)

    # PREPARING: stage the immutable bundle contents.
    def _stage_preparing(self, replication_id: str) -> None:
        state = self._load(replication_id)
        spec = state["spec"]
        bundle_dir = self._directory(replication_id) / "bundle"
        if bundle_dir.exists():
            shutil.rmtree(bundle_dir)
        bundle_dir.mkdir(parents=True, mode=0o700)
        binary = self.config.resolved_language_binary
        shutil.copy2(binary, bundle_dir / "mncs")
        os.chmod(bundle_dir / "mncs", 0o755)
        shutil.copy2(Path(spec["backend_artifact_path"]), bundle_dir / "backend-artifact.json")
        shutil.copy2(Path(spec["corpus_path"]), bundle_dir / "corpus.json")
        shutil.copy2(Path(spec["baseline_result_path"]), bundle_dir / "baseline-result.json")
        runner = bundle_dir / "run_frozen_experiment.py"
        runner.write_text(_RUNNER_SCRIPT, encoding="utf-8")
        corpus_digest = _identity_of_file(Path(spec["corpus_path"]))
        artifact_digest = _identity_of_file(Path(spec["backend_artifact_path"]))
        self._advance(
            replication_id,
            "PREPARING",
            identities={
                "corpus_digest": corpus_digest,
                "frozen_artifact_file_digest": artifact_digest,
            },
            fabric={"bundle_staged": True},
        )
        self._stage_executing(replication_id)

    # EXECUTING: hand the frozen bundle to Fabric's exact-target boundary.
    def _stage_executing(self, replication_id: str) -> None:
        state = self._load(replication_id)
        spec = state["spec"]
        if self.fabric is None:
            self._fail(replication_id, "FABRIC_UNAVAILABLE", "Fabric adapter is unavailable")
            return
        suffix = hashlib.sha256(f"{replication_id}".encode()).hexdigest()[:20]
        try:
            result = self.fabric.execute_exact_target(
                worker_id=spec["worker_id"],
                bundle_dir=self._directory(replication_id) / "bundle",
                argv=[
                    "@python",
                    "run_frozen_experiment.py",
                    str(int(float(spec["timeout_seconds"]))),
                ],
                job_id=f"mncs-control-repl:{suffix}",
                timeout_seconds=float(spec["timeout_seconds"]) + 60.0,
                result_paths=["replicated-result.json", "replicated-family-reference.json"],
            )
        except ControlError as exc:
            self._fail(
                replication_id,
                "FABRIC_TARGET_FAILED",
                str(exc),
                details=getattr(exc, "details", None),
            )
            return
        fabric_view = {
            key: result[key]
            for key in ("disposition", "requested_worker", "admitted_worker", "work_evidence")
            if key in result
        }
        family_reference = result.get("family_execution_reference")
        self._advance(
            replication_id,
            "EXECUTING",
            fabric={
                **fabric_view,
                "_stdout_cache": result.get("stdout") or "",
                "family_execution_reference": family_reference,
                "artifact_verified": result.get("disposition")
                in {"EXECUTED", "DUPLICATE_IDEMPOTENT"},
            },
        )
        self._stage_collecting(replication_id)

    # COLLECTING: parse the worker envelope and re-verify identities locally.
    def _stage_collecting(self, replication_id: str) -> None:
        state = self._load(replication_id)
        stdout_text = (state.get("fabric") or {}).get("_stdout_cache") or ""
        self._consume_envelope(replication_id, str(stdout_text))

    def _consume_envelope(self, replication_id: str, stdout_text: str) -> None:
        state = self._load(replication_id)
        if not stdout_text.strip():
            self._fail(
                replication_id,
                "REPLICA_OUTPUT_MISSING",
                "worker produced no parseable replication envelope; missing evidence stays UNKNOWN",
            )
            return
        try:
            envelope = json.loads(stdout_text)
        except ValueError as exc:
            self._fail(
                replication_id,
                "REPLICA_OUTPUT_MALFORMED",
                f"worker envelope was not valid JSON: {exc}",
            )
            return
        replicated_result = envelope.get("replicated_result")
        summary = envelope.get("summary")
        if not isinstance(replicated_result, dict) or not isinstance(summary, dict):
            self._fail(
                replication_id,
                "REPLICA_EVIDENCE_INCOMPLETE",
                "worker envelope lacks replicated result or summary evidence",
                details={
                    "exit_code": envelope.get("exit_code"),
                    "stderr_tail": envelope.get("stderr_tail"),
                },
            )
            return
        definition_identity = (state.get("identities") or {}).get("definition_identity")
        replica_definition = (replicated_result.get("definition") or {}).get("identity")
        if replica_definition != definition_identity:
            self._fail(
                replication_id,
                "DEFINITION_IDENTITY_DIVERGENCE",
                "replicated result does not bind the baseline experiment definition",
                details={"expected": definition_identity, "observed": replica_definition},
            )
            return
        # Re-verify the returned record through the language CLI with our own binary.
        replica_path = self._directory(replication_id) / "replicated-result.json"
        replica_path.write_text(json.dumps(replicated_result, indent=2), encoding="utf-8")
        try:
            report = self._inspector(self.config.resolved_language_binary, replica_path)
        except ControlError as exc:
            self._fail(replication_id, "REPLICATED_IDENTITY_INVALID", str(exc))
            return
        agrees = bool(summary.get("boundedBehaviorAgrees"))
        language_status = str(summary.get("status", "UNKNOWN"))
        disposition = (state.get("fabric") or {}).get("disposition")
        executed = disposition in {"EXECUTED", "DUPLICATE_IDEMPOTENT"}
        if language_status == "FAIL" or (executed and not agrees and language_status == "PASS"):
            outcome = "FAIL"
        elif language_status == "PASS" and agrees and executed:
            outcome = "PASS"
        else:
            outcome = "UNKNOWN"
        self._advance(
            replication_id,
            "COLLECTING",
            identities={
                "replicated_result_identity": report.get("identity"),
                "replica_definition_identity": replica_definition,
                "replicated_identity_verified": bool(report.get("identity_valid")),
            },
            status_summary={
                "language_status": language_status,
                "bounded_behavior_agrees": agrees,
                "cases_matching_baseline": summary.get("casesMatchingBaseline"),
                "properties_matching_baseline": summary.get("propertiesMatchingBaseline"),
            },
            outcome=outcome,
        )
        self._stage_comparing(replication_id)

    # COMPARING: persist both records plus comparison in Forge.
    def _stage_comparing(self, replication_id: str) -> None:
        state = self._load(replication_id)
        if self.forge is None:
            self._fail(
                replication_id,
                "FORGE_UNAVAILABLE",
                "Forge adapter is unavailable; missing comparison evidence must not become PASS",
            )
            return
        baseline_path = Path(state["spec"]["baseline_result_path"])
        replica_path = self._directory(replication_id) / "replicated-result.json"
        try:
            baseline_result = json.loads(baseline_path.read_text(encoding="utf-8"))
            replicated_result = json.loads(replica_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._fail(replication_id, "FORGE_INPUT_INVALID", str(exc))
            return
        family_reference = (state.get("fabric") or {}).get("family_execution_reference") or {}
        execution_ids = [
            stable_id for stable_id in (family_reference.get("stable_id"),) if stable_id
        ]
        evidence = self.forge.record_concept_evidence(
            baseline_result=baseline_result,
            replicated_result=replicated_result,
            execution_stable_ids=[str(item) for item in execution_ids],
            concept_experiment_id=(state["spec"] or {}).get("concept_experiment_id"),
        )
        if evidence.get("status") != "completed":
            self._fail(
                replication_id,
                "FORGE_COMPARISON_FAILED",
                "Forge comparison evidence is incomplete; overall outcome remains UNKNOWN",
                details=evidence,
            )
            return
        self._advance(
            replication_id,
            "COMPARING",
            forge={
                "baseline_experiment_id": evidence.get("baseline_experiment_id"),
                "replica_experiment_id": evidence.get("replica_experiment_id"),
                "comparison_reference": {
                    "left": evidence.get("baseline_experiment_id"),
                    "right": evidence.get("replica_experiment_id"),
                    "earliest_observed_difference": (evidence.get("comparison") or {}).get(
                        "earliest_observed_difference"
                    ),
                    "bounded_behavior_agrees": (evidence.get("comparison") or {}).get(
                        "bounded_behavior_agrees"
                    ),
                    "same_backend": (evidence.get("comparison") or {}).get("same_backend"),
                    "interpretation": (evidence.get("comparison") or {}).get("interpretation"),
                },
                "concept_evaluation_id": evidence.get("concept_evaluation_id"),
            },
        )
        self._stage_publishing(replication_id)

    # PUBLISHING: append the Replication record to the Commons Family Record spine.
    def _stage_publishing(self, replication_id: str) -> None:
        state = self._load(replication_id)
        if self.commons is None:
            self._fail(replication_id, "COMMONS_UNAVAILABLE", "Commons adapter is unavailable")
            return
        try:
            family_module = self.commons._module()  # noqa: SLF001 - producer-neutral builder seam
            record = family_module.make_replication_record(
                replication_id=f"commons:replication:{replication_id}",
                created_at=_now(),
                target_record=(
                    state["spec"].get("concept_experiment_id")
                    or (state.get("identities") or {}).get("definition_identity")
                    or replication_id
                ),
                outcome=state.get("outcome") or "UNKNOWN",
                independence={
                    "orchestrator": "mncs-control-mcp",
                    "requestedWorker": state["spec"]["worker_id"],
                    "admittedWorker": (state.get("fabric") or {}).get("admitted_worker"),
                    "executionTransport": "mncs-fabric-exact-target",
                    "artifactAncestry": [
                        (state.get("identities") or {}).get("backend_artifact_identity"),
                    ],
                },
                references=self._replication_references(state),
                summary=(
                    "Replication of frozen Concept Experiment realization "
                    f"{(state.get('identities') or {}).get('backend_artifact_identity')} on "
                    f"Fabric worker {(state.get('fabric') or {}).get('requested_worker')}; "
                    f"coordination outcome {(state.get('outcome') or 'UNKNOWN')}."
                ),
            )
            receipt = self.commons.publish_record(record)
        except Exception as exc:  # noqa: BLE001 - publication failures stay visible
            self._fail(replication_id, "COMMONS_PUBLISH_FAILED", redact(str(exc)))
            return
        self._advance(
            replication_id,
            "PUBLISHING",
            commons={
                "publication": {
                    "deliveryStatus": receipt.get("deliveryStatus"),
                    "contentDigest": receipt.get("contentDigest"),
                    "logicalRecordId": receipt.get("logicalRecordId"),
                    "acceptanceStatus": receipt.get("acceptanceStatus"),
                },
                "replication_record_id": f"commons:replication:{replication_id}",
            },
        )
        self._advance(replication_id, "COMPLETED")

    def _replication_references(self, state: dict[str, Any]) -> list[dict[str, object]]:
        references: list[dict[str, object]] = []
        identities = state.get("identities") or {}
        replica_identity = identities.get("replicated_result_identity")
        if replica_identity:
            references.append(
                {
                    "relation": "compiler_record",
                    "reference": {
                        "producer": "mncs-language",
                        "recordKind": "LanguageExperimentResult",
                        "schemaVersion": "mncs.family-record.producer-reference.v0.1",
                        "stableId": str(replica_identity),
                    },
                }
            )
        baseline_identity = identities.get("baseline_result_identity")
        if baseline_identity:
            references.append(
                {
                    "relation": "compiler_record",
                    "reference": {
                        "producer": "mncs-language",
                        "recordKind": "LanguageExperimentResult",
                        "schemaVersion": "mncs.family-record.producer-reference.v0.1",
                        "stableId": str(baseline_identity),
                    },
                }
            )
        fabric_view = state.get("fabric") or {}
        family_reference = fabric_view.get("family_execution_reference") or {}
        if isinstance(family_reference, dict) and family_reference.get("stable_id"):
            references.append(
                {
                    "relation": "execution",
                    "reference": {
                        "producer": "mncs-fabric",
                        "recordKind": "FamilyExecutionReference",
                        "schemaVersion": family_reference.get(
                            "schema_version", "mncs-fabric.family-execution-reference.v0.1"
                        ),
                        "stableId": str(family_reference["stable_id"]),
                        "contentDigest": family_reference.get("content_digest"),
                    },
                }
            )
        forge_view = state.get("forge") or {}
        evaluation_id = forge_view.get("concept_evaluation_id")
        if evaluation_id:
            references.append(
                {
                    "relation": "evaluation",
                    "reference": {
                        "producer": "mncs-forge",
                        "recordKind": "ConceptEvaluation",
                        "schemaVersion": "mncs-forge.concept-evaluation.v0.1",
                        "stableId": str(evaluation_id),
                    },
                }
            )
        return references


_ALLOWED_SPEC_FIELDS = frozenset(
    {
        "baseline_result_path",
        "backend_artifact_path",
        "corpus_path",
        "worker_id",
        "concept_experiment_id",
        "timeout_seconds",
    }
)


def _empty_identities() -> dict[str, Any]:
    return {
        "baseline_result_identity": None,
        "definition_identity": None,
        "source_artifact_identity": None,
        "semantic_fingerprint": None,
        "hir_fingerprint": None,
        "ssa_fingerprint": None,
        "realization_request_identity": None,
        "realization_plan_identity": None,
        "backend_identity": None,
        "backend_artifact_identity": None,
        "backend_artifact_kind": None,
        "artifact_verified": False,
        "corpus_digest": None,
        "frozen_artifact_file_digest": None,
        "replicated_result_identity": None,
        "replica_definition_identity": None,
        "replicated_identity_verified": False,
    }


def _bounded_spec(spec: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in spec.items()}


def _bounded_fabric(fabric: Any) -> Any:
    if not isinstance(fabric, dict):
        return fabric
    return {key: value for key, value in fabric.items() if key != "_stdout_cache"}


def _bounded_forge(forge: Any) -> Any:
    return forge


def redact(text: str) -> str:
    return text[:500]


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

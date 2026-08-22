"""Durable multi-turn experiment coordination for the persistent Control plane.

Control owns only coordinator lifecycle and durable handoff state. Harness owns
model routing semantics and Fabric owns each detached model execution. An MCP
client may disconnect after ``experiment_start``; unfinished experiments are
resumed when the Control server process starts again.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from .config import ControlConfig
from .errors import ControlError
from .security import redact_text

EXPERIMENT_SCHEMA = "mncs-control.experiment.v0.1"
STATE_SCHEMA = "mncs-control.experiment-state.v0.1"
TURN_SCHEMA = "mncs-control.experiment-turn.v0.1"
CONCEPT_MANIFEST_SCHEMA = "mncs-control.concept-experiment-manifest.v0.1"
FAMILY_REFERENCE_SCHEMA = "commons.mncs.dev/producer-reference/v0alpha1"
_TERMINAL = {"COMPLETED", "FAILED", "STOPPED"}
_ACTIVE_FABRIC = {"ACCEPTED", "QUEUED", "RUNNING", "DISPATCHED", "SUBMITTED"}
_REFERENCE_RELATIONS = {
    "governed_by",
    "actor",
    "candidate",
    "compiler_record",
    "execution",
    "evaluation",
    "observation",
    "failure",
    "artifact",
    "backend",
}


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded_text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ControlError("INVALID_INPUT", f"experiment {field} must be text")
    text = value.strip()
    if not text or len(text) > maximum or "\x00" in text:
        raise ControlError("INVALID_INPUT", f"experiment {field} must be bounded non-empty text")
    return text


def _bounded_text_list(value: object, field: str, *, maximum: int = 128) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum:
        raise ControlError("INVALID_INPUT", f"experiment {field} must be a bounded list")
    return [_bounded_text(item, f"{field} item", 4096) for item in value]


def _bounded_json(value: object, field: str, *, maximum: int = 256_000) -> object:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ControlError("INVALID_INPUT", f"experiment {field} must be JSON") from exc
    if len(encoded.encode("utf-8")) > maximum:
        raise ControlError("INVALID_INPUT", f"experiment {field} is oversized")
    return json.loads(encoded)


def validate_spec(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ControlError("INVALID_INPUT", "experiment spec must be an object")
    actors_raw = value.get("actors")
    if not isinstance(actors_raw, list) or not 1 <= len(actors_raw) <= 32:
        raise ControlError("INVALID_INPUT", "experiment actors must contain between 1 and 32 entries")
    actors: list[dict[str, str]] = []
    names: set[str] = set()
    for index, item in enumerate(actors_raw):
        if not isinstance(item, Mapping):
            raise ControlError("INVALID_INPUT", f"experiment actor {index + 1} must be an object")
        actor = {
            "name": _bounded_text(item.get("name") or f"actor-{index + 1}", "actor name", 128),
            "worker": _bounded_text(item.get("worker"), "actor worker", 256),
            "model": _bounded_text(item.get("model"), "actor model", 256),
        }
        if item.get("role"):
            actor["role"] = _bounded_text(item.get("role"), "actor role", 64)
        if actor["name"] in names:
            raise ControlError("INVALID_INPUT", "experiment actor names must be unique")
        names.add(actor["name"])
        actors.append(actor)

    stages_raw = value.get("stages")
    if not isinstance(stages_raw, list) or not 1 <= len(stages_raw) <= 64:
        raise ControlError("INVALID_INPUT", "experiment stages must contain between 1 and 64 prompts")
    stages = [
        _bounded_text(item, f"stage {index + 1}", 12_000)
        for index, item in enumerate(stages_raw)
    ]
    try:
        duration_seconds = int(value.get("duration_seconds", 3600))
        max_turns = int(value.get("max_turns", 48))
        poll_seconds = float(value.get("poll_seconds", 1.0))
        max_turn_wait_seconds = int(value.get("max_turn_wait_seconds", 900))
        max_handoff_chars = int(value.get("max_handoff_chars", 12_000))
        max_tool_steps = int(value.get("max_tool_steps", 8))
    except (TypeError, ValueError) as exc:
        raise ControlError("INVALID_INPUT", "experiment numeric bounds are invalid") from exc
    if not 30 <= duration_seconds <= 7 * 24 * 3600:
        raise ControlError("INVALID_INPUT", "duration_seconds must be between 30 and 604800")
    if not 1 <= max_turns <= 10_000:
        raise ControlError("INVALID_INPUT", "max_turns must be between 1 and 10000")
    if not 0.25 <= poll_seconds <= 30:
        raise ControlError("INVALID_INPUT", "poll_seconds must be between 0.25 and 30")
    if not 30 <= max_turn_wait_seconds <= 3600:
        raise ControlError("INVALID_INPUT", "max_turn_wait_seconds must be between 30 and 3600")
    if not 256 <= max_handoff_chars <= 100_000:
        raise ControlError("INVALID_INPUT", "max_handoff_chars must be between 256 and 100000")
    if not 0 <= max_tool_steps <= 32:
        raise ControlError("INVALID_INPUT", "max_tool_steps must be between 0 and 32")
    initial_handoff = str(value.get("initial_handoff") or "No prior handoff is available.")
    instructions = str(value.get("instructions") or "").strip()
    residency = str(value.get("residency") or "pinned")
    if residency not in {"pinned", "request"}:
        raise ControlError("INVALID_INPUT", "experiment residency must be pinned or request")
    if len(initial_handoff) > max_handoff_chars:
        raise ControlError("INVALID_INPUT", "initial_handoff exceeds max_handoff_chars")
    if len(instructions) > 20_000 or "\x00" in instructions:
        raise ControlError("INVALID_INPUT", "experiment instructions are invalid or oversized")
    goal = _bounded_text(value.get("goal"), "goal", 20_000)
    concept_raw = value.get("concept") or {}
    if not isinstance(concept_raw, Mapping):
        raise ControlError("INVALID_INPUT", "experiment concept must be an object")
    target_profile = concept_raw.get("target_profile") or {"kind": "unspecified"}
    if not isinstance(target_profile, Mapping):
        raise ControlError("INVALID_INPUT", "experiment target_profile must be an object")
    frozen_inputs = concept_raw.get("frozen_inputs") or []
    hidden_inputs = concept_raw.get("hidden_inputs") or []
    if not isinstance(frozen_inputs, list) or not isinstance(hidden_inputs, list):
        raise ControlError("INVALID_INPUT", "experiment frozen_inputs and hidden_inputs must be lists")
    concept_seed = _identity({"goal": goal, "language_profile": concept_raw.get("language_profile")})
    concept = {
        "concept_id": _bounded_text(
            concept_raw.get("concept_id") or f"concept:{concept_seed.removeprefix('sha256:')}",
            "concept_id",
            512,
        ),
        "language_profile": _bounded_text(
            concept_raw.get("language_profile") or "unspecified", "language_profile", 1024
        ),
        "target_profile": _bounded_json(dict(target_profile), "target_profile", maximum=64_000),
        "hypothesis": _bounded_text(concept_raw.get("hypothesis") or goal, "hypothesis", 20_000),
        "task": _bounded_text(concept_raw.get("task") or goal, "task", 20_000),
        "falsifiers": _bounded_text_list(concept_raw.get("falsifiers"), "falsifiers"),
        "protected_properties": _bounded_text_list(
            concept_raw.get("protected_properties"), "protected_properties"
        ),
        "governing_contracts": _bounded_text_list(
            concept_raw.get("governing_contracts"), "governing_contracts"
        ),
        "frozen_inputs": _bounded_json(frozen_inputs, "frozen_inputs"),
        "hidden_inputs": _bounded_json(hidden_inputs, "hidden_inputs"),
    }
    return {
        "schema": EXPERIMENT_SCHEMA,
        "goal": goal,
        "concept": concept,
        "actors": actors,
        "stages": stages,
        "duration_seconds": duration_seconds,
        "max_turns": max_turns,
        "poll_seconds": poll_seconds,
        "max_turn_wait_seconds": max_turn_wait_seconds,
        "max_handoff_chars": max_handoff_chars,
        "max_tool_steps": max_tool_steps,
        "residency": residency,
        "release_models_on_end": bool(value.get("release_models_on_end", True)),
        "initial_handoff": initial_handoff,
        "instructions": instructions,
        "stop_on_turn_failure": bool(value.get("stop_on_turn_failure", True)),
        "claim_boundary": (
            "Control coordinates durable handoffs; Harness resolves exact model placement; "
            "Fabric owns detached execution and receipts. Execution success does not establish "
            "model correctness, scientific validity, independence, or Commons acceptance. "
            "Harness residency concerns worker-local weights only; Control remains authoritative "
            "for messages and experiment context."
        ),
    }


def build_concept_manifest(
    experiment_id: str,
    spec: Mapping[str, Any],
    *,
    frozen_at: str,
    rerun_of: str | None = None,
) -> dict[str, Any]:
    """Freeze Control-owned CRE intent without claiming an experimental outcome."""

    concept = spec["concept"]
    manifest: dict[str, Any] = {
        "schema": CONCEPT_MANIFEST_SCHEMA,
        "experiment_id": experiment_id,
        "family_record_id": experiment_id,
        "frozen_at": frozen_at,
        "concept_id": concept["concept_id"],
        "language_profile": concept["language_profile"],
        "target_profile": concept["target_profile"],
        "hypothesis": concept["hypothesis"],
        "task": concept["task"],
        "falsifiers": concept["falsifiers"],
        "protected_properties": concept["protected_properties"],
        "governing_contracts": concept["governing_contracts"],
        "frozen_inputs": concept["frozen_inputs"],
        "hidden_inputs": concept["hidden_inputs"],
        "actors": spec["actors"],
        "resource_budget": {
            "duration_seconds": spec["duration_seconds"],
            "max_turns": spec["max_turns"],
            "max_turn_wait_seconds": spec["max_turn_wait_seconds"],
            "max_handoff_chars": spec["max_handoff_chars"],
            "max_tool_steps": spec["max_tool_steps"],
        },
        "rerun_of": rerun_of,
        "authority_boundary": (
            "Control freezes intent and coordinates lifecycle; this manifest does not assert "
            "scientific truth, compiler correctness, execution conformance, or evaluation success."
        ),
    }
    manifest["manifest_identity"] = _identity(manifest)
    return manifest


def validate_family_reference(value: object) -> dict[str, Any]:
    """Fail closed on the producer-neutral reference fields Commons accepts."""

    if not isinstance(value, Mapping):
        raise ControlError("INVALID_INPUT", "producer reference must be an object")
    required = ("producer", "recordKind", "schemaVersion", "stableId")
    reference = {
        "schema": FAMILY_REFERENCE_SCHEMA,
        **{name: _bounded_text(value.get(name), f"reference {name}", 2048) for name in required},
    }
    if value.get("schema", FAMILY_REFERENCE_SCHEMA) != FAMILY_REFERENCE_SCHEMA:
        raise ControlError("INVALID_INPUT", "producer reference schema is unsupported")
    digest = value.get("contentDigest")
    if digest is not None:
        digest = _bounded_text(digest, "reference contentDigest", 80)
        if len(digest) != 71 or not digest.startswith("sha256:") or any(
            char not in "0123456789abcdef" for char in digest[7:]
        ):
            raise ControlError("INVALID_INPUT", "reference contentDigest must be a sha256 identity")
        reference["contentDigest"] = digest
    for field in ("artifact", "scope"):
        if value.get(field) is not None:
            if not isinstance(value[field], Mapping):
                raise ControlError("INVALID_INPUT", f"reference {field} must be an object")
            reference[field] = _bounded_json(dict(value[field]), f"reference {field}", maximum=64_000)
    return reference


class ExperimentRuntime(Protocol):
    def prepare(
        self,
        experiment_id: str,
        actors: list[Mapping[str, str]],
        prior_leases: tuple[dict[str, Any], ...] = (),
    ) -> list[dict[str, Any]]: ...
    def release(
        self,
        experiment_id: str,
        leases: list[dict[str, Any]],
    ) -> list[dict[str, Any]]: ...
    def submit(
        self,
        actor: Mapping[str, str],
        prompt: str,
        idempotency_key: str,
        *,
        messages: list[dict[str, Any]] | None = None,
    ) -> str: ...
    def status(self, work_id: str) -> str: ...
    def result(self, work_id: str) -> dict[str, Any]: ...


class HarnessFabricRuntime:
    """Host-side adapter to Harness exact-pin detached Fabric execution."""

    def __init__(self, config: ControlConfig) -> None:
        sources = (config.harness_path / "src", config.fabric_path / "src", config.commons_path / "src")
        if not sources[0].is_dir():
            raise ControlError("HARNESS_UNAVAILABLE", "Harness source checkout is unavailable")
        inserted: list[str] = []
        for source in reversed(sources):
            value = str(source)
            if source.is_dir() and value not in sys.path:
                sys.path.insert(0, value)
                inserted.append(value)
        try:
            harness_config = importlib.import_module("epi13_local_harness.config").load_config(
                config.harness_config_path
            )
            session_type = importlib.import_module(
                "epi13_local_harness.fabric_inventory_session"
            ).InventoryAwareFabricSession
            models_mod = importlib.import_module("epi13_local_harness.models")
            self._routing_override = models_mod.RoutingOverride
            self._policy_decision_type = models_mod.PolicyDecision
            self._tool_execution_type = models_mod.ToolExecution
            tools_mod = importlib.import_module("epi13_local_harness.tools")
            fabric_tools_mod = importlib.import_module("epi13_local_harness.fabric_target_tools")
            residency_mod = importlib.import_module("epi13_local_harness.residency")
            self._tool_registry_type = tools_mod.ToolRegistry
            self._fabric_tool_executor_type = fabric_tools_mod.FabricTargetToolExecutor
            self._actor_provenance_builder = importlib.import_module(
                "epi13_local_harness.actor_provenance"
            ).build_actor_provenance
            self._residency_manager_type = residency_mod.ResidencyManager
        except Exception as exc:
            raise ControlError("HARNESS_UNAVAILABLE", redact_text(str(exc))) from exc
        finally:
            for value in inserted:
                try:
                    sys.path.remove(value)
                except ValueError:
                    pass
        self._config = harness_config
        self._workspace = config.workspace_root
        self._tool_registry = None
        self._session = session_type(
            harness_config.fabric, residency_config=harness_config.model_residency
        )
        try:
            self._session.initialize(refresh_inventory=False)
        except Exception as exc:
            raise ControlError("HARNESS_UNAVAILABLE", redact_text(str(exc))) from exc

    def prepare(
        self,
        experiment_id: str,
        actors: list[Mapping[str, str]],
        prior_leases: tuple[dict[str, Any], ...] = (),
    ) -> list[dict[str, Any]]:
        assignments: list[dict[str, str]] = []
        for actor in actors:
            role = self._role_name(actor)
            assignments.append(
                {
                    "worker_id": str(actor["worker"]),
                    "model": str(actor["model"]),
                    "role": role,
                }
            )
        manager = self._residency_manager_type(self._config, self._session)
        return list(
            manager.prepare_experiment(
                experiment_id,
                assignments,
                prior_leases=prior_leases,
            )
        )

    def release(
        self,
        experiment_id: str,
        leases: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        manager = self._residency_manager_type(self._config, self._session)
        return list(manager.release_experiment(experiment_id, leases))

    def close(self) -> None:
        self._session.close()

    @property
    def release_on_experiment_end(self) -> bool:
        return bool(self._config.model_residency.release_on_experiment_end)

    def _role_name(self, actor: Mapping[str, str]) -> str:
        requested = str(actor.get("role") or "")
        if requested:
            if requested not in self._config.models:
                raise ControlError("MODEL_ROUTE_UNAVAILABLE", f"Harness role {requested} is not configured")
            return requested
        if "coder" in self._config.models:
            return "coder"
        if "e4b" in self._config.models:
            return "e4b"
        return next(iter(self._config.models))

    def _resolved(self, actor: Mapping[str, str]):
        role = self._role_name(actor)
        base = self._config.models[role]
        override = self._routing_override.from_values(
            role=str(actor["role"]) if actor.get("role") else None,
            worker=str(actor["worker"]),
            model=str(actor["model"]),
        )
        model, selection = self._session.resolve_model(
            role,
            replace(
                base,
                name=str(actor["model"]),
                keep_alive=self._config.model_residency.experiment_keep_alive,
            ),
            override,
        )
        if selection is None or not selection.available or selection.worker_id != actor["worker"]:
            reason = selection.reason if selection is not None else "exact model pin could not be resolved"
            raise ControlError("MODEL_ROUTE_UNAVAILABLE", redact_text(str(reason)))
        return role, model, selection

    def offered_tools(self, actor: Mapping[str, str]) -> list[str]:
        role = self._role_name(actor)
        return list(self._config.models[role].tools)

    def actor_reference(
        self, actor: Mapping[str, str], *, prompt: str, session_identity: str
    ) -> dict[str, Any]:
        role, _model, selection = self._resolved(actor)
        route_identity = _identity(
            {
                "role": role,
                "worker": selection.worker_id,
                "model": actor["model"],
                "provider": "ollama",
            }
        )
        native = self._actor_provenance_builder(
            role=role,
            model_identity=str(actor["model"]),
            provider_identity="ollama",
            worker_identity=str(selection.worker_id),
            route_identity=route_identity,
            tool_exposure=self.offered_tools(actor),
            policy_profile="harness-configured-policy",
            prompt_digest=_identity(prompt),
            session_identity=session_identity,
            observed_at=_iso(),
            extra={"control_actor_name": actor["name"]},
        )
        return {
            "schema": FAMILY_REFERENCE_SCHEMA,
            "producer": native["producer"],
            "recordKind": "ActorProvenance",
            "schemaVersion": native["schema_version"],
            "stableId": native["stable_id"],
            "contentDigest": native["content_digest"],
            "scope": {
                "role": role,
                "model": actor["model"],
                "provider": "ollama",
                "worker": selection.worker_id,
                "route": route_identity,
                "tools": native["tool_exposure"],
            },
        }

    def _registry(self):
        if self._tool_registry is None:
            self._tool_registry = self._tool_registry_type(
                self._workspace,
                self._config.policy,
                auto_approve=True,
                interactive=False,
            )
        return self._tool_registry

    def _tool_schemas(self, actor: Mapping[str, str]) -> list[dict[str, Any]]:
        names = tuple(self.offered_tools(actor))
        return self._registry().available_schemas(names)

    @staticmethod
    def _tool_call_parts(call: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        function = call.get("function", {})
        if not isinstance(function, Mapping):
            function = {}
        name = str(function.get("name") or call.get("name") or "")
        arguments = function.get("arguments", call.get("arguments", {}))
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        return name, arguments

    def execute_tools(self, actor: Mapping[str, str], calls: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Execute Harness model tools. File tools stay controller-workspace; run_command may go to the actor worker."""

        registry = self._registry()
        offered = set(self.offered_tools(actor))
        records: list[dict[str, Any]] = []
        for call in calls:
            name, arguments = self._tool_call_parts(call)
            if name not in offered:
                records.append(
                    {
                        "name": name or "unknown",
                        "arguments": arguments,
                        "output": f"Tool {name!r} is not authorized for this experiment actor",
                        "success": False,
                        "execution_target": "controller",
                        "allowed": False,
                        "risk": "blocked",
                        "reason": "tool not in the actor role",
                    }
                )
                continue
            execution_target = "controller"
            if name == "run_command":
                argv = arguments.get("argv")
                if isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv):
                    try:
                        executor = self._fabric_tool_executor_type(self._session, registry)
                        result = executor.execute(str(actor["worker"]), [str(item) for item in argv])
                        execution = result.execution
                        execution_target = result.target.label
                    except Exception as exc:
                        execution = self._tool_execution_type(
                            name,
                            arguments,
                            f"FABRIC_TARGET_EXECUTION_FAILED: {exc}",
                            False,
                            self._policy_decision_type(False, "blocked", redact_text(str(exc))),
                        )
                else:
                    execution = registry.execute(name, arguments)
            else:
                execution = registry.execute(name, arguments)
            decision = execution.decision
            records.append(
                {
                    "name": name,
                    "arguments": arguments,
                    "output": redact_text(str(execution.output))[:16_000],
                    "success": bool(execution.success),
                    "execution_target": execution_target,
                    "allowed": bool(decision.allowed),
                    "risk": str(decision.risk),
                    "reason": redact_text(str(decision.reason))[:1000],
                }
            )
        return records

    def submit(
        self,
        actor: Mapping[str, str],
        prompt: str,
        idempotency_key: str,
        *,
        messages: list[dict[str, Any]] | None = None,
    ) -> str:
        role, model, selection = self._resolved(actor)
        chat_messages = [dict(item) for item in messages] if messages else [{"role": "user", "content": prompt}]
        self._session.set_consumer_context(
            workload_identity=_identity({"idempotency_key": idempotency_key, "messages": chat_messages}),
            provider_identity=_identity(
                {
                    "provider": "ollama",
                    "worker": actor["worker"],
                    "model": actor["model"],
                    "role": role,
                }
            ),
            partition_identity=_identity({"worker": actor["worker"]}),
        )
        try:
            accepted = self._session.submit_chat(
                model,
                chat_messages,
                worker_id=selection.worker_id,
                idempotency_key=idempotency_key,
                tools=self._tool_schemas(actor) or None,
            )
        except Exception as exc:
            raise ControlError("FABRIC_SUBMIT_FAILED", redact_text(str(exc))) from exc
        work_id = accepted.get("work_id")
        if not isinstance(work_id, str) or not work_id:
            raise ControlError("FABRIC_SUBMIT_FAILED", "detached Fabric submission returned no work id")
        return work_id

    def status(self, work_id: str) -> str:
        try:
            payload = self._session.work_status(work_id)
        except Exception as exc:
            raise ControlError("FABRIC_STATUS_FAILED", redact_text(str(exc))) from exc
        status = payload.get("status")
        if isinstance(status, Mapping):
            value = status.get("state")
        else:
            value = payload.get("state")
        return str(value or "UNKNOWN").upper()

    def result(self, work_id: str) -> dict[str, Any]:
        try:
            return dict(self._session.work_result(work_id))
        except Exception as exc:
            raise ControlError("FABRIC_RESULT_FAILED", redact_text(str(exc))) from exc


def _assistant_message(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    response = payload.get("response")
    if not isinstance(response, Mapping):
        return None
    message = response.get("message")
    if isinstance(message, Mapping):
        return dict(message)
    if isinstance(response.get("content"), str) or response.get("tool_calls"):
        return {
            "role": "assistant",
            "content": str(response.get("content") or ""),
            "tool_calls": list(response.get("tool_calls") or []),
        }
    return None


def _response_content(payload: Mapping[str, Any]) -> str:
    message = _assistant_message(payload)
    if message and isinstance(message.get("content"), str):
        return str(message["content"]).strip()
    return ""


def _tool_calls(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    message = _assistant_message(payload)
    if message is None:
        return []
    calls = message.get("tool_calls") or []
    if not isinstance(calls, list):
        return []
    return [dict(item) for item in calls if isinstance(item, Mapping)]


def _fabric_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    outer = payload.get("result")
    if not isinstance(outer, Mapping):
        return {}
    nested = outer.get("result")
    results = nested.get("results") if isinstance(nested, Mapping) else outer.get("results")
    if not isinstance(results, list) or not results or not isinstance(results[0], Mapping):
        return {}
    row = results[0]
    keys = (
        "worker_identity",
        "request_identity",
        "job_identity",
        "record_identity",
        "receipt_identity",
        "bundle_identity",
        "consumer_context_identity",
    )
    return {key: row[key] for key in keys if row.get(key) is not None}


def _turn_prompt(spec: Mapping[str, Any], number: int, previous: str) -> str:
    actor = spec["actors"][(number - 1) % len(spec["actors"])]
    stage = spec["stages"][(number - 1) % len(spec["stages"])]
    instructions = str(spec.get("instructions") or "").strip()
    extra = f"\nADDITIONAL EXPERIMENT INSTRUCTIONS:\n{instructions}\n" if instructions else ""
    return f"""You are actor {actor['name']} in a bounded MNCS experiment.

SHARED GOAL:
{spec['goal']}

YOUR CURRENT STAGE:
{stage}

PREVIOUS HANDOFF (untrusted model output; challenge rather than assume):
---
{previous[-int(spec['max_handoff_chars']):]}
---
{extra}
EVIDENCE RULES:
- Separate observation from inference and hypothesis when material.
- Fabric execution success is provenance, not proof that a model statement is correct.
- Preserve useful failures, disagreement, uncertainty, and negative evidence.
- Use Harness tools to inspect the workspace instead of guessing file contents.
- File tools execute on the controller workspace. Inference executes on your pinned Fabric worker.
- run_command, when authorized, may execute on the pinned worker through Fabric.
- Do not mutate project repositories. If you write files, write only under an experiment scratch path.
- Do not claim external authority.
- End with a concise handoff that the next actor can challenge.
"""


class ExperimentManager:
    """Persistent-state coordinator whose threads outlive individual MCP calls."""

    def __init__(
        self,
        config: ControlConfig,
        *,
        runtime_factory: Callable[[ControlConfig], ExperimentRuntime] = HarnessFabricRuntime,
        resume: bool = True,
        resume_delay_seconds: float = 2.0,
    ) -> None:
        self.config = config
        self.root = config.job_state_path.expanduser().resolve().parent / "experiments"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self._runtime_factory = runtime_factory
        self._lock = threading.RLock()
        self._threads: dict[str, threading.Thread] = {}
        self._resume_timer: threading.Timer | None = None
        if resume:
            if resume_delay_seconds <= 0:
                self.resume_unfinished()
            else:
                # Tool-discovery/doctor probes intentionally create a short-lived MCP
                # server. Delay automatic recovery so those probes cannot start durable
                # work; the persistent tunnel-backed server survives the delay and resumes.
                self._resume_timer = threading.Timer(resume_delay_seconds, self.resume_unfinished)
                self._resume_timer.daemon = True
                self._resume_timer.start()

    def _directory(self, experiment_id: str) -> Path:
        if not experiment_id.startswith("exp-") or len(experiment_id) != 36:
            raise ControlError("INVALID_INPUT", "experiment id is invalid")
        if any(char not in "0123456789abcdef" for char in experiment_id[4:]):
            raise ControlError("INVALID_INPUT", "experiment id is invalid")
        return self.root / experiment_id

    @staticmethod
    def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
        temporary = path.with_name(path.name + ".tmp")
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _load(self, experiment_id: str) -> dict[str, Any]:
        path = self._directory(experiment_id) / "state.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ControlError("EXPERIMENT_NOT_FOUND", "experiment state was not found") from exc
        except json.JSONDecodeError as exc:
            raise ControlError("EXPERIMENT_STATE_INVALID", "experiment state is invalid JSON") from exc
        if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
            raise ControlError("EXPERIMENT_STATE_INVALID", "experiment state schema is invalid")
        manifest = value.get("concept_manifest")
        if manifest is not None:
            if not isinstance(manifest, dict) or manifest.get("schema") != CONCEPT_MANIFEST_SCHEMA:
                raise ControlError("EXPERIMENT_STATE_INVALID", "concept manifest schema is invalid")
            material = {key: item for key, item in manifest.items() if key != "manifest_identity"}
            if manifest.get("manifest_identity") != _identity(material):
                raise ControlError("EXPERIMENT_STATE_INVALID", "frozen concept manifest identity is invalid")
        return value

    def _save(self, state: dict[str, Any]) -> None:
        experiment_id = str(state["experiment_id"])
        directory = self._directory(experiment_id)
        lock_path = directory / "state.lock"
        lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(lock_path, 0o600)
        with lock_path.open("r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            existing_path = directory / "state.json"
            if existing_path.exists():
                try:
                    existing = json.loads(existing_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    existing = None
                if isinstance(existing, dict) and existing.get("stop_requested"):
                    state["stop_requested"] = True
                    if existing.get("stop_requested_at"):
                        state["stop_requested_at"] = existing["stop_requested_at"]
                if isinstance(existing, dict):
                    retained: dict[tuple[str, str], dict[str, Any]] = {}
                    for item in [
                        *(state.get("producer_references") or []),
                        *(existing.get("producer_references") or []),
                    ]:
                        if isinstance(item, dict) and isinstance(item.get("reference"), dict):
                            key = (str(item.get("relation")), str(item["reference"].get("stableId")))
                            retained[key] = item
                    state["producer_references"] = [retained[key] for key in sorted(retained)]
                    if existing.get("publication") is not None:
                        state["publication"] = existing["publication"]
                    for field in ("family_record_id", "concept_manifest"):
                        if existing.get(field) is not None:
                            state[field] = existing[field]
            state["updated_at"] = _iso()
            self._atomic_json(existing_path, state)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _mutate(self, experiment_id: str, update: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        """Serialize API mutations with coordinator saves and preserve their exact state."""

        directory = self._directory(experiment_id)
        lock_path = directory / "state.lock"
        lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(lock_path, 0o600)
        with lock_path.open("r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            state = self._load(experiment_id)
            update(state)
            state["updated_at"] = _iso()
            self._atomic_json(directory / "state.json", state)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return state

    def _active_residency_leases(
        self,
        *,
        exclude_experiment_id: str,
    ) -> list[dict[str, Any]]:
        leases: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("exp-*/state.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (
                not isinstance(value, dict)
                or value.get("experiment_id") == exclude_experiment_id
                or value.get("state") in _TERMINAL
            ):
                continue
            residency = value.get("residency")
            if not isinstance(residency, Mapping):
                continue
            for item in residency.get("leases") or []:
                if isinstance(item, Mapping) and item.get("outcome") == "PASS":
                    leases.append(dict(item))
        return leases

    def _prepare_residency(
        self,
        runtime: ExperimentRuntime,
        state: dict[str, Any],
    ) -> bool:
        spec = state["spec"]
        if spec.get("residency") != "pinned":
            state["residency"] = {
                "status": "REQUEST_LIFETIME",
                "policy_mode": "request",
                "leases": [],
                "detail": "per-request provider keep-alive remains in effect",
            }
            self._save(state)
            return True
        current = state.get("residency")
        if isinstance(current, Mapping) and current.get("status") == "PREPARED":
            prior_leases = tuple(
                dict(item) for item in current.get("leases") or [] if isinstance(item, Mapping)
            )
        else:
            prior_leases = ()
        lock_path = self.root / "residency.lock"
        lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(lock_path, 0o600)
        with lock_path.open("r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            active = self._active_residency_leases(
                exclude_experiment_id=str(state["experiment_id"])
            )
            prepare = getattr(runtime, "prepare", None)
            if not callable(prepare):
                leases = [{
                    "outcome": "FAIL",
                    "code": "RESIDENCY_RUNTIME_UNSUPPORTED",
                    "detail": "runtime does not expose experiment residency preparation",
                }]
            else:
                try:
                    leases = list(
                        prepare(
                            str(state["experiment_id"]),
                            list(spec["actors"]),
                            prior_leases,
                        )
                    )
                except Exception as exc:
                    leases = [{
                        "outcome": "FAIL",
                        "code": "RESIDENCY_PREPARE_FAILED",
                        "detail": redact_text(str(exc))[:4000],
                    }]
            active_managed = {
                (str(item.get("worker_id")), str(item.get("model")))
                for item in active
                if item.get("managed")
            }
            for lease in leases:
                key = (str(lease.get("worker_id")), str(lease.get("model")))
                if lease.get("outcome") == "PASS" and key in active_managed:
                    lease["managed"] = True
                    lease["shared_with_active_experiment"] = True
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        success = bool(leases) and all(item.get("outcome") == "PASS" for item in leases)
        state["residency"] = {
            "status": "PREPARED" if success else "FAILED",
            "policy_mode": "experiment-pinned",
            "prepared_at": _iso(),
            "leases": leases,
            "conversation_state_authority": "mncs-control-mcp",
            "weights_state_authority": "worker-local-provider-observation",
        }
        self._save(state)
        return success

    @staticmethod
    def _needs_residency_teardown(state: Mapping[str, Any]) -> bool:
        residency = state.get("residency")
        if not isinstance(residency, Mapping):
            return False
        if residency.get("policy_mode") != "experiment-pinned":
            return False
        teardown = residency.get("teardown")
        return not (
            isinstance(teardown, Mapping)
            and teardown.get("status") in {"RELEASED", "RETAINED"}
        )

    def _record_teardown_failure(
        self,
        state: dict[str, Any],
        exc: Exception,
    ) -> None:
        residency = state.get("residency")
        if not isinstance(residency, Mapping):
            return
        state["residency"] = {
            **dict(residency),
            "teardown": {
                "status": "DEGRADED",
                "completed_at": _iso(),
                "results": [{
                    "outcome": "UNKNOWN",
                    "code": "RESIDENCY_TEARDOWN_FAILED",
                    "released": False,
                    "detail": redact_text(str(exc))[:4000],
                }],
            },
        }
        self._save(state)

    def _attempt_terminal_teardown(self, experiment_id: str) -> None:
        state = self._load(experiment_id)
        if state.get("state") not in _TERMINAL or not self._needs_residency_teardown(state):
            return
        runtime = self._runtime_factory(self.config)
        try:
            try:
                self._teardown_residency(runtime, state)
            except Exception as exc:
                self._record_teardown_failure(state, exc)
        finally:
            close = getattr(runtime, "close", None)
            if callable(close):
                close()

    def _teardown_residency(
        self,
        runtime: ExperimentRuntime,
        state: dict[str, Any],
    ) -> None:
        residency = state.get("residency")
        if not isinstance(residency, Mapping) or residency.get("policy_mode") != "experiment-pinned":
            return
        teardown = residency.get("teardown")
        if isinstance(teardown, Mapping) and teardown.get("status") in {"RELEASED", "RETAINED"}:
            return
        leases = [
            dict(item) for item in residency.get("leases") or []
            if isinstance(item, Mapping) and item.get("outcome") == "PASS"
        ]
        runtime_release_policy = getattr(runtime, "release_on_experiment_end", True)
        if callable(runtime_release_policy):
            runtime_release_policy = runtime_release_policy()
        retain_reason = None
        if not state["spec"].get("release_models_on_end", True):
            retain_reason = "experiment policy requested retained residency"
        elif runtime_release_policy is False:
            retain_reason = "Harness policy disabled automatic experiment teardown release"
        if retain_reason is not None:
            state["residency"] = {
                **dict(residency),
                "teardown": {
                    "status": "RETAINED",
                    "completed_at": _iso(),
                    "detail": retain_reason,
                },
            }
            self._save(state)
            return
        lock_path = self.root / "residency.lock"
        lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(lock_path, 0o600)
        with lock_path.open("r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            active = self._active_residency_leases(
                exclude_experiment_id=str(state["experiment_id"])
            )
            active_keys = {
                (str(item.get("worker_id")), str(item.get("model"))) for item in active
            }
            releasable: list[dict[str, Any]] = []
            results: list[dict[str, Any]] = []
            for lease in leases:
                key = (str(lease.get("worker_id")), str(lease.get("model")))
                if key in active_keys:
                    results.append({
                        "outcome": "PASS",
                        "code": "RESIDENCY_RETAINED_SHARED",
                        "worker_id": key[0],
                        "model": key[1],
                        "released": False,
                        "detail": "another active experiment still references this residency",
                    })
                else:
                    releasable.append(lease)
            release = getattr(runtime, "release", None)
            if releasable and callable(release):
                results.extend(release(str(state["experiment_id"]), releasable))
            elif releasable:
                results.extend({
                    "outcome": "UNKNOWN",
                    "code": "RESIDENCY_RELEASE_UNSUPPORTED",
                    "worker_id": item.get("worker_id"),
                    "model": item.get("model"),
                    "released": False,
                } for item in releasable)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        complete = all(item.get("outcome") == "PASS" for item in results)
        state["residency"] = {
            **dict(residency),
            "teardown": {
                "status": "RELEASED" if complete else "DEGRADED",
                "completed_at": _iso(),
                "results": results,
            },
        }
        self._save(state)

    def start(self, raw_spec: object, *, rerun_of: str | None = None) -> dict[str, Any]:
        spec = validate_spec(raw_spec)
        if rerun_of is not None:
            self._load(rerun_of)
        experiment_id = "exp-" + uuid.uuid4().hex
        directory = self._directory(experiment_id)
        directory.mkdir(mode=0o700)
        accepted = _now()
        state: dict[str, Any] = {
            "schema": STATE_SCHEMA,
            "experiment_id": experiment_id,
            "state": "ACCEPTED",
            "accepted_at": _iso(accepted),
            "deadline_at": _iso(accepted + timedelta(seconds=int(spec["duration_seconds"]))),
            "spec": spec,
            "spec_identity": _identity(spec),
            "family_record_id": experiment_id,
            "concept_manifest": build_concept_manifest(
                experiment_id, spec, frozen_at=_iso(accepted), rerun_of=rerun_of
            ),
            "producer_references": [],
            "publication": {"state": "NOT_PUBLISHED", "attempts": 0},
            "turns": [],
            "stop_requested": False,
            "authority": {
                "coordinator": "mncs-control-mcp",
                "routing": "mncs-harness",
                "execution": "persistent-fabric-detached",
                "model_residency": "mncs-harness-over-fabric-provider-observation",
                "conversation_state": "mncs-control-mcp",
                "commons": "none",
            },
        }
        self._save(state)
        self._spawn(experiment_id)
        return self.status(experiment_id)

    def attach_reference(
        self, experiment_id: str, relation: str, raw_reference: object
    ) -> dict[str, Any]:
        if relation not in _REFERENCE_RELATIONS:
            raise ControlError("INVALID_INPUT", "producer reference relation is unsupported")
        reference = validate_family_reference(raw_reference)

        def update(state: dict[str, Any]) -> None:
            entries = list(state.get("producer_references") or [])
            for entry in entries:
                existing = entry.get("reference") if isinstance(entry, Mapping) else None
                if not isinstance(existing, Mapping) or existing.get("stableId") != reference["stableId"]:
                    continue
                if existing.get("contentDigest") != reference.get("contentDigest"):
                    raise ControlError(
                        "REFERENCE_CONFLICT",
                        "a stable producer identity cannot be rebound to another content digest",
                    )
                if entry.get("relation") == relation:
                    return
            entries.append({"relation": relation, "reference": reference, "attached_at": _iso()})
            entries.sort(
                key=lambda item: (str(item["relation"]), str(item["reference"]["stableId"]))
            )
            state["producer_references"] = entries
            publication = state.get("publication", {})
            if publication.get("state") == "PUBLISHED":
                publication["state"] = "SYNC_REQUIRED"
            elif publication.get("state") == "PUBLISHING":
                publication["sync_requested"] = True

        self._mutate(experiment_id, update)
        return self.status(experiment_id)

    def rerun(self, experiment_id: str) -> dict[str, Any]:
        predecessor = self._load(experiment_id)
        return self.start(predecessor["spec"], rerun_of=experiment_id)

    @staticmethod
    def _control_actor_reference(experiment_id: str, actor: Mapping[str, Any]) -> dict[str, Any]:
        digest = _identity({"experiment_id": experiment_id, "actor": dict(actor)})
        return {
            "schema": FAMILY_REFERENCE_SCHEMA,
            "producer": "mncs-control-mcp",
            "recordKind": "ExperimentActorAssignment",
            "schemaVersion": EXPERIMENT_SCHEMA,
            "stableId": f"{experiment_id}:actor:{actor['name']}",
            "contentDigest": digest,
            "scope": {
                "role": actor.get("role") or actor["name"],
                "model": actor["model"],
                "worker": actor["worker"],
            },
        }

    def _family_record(self, state: Mapping[str, Any]) -> dict[str, Any]:
        from .adapters import CommonsAdapter

        manifest = state["concept_manifest"]
        entries = [
            {"relation": item["relation"], "reference": item["reference"]}
            for item in state.get("producer_references") or []
        ]
        for contract in manifest["governing_contracts"]:
            entries.append(
                {
                    "relation": "governed_by",
                    "reference": {
                        "schema": FAMILY_REFERENCE_SCHEMA,
                        "producer": "mncs-control-mcp",
                        "recordKind": "GoverningContractReference",
                        "schemaVersion": CONCEPT_MANIFEST_SCHEMA,
                        "stableId": contract,
                        "contentDigest": _identity({"contract": contract}),
                    },
                }
            )
        actor_entries = [
            item
            for item in entries
            if item["relation"] == "actor" and isinstance(item["reference"], Mapping)
        ]
        actors: list[dict[str, Any]] = []
        for actor in manifest["actors"]:
            role = actor.get("role") or actor["name"]
            matched = next(
                (
                    item["reference"]
                    for item in actor_entries
                    if (item["reference"].get("scope") or {}).get("role") in {role, actor["name"]}
                ),
                None,
            )
            actors.append(
                {
                    "role": role,
                    "model": actor["model"],
                    "worker": actor["worker"],
                    "reference": matched
                    or self._control_actor_reference(str(state["experiment_id"]), actor),
                }
            )
        publication = state.get("publication") or {}
        revision = int(publication.get("revision") or 0) + 1
        status = {"COMPLETED": "TERMINAL", "FAILED": "FAILED", "STOPPED": "STOPPED"}.get(
            str(state.get("state")), "UNKNOWN"
        )
        commons = CommonsAdapter(self.config)._module()
        return commons.make_concept_experiment_record(
            experiment_id=state["family_record_id"],
            concept_id=manifest["concept_id"],
            created_at=state["accepted_at"],
            language_profile=manifest["language_profile"],
            target_profile=manifest["target_profile"],
            hypothesis=manifest["hypothesis"],
            task=manifest["task"],
            falsifiers=manifest["falsifiers"],
            protected_properties=manifest["protected_properties"],
            frozen_inputs=manifest["frozen_inputs"],
            hidden_inputs=manifest["hidden_inputs"],
            resource_budget=manifest["resource_budget"],
            actors=actors,
            references=entries,
            status=status,
            rerun_of=manifest.get("rerun_of"),
            predecessor=manifest.get("rerun_of"),
            revision=revision,
            previous_digest=publication.get("content_digest"),
        )

    def publish(self, experiment_id: str) -> dict[str, Any]:
        from .adapters import CommonsAdapter

        state = self._load(experiment_id)
        if state.get("state") not in _TERMINAL:
            raise ControlError("EXPERIMENT_NOT_TERMINAL", "only terminal experiments can be published")
        publication = dict(state.get("publication") or {})
        if publication.get("state") == "PUBLISHED":
            return {"experiment": self.status(experiment_id), "publication": publication}
        record = self._family_record(state)
        record_identity = _identity(record)
        publication.update(
            state="PUBLISHING",
            attempts=int(publication.get("attempts") or 0) + 1,
            last_attempt_at=_iso(),
            record_identity=record_identity,
        )
        self._mutate(experiment_id, lambda latest: latest.update(publication=publication))
        try:
            receipt = CommonsAdapter(self.config).publish_record(record)
        except ControlError as exc:
            error_code = exc.code
            error_detail = exc.message

            def retain_error(latest: dict[str, Any]) -> None:
                latest["publication"].update(
                    state="RETRY_PENDING",
                    last_error={
                        "code": error_code,
                        "detail": error_detail,
                        "observed_at": _iso(),
                    },
                )

            self._mutate(experiment_id, retain_error)
            raise
        def retain_receipt(latest: dict[str, Any]) -> None:
            needs_sync = bool(latest["publication"].pop("sync_requested", False))
            latest["publication"].update(
                state="SYNC_REQUIRED" if needs_sync else "PUBLISHED",
                revision=int(record["metadata"]["revision"]),
                content_digest=receipt.get("contentDigest"),
                delivery_status=receipt.get("deliveryStatus"),
                published_at=_iso(),
                receipt=receipt,
            )
            latest["publication"].pop("last_error", None)

        latest = self._mutate(experiment_id, retain_receipt)
        return {"experiment": self.status(experiment_id), "publication": latest["publication"]}

    def _spawn(self, experiment_id: str) -> None:
        with self._lock:
            current = self._threads.get(experiment_id)
            if current is not None and current.is_alive():
                return
            thread = threading.Thread(
                target=self._thread_main,
                args=(experiment_id,),
                daemon=True,
                name=f"mncs-experiment-{experiment_id[4:16]}",
            )
            self._threads[experiment_id] = thread
            thread.start()

    def resume_unfinished(self) -> None:
        for path in sorted(self.root.glob("exp-*/state.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
                continue
            should_resume = value.get("state") not in _TERMINAL
            should_teardown = (
                value.get("state") in _TERMINAL
                and self._needs_residency_teardown(value)
            )
            experiment_id = value.get("experiment_id")
            if (should_resume or should_teardown) and isinstance(experiment_id, str):
                self._spawn(experiment_id)

    def _thread_main(self, experiment_id: str) -> None:
        directory = self._directory(experiment_id)
        lock_path = directory / "coordinator.lock"
        lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(lock_path, 0o600)
        with lock_path.open("r+b") as coordinator_lock:
            try:
                fcntl.flock(coordinator_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # Another Control process already owns recovery for this experiment.
                return
            consecutive_crashes = 0
            while True:
                try:
                    state = self._load(experiment_id)
                    if state.get("state") in _TERMINAL:
                        self._attempt_terminal_teardown(experiment_id)
                        return
                    self._run(experiment_id)
                    return
                except Exception as exc:  # retry unexpected coordinator/runtime loss
                    consecutive_crashes += 1
                    try:
                        state = self._load(experiment_id)
                        state["last_coordinator_error"] = {
                            "observed_at": _iso(),
                            "type": type(exc).__name__,
                            "detail": redact_text(str(exc))[:4000],
                            "consecutive_count": consecutive_crashes,
                        }
                        self._save(state)
                        if _now() >= _parse_time(str(state["deadline_at"])):
                            state.update(
                                state="FAILED",
                                completed_at=_iso(),
                                reason="coordinator could not recover before experiment deadline",
                            )
                            self._save(state)
                            return
                    except Exception:
                        return
                    time.sleep(min(30.0, 2.0**min(consecutive_crashes, 4)))

    def _previous(self, state: Mapping[str, Any]) -> str:
        completed = [turn for turn in state.get("turns", []) if turn.get("state") == "COMPLETED"]
        if not completed:
            return str(state["spec"]["initial_handoff"])
        output_file = completed[-1].get("output_file")
        if not isinstance(output_file, str):
            return "Prior handoff metadata is incomplete; preserve this as negative evidence."
        try:
            return (self._directory(str(state["experiment_id"])) / output_file).read_text(encoding="utf-8")
        except OSError:
            return "Prior handoff artifact is unavailable; preserve this as negative evidence."

    def _current(self, state: Mapping[str, Any]) -> dict[str, Any] | None:
        turns = state.get("turns") or []
        if not turns:
            return None
        current = turns[-1]
        return current if current.get("state") in {"PREPARING", "SUBMITTED", "RUNNING"} else None

    def _new_turn(self, state: Mapping[str, Any]) -> dict[str, Any]:
        number = len(state.get("turns") or []) + 1
        spec = state["spec"]
        return {
            "schema": TURN_SCHEMA,
            "turn": number,
            "actor": dict(spec["actors"][(number - 1) % len(spec["actors"])]),
            "stage_index": (number - 1) % len(spec["stages"]),
            "state": "PREPARING",
            "observed_at": _iso(),
        }

    def _submit(
        self,
        runtime: ExperimentRuntime,
        state: dict[str, Any],
        turn: dict[str, Any],
        *,
        messages: list[dict[str, Any]] | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        prompt = _turn_prompt(state["spec"], int(turn["turn"]), self._previous(state))
        chat_messages = messages or list(turn.get("messages") or [{"role": "user", "content": prompt}])
        key = idempotency_key or f"{state['experiment_id']}:turn:{turn['turn']}"
        offered = getattr(runtime, "offered_tools", None)
        if callable(offered) and "tools_offered" not in turn:
            try:
                turn["tools_offered"] = list(offered(turn["actor"]))
            except Exception:
                turn["tools_offered"] = []
        actor_reference = getattr(runtime, "actor_reference", None)
        if callable(actor_reference) and "actor_reference" not in turn:
            reference = validate_family_reference(
                actor_reference(turn["actor"], prompt=prompt, session_identity=key)
            )
            turn["actor_reference"] = reference
            known = {
                item["reference"]["stableId"]
                for item in state.get("producer_references") or []
                if isinstance(item, Mapping) and isinstance(item.get("reference"), Mapping)
            }
            if reference["stableId"] not in known:
                state.setdefault("producer_references", []).append(
                    {"relation": "actor", "reference": reference, "attached_at": _iso()}
                )
        work_id = runtime.submit(turn["actor"], prompt, key, messages=chat_messages)
        turn.update(
            state="SUBMITTED",
            submitted_at=_iso(),
            work_id=work_id,
            idempotency_key=key,
            prompt_identity=_identity(prompt),
            messages=chat_messages,
        )
        self._save(state)

    def _maybe_tool_followup(
        self,
        runtime: ExperimentRuntime,
        state: dict[str, Any],
        turn: dict[str, Any],
        payload: Mapping[str, Any],
    ) -> bool:
        execute = getattr(runtime, "execute_tools", None)
        if not callable(execute):
            return False
        calls = _tool_calls(payload)
        if not calls:
            return False
        maximum = int(state["spec"].get("max_tool_steps", 8))
        step = int(turn.get("tool_step") or 0)
        if step >= maximum:
            turn["tool_step_limit_reached"] = True
            return False
        executions = execute(turn["actor"], calls)
        turn.setdefault("tool_executions", []).extend(executions)
        turn["tool_step"] = step + 1
        assistant = _assistant_message(payload) or {
            "role": "assistant",
            "content": _response_content(payload),
            "tool_calls": calls,
        }
        messages = list(turn.get("messages") or [])
        messages.append(assistant)
        for item in executions:
            messages.append(
                {
                    "role": "tool",
                    "tool_name": item.get("name"),
                    "content": str(item.get("output") or ""),
                }
            )
        turn.setdefault("inference_work", []).append(
            {
                "work_id": turn.get("work_id"),
                "fabric_evidence": _fabric_evidence(payload),
                "tool_calls": [item.get("name") for item in executions],
            }
        )
        self._submit(
            runtime,
            state,
            turn,
            messages=messages,
            idempotency_key=f"{state['experiment_id']}:turn:{turn['turn']}:tool:{step + 1}",
        )
        return True

    def _complete(self, state: dict[str, Any], turn: dict[str, Any], payload: Mapping[str, Any]) -> None:
        content = _response_content(payload)
        if not content:
            executions = turn.get("tool_executions") or []
            if executions:
                names = [str(item.get("name") or "unknown") for item in executions if isinstance(item, Mapping)]
                bound = "tool-step bound reached" if turn.get("tool_step_limit_reached") else "no final model text after tools"
                content = (
                    f"Turn ended with {bound}. {len(executions)} Harness tool execution(s) are retained "
                    f"as evidence ({', '.join(names[:16])}). This is not a successful semantic claim."
                )
            else:
                raise ControlError("FABRIC_RESULT_INVALID", "completed Fabric turn returned no model content")
        directory = self._directory(str(state["experiment_id"]))
        turns_dir = directory / "turns"
        turns_dir.mkdir(parents=True, exist_ok=True)
        output = turns_dir / f"turn-{int(turn['turn']):04d}-{turn['actor']['name']}.md"
        output.write_text(content + "\n", encoding="utf-8")
        fabric_evidence = _fabric_evidence(payload)
        turn.update(
            state="COMPLETED",
            completed_at=_iso(),
            output_file=str(output.relative_to(directory)),
            output_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            inference_stages=list(payload.get("inference_stages") or []),
            fabric_evidence=fabric_evidence,
        )
        stable_id = fabric_evidence.get("record_identity") or fabric_evidence.get("receipt_identity")
        if isinstance(stable_id, str) and stable_id:
            reference: dict[str, Any] = {
                "schema": FAMILY_REFERENCE_SCHEMA,
                "producer": "mncs-fabric",
                "recordKind": "ExecutionObservation",
                "schemaVersion": "mncs-fabric.execution-observation.v0.1",
                "stableId": stable_id,
                "scope": {
                    "worker": fabric_evidence.get("worker_identity"),
                    "request": fabric_evidence.get("request_identity"),
                    "job": fabric_evidence.get("job_identity"),
                    "receipt": fabric_evidence.get("receipt_identity"),
                    "bundle": fabric_evidence.get("bundle_identity"),
                },
            }
            if stable_id.startswith("sha256:") and len(stable_id) == 71:
                reference["contentDigest"] = stable_id
            known = {
                item["reference"]["stableId"]
                for item in state.get("producer_references") or []
                if isinstance(item, Mapping) and isinstance(item.get("reference"), Mapping)
            }
            if stable_id not in known:
                state.setdefault("producer_references", []).append(
                    {"relation": "execution", "reference": reference, "attached_at": _iso()}
                )
        self._save(state)

    def _fail_turn(self, state: dict[str, Any], turn: dict[str, Any], reason: str) -> None:
        turn.update(state="FAILED", failed_at=_iso(), reason=redact_text(str(reason))[:4000])
        self._save(state)

    def _poll(self, runtime: ExperimentRuntime, state: dict[str, Any], turn: dict[str, Any]) -> bool:
        submitted_at = _parse_time(str(turn.get("submitted_at") or _iso()))
        maximum = int(state["spec"]["max_turn_wait_seconds"])
        poll_seconds = float(state["spec"]["poll_seconds"])
        while True:
            latest = self._load(str(state["experiment_id"]))
            if latest.get("stop_requested"):
                latest.update(
                    state="STOPPED",
                    completed_at=_iso(),
                    reason="operator stopped coordinator; detached Fabric work may continue independently",
                    detached_work_id=turn.get("work_id"),
                )
                self._save(latest)
                return False
            try:
                fabric_state = runtime.status(str(turn["work_id"]))
                turn.pop("last_poll_error", None)
            except ControlError as exc:
                turn["last_poll_error"] = {"observed_at": _iso(), "code": exc.code, "detail": exc.message}
                self._save(state)
                if (_now() - submitted_at).total_seconds() >= maximum:
                    self._fail_turn(state, turn, f"Fabric status remained unavailable for {maximum} seconds")
                    return False
                time.sleep(poll_seconds)
                continue
            turn["fabric_state"] = fabric_state
            if fabric_state == "COMPLETED":
                payload = runtime.result(str(turn["work_id"]))
                if self._maybe_tool_followup(runtime, state, turn, payload):
                    submitted_at = _parse_time(str(turn.get("submitted_at") or _iso()))
                    continue
                self._complete(state, turn, payload)
                return True
            if fabric_state in {"FAILED", "CANCELLED", "TIMED_OUT"}:
                payload = runtime.result(str(turn["work_id"]))
                reason = payload.get("reason") or payload.get("error") or f"Fabric work {fabric_state}"
                self._fail_turn(state, turn, str(reason))
                return False
            if fabric_state not in _ACTIVE_FABRIC:
                turn["last_unknown_fabric_state"] = fabric_state
            turn["state"] = "RUNNING"
            self._save(state)
            if (_now() - submitted_at).total_seconds() >= maximum:
                self._fail_turn(
                    state,
                    turn,
                    f"turn exceeded max_turn_wait_seconds={maximum}; Fabric work may still complete later",
                )
                return False
            time.sleep(poll_seconds)

    def _run(self, experiment_id: str) -> None:
        runtime = self._runtime_factory(self.config)
        try:
            state = self._load(experiment_id)
            if not self._prepare_residency(runtime, state):
                state = self._load(experiment_id)
                state.update(
                    state="FAILED",
                    completed_at=_iso(),
                    reason="experiment model residency could not be established",
                )
                self._save(state)
                return
            self._run_active(experiment_id, runtime)
        finally:
            try:
                latest = self._load(experiment_id)
                if latest.get("state") in _TERMINAL:
                    try:
                        self._teardown_residency(runtime, latest)
                    except Exception as exc:
                        self._record_teardown_failure(latest, exc)
            finally:
                close = getattr(runtime, "close", None)
                if callable(close):
                    close()

    def _run_active(self, experiment_id: str, runtime: ExperimentRuntime) -> None:
        state = self._load(experiment_id)
        state["state"] = "RUNNING"
        state.setdefault("started_at", _iso())
        state["coordinator_instance"] = f"pid:{os.getpid()}"
        self._save(state)
        deadline = _parse_time(str(state["deadline_at"]))
        while True:
            state = self._load(experiment_id)
            if state.get("stop_requested"):
                state.update(state="STOPPED", completed_at=_iso(), reason="operator stopped coordinator")
                self._save(state)
                return
            current = self._current(state)
            if current is not None:
                if current["state"] == "PREPARING":
                    try:
                        self._submit(runtime, state, current)
                    except ControlError as exc:
                        self._fail_turn(state, current, f"{exc.code}: {exc.message}")
                        if state["spec"]["stop_on_turn_failure"]:
                            state.update(
                                state="FAILED",
                                completed_at=_iso(),
                                reason="turn submission failure stopped the experiment",
                            )
                            self._save(state)
                            return
                        continue
                ok = self._poll(runtime, state, current)
                if not ok:
                    refreshed = self._load(experiment_id)
                    if refreshed.get("state") == "STOPPED":
                        return
                    if refreshed["spec"]["stop_on_turn_failure"]:
                        refreshed.update(
                            state="FAILED",
                            completed_at=_iso(),
                            reason="turn failure stopped the experiment",
                        )
                        self._save(refreshed)
                        return
                continue

            if len(state["turns"]) >= int(state["spec"]["max_turns"]) or _now() >= deadline:
                state.update(
                    state="COMPLETED",
                    completed_at=_iso(),
                    turn_count=len(state["turns"]),
                    successful_turns=sum(
                        1 for turn in state["turns"] if turn.get("state") == "COMPLETED"
                    ),
                )
                self._save(state)
                return
            state["turns"].append(self._new_turn(state))
            self._save(state)

    def status(self, experiment_id: str) -> dict[str, Any]:
        state = self._load(experiment_id)
        turns = list(state.get("turns") or [])
        with self._lock:
            thread = self._threads.get(experiment_id)
            coordinator_live = bool(thread and thread.is_alive())
        coordinator_external = False
        if not coordinator_live and state.get("state") not in _TERMINAL:
            lock_path = self._directory(experiment_id) / "coordinator.lock"
            if lock_path.exists():
                with lock_path.open("r+b") as stream:
                    try:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        coordinator_external = True
                    else:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        effective = str(state.get("state") or "UNKNOWN")
        residency = state.get("residency")
        teardown = residency.get("teardown") if isinstance(residency, Mapping) else None
        teardown_status = teardown.get("status") if isinstance(teardown, Mapping) else None
        finalization_pending = (
            effective in _TERMINAL
            and self._needs_residency_teardown(state)
            and teardown_status != "DEGRADED"
        )
        if finalization_pending:
            effective = "FINALIZING" if coordinator_live else "RECOVERY_PENDING"
        elif effective not in _TERMINAL and not coordinator_live:
            effective = "RUNNING_EXTERNAL" if coordinator_external else "RECOVERY_PENDING"
        return {
            "schema": STATE_SCHEMA,
            "experiment_id": experiment_id,
            "state": effective,
            "recorded_state": state.get("state"),
            "accepted_at": state.get("accepted_at"),
            "started_at": state.get("started_at"),
            "deadline_at": state.get("deadline_at"),
            "completed_at": state.get("completed_at"),
            "turn_count": len(turns),
            "successful_turns": sum(1 for turn in turns if turn.get("state") == "COMPLETED"),
            "failed_turns": sum(1 for turn in turns if turn.get("state") == "FAILED"),
            "current_turn": turns[-1] if turns and turns[-1].get("state") in {"PREPARING", "SUBMITTED", "RUNNING"} else None,
            "coordinator_live": coordinator_live,
            "coordinator_external": coordinator_external,
            "last_coordinator_error": state.get("last_coordinator_error"),
            "spec_identity": state.get("spec_identity"),
            "claim_boundary": state.get("spec", {}).get("claim_boundary"),
            "authority": state.get("authority"),
            "family_record_id": state.get("family_record_id"),
            "concept_manifest": state.get("concept_manifest"),
            "producer_references": state.get("producer_references", []),
            "publication": state.get("publication"),
            "residency": state.get("residency"),
        }

    def result(self, experiment_id: str) -> dict[str, Any]:
        state = self._load(experiment_id)
        directory = self._directory(experiment_id)
        turns: list[dict[str, Any]] = []
        for turn in state.get("turns") or []:
            item = dict(turn)
            output_file = item.get("output_file")
            if isinstance(output_file, str):
                try:
                    item["content"] = (directory / output_file).read_text(encoding="utf-8").rstrip()
                except OSError:
                    item["content"] = None
            turns.append(item)
        return {
            "schema": STATE_SCHEMA,
            "experiment_id": experiment_id,
            "state": state.get("state"),
            "accepted_at": state.get("accepted_at"),
            "started_at": state.get("started_at"),
            "completed_at": state.get("completed_at"),
            "reason": state.get("reason"),
            "spec_identity": state.get("spec_identity"),
            "claim_boundary": state.get("spec", {}).get("claim_boundary"),
            "family_record_id": state.get("family_record_id"),
            "concept_manifest": state.get("concept_manifest"),
            "producer_references": state.get("producer_references", []),
            "publication": state.get("publication"),
            "residency": state.get("residency"),
            "turns": turns,
        }

    def stop(self, experiment_id: str) -> dict[str, Any]:
        state = self._load(experiment_id)
        if state.get("state") in _TERMINAL:
            return self.status(experiment_id)
        state["stop_requested"] = True
        state["stop_requested_at"] = _iso()
        self._save(state)
        return self.status(experiment_id)

    def list(self) -> dict[str, Any]:
        experiments: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("exp-*/state.json"), reverse=True)[:100]:
            experiment_id = path.parent.name
            try:
                experiments.append(self.status(experiment_id))
            except ControlError:
                continue
        return {"experiments": experiments, "count": len(experiments)}

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
_TERMINAL = {"COMPLETED", "FAILED", "STOPPED"}
_ACTIVE_FABRIC = {"ACCEPTED", "QUEUED", "RUNNING", "DISPATCHED", "SUBMITTED"}


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
    if len(initial_handoff) > max_handoff_chars:
        raise ControlError("INVALID_INPUT", "initial_handoff exceeds max_handoff_chars")
    if len(instructions) > 20_000 or "\x00" in instructions:
        raise ControlError("INVALID_INPUT", "experiment instructions are invalid or oversized")
    return {
        "schema": EXPERIMENT_SCHEMA,
        "goal": _bounded_text(value.get("goal"), "goal", 20_000),
        "actors": actors,
        "stages": stages,
        "duration_seconds": duration_seconds,
        "max_turns": max_turns,
        "poll_seconds": poll_seconds,
        "max_turn_wait_seconds": max_turn_wait_seconds,
        "max_handoff_chars": max_handoff_chars,
        "max_tool_steps": max_tool_steps,
        "initial_handoff": initial_handoff,
        "instructions": instructions,
        "stop_on_turn_failure": bool(value.get("stop_on_turn_failure", True)),
        "claim_boundary": (
            "Control coordinates durable handoffs; Harness resolves exact model placement; "
            "Fabric owns detached execution and receipts. Execution success does not establish "
            "model correctness, scientific validity, independence, or Commons acceptance."
        ),
    }


class ExperimentRuntime(Protocol):
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
            self._tool_registry_type = tools_mod.ToolRegistry
            self._fabric_tool_executor_type = fabric_tools_mod.FabricTargetToolExecutor
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
            replace(base, name=str(actor["model"])),
            override,
        )
        if selection is None or not selection.available or selection.worker_id != actor["worker"]:
            reason = selection.reason if selection is not None else "exact model pin could not be resolved"
            raise ControlError("MODEL_ROUTE_UNAVAILABLE", redact_text(str(reason)))
        return role, model, selection

    def offered_tools(self, actor: Mapping[str, str]) -> list[str]:
        role = self._role_name(actor)
        return list(self._config.models[role].tools)

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
            state["updated_at"] = _iso()
            self._atomic_json(existing_path, state)
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def start(self, raw_spec: object) -> dict[str, Any]:
        spec = validate_spec(raw_spec)
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
            "turns": [],
            "stop_requested": False,
            "authority": {
                "coordinator": "mncs-control-mcp",
                "routing": "mncs-harness",
                "execution": "persistent-fabric-detached",
                "commons": "none",
            },
        }
        self._save(state)
        self._spawn(experiment_id)
        return self.status(experiment_id)

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
            if isinstance(value, dict) and value.get("schema") == STATE_SCHEMA and value.get("state") not in _TERMINAL:
                experiment_id = value.get("experiment_id")
                if isinstance(experiment_id, str):
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
            raise ControlError("FABRIC_RESULT_INVALID", "completed Fabric turn returned no model content")
        directory = self._directory(str(state["experiment_id"]))
        turns_dir = directory / "turns"
        turns_dir.mkdir(parents=True, exist_ok=True)
        output = turns_dir / f"turn-{int(turn['turn']):04d}-{turn['actor']['name']}.md"
        output.write_text(content + "\n", encoding="utf-8")
        turn.update(
            state="COMPLETED",
            completed_at=_iso(),
            output_file=str(output.relative_to(directory)),
            output_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            inference_stages=list(payload.get("inference_stages") or []),
            fabric_evidence=_fabric_evidence(payload),
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
        if effective not in _TERMINAL and not coordinator_live:
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

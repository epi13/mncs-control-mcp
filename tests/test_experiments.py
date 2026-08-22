from __future__ import annotations

import json
import tempfile
import time
import unittest
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.experiments import (
    STATE_SCHEMA,
    TURN_SCHEMA,
    ExperimentManager,
    HarnessFabricRuntime,
    _identity,
    _iso,
    validate_spec,
)


class FakeRuntime:
    def __init__(self) -> None:
        self.submissions: list[tuple[dict[str, str], str, str]] = []
        self.preparations: list[str] = []
        self.releases: list[str] = []
        self.statuses: dict[str, str] = {"existing-work": "COMPLETED"}
        self.results: dict[str, dict[str, object]] = {
            "existing-work": {
                "response": {"message": {"content": "resumed output"}},
                "inference_stages": ["worker-started", "completed"],
            }
        }

    def prepare(self, experiment_id, actors, prior_leases=()):
        self.preparations.append(experiment_id)
        prior = {
            (item.get("worker_id"), item.get("model")): item for item in prior_leases
        }
        return [
            {
                "outcome": "PASS",
                "code": "RESIDENCY_WARMED",
                "experiment_id": experiment_id,
                "worker_id": actor["worker"],
                "model": actor["model"],
                "provider": "ollama",
                "loaded": True,
                "managed": prior.get((actor["worker"], actor["model"]), {}).get(
                    "managed", True
                ),
            }
            for actor in actors
        ]

    def release(self, experiment_id, leases):
        self.releases.append(experiment_id)
        return [
            {
                "outcome": "PASS",
                "code": "RESIDENCY_RELEASED",
                "worker_id": lease["worker_id"],
                "model": lease["model"],
                "released": True,
                "remaining_loaded_models": [],
            }
            for lease in leases
        ]

    def close(self):
        return None

    def submit(self, actor, prompt: str, idempotency_key: str, *, messages=None) -> str:
        work_id = f"work-{len(self.submissions) + 1}"
        self.submissions.append((dict(actor), prompt, idempotency_key))
        self.statuses[work_id] = "COMPLETED"
        self.results[work_id] = {
            "response": {"message": {"content": f"answer-{len(self.submissions)}"}},
            "inference_stages": ["worker-started", "inference-completed", "completed"],
            "result": {
                "result": {
                    "results": [
                        {
                            "worker_identity": actor["worker"],
                            "record_identity": "sha256:" + "a" * 64,
                            "receipt_identity": "sha256:" + "b" * 64,
                        }
                    ]
                }
            },
        }
        return work_id

    def status(self, work_id: str) -> str:
        return self.statuses[work_id]

    def result(self, work_id: str) -> dict[str, object]:
        return self.results[work_id]


class BlockingRuntime(FakeRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.statuses = {}

    def status(self, work_id: str) -> str:
        return "RUNNING"


class ExperimentManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = replace(
            ControlConfig(),
            job_state_path=root / "jobs.json",
            workspace_root=root / "projects",
        )
        self.spec = {
            "goal": "Test whether bounded handoffs improve a proposed MNCS protocol.",
            "actors": [
                {"name": "planner", "worker": "worker-a", "model": "model-a"},
                {"name": "critic", "worker": "worker-b", "model": "model-b"},
            ],
            "stages": ["Propose a falsifiable design.", "Attack the prior handoff."],
            "duration_seconds": 30,
            "max_turns": 2,
            "poll_seconds": 0.25,
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def wait_terminal(manager: ExperimentManager, experiment_id: str) -> dict[str, object]:
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            status = manager.status(experiment_id)
            if status["state"] in {"COMPLETED", "FAILED", "STOPPED"}:
                return status
            time.sleep(0.02)
        raise AssertionError("experiment did not reach a terminal state")

    def test_alternating_turns_use_detached_handoffs_and_retain_evidence(self) -> None:
        runtime = FakeRuntime()
        manager = ExperimentManager(self.config, runtime_factory=lambda _config: runtime, resume=False)
        accepted = manager.start(self.spec)
        experiment_id = str(accepted["experiment_id"])
        status = self.wait_terminal(manager, experiment_id)
        self.assertEqual(status["recorded_state"], "COMPLETED")
        self.assertEqual(status["successful_turns"], 2)
        self.assertEqual(len(runtime.submissions), 2)
        self.assertEqual(runtime.preparations, [experiment_id])
        self.assertEqual(runtime.releases, [experiment_id])
        self.assertEqual(runtime.submissions[0][0]["worker"], "worker-a")
        self.assertEqual(runtime.submissions[1][0]["worker"], "worker-b")
        self.assertIn("answer-1", runtime.submissions[1][1])
        self.assertEqual(
            runtime.submissions[0][2],
            f"{experiment_id}:turn:1",
        )
        result = manager.result(experiment_id)
        self.assertEqual(result["turns"][0]["content"], "answer-1")
        self.assertEqual(result["turns"][1]["content"], "answer-2")
        self.assertEqual(result["turns"][0]["fabric_evidence"]["worker_identity"], "worker-a")
        self.assertTrue(result["turns"][0]["fabric_evidence"]["receipt_identity"].startswith("sha256:"))
        self.assertEqual(result["residency"]["status"], "PREPARED")
        self.assertEqual(result["residency"]["teardown"]["status"], "RELEASED")

    def test_resume_existing_detached_work_without_resubmitting(self) -> None:
        runtime = FakeRuntime()
        manager = ExperimentManager(self.config, runtime_factory=lambda _config: runtime, resume=False)
        experiment_id = "exp-" + "1" * 32
        directory = manager.root / experiment_id
        directory.mkdir(mode=0o700)
        spec = validate_spec({**self.spec, "max_turns": 1})
        now = datetime.now(UTC)
        state = {
            "schema": STATE_SCHEMA,
            "experiment_id": experiment_id,
            "state": "RUNNING",
            "accepted_at": _iso(now),
            "started_at": _iso(now),
            "deadline_at": _iso(now + timedelta(seconds=30)),
            "spec": spec,
            "spec_identity": _identity(spec),
            "turns": [
                {
                    "schema": TURN_SCHEMA,
                    "turn": 1,
                    "actor": dict(spec["actors"][0]),
                    "stage_index": 0,
                    "state": "SUBMITTED",
                    "submitted_at": _iso(now),
                    "work_id": "existing-work",
                    "idempotency_key": f"{experiment_id}:turn:1",
                }
            ],
            "stop_requested": False,
        }
        manager._atomic_json(directory / "state.json", state)
        resumed = ExperimentManager(
            self.config, runtime_factory=lambda _config: runtime, resume=True, resume_delay_seconds=0
        )
        status = self.wait_terminal(resumed, experiment_id)
        self.assertEqual(status["recorded_state"], "COMPLETED")
        self.assertEqual(runtime.submissions, [])
        result = resumed.result(experiment_id)
        self.assertEqual(result["turns"][0]["content"], "resumed output")

    def test_stop_does_not_claim_to_cancel_detached_fabric_work(self) -> None:
        runtime = BlockingRuntime()
        manager = ExperimentManager(self.config, runtime_factory=lambda _config: runtime, resume=False)
        accepted = manager.start({**self.spec, "max_turns": 1})
        experiment_id = str(accepted["experiment_id"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status = manager.status(experiment_id)
            if status.get("current_turn") and status["current_turn"].get("work_id"):
                break
            time.sleep(0.02)
        manager.stop(experiment_id)
        status = self.wait_terminal(manager, experiment_id)
        self.assertEqual(status["recorded_state"], "STOPPED")
        raw = json.loads((manager.root / experiment_id / "state.json").read_text())
        self.assertIn("detached Fabric work may continue independently", raw["reason"])
        self.assertTrue(raw.get("detached_work_id"))

    def test_invalid_spec_fails_closed(self) -> None:
        with self.assertRaises(ControlError):
            validate_spec({"goal": "x", "actors": [], "stages": ["x"]})

    def test_residency_prepare_exception_fails_experiment_without_submission(self) -> None:
        class FailingPrepareRuntime(FakeRuntime):
            def prepare(self, experiment_id, actors, prior_leases=()):
                del experiment_id, actors, prior_leases
                raise RuntimeError("provider observation unavailable")

        runtime = FailingPrepareRuntime()
        manager = ExperimentManager(
            self.config, runtime_factory=lambda _config: runtime, resume=False
        )
        accepted = manager.start({**self.spec, "max_turns": 1})
        result = manager.result(str(accepted["experiment_id"]))
        deadline = time.monotonic() + 4
        while result["state"] not in {"COMPLETED", "FAILED", "STOPPED"}:
            if time.monotonic() >= deadline:
                raise AssertionError("experiment did not fail after residency preparation")
            time.sleep(0.02)
            result = manager.result(str(accepted["experiment_id"]))
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(result["residency"]["leases"][0]["code"], "RESIDENCY_PREPARE_FAILED")
        self.assertEqual(runtime.submissions, [])

    def test_release_failure_is_durable_degraded_evidence(self) -> None:
        class FailingReleaseRuntime(FakeRuntime):
            def release(self, experiment_id, leases):
                del experiment_id, leases
                raise RuntimeError("provider release timed out")

        runtime = FailingReleaseRuntime()
        manager = ExperimentManager(
            self.config, runtime_factory=lambda _config: runtime, resume=False
        )
        accepted = manager.start({**self.spec, "max_turns": 1})
        experiment_id = str(accepted["experiment_id"])
        status = self.wait_terminal(manager, experiment_id)
        self.assertEqual(status["state"], "COMPLETED")
        teardown = (status.get("residency") or {}).get("teardown") or {}
        self.assertEqual(teardown.get("status"), "DEGRADED")
        self.assertEqual(teardown["results"][0]["code"], "RESIDENCY_TEARDOWN_FAILED")

    def test_harness_policy_can_retain_residency_at_teardown(self) -> None:
        runtime = FakeRuntime()
        runtime.release_on_experiment_end = False
        manager = ExperimentManager(
            self.config, runtime_factory=lambda _config: runtime, resume=False
        )
        accepted = manager.start({**self.spec, "max_turns": 1})
        experiment_id = str(accepted["experiment_id"])
        self.wait_terminal(manager, experiment_id)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            teardown = (
                (manager.result(experiment_id).get("residency") or {}).get("teardown")
                or {}
            )
            if teardown.get("status") == "RETAINED":
                break
            time.sleep(0.02)
        else:
            raise AssertionError("Harness retain policy was not persisted")
        self.assertEqual(runtime.releases, [])

    def test_terminal_state_with_incomplete_teardown_is_recovered(self) -> None:
        runtime = FakeRuntime()
        manager = ExperimentManager(
            self.config, runtime_factory=lambda _config: runtime, resume=False
        )
        experiment_id = "exp-" + "2" * 32
        directory = manager.root / experiment_id
        directory.mkdir(mode=0o700)
        spec = validate_spec({**self.spec, "max_turns": 1})
        state = {
            "schema": STATE_SCHEMA,
            "experiment_id": experiment_id,
            "state": "COMPLETED",
            "accepted_at": _iso(),
            "deadline_at": _iso(datetime.now(UTC) + timedelta(seconds=30)),
            "spec": spec,
            "spec_identity": _identity(spec),
            "turns": [],
            "stop_requested": False,
            "residency": {
                "status": "PREPARED",
                "policy_mode": "experiment-pinned",
                "leases": [{
                    "outcome": "PASS",
                    "worker_id": "worker-a",
                    "model": "model-a",
                    "managed": True,
                }],
            },
        }
        manager._atomic_json(directory / "state.json", state)
        resumed = ExperimentManager(
            self.config,
            runtime_factory=lambda _config: runtime,
            resume=True,
            resume_delay_seconds=0,
        )
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            teardown = (resumed.result(experiment_id).get("residency") or {}).get("teardown") or {}
            if teardown.get("status") == "RELEASED":
                break
            time.sleep(0.02)
        else:
            raise AssertionError("terminal residency teardown was not recovered")
        self.assertEqual(runtime.releases, [experiment_id])

    def test_actor_role_and_tool_followup_are_retained(self) -> None:
        spec = validate_spec(
            {
                **self.spec,
                "actors": [
                    {
                        "name": "builder",
                        "worker": "worker-a",
                        "model": "model-a",
                        "role": "coder",
                    }
                ],
                "max_turns": 1,
                "max_tool_steps": 2,
            }
        )
        self.assertEqual(spec["actors"][0]["role"], "coder")
        self.assertEqual(spec["max_tool_steps"], 2)

        class ToolRuntime(FakeRuntime):
            def offered_tools(self, actor):
                return ["read_file"]

            def execute_tools(self, actor, calls):
                return [
                    {
                        "name": "read_file",
                        "arguments": {"path": "mncs-language/README.md"},
                        "output": "README contents",
                        "success": True,
                        "execution_target": "controller",
                        "allowed": True,
                        "risk": "low",
                        "reason": "read",
                    }
                ]

            def submit(self, actor, prompt: str, idempotency_key: str, *, messages=None) -> str:
                work_id = super().submit(actor, prompt, idempotency_key, messages=messages)
                if ":tool:" not in idempotency_key:
                    self.results[work_id] = {
                        "response": {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": "read_file",
                                            "arguments": {"path": "mncs-language/README.md"},
                                        }
                                    }
                                ],
                            }
                        },
                        "inference_stages": ["worker-started", "completed"],
                        "result": {
                            "result": {
                                "results": [
                                    {
                                        "worker_identity": actor["worker"],
                                        "record_identity": "sha256:" + "a" * 64,
                                        "receipt_identity": "sha256:" + "b" * 64,
                                    }
                                ]
                            }
                        },
                    }
                else:
                    self.results[work_id]["response"] = {
                        "message": {"content": "Inspected README via tools."}
                    }
                return work_id

        runtime = ToolRuntime()
        manager = ExperimentManager(self.config, runtime_factory=lambda _config: runtime, resume=False)
        accepted = manager.start(
            {
                **self.spec,
                "actors": [
                    {
                        "name": "builder",
                        "worker": "worker-a",
                        "model": "model-a",
                        "role": "coder",
                    }
                ],
                "max_turns": 1,
                "max_tool_steps": 2,
            }
        )
        experiment_id = str(accepted["experiment_id"])
        status = self.wait_terminal(manager, experiment_id)
        self.assertEqual(status["recorded_state"], "COMPLETED")
        self.assertEqual(len(runtime.submissions), 2)
        self.assertIn(":tool:1", runtime.submissions[1][2])
        result = manager.result(experiment_id)
        self.assertEqual(result["turns"][0]["content"].strip(), "Inspected README via tools.")
        self.assertEqual(result["turns"][0]["tools_offered"], ["read_file"])
        self.assertEqual(result["turns"][0]["tool_executions"][0]["name"], "read_file")
        self.assertEqual(result["turns"][0]["tool_executions"][0]["execution_target"], "controller")

    def test_detached_and_tool_followup_resolution_reinforces_experiment_pin(self) -> None:
        @dataclass(frozen=True)
        class Model:
            name: str
            keep_alive: object

        class RoutingOverride:
            @staticmethod
            def from_values(**values):
                return values

        captured: list[Model] = []

        class Session:
            def resolve_model(self, role, model, override):
                del role, override
                captured.append(model)
                return model, SimpleNamespace(
                    available=True,
                    worker_id="worker-a",
                    reason="exact",
                )

        runtime = object.__new__(HarnessFabricRuntime)
        runtime._config = SimpleNamespace(
            models={"coder": Model("default", 0)},
            model_residency=SimpleNamespace(experiment_keep_alive=-1),
        )
        runtime._routing_override = RoutingOverride
        runtime._session = Session()
        actor = {
            "name": "builder",
            "worker": "worker-a",
            "model": "qwen3:8b",
            "role": "coder",
        }
        runtime._resolved(actor)
        runtime._resolved(actor)
        self.assertEqual([model.keep_alive for model in captured], [-1, -1])
        self.assertEqual([model.name for model in captured], ["qwen3:8b", "qwen3:8b"])

    def test_tool_step_bound_without_final_text_is_retained_evidence(self) -> None:
        class OnlyToolsRuntime(FakeRuntime):
            def offered_tools(self, actor):
                return ["system_info"]

            def execute_tools(self, actor, calls):
                return [
                    {
                        "name": "system_info",
                        "arguments": {},
                        "output": "linux",
                        "success": True,
                        "execution_target": "controller",
                        "allowed": True,
                        "risk": "low",
                        "reason": "read",
                    }
                ]

            def submit(self, actor, prompt: str, idempotency_key: str, *, messages=None) -> str:
                work_id = super().submit(actor, prompt, idempotency_key, messages=messages)
                self.results[work_id] = {
                    "response": {
                        "message": {
                            "content": "",
                            "tool_calls": [{"function": {"name": "system_info", "arguments": {}}}],
                        }
                    },
                    "inference_stages": ["completed"],
                    "result": {
                        "result": {
                            "results": [
                                {
                                    "worker_identity": actor["worker"],
                                    "record_identity": "sha256:" + "a" * 64,
                                    "receipt_identity": "sha256:" + "b" * 64,
                                }
                            ]
                        }
                    },
                }
                return work_id

        runtime = OnlyToolsRuntime()
        manager = ExperimentManager(self.config, runtime_factory=lambda _config: runtime, resume=False)
        accepted = manager.start({**self.spec, "max_turns": 1, "max_tool_steps": 1})
        status = self.wait_terminal(manager, str(accepted["experiment_id"]))
        self.assertEqual(status["recorded_state"], "COMPLETED")
        result = manager.result(str(accepted["experiment_id"]))
        self.assertIn("tool-step bound reached", result["turns"][0]["content"])
        self.assertEqual(result["turns"][0]["tool_executions"][0]["name"], "system_info")


if __name__ == "__main__":
    unittest.main()

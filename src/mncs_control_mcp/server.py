from __future__ import annotations

import argparse
import json
import logging
import time
from typing import Any

from . import __version__
from .actions import ActionRegistry, ActionSpec
from .adapters import IntegrationBundle
from .config import load_config
from .errors import ControlError
from .jobs import JobStore
from .security import redact_text, resolve_repository

LOGGER = logging.getLogger("mncs_control_mcp")


def _logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _register_actions() -> ActionRegistry:
    registry = ActionRegistry()
    for name, executable, description in (
        ("repo.status", "git", "read approved repository metadata"),
        ("test.pytest", "python", "run the fixed pytest test action"),
        ("test.cargo", "cargo", "run the fixed cargo test action"),
        ("model.ollama_list", "ollama", "list local Ollama models"),
        ("system.nvidia_smi", "nvidia-smi", "read local NVIDIA diagnostics"),
    ):
        registry.register(ActionSpec(name, executable, description))
    return registry


def _bounded_response(value: object, maximum: int) -> object:
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if len(encoded.encode("utf-8")) <= maximum:
        return value
    return {
        "error": "RESPONSE_LIMIT_EXCEEDED",
        "message": "MCP response exceeds the configured limit",
        "output_truncated": True,
    }


def build_server(config: Any | None = None) -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised in a missing-extra environment
        raise RuntimeError("MCP support requires the 'mcp' dependency") from exc

    selected = config or load_config()
    actions = _register_actions()
    integrations = IntegrationBundle(selected, actions)
    jobs = JobStore()
    server = FastMCP(
        selected.name,
        instructions=(
            "Secure MNCS laboratory control boundary. Inputs are structured and limited to "
            "approved repositories and registered capabilities; never provide shell commands."
        ),
    )

    def invoke(name: str, function: Any, *args: Any, **kwargs: Any) -> object:
        started = time.monotonic()
        LOGGER.info("MCP call received tool=%s", name)
        try:
            LOGGER.info("MCP request validated tool=%s action_dispatched=%s", name, name)
            result = function(*args, **kwargs)
            LOGGER.info("MCP call completed tool=%s success=true duration=%.3f", name, time.monotonic() - started)
            return _bounded_response(result, selected.max_response_bytes)
        except ControlError as exc:
            LOGGER.info("MCP call completed tool=%s success=false code=%s", name, exc.code)
            return exc.as_dict()
        except Exception as exc:
            LOGGER.exception("MCP call failed tool=%s", name)
            return {"error": "INTEGRATION_FAILURE", "message": redact_text(str(exc))}

    @server.tool(name="system_status", description="Inspect bounded local Fedora controller and optional subsystem status.")
    def system_status() -> dict[str, object]:
        return invoke(
            "system_status",
            lambda: {
                **integrations.system.status(),
                "local_harness": integrations.harness.status(),
                "fabric": integrations.fabric.status(),
                "forge": {"available": integrations.forge.config.forge_path.is_dir(), "path": str(integrations.forge.config.forge_path)},
                "server": {"name": selected.name, "version": __version__, "transport": "stdio"},
            },
        )  # type: ignore[return-value]

    @server.tool(name="list_repositories", description="List the approved MNCS repository registry without exposing arbitrary paths.")
    def list_repositories() -> dict[str, object]:
        def read() -> dict[str, object]:
            rows = []
            for key, name in sorted(selected.repositories.items()):
                _, path = resolve_repository(selected, key)
                rows.append({"repository": key, "name": name, "path": str(path), "exists": path.is_dir()})
            return {"projects_root": str(selected.projects_root), "repositories": rows}

        return invoke("list_repositories", read)  # type: ignore[return-value]

    @server.tool(name="repo_status", description="Inspect Git status for one approved MNCS repository key.")
    def repo_status(repository: str) -> dict[str, object]:
        return invoke("repo_status", integrations.git.status, repository)  # type: ignore[return-value]

    @server.tool(name="fabric_status", description="Inspect Fabric workers through the Fabric public API.")
    def fabric_status() -> dict[str, object]:
        return invoke("fabric_status", integrations.fabric.status)  # type: ignore[return-value]

    @server.tool(name="model_status", description="Report bounded model inventory from Ollama and Fabric.")
    def model_status() -> dict[str, object]:
        return invoke("model_status", integrations.models.status)  # type: ignore[return-value]

    @server.tool(name="run_tests", description="Run one approved test suite in one approved repository.")
    def run_tests(repository: str, test_suite: str, component: str | None = None, timeout: float | None = None) -> dict[str, object]:
        return invoke("run_tests", integrations.tests.run, repository, test_suite, component, timeout)  # type: ignore[return-value]

    @server.tool(name="run_mncs_evaluation", description="Invoke a configured Forge development check when the upstream interface supports it.")
    def run_mncs_evaluation(repository: str, case_study: str, model: str | None = None, evaluation_profile: str | None = None) -> dict[str, object]:
        return invoke("run_mncs_evaluation", integrations.forge.evaluate, repository, case_study, model, evaluation_profile)  # type: ignore[return-value]

    @server.tool(name="dispatch_fabric_job", description="Check controlled Fabric dispatch capability; arbitrary commands are never accepted.")
    def dispatch_fabric_job(task_type: str, target_node: str | None = None, model: str | None = None, repository: str | None = None, test_suite: str | None = None, evaluation: str | None = None) -> dict[str, object]:
        def dispatch() -> dict[str, object]:
            if task_type not in {"run_tests", "evaluation"}:
                raise ControlError("INVALID_INPUT", "task_type must be run_tests or evaluation")
            for field_name, value in {
                "target_node": target_node,
                "model": model,
                "evaluation": evaluation,
            }.items():
                if value is not None and (not isinstance(value, str) or not value or len(value) > 160 or any(ord(char) < 32 for char in value)):
                    raise ControlError("INVALID_INPUT", f"{field_name} must be bounded text")
            if repository is not None:
                resolve_repository(selected, repository)
            if test_suite is not None and test_suite not in {"repository", "pytest", "cargo"}:
                raise ControlError("INVALID_INPUT", "test_suite must be repository, pytest, or cargo")
            supported = {"run_tests": False, "evaluation": False}
            return {
                "status": "not_supported_yet",
                "reason": "Fabric's public API requires a validated plan, manifest, and execution bundle; this first control boundary does not synthesize those artifacts from agent input.",
                "supported_task_types": supported,
                "received": {"task_type": task_type, "target_node": target_node, "model": model, "repository": repository, "test_suite": test_suite, "evaluation": evaluation},
            }

        return invoke("dispatch_fabric_job", dispatch)  # type: ignore[return-value]

    @server.tool(name="job_status", description="Return the status of a job created by this control boundary.")
    def job_status(job_id: str) -> dict[str, object]:
        def read() -> dict[str, object]:
            job = jobs.get(job_id)
            if job is None:
                raise ControlError("UNKNOWN_JOB", "job ID is not recognized")
            return job.public()

        return invoke("job_status", read)  # type: ignore[return-value]

    @server.tool(name="job_result", description="Retrieve a bounded result for a recognized job ID.")
    def job_result(job_id: str) -> dict[str, object]:
        def read() -> dict[str, object]:
            job = jobs.get(job_id)
            if job is None:
                raise ControlError("UNKNOWN_JOB", "job ID is not recognized")
            if job.status not in {"completed", "failed"}:
                return {**job.public(), "result_available": False}
            return {**job.public(), "result_available": True, "result": job.result}

        return invoke("job_result", read)  # type: ignore[return-value]

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mncs-control-mcp")
    parser.add_argument("--config", help="path to a control TOML configuration")
    args = parser.parse_args(argv)
    _logging()
    config = load_config(args.config)
    build_server(config).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

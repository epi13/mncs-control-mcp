from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .actions import ActionRegistry, run_bounded
from .config import ControlConfig
from .errors import ControlError
from .runtime import prepare_fabric_runtime
from .sandbox import Sandbox
from .security import redact_text, resolve_repository, safe_host_probe_environment
from .test_results import parse_test_output
from .tooling import ToolchainResolver
from .workspace import WorkspacePolicy


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_sibling_package(package: str, source_root: Path) -> Any:
    """Import an optional sibling package without making it a dependency of this project."""
    source = source_root / "src"
    inserted = False
    if source.is_dir() and str(source) not in sys.path:
        sys.path.insert(0, str(source))
        inserted = True
    try:
        return importlib.import_module(package)
    finally:
        if inserted:
            try:
                sys.path.remove(str(source))
            except ValueError:
                pass


class TestAdapter:
    SUITES = ("repository", "pytest", "ruff", "cargo", "node", "go", "cmake")

    def __init__(
        self,
        config: ControlConfig,
        actions: ActionRegistry,
        policy: WorkspacePolicy | None = None,
        sandbox: Sandbox | None = None,
    ) -> None:
        self.config = config
        self.actions = actions
        self.policy = policy
        self.sandbox = sandbox
        self.toolchains = ToolchainResolver()

    def _root(self, repository: str) -> tuple[str, Path]:
        if repository in self.config.repositories:
            key, root = resolve_repository(self.config, repository)
            return key, root
        if self.policy is None:
            raise ControlError("UNAUTHORIZED_REPOSITORY", f"repository alias is unknown: {repository}")
        return repository, self.policy.project_path(repository)

    def _detected_suite(self, root: Path) -> str | None:
        if (root / "Cargo.toml").is_file():
            return "cargo"
        if (root / "pyproject.toml").is_file() or (root / "pytest.ini").is_file() or (root / "tests").is_dir():
            return "pytest"
        if (root / "package.json").is_file():
            return "node"
        if (root / "go.mod").is_file():
            return "go"
        if (root / "CMakeLists.txt").is_file():
            return "cmake"
        return None

    def discover(self, repository: str) -> dict[str, object]:
        key, root = self._root(repository)
        if not root.is_dir():
            raise ControlError("REPOSITORY_MISSING", f"approved repository does not exist: {key}")
        detected = self._detected_suite(root)
        commands: list[dict[str, object]] = []
        toolchain = self.toolchains.resolve(root, "python" if detected == "pytest" else detected) if detected else None
        if detected == "pytest":
            executable = toolchain.executable if toolchain and toolchain.executable else "python"
            commands.append({"suite": "pytest", "command": [executable, "-m", "pytest"], "toolchain": toolchain.public() if toolchain else None})
        elif detected == "cargo":
            executable = toolchain.executable if toolchain and toolchain.executable else "cargo"
            commands.append({"suite": "cargo", "command": [executable, "test"], "toolchain": toolchain.public() if toolchain else None})
        elif detected == "node":
            executable = toolchain.executable if toolchain and toolchain.executable else "npm"
            commands.append({"suite": "node", "command": [executable, "test", "--"], "toolchain": toolchain.public() if toolchain else None})
        elif detected == "go":
            executable = toolchain.executable if toolchain and toolchain.executable else "go"
            commands.append({"suite": "go", "command": [executable, "test", "./..."], "toolchain": toolchain.public() if toolchain else None})
        elif detected == "cmake":
            executable = toolchain.executable if toolchain and toolchain.executable else "ctest"
            commands.append({"suite": "cmake", "command": [executable, "--test-dir", "build"], "toolchain": toolchain.public() if toolchain else None})
        return {
            "repository": key,
            "path": str(root),
            "detected_suite": detected,
            "supported_suites": list(self.SUITES),
            "commands": commands,
            "test_directories": [name for name in ("tests", "test", "spec") if (root / name).is_dir()],
            "toolchain": toolchain.public() if toolchain else None,
        }

    def _command(self, root: Path, suite: str, component: str | None) -> tuple[tuple[str, ...], dict[str, object]]:
        if suite not in self.SUITES:
            raise ControlError("INVALID_TEST_SUITE", f"test suite must be one of {self.SUITES}")
        if suite == "repository":
            suite = self._detected_suite(root) or ""
            if not suite:
                raise ControlError("TEST_SUITE_UNAVAILABLE", "no approved repository test runner was detected")
        ecosystem = "python" if suite == "pytest" else suite
        toolchain = self.toolchains.resolve(root, ecosystem)
        if toolchain.executable is None:
            raise ControlError("TOOLCHAIN_UNAVAILABLE", toolchain.diagnostic or f"{ecosystem} toolchain is unavailable")
        executable = toolchain.executable
        if suite == "cargo":
            return ((executable, "test", "--", component) if component else (executable, "test"), toolchain.public())
        if suite == "pytest":
            return ((executable, "-m", "pytest", component) if component else (executable, "-m", "pytest"), toolchain.public())
        if suite == "ruff":
            return ((executable, "check", component or "."), toolchain.public())
        if suite == "node":
            return ((executable, "test", "--", component) if component else (executable, "test", "--"), toolchain.public())
        if suite == "go":
            return ((executable, "test", component or "./..."), toolchain.public())
        if suite == "cmake":
            return ((executable, "--test-dir", component or "build"), toolchain.public())
        raise ControlError("INVALID_TEST_SUITE", f"test suite must be one of {self.SUITES}")

    def run(
        self,
        repository: str,
        test_suite: str,
        component: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, object]:
        key, root = self._root(repository)
        if not root.is_dir():
            raise ControlError("REPOSITORY_MISSING", f"approved repository does not exist: {key}")
        if component is not None:
            if not re.fullmatch(r"[A-Za-z0-9_.:\-/]{1,160}", component) or component.startswith("-") or ".." in Path(component).parts:
                raise ControlError("INVALID_INPUT", "component must be a safe relative test selector")
        timeout_value = self.config.default_timeout_seconds if timeout is None else float(timeout)
        timeout_value = min(timeout_value, self.config.max_timeout_seconds)
        argv, toolchain = self._command(root, test_suite, component)
        if toolchain["source"] == "system":
            argv = (Path(argv[0]).name, *argv[1:])
        else:
            try:
                executable_path = Path(argv[0]).absolute()
                relative_executable = executable_path.relative_to(root.resolve())
            except ValueError:
                pass
            else:
                argv = ("./" + relative_executable.as_posix(), *argv[1:])
        self.actions.resolve(f"test.{('cargo' if argv[0].endswith('cargo') else 'pytest')}") if argv[0].endswith(("cargo", "python", "python3")) else None
        self_test = root.name == "mncs-control-mcp"
        command = shlex.join(argv)
        security_skips: list[dict[str, str]] = []
        if self_test and argv[1:3] == ("-m", "pytest"):
            command += " -m 'not requires_bwrap_namespace'"
            security_skips.append({
                "marker": "requires_bwrap_namespace",
                "reason": "the MCP invocation already runs inside the production Bubblewrap boundary; nested user namespaces are unavailable",
            })
        started = utc_now()
        if self.sandbox is not None:
            sandbox_result = self.sandbox.run(
                command,
                scope="project",
                project=root.relative_to(self.config.workspace_root).parts[0],
                cwd=Path(*root.relative_to(self.config.workspace_root).parts[1:]).as_posix()
                if len(root.relative_to(self.config.workspace_root).parts) > 1
                else ".",
                timeout_seconds=timeout_value,
                network=False,
                environment={"MNCS_CONTROL_SELF_TEST": "1"} if self_test else None,
            )
            returncode = sandbox_result.exit_code
            stdout = sandbox_result.stdout
            stderr = sandbox_result.stderr
            timed_out = sandbox_result.timed_out
            output_truncated = sandbox_result.output_truncated
            duration = sandbox_result.duration_seconds
            backend = sandbox_result.sandbox_backend
        else:
            result = run_bounded(
                argv,
                cwd=root,
                timeout_seconds=timeout_value,
                output_limit_bytes=self.config.max_output_bytes,
            )
            returncode = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            timed_out = result.timed_out
            output_truncated = result.output_truncated
            duration = result.duration_seconds
            backend = "none"
        completed = utc_now()
        passed = returncode == 0 and not timed_out
        return {
            "repository": key,
            "test_suite": test_suite,
            "resolved_command": list(argv),
            "command_identity": f"approved:{'cargo' if argv[1] == 'test' else 'pytest'}",
            "started_at": started,
            "completed_at": completed,
            "exit_code": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output_truncated": output_truncated,
            "timed_out": timed_out,
            "duration_seconds": round(duration, 3),
            "sandbox_backend": backend,
            "summary": "PASS" if passed else "FAIL",
            "test_counts": parse_test_output(test_suite if test_suite != "repository" else self._detected_suite(root) or "", stdout, stderr),
            "toolchain": toolchain,
            "security_tests_skipped": security_skips,
            "self_test_mode": self_test,
        }

    def check(self, repository: str, profile: str = "standard", timeout: float | None = None) -> dict[str, object]:
        if profile not in {"quick", "standard", "full"}:
            raise ControlError("INVALID_INPUT", "profile must be quick, standard, or full")
        key, root = self._root(repository)
        if not root.is_dir():
            raise ControlError("REPOSITORY_MISSING", f"approved repository does not exist: {key}")
        checks: list[tuple[str, str, str]] = []
        if (root / "pyproject.toml").is_file() or (root / "tests").is_dir():
            if profile != "quick" and self.toolchains.resolve(root, "ruff").executable:
                checks.append(("lint", "ruff", "ruff check ."))
            checks.append(("tests", "pytest", "python -m pytest"))
        elif (root / "Cargo.toml").is_file():
            checks.append(("tests", "cargo", "cargo test"))
            if profile == "full":
                checks.append(("check", "cargo", "cargo check"))
        elif (root / "package.json").is_file():
            checks.append(("tests", "node", "npm test --"))
        elif (root / "go.mod").is_file():
            checks.append(("tests", "go", "go test ./..."))
        elif (root / "CMakeLists.txt").is_file():
            checks.append(("build", "cmake", "cmake --build build"))
        if not checks:
            return {"repository": key, "profile": profile, "status": "not_supported", "checks": []}
        results = []
        for name, suite, _ in checks:
            result = self.run(key, suite, timeout=timeout)
            result["check"] = name
            results.append(result)
            if result["summary"] != "PASS":
                break
        return {
            "repository": key,
            "profile": profile,
            "status": "PASS" if all(item["summary"] == "PASS" for item in results) else "FAIL",
            "checks": results,
        }


class OllamaAdapter:
    def __init__(self, config: ControlConfig, actions: ActionRegistry) -> None:
        self.config = config
        self.actions = actions

    def status(self) -> dict[str, object]:
        executable = shutil.which("ollama")
        if executable is None:
            return {"available": False, "status": "not_installed", "models": []}
        self.actions.resolve("model.ollama_list")
        result = run_bounded(
            (executable, "list"), timeout_seconds=15, output_limit_bytes=self.config.max_output_bytes,
            env=safe_host_probe_environment(),
        )
        models: list[dict[str, object]] = []
        for line in result.stdout.splitlines()[1:]:
            columns = line.split()
            if columns:
                models.append({"model": columns[0], "runtime": "ollama", "provider": "ollama", "available": True})
        return {
            "available": result.returncode == 0,
            "status": "available" if result.returncode == 0 else "unavailable",
            "models": models,
            "diagnostic": redact_text(result.stderr) if result.stderr else None,
        }


def _meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, _, raw = line.partition(":")
            parts = raw.strip().split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    except OSError:
        pass
    return values


class SystemAdapter:
    def __init__(self, config: ControlConfig, actions: ActionRegistry, ollama: OllamaAdapter) -> None:
        self.config = config
        self.actions = actions
        self.ollama = ollama

    def _nvidia(self) -> dict[str, object]:
        executable = shutil.which("nvidia-smi")
        if executable is None:
            return {"available": False, "gpus": [], "driver": None, "cuda": None}
        self.actions.resolve("system.nvidia_smi")
        result = run_bounded(
            (executable, "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader,nounits"),
            timeout_seconds=10,
            output_limit_bytes=32 * 1024,
            env=safe_host_probe_environment(),
        )
        gpus = []
        driver = None
        for line in result.stdout.splitlines():
            fields = [item.strip() for item in line.split(",")]
            if fields:
                driver = driver or (fields[1] if len(fields) > 1 else None)
                gpus.append({"name": fields[0], "driver": fields[1] if len(fields) > 1 else None, "vram_mib": fields[2] if len(fields) > 2 else None})
        cuda = None
        version = run_bounded((executable,), timeout_seconds=10, output_limit_bytes=16 * 1024, env=safe_host_probe_environment())
        match = re.search(r"CUDA Version:\s*([\d.]+)", version.stdout + version.stderr)
        if match:
            cuda = match.group(1)
        return {"available": result.returncode == 0, "gpus": gpus, "driver": driver, "cuda": cuda}

    def status(self) -> dict[str, object]:
        memory = _meminfo()
        try:
            disk = shutil.disk_usage(self.config.projects_root)
            disk_status: dict[str, object] = {
                "path": str(self.config.projects_root),
                "total_bytes": disk.total,
                "available_bytes": disk.free,
            }
        except OSError as exc:
            disk_status = {"path": str(self.config.projects_root), "available": False, "diagnostic": redact_text(str(exc))}
        return {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "kernel": platform.release(),
            "cpu": {"processor": platform.processor() or platform.machine(), "count": os.cpu_count()},
            "ram": {"total_bytes": memory.get("MemTotal"), "available_bytes": memory.get("MemAvailable")},
            "disk": disk_status,
            "gpu": self._nvidia(),
            "ollama": self.ollama.status(),
        }


class HarnessAdapter:
    def __init__(self, config: ControlConfig) -> None:
        self.config = config

    def status(self) -> dict[str, object]:
        path = self.config.harness_config
        try:
            package = _load_sibling_package("epi13_local_harness", self.config.harness_path)
            # Implementation package remains epi13_local_harness in this release.
            loader = importlib.import_module("epi13_local_harness.config").load_config
            harness_config = loader(path)
            service_support = None
            if harness_config.fabric.controller_mode == "service":
                try:
                    fabric_package = _load_sibling_package(
                        "mncs_fabric",
                        self.config.workspace_root / self.config.repositories.get("fabric", "mncs-fabric"),
                    )
                    service_support = FabricContractSupport.from_client(fabric_package)
                    service_client = fabric_package.FabricClient.connect(
                        harness_config.fabric.service_socket,
                        client_identity=harness_config.fabric.consumer_identity,
                        timeout=harness_config.fabric.service_timeout_seconds,
                    )
                    try:
                        service_support = FabricContractSupport.from_service_status(
                            service_client.controller_status(), service_support
                        )
                    finally:
                        service_client.close()
                except Exception:
                    service_support = FabricContractSupport()
            return {
                "available": True,
                "status": "configured",
                "package_version": getattr(package, "__version__", "unknown"),
                "config_path": str(path or "default"),
                "fabric_enabled": bool(harness_config.fabric.enabled),
                "fabric_controller_mode": harness_config.fabric.controller_mode,
                "fabric_service_configured": harness_config.fabric.controller_mode in {"service", "transitional"},
                "fabric_controller_connected": None,
                "fabric_execution_mode": (
                    "persistent-service" if service_support and service_support.persistent_service_execution
                    else "unsupported" if harness_config.fabric.controller_mode == "service"
                    else "embedded-direct-compatibility" if harness_config.fabric.controller_mode == "transitional"
                    else "embedded-direct"
                ),
                "fabric_service_support": (
                    {
                        "persistent_fleet_read": service_support.persistent_fleet_read,
                        "persistent_service_execution": service_support.persistent_service_execution,
                        "persistent_detached_execution": service_support.persistent_detached_execution,
                        "persistent_service_capability_ingestion": service_support.persistent_service_capability_ingestion,
                        "worker_rendezvous": service_support.worker_rendezvous,
                    }
                    if service_support is not None
                    else None
                ),
                "providers": sorted({model.provider for model in harness_config.models.values()}),
                "models": [
                    {
                        "role": role,
                        "name": model.name,
                        "provider": model.provider,
                        "worker": getattr(model, "worker", None),
                        "execution_device": model.execution_device,
                        "required_capabilities": list(model.required_capabilities),
                        "tools": list(model.tools),
                    }
                    for role, model in sorted(harness_config.models.items())
                ],
                "router": {
                    "mode": harness_config.router.mode,
                    "backend": harness_config.router.backend,
                    "enabled": harness_config.router.enable_semantic_routing,
                    "device": harness_config.router.device,
                },
                "fabric_workers_configured": len(harness_config.fabric.workers)
                if harness_config.fabric.controller_mode != "service" else 0,
                "policy": {
                    "approval_mode": harness_config.policy.approval_mode,
                    "allowed_executables": list(harness_config.policy.allowed_executables),
                },
            }
        except Exception as exc:
            return {"available": False, "status": "unavailable", "diagnostic": redact_text(str(exc))}


class CommonsAdapter:
    """Read-only Control facade over the persistent Commons consumer socket."""

    MAX_TEXT_ARGUMENT = 4096
    MAX_CURSOR_BYTES = 64 * 1024
    MAX_LIMIT = 1000

    def __init__(self, config: ControlConfig) -> None:
        self.config = config

    def _module(self) -> Any:
        try:
            return importlib.import_module("mncs_commons")
        except ImportError:
            return _load_sibling_package("mncs_commons", self.config.commons_path)

    def _client(self) -> Any:
        try:
            commons = self._module()
            return commons.CommonsClient.connect(
                self.config.commons_socket,
                timeout=self.config.commons_service_timeout_seconds,
            )
        except Exception as exc:
            raise ControlError(
                "COMMONS_SERVICE_UNAVAILABLE", redact_text(str(exc))
            ) from exc

    def _operator(self) -> Any:
        try:
            commons = self._module()
            return commons.CommonsAdminClient.connect(
                self.config.commons_operator_socket,
                timeout=self.config.commons_service_timeout_seconds,
            )
        except Exception as exc:
            raise ControlError("COMMONS_OPERATOR_UNAVAILABLE", redact_text(str(exc))) from exc

    def _bounded(self, payload: object) -> dict[str, object]:
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ControlError(
                "COMMONS_RESPONSE_MALFORMED", "Commons response was not JSON"
            ) from exc
        if len(encoded.encode("utf-8")) > self.config.max_response_bytes:
            raise ControlError("COMMONS_RESPONSE_OVERSIZED", "Commons response exceeded Control policy")
        if not isinstance(payload, dict):
            raise ControlError(
                "COMMONS_RESPONSE_MALFORMED", "Commons response was not an object"
            )
        result = dict(payload)
        result.setdefault("content_trust", "UNTRUSTED")
        return result

    def _read(self, method: str, *args: Any, **kwargs: Any) -> dict[str, object]:
        client = self._client()
        try:
            operation = getattr(client, method, None)
            if not callable(operation) or method not in {
                "status",
                "work",
                "work_list",
                "work_status",
                "query",
                "get",
                "conversation",
                "evidence",
                "sync",
            }:
                raise ControlError(
                    "COMMONS_OPERATION_DENIED", "Commons operation is not allowed"
                )
            return self._bounded(operation(*args, **kwargs))
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("COMMONS_REQUEST_FAILED", redact_text(str(exc))) from exc
        finally:
            client.close()

    @classmethod
    def _text(cls, value: str | None, name: str) -> str | None:
        if value is None:
            return None
        if not value or len(value) > cls.MAX_TEXT_ARGUMENT or "\x00" in value:
            raise ControlError("INVALID_INPUT", f"{name} must be bounded non-empty text")
        return value

    @classmethod
    def _limit(cls, value: int) -> int:
        if not 1 <= int(value) <= cls.MAX_LIMIT:
            raise ControlError("INVALID_INPUT", f"limit must be between 1 and {cls.MAX_LIMIT}")
        return int(value)

    def status(self) -> dict[str, object]:
        try:
            payload = self._read("status")
            return {
                "available": payload.get("storeHealthy") is True,
                "reachable": True,
                "status": (
                    "available" if payload.get("storeHealthy") is True else "unavailable"
                ),
                "ready": payload.get("storeHealthy") is True,
                "transport": "local-unix-service",
                "authority": "read-only Commons consumer socket",
                **payload,
            }
        except ControlError as exc:
            return {
                "available": False,
                "reachable": False,
                "status": "unavailable",
                "ready": False,
                "code": exc.code,
                "transport": "local-unix-service",
                "content_trust": "UNTRUSTED",
                "diagnostic": redact_text(exc.message),
            }

    def work(self, limit: int = 100) -> dict[str, object]:
        return self._read("work_list", limit=self._limit(limit))

    def work_status(self, work_id: str) -> dict[str, object]:
        return self._read("work_status", self._text(work_id, "work_id") or "")

    def submit_work(self, request: dict[str, object]) -> dict[str, object]:
        operator = self._operator()
        try:
            return self._bounded(operator.submit_work(request))
        except Exception as exc:
            raise ControlError("COMMONS_WORK_SUBMIT_FAILED", redact_text(str(exc))) from exc
        finally:
            operator.close()

    def transition_work(self, work_id: str, transition: dict[str, object]) -> dict[str, object]:
        operator = self._operator()
        try:
            return self._bounded(operator.transition_work(work_id, transition))
        except Exception as exc:
            raise ControlError("COMMONS_WORK_TRANSITION_FAILED", redact_text(str(exc))) from exc
        finally:
            operator.close()

    def opportunities(self, limit: int = 100) -> dict[str, object]:
        return self._read("work", limit=self._limit(limit))

    def query(
        self,
        *,
        kind: str | None = None,
        state: str | None = None,
        subject: str | None = None,
        related: str | None = None,
        limit: int = 100,
        open_work: bool = False,
    ) -> dict[str, object]:
        return self._read(
            "query",
            kind=self._text(kind, "kind"),
            state=self._text(state, "state"),
            subject=self._text(subject, "subject"),
            related=self._text(related, "related"),
            limit=self._limit(limit),
            openWorkRequests=bool(open_work),
        )

    def get(self, digest: str) -> dict[str, object]:
        return self._read("get", self._text(digest, "digest") or "")

    def conversation(self, digest: str) -> dict[str, object]:
        return self._read("conversation", self._text(digest, "digest") or "")

    def evidence(self, digest: str) -> dict[str, object]:
        return self._read("evidence", self._text(digest, "digest") or "")

    def sync(self, cursor: dict[str, object] | None = None, limit: int = 1000) -> dict[str, object]:
        if cursor is not None:
            encoded = json.dumps(cursor, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > self.MAX_CURSOR_BYTES:
                raise ControlError("INVALID_INPUT", "cursor exceeds the configured bound")
        return self._read("sync", cursor, limit=self._limit(limit))


@dataclass(frozen=True, slots=True)
class FabricContractSupport:
    """Service-boundary capabilities declared by Fabric's public contract."""

    persistent_fleet_read: bool = False
    persistent_fleet_refresh: bool = False
    last_known_fleet_status: bool = False
    persistent_service_execution: bool = False
    persistent_detached_execution: bool = False
    persistent_service_capability_ingestion: bool = False
    persistent_worker_observations: bool = False
    scheduled_work_queue: bool = False
    worker_rendezvous: bool = False
    client_version: str | None = None
    contract_identity: str | None = None
    operations: tuple[str, ...] = ()

    @classmethod
    def from_client(cls, fabric: Any) -> FabricContractSupport:
        contract_method = getattr(getattr(fabric, "FabricClient", None), "contract", None)
        contract = contract_method() if callable(contract_method) else {}
        if not isinstance(contract, dict):
            contract = {}
        features = contract.get("features", {})
        if not isinstance(features, dict):
            features = {}
        return cls(
            persistent_fleet_read=features.get("persistent_fleet_read") is True,
            persistent_fleet_refresh=features.get("persistent_fleet_refresh") is True,
            last_known_fleet_status=features.get("last_known_fleet_status") is True,
            persistent_service_execution=features.get("persistent_service_execution") is True,
            persistent_detached_execution=features.get("persistent_detached_execution") is True,
            persistent_service_capability_ingestion=features.get("persistent_service_capability_ingestion") is True,
            persistent_worker_observations=features.get("persistent_worker_observations") is True,
            scheduled_work_queue=features.get("scheduled_work_queue") is True,
            worker_rendezvous=features.get("worker_rendezvous") is True,
            client_version=str(contract.get("package_version")) if contract.get("package_version") else None,
            contract_identity=str(contract.get("contract_identity")) if contract.get("contract_identity") else None,
        )

    @classmethod
    def from_service_status(cls, status: Any, fallback: FabricContractSupport) -> FabricContractSupport:
        features = status.get("service_features", {}) if isinstance(status, dict) else {}
        capabilities = status.get("service_capabilities", {}) if isinstance(status, dict) else {}
        if not isinstance(features, dict):
            return fallback
        operations = capabilities.get("operations") if isinstance(capabilities, dict) else {}
        advertised = tuple(
            sorted(str(name) for name, enabled in (operations or {}).items() if enabled)
        )
        return cls(
            persistent_fleet_read=features.get("persistent_fleet_read") is True,
            persistent_fleet_refresh=features.get("persistent_fleet_refresh") is True,
            last_known_fleet_status=features.get("last_known_fleet_status") is True,
            persistent_service_execution=features.get("persistent_service_execution") is True,
            persistent_detached_execution=features.get("persistent_detached_execution") is True,
            persistent_service_capability_ingestion=features.get("persistent_service_capability_ingestion") is True,
            persistent_worker_observations=features.get("persistent_worker_observations") is True,
            scheduled_work_queue=features.get("scheduled_work_queue") is True,
            worker_rendezvous=features.get("worker_rendezvous") is True,
            client_version=str(status.get("fabric_version") or fallback.client_version),
            contract_identity=str(status.get("public_contract_identity") or fallback.contract_identity),
            operations=advertised,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "persistent_fleet_read": self.persistent_fleet_read,
            "persistent_fleet_refresh": self.persistent_fleet_refresh,
            "last_known_fleet_status": self.last_known_fleet_status,
            "persistent_service_execution": self.persistent_service_execution,
            "persistent_detached_execution": self.persistent_detached_execution,
            "persistent_service_capability_ingestion": self.persistent_service_capability_ingestion,
            "persistent_worker_observations": self.persistent_worker_observations,
            "scheduled_work_queue": self.scheduled_work_queue,
            "worker_rendezvous": self.worker_rendezvous,
            "client_version": self.client_version,
            "contract_identity": self.contract_identity,
            "operations": list(self.operations),
        }


class FabricAdapter:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy | None = None) -> None:
        self.config = config
        self.policy = policy

    def _module(self) -> Any:
        try:
            return importlib.import_module("mncs_fabric")
        except ImportError:
            return _load_sibling_package("mncs_fabric", self.config.fabric_path)

    @staticmethod
    def _public_support(fabric: Any) -> FabricContractSupport:
        return FabricContractSupport.from_client(fabric)

    def _service_client(self, fabric: Any) -> Any:
        return fabric.FabricClient.connect(
            self.config.fabric_socket,
            client_identity=self.config.fabric_consumer_identity,
            timeout=self.config.fabric_service_timeout_seconds,
        )

    @staticmethod
    def _fleet_counts(workers: list[dict[str, Any]]) -> dict[str, int]:
        present = sum(
            1
            for worker in workers
            if worker.get("presence") == "PRESENT"
            or ("presence" not in worker and worker.get("availability") == "AVAILABLE")
        )
        available = sum(1 for worker in workers if worker.get("availability") == "AVAILABLE")
        stale = sum(1 for worker in workers if worker.get("presence") == "STALE" or worker.get("availability") == "UNKNOWN")
        return {"fleet_count": len(workers), "present_workers": present, "available_workers": available, "stale_workers": stale}

    @staticmethod
    def _version_compatibility(fabric: Any, controller: dict[str, Any]) -> dict[str, object]:
        client_version = str(getattr(fabric, "__version__", "unknown"))
        controller_version = controller.get("fabric_version")
        controller_version = str(controller_version) if controller_version else "unknown"
        features = controller.get("service_features") if isinstance(controller.get("service_features"), dict) else {}
        capabilities = controller.get("service_capabilities") if isinstance(controller.get("service_capabilities"), dict) else {}
        operations = capabilities.get("operations") if isinstance(capabilities.get("operations"), dict) else {}
        required_features = ("persistent_fleet_read", "last_known_fleet_status", "persistent_fleet_refresh")
        missing = [name for name in required_features if features.get(name) is not True]
        if "fleet.refresh" in operations and operations.get("fleet.refresh") is not True:
            missing.append("fleet.refresh")
        elif missing and "fleet.refresh" not in operations:
            missing.append("fleet.refresh")
        if missing:
            state = "restart_required"
            action = "restart_persistent_controller"
            reason = (
                "source/client is newer than the running persistent controller service; "
                f"missing {', '.join(missing)}"
            )
        elif client_version == "unknown" or controller_version == "unknown":
            state = "unknown"
            action = "fail_closed"
            reason = "Fabric version could not be determined"
        elif client_version != controller_version:
            state = "restart_required"
            action = "restart_persistent_controller"
            reason = "package versions differ; restart or update the persistent controller"
        else:
            state = "compatible"
            action = "dispatch_allowed"
            reason = "service capabilities match the connected client"
        return {
            "state": state,
            "client_version": client_version,
            "controller_version": controller_version,
            "action": action,
            "reason": reason,
            "missing_capabilities": missing,
        }

    def status(self) -> dict[str, object]:
        try:
            fabric = self._module()
            support = self._public_support(fabric)
            if self.config.fabric_mode in {"service", "transitional"}:
                if not support.persistent_fleet_read:
                    raise ControlError(
                        "FABRIC_SERVICE_FLEET_READ_UNSUPPORTED",
                        "Fabric public contract does not advertise persistent fleet reads",
                        details={"persistent_service_support": support.as_dict()},
                    )
                client = self._service_client(fabric)
                try:
                    controller = client.controller_status()
                    support = FabricContractSupport.from_service_status(controller, support)
                    workers = [dict(worker) for worker in client.workers()]
                finally:
                    client.close()
                counts = self._fleet_counts(workers)
                compatibility = self._version_compatibility(fabric, controller)
                return {
                    "available": True,
                    "status": "available" if workers else "empty",
                    "version": getattr(fabric, "__version__", "unknown"),
                    "controller_connected": True,
                    "client_fabric_version": getattr(fabric, "__version__", "unknown"),
                    "controller_version": controller.get("fabric_version"),
                    "compatibility": compatibility,
                    "controller_contract_identity": controller.get("public_contract_identity"),
                    "service_contract": controller.get("service_contract"),
                    "service_mode": self.config.fabric_mode == "service",
                    "fabric_mode": self.config.fabric_mode,
                    "fleet_authority": "persistent-controller",
                    "execution_transport": (
                        "persistent-service" if self.config.fabric_mode == "service" and support.persistent_service_execution
                        else "embedded-direct-compatibility" if self.config.fabric_mode == "transitional"
                        else "unsupported"
                    ),
                    "persistent_service_support": support.as_dict(),
                    "controller": {"runtime": controller.get("service_runtime"), "worker_rendezvous": controller.get("worker_rendezvous")},
                    **counts,
                    "known_nodes": [self._public_worker(worker) for worker in workers],
                }
            registry_path = prepare_fabric_runtime(self.config)
            client = fabric.FabricClient(self.config.fabric_controller_id, self.config.fabric_state)
            try:
                registry_report: dict[str, object] | None = None
                if registry_path.exists():
                    registry_report = client.load_registry(registry_path)
                client.refresh_workers()
                workers = [dict(worker) for worker in client.workers()]
            finally:
                close = getattr(client, "close", None)
                if callable(close):
                    close()
            counts = self._fleet_counts(workers)
            return {
                "available": True,
                "status": "available" if workers else "empty",
                "version": getattr(fabric, "__version__", "unknown"),
                "fabric_mode": self.config.fabric_mode,
                "controller_connected": True,
                "fleet_authority": "embedded-compatibility-controller",
                "execution_transport": "embedded-direct",
                "persistent_service_support": support.as_dict(),
                "registry_path": str(registry_path),
                "state_path": str(self.config.fabric_state),
                "state_policy": "explicit-embedded-compatibility",
                "registry": registry_report,
                **counts,
                "known_nodes": [self._public_worker(worker) for worker in workers],
            }
        except Exception as exc:
            return {
                "available": False,
                "status": "unavailable",
                "controller_connected": False,
                "fabric_mode": self.config.fabric_mode,
                "fleet_authority": "persistent-controller" if self.config.fabric_mode in {"service", "transitional"} else "embedded-compatibility-controller",
                "execution_transport": "unsupported" if self.config.fabric_mode == "service" else self.config.fabric_execution_mode,
                "known_nodes": [],
                "diagnostic": redact_text(str(exc)),
            }

    def dispatch(
        self,
        task_type: str,
        project: str,
        model: str | None = None,
        node: str | None = None,
        parameters: dict[str, object] | None = None,
        *,
        detached: bool = False,
    ) -> dict[str, object]:
        """Construct current public Fabric artifacts for bounded task families."""
        fabric = self._module()
        support = self._public_support(fabric)
        service_controller: dict[str, Any] | None = None
        if self.config.fabric_mode == "service":
            client = self._service_client(fabric)
            try:
                service_controller = client.controller_status()
                support = FabricContractSupport.from_service_status(service_controller, support)
            finally:
                client.close()
            if not support.persistent_service_execution:
                raise ControlError(
                    "FABRIC_SERVICE_EXECUTION_UNSUPPORTED",
                    "persistent Fabric service does not advertise execution dispatch",
                    details={
                        "fabric_controller": "persistent-service",
                        "fleet_authority": "persistent-controller",
                        "execution_transport": "unsupported",
                        "persistent_service_support": support.as_dict(),
                    },
                )
            compatibility = self._version_compatibility(fabric, service_controller or {})
            if compatibility["state"] != "compatible":
                raise ControlError(
                    "FABRIC_SERVICE_RESTART_REQUIRED"
                    if compatibility["state"] == "restart_required"
                    else "FABRIC_VERSION_MISMATCH",
                    str(compatibility.get("reason") or "Fabric client and persistent controller are incompatible"),
                    details={"compatibility": compatibility},
                )
        if self.config.fabric_mode == "transitional":
            try:
                fabric = self._module()
                authority_client = self._service_client(fabric)
                try:
                    authority_client.controller_status()
                finally:
                    authority_client.close()
            except Exception as exc:
                raise ControlError(
                    "FABRIC_CONTROLLER_UNAVAILABLE",
                    "transitional execution requires the persistent Fabric controller to remain reachable",
                    details={
                        "fabric_controller": "persistent-service",
                        "fleet_authority": "persistent-controller",
                        "execution_transport": "embedded-direct-compatibility",
                        "diagnostic": redact_text(str(exc)),
                    },
                ) from exc
        if self.policy is None:
            raise ControlError("FABRIC_UNAVAILABLE", "workspace policy is unavailable")
        if task_type not in {"pytest", "python", "cargo_test"}:
            raise ControlError("INVALID_INPUT", "task_type must be pytest, python, or cargo_test")
        root = self.policy.project_path(project)
        values = parameters or {}
        if not isinstance(values, dict):
            raise ControlError("INVALID_INPUT", "parameters must be an object")
        if "artifact_path" not in values:
            raise ControlError(
                "FABRIC_ARTIFACT_ROOT_REQUIRED",
                "raw Fabric jobs require an explicit bounded artifact_path",
            )
        artifact_path = str(values["artifact_path"])
        relative = self.policy.normalize_relative(artifact_path)
        if relative == Path("."):
            raise ControlError(
                "FABRIC_ARTIFACT_ROOT_TOO_BROAD",
                "raw Fabric jobs cannot bundle the entire project; select a bounded artifact subdirectory",
            )
        artifact_root = root.joinpath(*relative.parts).resolve(strict=True)
        try:
            artifact_root.relative_to(root)
        except ValueError as exc:
            raise ControlError("PATH_ESCAPE", "Fabric artifact path escapes project") from exc
        if not artifact_root.is_dir() or artifact_root.is_symlink():
            raise ControlError("INVALID_INPUT", "artifact_path must be a real directory")
        arguments = values.get("arguments", [])
        if not isinstance(arguments, list) or len(arguments) > 64 or not all(
            isinstance(item, str) and item and len(item) <= 4096 and "\x00" not in item for item in arguments
        ):
            raise ControlError("INVALID_INPUT", "parameters.arguments must be a bounded string array")
        if task_type == "pytest":
            argv = ["@python", "-m", "pytest", *arguments]
            capabilities = ["python"]
        elif task_type == "cargo_test":
            argv = ["/usr/bin/cargo", "test", *arguments]
            capabilities = ["cargo"]
        else:
            script = str(values.get("script", ""))
            script_path = self.policy.normalize_relative(script, allow_root=False).as_posix()
            candidate_script = artifact_root / script_path
            if not candidate_script.is_file() or candidate_script.is_symlink():
                raise ControlError("INVALID_INPUT", "python task script must be a regular artifact file")
            argv = ["@python", script_path, *arguments]
            capabilities = ["python"]
        timeout = float(values.get("timeout_seconds", self.config.default_timeout_seconds))
        timeout = min(max(timeout, 0.05), self.config.max_timeout_seconds)
        result_paths = values.get("result_paths", [])
        if not isinstance(result_paths, list) or not all(isinstance(item, str) for item in result_paths):
            raise ControlError("INVALID_INPUT", "result_paths must be a string array")
        network = bool(values.get("network", False))
        try:
            artifacts = importlib.import_module("mncs_fabric.artifacts")
            bundles = importlib.import_module("mncs_fabric.bundles")
            models = importlib.import_module("mncs_fabric.models")
            manifest = artifacts.build_manifest(artifact_root)
            idempotency_key = values.get("idempotency_key")
            if detached and (
                not isinstance(idempotency_key, str)
                or not idempotency_key
                or len(idempotency_key) > 256
                or "\x00" in idempotency_key
            ):
                raise ControlError(
                    "FABRIC_IDEMPOTENCY_KEY_REQUIRED",
                    "detached Fabric jobs require a bounded idempotency_key",
                )
            uniqueness = idempotency_key if detached else str(time.time_ns())
            job_suffix = hashlib.sha256(
                f"{project}:{task_type}:{manifest['manifest_identity']}:{uniqueness}".encode()
            ).hexdigest()[:20]
            plan = models.validate_job_plan(
                {
                    "schema_version": "mncs-fabric.job-plan.v0.1",
                    "job_id": f"mncs-control:{job_suffix}",
                    "candidate_identity": manifest["manifest_identity"],
                    "evaluator_identity": None,
                    "artifact_manifest_identity": manifest["manifest_identity"],
                    "argv": argv,
                    "working_directory": ".",
                    "timeout_seconds": timeout,
                    "output_limit_bytes": self.config.max_output_bytes,
                    "environment": {},
                    "required_capabilities": capabilities,
                    "result_paths": result_paths,
                    "network_policy": "UNRESTRICTED" if network else "DECLARED_OFFLINE",
                }
            )
            archive_root = (
                self.config.job_state_path.parent / "fabric-bundles"
                if self.config.fabric_mode == "service"
                else self.config.fabric_state.parent / "bundles"
            )
            archive = archive_root / f"{job_suffix}.zip"
            bundle_report = bundles.build_bundle_archive(artifact_root, archive).as_dict()
            registry_report = None
            if self.config.fabric_mode == "service":
                client = self._service_client(fabric)
            else:
                registry_path = prepare_fabric_runtime(self.config)
                client = fabric.FabricClient(self.config.fabric_controller_id, self.config.fabric_state)
            try:
                if self.config.fabric_mode != "service":
                    registry_report = client.load_registry(registry_path) if registry_path.exists() else None
                if detached:
                    if self.config.fabric_mode != "service" or not support.persistent_detached_execution:
                        raise ControlError(
                            "FABRIC_DETACHED_EXECUTION_UNSUPPORTED",
                            "detached execution requires live persistent Fabric support",
                        )
                    accepted = client.submit_execution(
                        plan,
                        manifest,
                        worker_id=node,
                        idempotency_key=str(idempotency_key),
                        execution_bundle_archive=archive,
                    )
                    results = []
                else:
                    accepted = None
                    results = client.execute(
                        plan,
                        manifest,
                        worker_id=node,
                        execution_bundle_archive=archive,
                    )
            finally:
                close = getattr(client, "close", None)
                if callable(close):
                    close()
            return {
                "status": "accepted" if detached else "completed",
                "accepted": accepted,
                "task_type": task_type,
                "project": project,
                "model": model,
                "model_routing": "not-applicable-to-raw-fabric-execution" if model else None,
                "node": node,
                "plan": plan,
                "manifest_identity": manifest["manifest_identity"],
                "bundle": bundle_report,
                "registry": registry_report,
                "fabric_controller": "persistent-service" if self.config.fabric_mode in {"service", "transitional"} else "embedded-compatibility",
                "fleet_authority": "persistent-controller" if self.config.fabric_mode in {"service", "transitional"} else "embedded-compatibility-controller",
                "execution_transport": "persistent-service" if self.config.fabric_mode == "service" and support.persistent_service_execution else self.config.fabric_execution_mode,
                "results": results,
            }
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("FABRIC_DISPATCH_FAILED", redact_text(str(exc))) from exc

    def work_status(self, work_id: str) -> dict[str, object]:
        return self._detached_read("execution_status", work_id)

    def work_result(self, work_id: str) -> dict[str, object]:
        return self._detached_read("execution_result", work_id)

    def work_list(self, limit: int = 100) -> dict[str, object]:
        if not 1 <= int(limit) <= 1000:
            raise ControlError("INVALID_INPUT", "limit must be between 1 and 1000")
        fabric = self._module()
        client = self._service_client(fabric)
        try:
            return {"work": client.executions(limit=int(limit)), "persistent": True}
        except Exception as exc:
            raise ControlError("FABRIC_REQUEST_FAILED", redact_text(str(exc))) from exc
        finally:
            client.close()

    def schedule_list(self) -> dict[str, object]:
        fabric = self._module()
        client = self._service_client(fabric)
        try:
            payload = dict(client.scheduled_work())
        except Exception as exc:
            raise ControlError("FABRIC_REQUEST_FAILED", redact_text(str(exc))) from exc
        finally:
            client.close()
        payload["commons_authority"] = "none"
        payload["authority"] = "persistent-fabric"
        return payload

    def schedule_tick(self, now: str | None = None) -> dict[str, object]:
        fabric = self._module()
        client = self._service_client(fabric)
        try:
            arguments = {} if now is None else {"now": now}
            payload = dict(client.tick_schedule(**arguments))
        except Exception as exc:
            raise ControlError("FABRIC_REQUEST_FAILED", redact_text(str(exc))) from exc
        finally:
            client.close()
        payload["commons_authority"] = "none"
        return payload

    def _detached_read(self, operation: str, work_id: str) -> dict[str, object]:
        if not isinstance(work_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", work_id):
            raise ControlError("INVALID_INPUT", "work_id must be a SHA-256 identity")
        fabric = self._module()
        client = self._service_client(fabric)
        try:
            method = getattr(client, operation)
            return dict(method(work_id))
        except Exception as exc:
            raise ControlError("FABRIC_REQUEST_FAILED", redact_text(str(exc))) from exc
        finally:
            client.close()

    @staticmethod
    def _public_worker(worker: dict[str, Any]) -> dict[str, object]:
        allowed = (
            "worker_id", "availability", "available", "host", "port", "platform", "os",
            "capabilities", "resource_snapshot", "model_names", "model_inventory",
            "loaded_model_names", "capability_inventory_status", "runtime_observation",
        )
        return {key: worker[key] for key in allowed if key in worker}


class ModelAdapter:
    def __init__(self, config: ControlConfig, ollama: OllamaAdapter, fabric: FabricAdapter) -> None:
        self.config = config
        self.ollama = ollama
        self.fabric = fabric

    def status(self) -> dict[str, object]:
        inventory: list[dict[str, object]] = []
        ollama = self.ollama.status()
        inventory.extend(ollama.get("models", []))
        fabric = self.fabric.status()
        for node in fabric.get("known_nodes", []):
            if not isinstance(node, dict):
                continue
            host = node.get("worker_id")
            for name in node.get("model_names", []) or []:
                inventory.append({"model": name, "runtime": "fabric", "provider": "ollama", "host_node": host, "available": node.get("availability") == "AVAILABLE", "capabilities": node.get("capabilities", [])})
        return {"models": inventory, "sources": {"ollama": ollama.get("status"), "fabric": fabric.get("status")}}


class ForgeAdapter:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy | None = None) -> None:
        self.config = config
        self.policy = policy

    async def _mcp_probe(self, executable: Path, config: Path) -> dict[str, object]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        required = {
            "mncs_forge_project_inspect",
            "mncs_forge_providers_list",
            "mncs_forge_capability_blockers",
        }

        def value(item: object, *names: str) -> object:
            for name in names:
                try:
                    return getattr(item, name)
                except AttributeError:
                    continue
            return None

        def server_value(initialization: object, *names: str) -> object:
            return value(value(initialization, "serverInfo", "server_info"), *names)
        parameters = StdioServerParameters(
            command=str(executable),
            args=["--config", str(config), "--mode", "development"],
            env={**os.environ, "MNCS_FORGE_STATE_DIR": str(self.config.job_state_path.parent / "forge-state")},
        )
        try:
            async with (
                stdio_client(parameters) as (reader, writer),
                ClientSession(reader, writer) as session,
            ):
                initialization = await session.initialize()
                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                missing = sorted(required - names)
                if missing:
                    return {
                        "health_status": "capability_unavailable",
                        "reachable": True,
                        "missing_capabilities": missing,
                        "server": server_value(initialization, "name"),
                        "version": server_value(initialization, "version"),
                        "protocol_version": value(initialization, "protocolVersion", "protocol_version"),
                        "capabilities": sorted(names),
                    }
                inspection = await session.call_tool("mncs_forge_project_inspect", {})
                if bool(value(inspection, "isError", "is_error")):
                    return {
                        "health_status": "capability_unavailable",
                        "reachable": True,
                        "diagnostic": "project inspection tool returned an MCP error",
                        "server": server_value(initialization, "name"),
                        "version": server_value(initialization, "version"),
                        "protocol_version": value(initialization, "protocolVersion", "protocol_version"),
                        "capabilities": sorted(names),
                    }
                return {
                    "health_status": "healthy",
                    "reachable": True,
                    "server": server_value(initialization, "name"),
                    "version": server_value(initialization, "version"),
                    "protocol_version": value(initialization, "protocolVersion", "protocol_version"),
                    "capabilities": sorted(names),
                }
        except (FileNotFoundError, PermissionError) as exc:
            return {"health_status": "process_start_failed", "reachable": False, "diagnostic": redact_text(str(exc))}
        except BaseException as exc:
            return {"health_status": "mcp_initialization_failed", "reachable": False, "diagnostic": redact_text(str(exc))}

    def _probe(self, executable: Path, config: Path) -> dict[str, object]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._mcp_probe(executable, config))

        result: list[dict[str, object]] = []

        def run_probe() -> None:
            result.append(asyncio.run(self._mcp_probe(executable, config)))

        worker = threading.Thread(target=run_probe, name="forge-mcp-health", daemon=True)
        worker.start()
        worker.join(timeout=30)
        if not result:
            return {
                "health_status": "mcp_initialization_failed",
                "reachable": False,
                "diagnostic": "Forge MCP health probe timed out after 30 seconds",
            }
        return result[0]

    def status(self) -> dict[str, object]:
        """Report Forge configuration, MCP reachability, and public capabilities."""

        executable = self.config.forge_server_path
        forge_config = self.config.forge_probe_config
        base: dict[str, object] = {
            "configured": forge_config is not None and forge_config.is_file(),
            "reachable": False,
            "protocol": "MCP",
            "executable": str(executable),
            "config": str(forge_config) if forge_config else None,
            "operations": [],
        }
        if not executable.is_file() or not os.access(executable, os.X_OK):
            base.update(available=False, status="executable_missing", health_status="executable_missing")
            return base
        if forge_config is None or not forge_config.is_file():
            base.update(available=False, status="configuration_missing", health_status="configuration_missing")
            return base
        probe = self._probe(executable, forge_config)
        base.update(probe)
        if probe.get("health_status") != "healthy":
            base.update(available=False, status=str(probe["health_status"]))
            return base
        try:
            _load_sibling_package("mncs_forge", self.config.forge_path)
            operations = importlib.import_module("mncs_forge.operations")
            registry = getattr(operations, "DEFAULT_OPERATION_REGISTRY", None)
            inventory = registry.inventory() if registry and hasattr(registry, "inventory") else {}
            names = sorted(
                str(item.get("operation_id"))
                for item in inventory.get("operations", [])
                if isinstance(item, dict) and item.get("operation_id")
            )
            base.update({
                "available": True,
                "status": "available",
                "version": getattr(importlib.import_module("mncs_forge"), "__version__", probe.get("version", "unknown")),
                "operations": names[:200],
                "operation_count": len(names),
                "authority": "Forge owns evaluation semantics, evidence, scoring, and claims",
            })
            return base
        except Exception as exc:
            base.update(available=False, status="library_unavailable", diagnostic=redact_text(str(exc)))
            return base

    def evaluate(
        self,
        repository: str,
        case_study: str,
        model: str | None = None,
        evaluation_profile: str | None = None,
    ) -> dict[str, object]:
        if repository in self.config.repositories:
            _, root = resolve_repository(self.config, repository)
        elif self.policy is not None:
            root = self.policy.project_path(repository)
        else:
            raise ControlError("UNAUTHORIZED_REPOSITORY", f"repository alias is unknown: {repository}")
        forge_config_path = root / self.config.forge_config_name
        if not forge_config_path.is_file():
            return {"status": "not_supported_yet", "reason": "repository has no Forge configuration", "forge_config": str(forge_config_path)}
        try:
            _load_sibling_package("mncs_forge", self.config.forge_path)
            config_module = importlib.import_module("mncs_forge.config")
            engine_module = importlib.import_module("mncs_forge.engine")
            operations = importlib.import_module("mncs_forge.operations")
            forge_config = config_module.load_config(forge_config_path)
            if case_study not in forge_config.workflows:
                return {"status": "not_supported_yet", "reason": "case_study is not a configured Forge workflow", "available_workflows": sorted(forge_config.workflows)}
            forge = engine_module.Forge(forge_config, mode="development")
            result = operations.DEFAULT_OPERATION_REGISTRY.invoke(
                forge,
                "development.checks.run",
                {"workflow_names": [case_study], "candidate_identity": None},
                interface=operations.OperationInterface.INTERNAL,
            )
            return {"status": "completed", "repository": repository, "case_study": case_study, "model": model, "evaluation_profile": evaluation_profile, "forge_result": result}
        except Exception as exc:
            return {"status": "not_supported_yet", "reason": "Forge interface could not be loaded", "diagnostic": redact_text(str(exc))}


class IntegrationBundle:
    def __init__(
        self,
        config: ControlConfig,
        actions: ActionRegistry,
        policy: WorkspacePolicy | None = None,
        sandbox: Sandbox | None = None,
    ) -> None:
        ollama = OllamaAdapter(config, actions)
        fabric = FabricAdapter(config, policy)
        self.tests = TestAdapter(config, actions, policy, sandbox)
        self.ollama = ollama
        self.system = SystemAdapter(config, actions, ollama)
        self.harness = HarnessAdapter(config)
        self.commons = CommonsAdapter(config)
        self.fabric = fabric
        self.models = ModelAdapter(config, ollama, fabric)
        self.forge = ForgeAdapter(config, policy)

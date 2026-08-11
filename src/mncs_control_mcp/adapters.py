from __future__ import annotations

import hashlib
import importlib
import os
import platform
import re
import shlex
import shutil
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .actions import ActionRegistry, run_bounded
from .config import ControlConfig
from .errors import ControlError
from .sandbox import Sandbox
from .security import redact_text, resolve_repository, safe_host_probe_environment
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
        if detected == "pytest":
            commands.append({"suite": "pytest", "command": ["python", "-m", "pytest"]})
        elif detected == "cargo":
            commands.append({"suite": "cargo", "command": ["cargo", "test"]})
        elif detected == "node":
            commands.append({"suite": "node", "command": ["npm", "test", "--"]})
        elif detected == "go":
            commands.append({"suite": "go", "command": ["go", "test", "./..."]})
        elif detected == "cmake":
            commands.append({"suite": "cmake", "command": ["ctest", "--test-dir", "build"]})
        return {
            "repository": key,
            "path": str(root),
            "detected_suite": detected,
            "supported_suites": list(self.SUITES),
            "commands": commands,
            "test_directories": [name for name in ("tests", "test", "spec") if (root / name).is_dir()],
        }

    def _command(self, root: Path, suite: str, component: str | None) -> tuple[str, ...]:
        if suite not in self.SUITES:
            raise ControlError("INVALID_TEST_SUITE", f"test suite must be one of {self.SUITES}")
        if suite == "repository":
            suite = self._detected_suite(root) or ""
            if not suite:
                raise ControlError("TEST_SUITE_UNAVAILABLE", "no approved repository test runner was detected")
        if suite == "cargo":
            return ("cargo", "test", "--", component) if component else ("cargo", "test")
        if suite == "pytest":
            return ("python", "-m", "pytest", component) if component else ("python", "-m", "pytest")
        if suite == "ruff":
            return ("ruff", "check", component or ".")
        if suite == "node":
            return ("npm", "test", "--", component) if component else ("npm", "test", "--")
        if suite == "go":
            return ("go", "test", component or "./...")
        if suite == "cmake":
            return ("ctest", "--test-dir", component or "build")
        raise ControlError("INVALID_TEST_SUITE", f"test suite must be one of {self.SUITES}")

    @staticmethod
    def _summary(suite: str, stdout: str, stderr: str) -> dict[str, object]:
        text = f"{stdout}\n{stderr}"
        patterns = {
            "passed": r"(?i)(?:passed|tests? passed)[\s:=]+(\d+)",
            "failed": r"(?i)(?:failed|tests? failed)[\s:=]+(\d+)",
            "skipped": r"(?i)(?:skipped|tests? skipped)[\s:=]+(\d+)",
        }
        result: dict[str, object] = {}
        for name, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                result[name] = int(match.group(1))
        return result

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
        argv = self._command(root, test_suite, component)
        self.actions.resolve(f"test.{('cargo' if argv[0] == 'cargo' else 'pytest')}") if argv[0] in {"cargo", "python"} else None
        self_test = root.name == "mncs-control-mcp"
        command = shlex.join(argv)
        security_skips: list[dict[str, str]] = []
        if self_test and argv[:3] == ("python", "-m", "pytest"):
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
            "command_identity": f"approved:{'cargo' if argv[0] == 'cargo' else 'pytest'}",
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
            "test_counts": self._summary(test_suite, stdout, stderr),
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
            if profile != "quick" and shutil.which("ruff"):
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
            loader = importlib.import_module("epi13_local_harness.config").load_config
            harness_config = loader(path)
            return {
                "available": True,
                "status": "configured",
                "package_version": getattr(package, "__version__", "unknown"),
                "config_path": str(path or "default"),
                "fabric_enabled": bool(harness_config.fabric.enabled),
            }
        except Exception as exc:
            return {"available": False, "status": "unavailable", "diagnostic": redact_text(str(exc))}


class FabricAdapter:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy | None = None) -> None:
        self.config = config
        self.policy = policy

    def _module(self) -> Any:
        try:
            return importlib.import_module("mncs_fabric")
        except ImportError:
            return _load_sibling_package("mncs_fabric", self.config.fabric_path)

    def status(self) -> dict[str, object]:
        try:
            fabric = self._module()
            client = fabric.FabricClient(self.config.fabric_controller_id, self.config.fabric_state)
            registry_report: dict[str, object] | None = None
            if self.config.fabric_registry.exists():
                registry_report = client.load_registry(self.config.fabric_registry)
            workers = client.workers()
            return {
                "available": True,
                "status": "available" if workers else "empty",
                "version": getattr(fabric, "__version__", "unknown"),
                "registry": registry_report,
                "known_nodes": [self._public_worker(worker) for worker in workers],
            }
        except Exception as exc:
            return {"available": False, "status": "unavailable", "known_nodes": [], "diagnostic": redact_text(str(exc))}

    def dispatch(
        self,
        task_type: str,
        project: str,
        model: str | None = None,
        node: str | None = None,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Construct current public Fabric artifacts for bounded task families."""
        if self.policy is None:
            raise ControlError("FABRIC_UNAVAILABLE", "workspace policy is unavailable")
        if task_type not in {"pytest", "python", "cargo_test"}:
            raise ControlError("INVALID_INPUT", "task_type must be pytest, python, or cargo_test")
        root = self.policy.project_path(project)
        values = parameters or {}
        if not isinstance(values, dict):
            raise ControlError("INVALID_INPUT", "parameters must be an object")
        artifact_path = str(values.get("artifact_path", "."))
        relative = self.policy.normalize_relative(artifact_path)
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
            fabric = self._module()
            artifacts = importlib.import_module("mncs_fabric.artifacts")
            bundles = importlib.import_module("mncs_fabric.bundles")
            models = importlib.import_module("mncs_fabric.models")
            manifest = artifacts.build_manifest(artifact_root)
            job_suffix = hashlib.sha256(
                f"{project}:{task_type}:{manifest['manifest_identity']}:{time.time_ns()}".encode()
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
            archive = self.config.fabric_state.parent / "bundles" / f"{job_suffix}.zip"
            bundle_report = bundles.build_bundle_archive(artifact_root, archive).as_dict()
            client = fabric.FabricClient(self.config.fabric_controller_id, self.config.fabric_state)
            registry_report = client.load_registry(self.config.fabric_registry) if self.config.fabric_registry.exists() else None
            results = client.execute(
                plan,
                manifest,
                worker_id=node,
                execution_bundle_archive=archive,
            )
            return {
                "status": "completed",
                "task_type": task_type,
                "project": project,
                "model": model,
                "model_routing": "not-applicable-to-raw-fabric-execution" if model else None,
                "node": node,
                "plan": plan,
                "manifest_identity": manifest["manifest_identity"],
                "bundle": bundle_report,
                "registry": registry_report,
                "results": results,
            }
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("FABRIC_DISPATCH_FAILED", redact_text(str(exc))) from exc

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
        self.fabric = fabric
        self.models = ModelAdapter(config, ollama, fabric)
        self.forge = ForgeAdapter(config, policy)

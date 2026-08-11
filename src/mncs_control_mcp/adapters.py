from __future__ import annotations

import importlib
import os
import platform
import re
import shutil
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .actions import ActionRegistry, CommandResult, run_bounded
from .config import ControlConfig
from .errors import ControlError
from .security import (
    public_relative_path,
    redact_text,
    resolve_repository,
)


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


class GitAdapter:
    def __init__(self, config: ControlConfig, actions: ActionRegistry) -> None:
        self.config = config
        self.actions = actions

    def status(self, repository: str) -> dict[str, object]:
        key, root = resolve_repository(self.config, repository)
        if not root.is_dir():
            return {"repository": key, "path": str(root), "exists": False, "status": "missing"}
        if not (root / ".git").exists():
            return {"repository": key, "path": str(root), "exists": True, "status": "not_git"}

        def git(*args: str) -> CommandResult:
            self.actions.resolve("repo.status")
            return run_bounded(
                ("git", *args), cwd=root, timeout_seconds=15, output_limit_bytes=self.config.max_output_bytes
            )

        branch = git("branch", "--show-current")
        head = git("rev-parse", "HEAD")
        porcelain = git("status", "--porcelain=v1", "--untracked-files=all")
        upstream = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
        ahead_behind = git("rev-list", "--left-right", "--count", "HEAD...@{upstream}")

        modified: list[str] = []
        untracked: list[str] = []
        omitted = 0
        for line in porcelain.stdout.splitlines():
            if len(line) < 4:
                continue
            state, value = line[:2], line[3:]
            visible = public_relative_path(root, str((root / value).resolve()))
            if visible is None:
                omitted += 1
                continue
            if state == "??":
                untracked.append(visible)
            else:
                modified.append(visible)
        counts = ahead_behind.stdout.split()
        result: dict[str, object] = {
            "repository": key,
            "path": str(root),
            "exists": True,
            "branch": branch.stdout.strip() or None,
            "head": head.stdout.strip() or None,
            "clean": not modified and not untracked and porcelain.returncode == 0,
            "modified_files": sorted(modified),
            "untracked_files": sorted(untracked),
            "sensitive_files_omitted": omitted,
            "upstream": upstream.stdout.strip() or None,
            "ahead": int(counts[0]) if len(counts) == 2 and counts[0].isdigit() else None,
            "behind": int(counts[1]) if len(counts) == 2 and counts[1].isdigit() else None,
        }
        if porcelain.returncode != 0:
            result["diagnostic"] = redact_text(porcelain.stderr)
        return result


class TestAdapter:
    SUITES = ("repository", "pytest", "cargo")

    def __init__(self, config: ControlConfig, actions: ActionRegistry) -> None:
        self.config = config
        self.actions = actions

    def _command(self, root: Path, suite: str, component: str | None) -> tuple[str, ...]:
        if suite not in self.SUITES:
            raise ControlError("INVALID_TEST_SUITE", f"test suite must be one of {self.SUITES}")
        if suite == "repository":
            if (root / "Cargo.toml").is_file():
                suite = "cargo"
            elif (root / "pyproject.toml").is_file() or (root / "tests").is_dir():
                suite = "pytest"
            else:
                raise ControlError("TEST_SUITE_UNAVAILABLE", "no approved repository test runner was detected")
        if suite == "cargo":
            return ("cargo", "test", "--", component) if component else ("cargo", "test")
        return (sys.executable, "-m", "pytest", component) if component else (sys.executable, "-m", "pytest")

    def run(
        self,
        repository: str,
        test_suite: str,
        component: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, object]:
        key, root = resolve_repository(self.config, repository)
        if not root.is_dir():
            raise ControlError("REPOSITORY_MISSING", f"approved repository does not exist: {key}")
        if component is not None:
            if not re.fullmatch(r"[A-Za-z0-9_.:\-/]{1,160}", component) or component.startswith("-") or ".." in Path(component).parts:
                raise ControlError("INVALID_INPUT", "component must be a safe relative test selector")
        timeout_value = self.config.default_timeout_seconds if timeout is None else float(timeout)
        timeout_value = min(timeout_value, self.config.max_timeout_seconds)
        argv = self._command(root, test_suite, component)
        self.actions.resolve(f"test.{('cargo' if argv[0] == 'cargo' else 'pytest')}")
        started = utc_now()
        result = run_bounded(
            argv,
            cwd=root,
            timeout_seconds=timeout_value,
            output_limit_bytes=self.config.max_output_bytes,
        )
        completed = utc_now()
        passed = result.returncode == 0 and not result.timed_out
        return {
            "repository": key,
            "test_suite": test_suite,
            "resolved_command": list(argv),
            "command_identity": f"approved:{'cargo' if argv[0] == 'cargo' else 'pytest'}",
            "started_at": started,
            "completed_at": completed,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "output_truncated": result.output_truncated,
            "timed_out": result.timed_out,
            "duration_seconds": round(result.duration_seconds, 3),
            "summary": "PASS" if passed else "FAIL",
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
            (executable, "list"), timeout_seconds=15, output_limit_bytes=self.config.max_output_bytes
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
        )
        gpus = []
        driver = None
        for line in result.stdout.splitlines():
            fields = [item.strip() for item in line.split(",")]
            if fields:
                driver = driver or (fields[1] if len(fields) > 1 else None)
                gpus.append({"name": fields[0], "driver": fields[1] if len(fields) > 1 else None, "vram_mib": fields[2] if len(fields) > 2 else None})
        cuda = None
        version = run_bounded((executable,), timeout_seconds=10, output_limit_bytes=16 * 1024)
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
    def __init__(self, config: ControlConfig) -> None:
        self.config = config

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
    def __init__(self, config: ControlConfig) -> None:
        self.config = config

    def evaluate(
        self,
        repository: str,
        case_study: str,
        model: str | None = None,
        evaluation_profile: str | None = None,
    ) -> dict[str, object]:
        _, root = resolve_repository(self.config, repository)
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
    def __init__(self, config: ControlConfig, actions: ActionRegistry) -> None:
        ollama = OllamaAdapter(config, actions)
        fabric = FabricAdapter(config)
        self.git = GitAdapter(config, actions)
        self.tests = TestAdapter(config, actions)
        self.ollama = ollama
        self.system = SystemAdapter(config, actions, ollama)
        self.harness = HarnessAdapter(config)
        self.fabric = fabric
        self.models = ModelAdapter(config, ollama, fabric)
        self.forge = ForgeAdapter(config)

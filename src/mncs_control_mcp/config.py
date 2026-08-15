from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ControlError

DEFAULT_REPOSITORIES = {
    "local_harness": "mncs-harness",
    "fabric": "mncs-fabric",
    "forge": "mncs-forge-mcp",
    "language": "mncs-language",
    "standard": "machine-native-complexity-standard",
    "mncds": "machine-native-complexity-development-specification",
    "commons": "MNCS-Commons",
    "atlas": "mncs-atlas",
    "reference_studies": "mncs-reference-studies",
}
LEGACY_HARNESS_DIRECTORIES = ("mncs-harness", "epi13-local-harness")


@dataclass(frozen=True)
class ControlConfig:
    name: str = "mncs-control-mcp"
    workspace_root: Path = field(default_factory=lambda: Path.home() / "Documents" / "Projects")
    repositories: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_REPOSITORIES))
    protect_root: bool = True
    default_scope: str = "project"
    allow_workspace_scope: bool = True
    allow_terminal: bool = True
    terminal_network_default: bool = False
    terminal_network_allowed: bool = True
    sandbox_backend: str = "auto"
    require_real_sandbox: bool = True
    sandbox_home: Path = field(
        default_factory=lambda: Path.home() / ".local" / "share" / "mncs-control-mcp" / "sandbox-home"
    )
    sandbox_tool_paths: tuple[Path, ...] = field(default_factory=tuple)
    safe_environment: dict[str, str] = field(default_factory=dict)
    default_timeout_seconds: float = 120.0
    max_timeout_seconds: float = 1800.0
    max_output_bytes: int = 1024 * 1024
    max_response_bytes: int = 2 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024
    max_listing_entries: int = 2000
    max_search_results: int = 500
    max_concurrent_jobs: int = 4
    job_retention_seconds: int = 86400
    job_state_path: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-control-mcp" / "jobs.json"
    )
    audit_path: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-control-mcp" / "audit.jsonl"
    )
    git_allow_fetch: bool = True
    git_allow_pull: bool = True
    git_allow_push: bool = True
    git_allow_clone: bool = True
    git_allow_force_push: bool = False
    git_use_ssh_agent: bool = True
    harness_config: Path | None = None
    fabric_registry: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-control-mcp" / "fabric" / "workers.json"
    )
    fabric_state: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-control-mcp" / "fabric.jsonl"
    )
    # Persistent Fabric is the production ownership model. Embedded Fabric is
    # an explicit compatibility choice for isolated tests/deployments.
    fabric_mode: str = "service"
    fabric_socket: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-fabric" / "controller.sock"
    )
    # Controller status and persistent dispatch may include a bounded worker
    # round-trip; keep the default below the transport's 30-second ceiling.
    fabric_service_timeout_seconds: float = 30.0
    fabric_consumer_identity: str = "mncs-control-mcp"
    commons_socket: Path = field(
        default_factory=lambda: Path.home()
        / ".local"
        / "state"
        / "mncs-commons"
        / "commons.sock"
    )
    commons_operator_socket: Path = field(
        default_factory=lambda: Path.home()
        / ".local"
        / "state"
        / "mncs-commons"
        / "commons-operator.sock"
    )
    commons_service_timeout_seconds: float = 5.0
    fabric_execution_mode: str = "unavailable-until-service-support"
    fabric_controller_id: str = "mncs-harness"
    forge_config_name: str = "mncs-forge.toml"
    forge_mcp_executable: Path | None = None
    forge_mcp_config: Path | None = None

    @property
    def projects_root(self) -> Path:
        """Backward-compatible name used by the initial adapters."""
        return self.workspace_root

    @property
    def harness_path(self) -> Path:
        configured = self.workspace_root / self.repositories.get("local_harness", "mncs-harness")
        if configured.exists():
            return configured
        for name in LEGACY_HARNESS_DIRECTORIES:
            candidate = self.workspace_root / name
            if candidate.exists():
                return candidate
        return configured

    @property
    def harness_config_path(self) -> Path:
        if self.harness_config is not None:
            return self.harness_config.expanduser().resolve()
        preferred = Path.home() / ".config" / "mncs-harness" / "config.toml"
        legacy = Path.home() / ".config" / "epi13-local-harness" / "config.toml"
        selected = preferred if preferred.exists() or not legacy.exists() else legacy
        return selected.expanduser().resolve()

    @property
    def fabric_path(self) -> Path:
        return self.workspace_root / self.repositories.get("fabric", "mncs-fabric")

    @property
    def commons_path(self) -> Path:
        return self.workspace_root / self.repositories.get("commons", "MNCS-Commons")

    @property
    def forge_path(self) -> Path:
        return self.workspace_root / self.repositories.get("forge", "mncs-forge-mcp")

    @property
    def forge_server_path(self) -> Path:
        """Resolve the canonical repository-local Forge MCP entry point."""
        if self.forge_mcp_executable is not None:
            return self.forge_mcp_executable
        wrapper = self.forge_path / "scripts" / "codex-mcp"
        return wrapper if wrapper.is_file() else self.forge_path / ".venv" / "bin" / "mncs-forge-mcp"

    @property
    def forge_probe_config(self) -> Path | None:
        """Return the configured or migrated empirical Forge project config."""
        if self.forge_mcp_config is not None:
            return self.forge_mcp_config
        candidates = (
            self.workspace_root / self.repositories.get("reference_studies", "mncs-reference-studies") / self.forge_config_name,
            self.workspace_root / self.forge_config_name,
        )
        return next((candidate for candidate in candidates if candidate.is_file()), None)


def _path(value: object, *, base: Path | None = None) -> Path:
    if isinstance(value, Path):
        result = value
    elif isinstance(value, str) and value.strip():
        result = Path(value)
    else:
        raise ControlError("CONFIG_INVALID", "path settings must be non-empty strings")
    result = result.expanduser()
    if base is not None and not result.is_absolute():
        result = base / result
    return result.resolve()


def _table(raw: dict[str, object], name: str) -> dict[str, object]:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ControlError("CONFIG_INVALID", f"{name} must be a table")
    return value


def _boolean(table: dict[str, object], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ControlError("CONFIG_INVALID", f"{key} must be true or false")
    return value


def load_config(path: Path | str | None = None) -> ControlConfig:
    selected = Path(path).expanduser() if path else None
    if selected is None:
        override = os.environ.get("MNCS_CONTROL_CONFIG")
        selected = Path(override).expanduser() if override else Path.cwd() / "control.toml"
    raw: dict[str, object] = {}
    if selected.exists():
        try:
            with selected.open("rb") as handle:
                raw = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ControlError("CONFIG_READ", f"cannot read configuration: {exc}") from exc

    server = _table(raw, "server")
    workspace = _table(raw, "workspace")
    sandbox = _table(raw, "sandbox")
    terminal = _table(raw, "terminal")
    git = _table(raw, "git")
    mncs = _table(raw, "mncs")
    repos = _table(mncs, "repos") if "repos" in mncs else _table(raw, "repos")
    integration = _table(raw, "integration")
    limits = _table(raw, "limits")

    root_value = (
        os.environ.get("MNCS_CONTROL_WORKSPACE_ROOT")
        or os.environ.get("MNCS_PROJECTS_ROOT")
        or workspace.get("root")
        or mncs.get("projects_root")
        or (Path.home() / "Documents" / "Projects")
    )
    root = _path(root_value)
    repository_values = dict(DEFAULT_REPOSITORIES)
    for key, value in repos.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ControlError("CONFIG_INVALID", "MNCS repository aliases and values must be strings")
        repo_path = Path(value)
        if not key or repo_path.is_absolute() or ".." in repo_path.parts:
            raise ControlError("CONFIG_INVALID", f"invalid MNCS repository path for {key!r}")
        repository_values[key] = value

    default_scope = str(workspace.get("default_scope", "project"))
    if default_scope not in {"project", "workspace"}:
        raise ControlError("CONFIG_INVALID", "workspace.default_scope must be project or workspace")
    backend = str(sandbox.get("backend", "auto"))
    if backend not in {"auto", "bwrap", "none"}:
        raise ControlError("CONFIG_INVALID", "sandbox.backend must be auto, bwrap, or none")
    env_overrides = terminal.get("environment", {})
    if not isinstance(env_overrides, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env_overrides.items()
    ):
        raise ControlError("CONFIG_INVALID", "terminal.environment must contain string values")
    tool_values = sandbox.get("tool_paths", [])
    if not isinstance(tool_values, list):
        raise ControlError("CONFIG_INVALID", "sandbox.tool_paths must be an array")
    tool_paths = tuple(_path(item) for item in tool_values)

    def state_path(table: dict[str, object], key: str, default: Path) -> Path:
        return _path(table[key]) if key in table else default.resolve()

    fabric_mode = str(integration.get("fabric_mode", "service"))
    if fabric_mode not in {"service", "embedded", "transitional"}:
        raise ControlError("CONFIG_INVALID", "integration.fabric_mode must be service, embedded, or transitional")
    fabric_execution_mode = str(
        integration.get(
            "fabric_execution_mode",
            "unavailable-until-service-support" if fabric_mode == "service" else "embedded-direct",
        )
    )
    expected_execution_modes = {
        "service": {"unavailable-until-service-support", "persistent-service"},
        "embedded": {"embedded-direct"},
        "transitional": {"embedded-direct-compatibility"},
    }
    if fabric_execution_mode not in expected_execution_modes[fabric_mode]:
        raise ControlError("CONFIG_INVALID", "integration.fabric_execution_mode does not match fabric_mode")
    if fabric_mode == "service" and any(key in integration for key in ("fabric_registry", "fabric_state")):
        raise ControlError(
            "CONFIG_LEGACY_FABRIC_OWNERSHIP",
            "service mode does not accept Control-owned fabric_registry or fabric_state; remove them or select embedded/transitional",
        )
    fabric_timeout = float(integration.get("fabric_service_timeout_seconds", 30.0))
    if not 0.1 <= fabric_timeout <= 30:
        raise ControlError("CONFIG_INVALID", "integration.fabric_service_timeout_seconds must be between 0.1 and 30")
    fabric_identity = str(integration.get("fabric_consumer_identity", "mncs-control-mcp"))
    if not fabric_identity or len(fabric_identity) > 128 or "\x00" in fabric_identity:
        raise ControlError("CONFIG_INVALID", "integration.fabric_consumer_identity is invalid")
    commons_timeout = float(integration.get("commons_service_timeout_seconds", 5.0))
    if not 0.1 <= commons_timeout <= 30:
        raise ControlError(
            "CONFIG_INVALID",
            "integration.commons_service_timeout_seconds must be between 0.1 and 30",
        )

    harness_value = integration.get("harness_config")
    forge_executable = integration.get("forge_mcp_executable")
    forge_config = integration.get("forge_mcp_config")
    return ControlConfig(
        name=str(server.get("name", "mncs-control-mcp")),
        workspace_root=root,
        repositories=repository_values,
        protect_root=_boolean(workspace, "protect_root", True),
        default_scope=default_scope,
        allow_workspace_scope=_boolean(workspace, "allow_workspace_scope", True),
        allow_terminal=_boolean(workspace, "allow_terminal", True),
        terminal_network_default=_boolean(workspace, "terminal_network_default", False),
        terminal_network_allowed=_boolean(workspace, "terminal_network_allowed", True),
        sandbox_backend=backend,
        require_real_sandbox=_boolean(sandbox, "require_real_sandbox", True),
        sandbox_home=state_path(
            sandbox,
            "home",
            Path.home() / ".local" / "share" / "mncs-control-mcp" / "sandbox-home",
        ),
        sandbox_tool_paths=tool_paths,
        safe_environment=dict(env_overrides),
        default_timeout_seconds=max(
            1.0, float(terminal.get("default_timeout_seconds", limits.get("default_timeout_seconds", 120)))
        ),
        max_timeout_seconds=max(
            1.0, float(terminal.get("max_timeout_seconds", limits.get("max_timeout_seconds", 1800)))
        ),
        max_output_bytes=max(
            4096, int(terminal.get("max_output_bytes", limits.get("max_output_bytes", 1024 * 1024)))
        ),
        max_response_bytes=max(8192, int(limits.get("max_response_bytes", 2 * 1024 * 1024))),
        max_file_bytes=max(1024, int(limits.get("max_file_bytes", 4 * 1024 * 1024))),
        max_listing_entries=max(1, int(limits.get("max_listing_entries", 2000))),
        max_search_results=max(1, int(limits.get("max_search_results", 500))),
        max_concurrent_jobs=max(1, int(terminal.get("max_concurrent_jobs", 4))),
        job_retention_seconds=max(60, int(terminal.get("job_retention_seconds", 86400))),
        job_state_path=state_path(
            terminal, "job_state_path", Path.home() / ".local" / "state" / "mncs-control-mcp" / "jobs.json"
        ),
        audit_path=state_path(
            server, "audit_path", Path.home() / ".local" / "state" / "mncs-control-mcp" / "audit.jsonl"
        ),
        git_allow_fetch=_boolean(git, "allow_fetch", True),
        git_allow_pull=_boolean(git, "allow_pull", True),
        git_allow_push=_boolean(git, "allow_push", True),
        git_allow_clone=_boolean(git, "allow_clone", True),
        git_allow_force_push=_boolean(git, "allow_force_push", False),
        git_use_ssh_agent=_boolean(git, "use_ssh_agent", True),
        harness_config=_path(harness_value) if harness_value else None,
        fabric_registry=state_path(
            integration,
            "fabric_registry",
            Path.home() / ".local" / "state" / "mncs-fabric" / "workers.json",
        ),
        fabric_state=state_path(
            integration,
            "fabric_state",
            Path.home() / ".local" / "state" / "mncs-control-mcp" / "fabric.jsonl",
        ),
        fabric_mode=fabric_mode,
        fabric_socket=state_path(
            integration,
            "fabric_socket",
            Path.home() / ".local" / "state" / "mncs-fabric" / "controller.sock",
        ),
        fabric_service_timeout_seconds=fabric_timeout,
        fabric_consumer_identity=fabric_identity,
        commons_socket=state_path(
            integration,
            "commons_socket",
            Path.home() / ".local" / "state" / "mncs-commons" / "commons.sock",
        ),
        commons_operator_socket=state_path(
            integration,
            "commons_operator_socket",
            Path.home() / ".local" / "state" / "mncs-commons" / "commons-operator.sock",
        ),
        commons_service_timeout_seconds=commons_timeout,
        fabric_execution_mode=fabric_execution_mode,
        fabric_controller_id=str(integration.get("fabric_controller_id", "mncs-harness")),
        forge_config_name=str(integration.get("forge_config_name", "mncs-forge.toml")),
        forge_mcp_executable=_path(forge_executable) if forge_executable else None,
        forge_mcp_config=_path(forge_config) if forge_config else None,
    )

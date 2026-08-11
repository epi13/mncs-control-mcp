from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ControlError

DEFAULT_REPOSITORIES = {
    "local_harness": "epi13-local-harness",
    "fabric": "mncs-fabric",
    "forge": "mncs-forge-mcp",
    "language": "mncs-language",
    "standard": "machine-native-complexity-standard",
    "commons": "MNCS-Commons",
    "reference_studies": "mncs-reference-studies",
}


@dataclass(frozen=True)
class ControlConfig:
    name: str = "mncs-control-mcp"
    projects_root: Path = field(default_factory=lambda: Path.home() / "Documents" / "Projects")
    repositories: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_REPOSITORIES))
    harness_config: Path | None = None
    fabric_registry: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-fabric" / "workers.json"
    )
    fabric_state: Path = field(
        default_factory=lambda: Path.home() / ".local" / "state" / "mncs-control-mcp" / "fabric.jsonl"
    )
    fabric_controller_id: str = "mncs-control-mcp"
    forge_config_name: str = "mncs-forge.toml"
    max_output_bytes: int = 128 * 1024
    max_response_bytes: int = 512 * 1024
    default_timeout_seconds: float = 120.0
    max_timeout_seconds: float = 600.0

    @property
    def harness_path(self) -> Path:
        return self.projects_root / self.repositories["local_harness"]

    @property
    def fabric_path(self) -> Path:
        return self.projects_root / self.repositories["fabric"]

    @property
    def forge_path(self) -> Path:
        return self.projects_root / self.repositories["forge"]


def _path(value: object, *, base: Path | None = None) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ControlError("CONFIG_INVALID", "path settings must be non-empty strings")
    result = Path(value).expanduser()
    if base is not None and not result.is_absolute():
        result = base / result
    return result.resolve()


def load_config(path: Path | str | None = None) -> ControlConfig:
    selected = Path(path).expanduser() if path else None
    if selected is None:
        override = os.environ.get("MNCS_CONTROL_CONFIG")
        selected = Path(override).expanduser() if override else Path.cwd() / "control.toml"

    raw: dict[str, object] = {}
    if selected.exists():
        try:
            with selected.open("rb") as handle:
                parsed = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ControlError("CONFIG_READ", f"cannot read configuration: {exc}") from exc
        raw = parsed

    server = raw.get("server", {})
    mncs = raw.get("mncs", {})
    repos = raw.get("repos", {})
    integration = raw.get("integration", {})
    limits = raw.get("limits", {})
    if not all(isinstance(item, dict) for item in (server, mncs, repos, integration, limits)):
        raise ControlError("CONFIG_INVALID", "server, mncs, repos, integration, and limits must be tables")

    projects_root_value = os.environ.get("MNCS_PROJECTS_ROOT") or mncs.get("projects_root")
    projects_root = _path(
        projects_root_value or (Path.home() / "Documents" / "Projects"),
    )
    repository_values = dict(DEFAULT_REPOSITORIES)
    for key, value in repos.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ControlError("CONFIG_INVALID", "repository registry keys and values must be strings")
        if not key or Path(value).is_absolute() or ".." in Path(value).parts:
            raise ControlError("CONFIG_INVALID", f"invalid approved repository name for {key!r}")
        repository_values[key] = value

    def integration_path(key: str, default: Path) -> Path:
        value = integration.get(key)
        return _path(value, base=projects_root) if value else default.resolve()

    harness_config = integration.get("harness_config")
    return ControlConfig(
        name=str(server.get("name", "mncs-control-mcp")),
        projects_root=projects_root,
        repositories=repository_values,
        harness_config=_path(harness_config) if harness_config else None,
        fabric_registry=integration_path(
            "fabric_registry",
            Path.home() / ".local" / "state" / "mncs-fabric" / "workers.json",
        ),
        fabric_state=integration_path(
            "fabric_state",
            Path.home() / ".local" / "state" / "mncs-control-mcp" / "fabric.jsonl",
        ),
        fabric_controller_id=str(integration.get("fabric_controller_id", "mncs-control-mcp")),
        forge_config_name=str(integration.get("forge_config_name", "mncs-forge.toml")),
        max_output_bytes=max(4096, int(limits.get("max_output_bytes", 128 * 1024))),
        max_response_bytes=max(8192, int(limits.get("max_response_bytes", 512 * 1024))),
        default_timeout_seconds=max(1.0, float(limits.get("default_timeout_seconds", 120))),
        max_timeout_seconds=max(1.0, float(limits.get("max_timeout_seconds", 600))),
    )

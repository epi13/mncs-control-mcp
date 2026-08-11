"""Private runtime directories shared by trusted integrations.

The MCP service runs with ``ProtectHome=read-only``.  Integrations must never
silently put mutable state in the real home directory.  This module provides a
small, deterministic state policy for those integrations and migrates the
legacy Fabric registry into the control-plane state tree when necessary.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config import ControlConfig
from .errors import ControlError
from .security import safe_host_probe_environment


def fabric_runtime_directory(config: ControlConfig) -> Path:
    """Return the private writable directory reserved for Fabric state."""

    parent = config.fabric_state.parent.expanduser()
    if parent.is_symlink():
        raise ControlError("FABRIC_STATE_INVALID", "Fabric state parent may not be a symlink")
    runtime = parent / "fabric"
    if runtime.is_symlink():
        raise ControlError("FABRIC_STATE_INVALID", "Fabric runtime directory may not be a symlink")
    return runtime.resolve()


def _looks_like_legacy_registry(path: Path) -> bool:
    parts = path.expanduser().resolve(strict=False).parts
    return len(parts) >= 4 and parts[-4:-1] == (".local", "state", "mncs-fabric") and path.name == "workers.json"


def effective_fabric_registry(config: ControlConfig) -> Path:
    """Resolve old ``~/.local/state/mncs-fabric`` settings safely.

    Explicit paths outside the legacy location remain supported for tests and
    operators who intentionally maintain a separate registry.  The historical
    default is redirected into the writable control-plane state tree.
    """

    configured = config.fabric_registry.expanduser().resolve(strict=False)
    if _looks_like_legacy_registry(configured):
        return fabric_runtime_directory(config) / "workers.json"
    return configured


def prepare_fabric_runtime(config: ControlConfig) -> Path:
    """Create private Fabric state and migrate a legacy registry once.

    Only the registry JSON is copied; lock files and mutable Fabric ledgers are
    intentionally not copied.  The source remains read-only and may continue
    to be used by other local Fabric tooling.
    """

    target = effective_fabric_registry(config)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    configured = config.fabric_registry.expanduser().resolve(strict=False)
    if target != configured and configured.is_file() and not target.exists():
        if config.fabric_registry.expanduser().is_symlink():
            raise ControlError("FABRIC_REGISTRY_INVALID", "legacy Fabric registry may not be a symlink")
        if configured.stat().st_size > 1024 * 1024:
            raise ControlError("FABRIC_REGISTRY_INVALID", "legacy Fabric registry exceeds the bounded size")
        temporary = target.with_suffix(target.suffix + ".tmp")
        shutil.copyfile(configured, temporary)
        os.chmod(temporary, 0o600)
        temporary.replace(target)
    return target


def fabric_environment(config: ControlConfig) -> dict[str, str]:
    """Environment for trusted Fabric probes, with state rooted privately."""

    runtime = fabric_runtime_directory(config)
    return safe_host_probe_environment(
        {
            "XDG_STATE_HOME": str(runtime.parent),
            "MNCS_FABRIC_STATE_DIR": str(runtime),
        }
    )

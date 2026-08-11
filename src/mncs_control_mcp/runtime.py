"""Private runtime directories shared by trusted integrations.

The MCP service runs with ``ProtectHome=read-only``.  Integrations must never
silently put mutable state in the real home directory.  This module provides a
small, deterministic state policy for those integrations and migrates the
legacy Fabric registry into the control-plane state tree when necessary.
"""

from __future__ import annotations

import errno
import os
import tempfile
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - the service is Linux/Fedora oriented
    fcntl = None

from .config import ControlConfig
from .errors import ControlError


def fabric_runtime_directory(config: ControlConfig) -> Path:
    """Return the private writable directory reserved for Fabric state."""

    parent = config.fabric_state.parent.expanduser()
    if parent.is_symlink() or parent.exists() and not parent.is_dir():
        raise ControlError("FABRIC_STATE_INVALID", "Fabric state parent may not be a symlink")
    runtime = parent / "fabric"
    if runtime.is_symlink():
        raise ControlError("FABRIC_STATE_INVALID", "Fabric runtime directory may not be a symlink")
    return runtime.resolve(strict=False)


def _looks_like_legacy_registry(path: Path) -> bool:
    parts = path.expanduser().parts
    return len(parts) >= 4 and parts[-4:-1] == (".local", "state", "mncs-fabric") and path.name == "workers.json"


def effective_fabric_registry(config: ControlConfig) -> Path:
    """Resolve old ``~/.local/state/mncs-fabric`` settings safely.

    Explicit paths outside the legacy location remain supported for tests and
    operators who intentionally maintain a separate registry.  The historical
    default is redirected into the writable control-plane state tree.
    """

    configured = config.fabric_registry.expanduser()
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
    if target.exists() and target.is_symlink():
        raise ControlError("FABRIC_REGISTRY_INVALID", "private Fabric registry may not be a symlink")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    configured = config.fabric_registry.expanduser()
    if fcntl is None:  # pragma: no cover - Windows is not an approved service target
        raise ControlError("FABRIC_STATE_INVALID", "concurrent Fabric migration requires file locking")
    lock_path = target.parent / ".migration.lock"
    if lock_path.is_symlink():
        raise ControlError("FABRIC_REGISTRY_INVALID", "Fabric migration lock may not be a symlink")
    try:
        with lock_path.open("a+", encoding="ascii") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if target.exists():
                if target.is_symlink():
                    raise ControlError("FABRIC_REGISTRY_INVALID", "private Fabric registry may not be a symlink")
            elif target != configured and configured.exists():
                if configured.is_symlink() or not configured.is_file():
                    raise ControlError("FABRIC_REGISTRY_INVALID", "legacy Fabric registry must be a regular file")
                source_stat = configured.stat()
                if source_stat.st_size > 1024 * 1024:
                    raise ControlError("FABRIC_REGISTRY_INVALID", "legacy Fabric registry exceeds the bounded size")
                temporary_fd, temporary_name = tempfile.mkstemp(
                    prefix=".workers.", suffix=".tmp", dir=target.parent
                )
                try:
                    with os.fdopen(temporary_fd, "wb") as destination, configured.open("rb") as source:
                        remaining = 1024 * 1024
                        while chunk := source.read(min(64 * 1024, remaining)):
                            destination.write(chunk)
                            remaining -= len(chunk)
                            if remaining < 0:
                                raise ControlError("FABRIC_REGISTRY_INVALID", "legacy Fabric registry exceeds the bounded size")
                        destination.flush()
                        os.fsync(destination.fileno())
                    os.chmod(temporary_name, 0o600)
                    os.replace(temporary_name, target)
                    directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                finally:
                    try:
                        os.unlink(temporary_name)
                    except FileNotFoundError:
                        pass
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ControlError("FABRIC_REGISTRY_INVALID", "Fabric registry path contains an unsafe link") from exc
        raise
    return target

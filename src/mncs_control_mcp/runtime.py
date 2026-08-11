"""Private runtime directories shared by trusted integrations.

The MCP service runs with ``ProtectHome=read-only``.  Integrations must never
silently put mutable state in the real home directory.  This module provides a
small, deterministic state policy for those integrations and migrates the
legacy Fabric registry into the control-plane state tree when necessary.
"""

from __future__ import annotations

import errno
import hashlib
import json
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



def _atomic_copy_private(source: Path, destination: Path, *, maximum_bytes: int = 1024 * 1024) -> None:
    """Copy one bounded regular file into private control state without following links."""

    if source.is_symlink() or not source.is_file():
        raise ControlError("FABRIC_TRUST_STATE_INVALID", "Fabric trust state must be a regular file")
    source_stat = source.stat()
    if source_stat.st_size > maximum_bytes:
        raise ControlError("FABRIC_TRUST_STATE_INVALID", "Fabric trust state exceeds the bounded size")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ControlError("FABRIC_TRUST_STATE_INVALID", "Fabric private trust directory may not be a symlink")
    try:
        os.chmod(destination.parent, 0o700)
    except OSError:
        pass
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_stream:
            remaining = maximum_bytes
            while chunk := input_stream.read(min(64 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ControlError("FABRIC_TRUST_STATE_INVALID", "Fabric trust state exceeds the bounded size")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _rewrite_migrated_trust_references(target: Path, configured: Path) -> None:
    """Relocate mutable trust ledgers referenced by a migrated legacy registry.

    Fabric's trust ledger takes an adjacent file lock even for reads.  Under the
    hardened service the historical home directory is read-only, so a private
    registry must not retain trust-state references there.  Certificate and key
    references remain untouched because they are read-only inputs.
    """

    if target == configured or not target.exists():
        return
    raw = target.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ControlError("FABRIC_REGISTRY_INVALID", "private Fabric registry exceeds the bounded size")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(value, dict) or not isinstance(value.get("workers"), list):
        return

    changed = False
    trust_root = target.parent / "trust"
    for worker in value["workers"]:
        if not isinstance(worker, dict):
            continue
        worker_id = worker.get("worker_id")
        reference = worker.get("trust_state")
        if not isinstance(worker_id, str) or not worker_id or not isinstance(reference, str) or not reference:
            continue
        source = Path(reference).expanduser()
        digest = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()[:24]
        destination = trust_root / f"{digest}.jsonl"
        if source.resolve(strict=False) == destination.resolve(strict=False):
            continue
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ControlError("FABRIC_TRUST_STATE_INVALID", "private Fabric trust state must be a regular file")
        elif source.exists():
            _atomic_copy_private(source, destination)
        else:
            # Preserve the original reference so Fabric reports the missing
            # enrollment material instead of manufacturing trust state.
            continue
        worker["trust_state"] = str(destination)
        changed = True

    if not changed:
        return
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ControlError("FABRIC_REGISTRY_INVALID", "private Fabric registry exceeds the bounded size")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".workers.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, target)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass

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
            _rewrite_migrated_trust_references(target, configured)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ControlError("FABRIC_REGISTRY_INVALID", "Fabric registry path contains an unsafe link") from exc
        raise
    return target

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import ControlError
from .security import bounded_text, filtered_environment


@dataclass(frozen=True)
class ActionSpec:
    name: str
    executable: str
    description: str


class ActionRegistry:
    """Internal allowlist for fixed executable identities and argument builders."""

    def __init__(self) -> None:
        self._actions: dict[str, ActionSpec] = {}

    def register(self, spec: ActionSpec) -> None:
        if spec.name in self._actions:
            raise ControlError("ACTION_REGISTRY_ERROR", f"action already registered: {spec.name}")
        self._actions[spec.name] = spec

    def resolve(self, name: str) -> ActionSpec:
        try:
            return self._actions[name]
        except KeyError as exc:
            raise ControlError("ACTION_NOT_ALLOWED", f"action is not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._actions))


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    duration_seconds: float


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: float = 120,
    output_limit_bytes: int = 128 * 1024,
    env: dict[str, str] | None = None,
) -> CommandResult:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ControlError("INVALID_COMMAND", "internal command argv must be non-empty strings")
    if timeout_seconds <= 0 or timeout_seconds > 600:
        raise ControlError("INVALID_TIMEOUT", "timeout is outside the permitted range")

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=str(cwd) if cwd else None,
            # Generic bounded commands receive only the minimal command
            # environment. Trusted read-only probes opt into host discovery.
            env=dict(env if env is not None else filtered_environment()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            text=False,
        )
    except OSError as exc:
        return CommandResult(tuple(argv), None, "", str(exc), False, False, time.monotonic() - started)

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    truncated = [False]

    def drain(stream: object, buffer: bytearray) -> None:
        while True:
            chunk = stream.read(8192)  # type: ignore[union-attr]
            if not chunk:
                return
            if len(buffer) < output_limit_bytes:
                remaining = output_limit_bytes - len(buffer)
                buffer.extend(chunk[:remaining])
            if len(chunk) > max(0, output_limit_bytes - len(buffer)) or len(buffer) >= output_limit_bytes:
                truncated[0] = True

    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_buffer), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for thread in threads:
        thread.join(timeout=2)

    stdout, stdout_truncated = bounded_text(bytes(stdout_buffer).decode("utf-8", errors="replace"), output_limit_bytes)
    stderr, stderr_truncated = bounded_text(bytes(stderr_buffer).decode("utf-8", errors="replace"), output_limit_bytes)
    return CommandResult(
        tuple(argv),
        process.returncode,
        stdout,
        stderr,
        timed_out,
        truncated[0] or stdout_truncated or stderr_truncated,
        time.monotonic() - started,
    )

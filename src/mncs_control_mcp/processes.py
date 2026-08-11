from __future__ import annotations

import atexit
import json
import os
import secrets
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import BinaryIO

from .config import ControlConfig
from .errors import ControlError
from .sandbox import Sandbox, utc_now
from .security import redact_text
from .workspace import WorkspacePolicy


class _LogBuffer:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.data = bytearray()
        self.start_offset = 0
        self.total = 0
        self.lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        with self.lock:
            self.data.extend(chunk)
            self.total += len(chunk)
            overflow = len(self.data) - self.maximum
            if overflow > 0:
                del self.data[:overflow]
                self.start_offset += overflow

    def read(self, offset: int) -> tuple[str, int, bool]:
        with self.lock:
            lost = offset < self.start_offset
            effective = max(offset, self.start_offset)
            index = effective - self.start_offset
            content = bytes(self.data[index:]).decode("utf-8", errors="replace")
            return redact_text(content), self.total, lost


@dataclass
class TerminalJob:
    job_id: str
    command: str
    cwd: str
    scope: str
    project: str | None
    network: bool
    sandbox_backend: str
    timeout_seconds: float
    process: subprocess.Popen[bytes] | None = None
    status: str = "running"
    created_at: str = field(default_factory=utc_now)
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stopped: bool = False
    stdout: _LogBuffer | None = None
    stderr: _LogBuffer | None = None

    def public(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "command": redact_text(self.command),
            "cwd": self.cwd,
            "scope": self.scope,
            "project": self.project,
            "network": self.network,
            "sandbox_backend": self.sandbox_backend,
            "status": self.status,
            "pid": self.process.pid if self.process and self.status == "running" else None,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stopped": self.stopped,
        }


class ProcessManager:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy, sandbox: Sandbox) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox
        self._jobs: dict[str, TerminalJob] = {}
        self._lock = threading.RLock()
        self._load_metadata()
        atexit.register(self.cleanup)

    def _load_metadata(self) -> None:
        try:
            raw = json.loads(self.config.job_state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for item in raw[-100:]:
            if not isinstance(item, dict) or not isinstance(item.get("job_id"), str):
                continue
            job = TerminalJob(
                job_id=item["job_id"],
                command=str(item.get("command", "[unavailable]")),
                cwd=str(item.get("cwd", "/workspace")),
                scope=str(item.get("scope", "workspace")),
                project=item.get("project") if isinstance(item.get("project"), str) else None,
                network=bool(item.get("network", False)),
                sandbox_backend=str(item.get("sandbox_backend", "unknown")),
                timeout_seconds=float(item.get("timeout_seconds", 0)),
                status="orphaned" if item.get("status") == "running" else str(item.get("status", "unknown")),
                created_at=str(item.get("created_at", utc_now())),
                started_at=str(item.get("started_at", utc_now())),
                completed_at=item.get("completed_at") if isinstance(item.get("completed_at"), str) else None,
                exit_code=item.get("exit_code") if isinstance(item.get("exit_code"), int) else None,
                timed_out=bool(item.get("timed_out", False)),
                stopped=bool(item.get("stopped", False)),
            )
            self._jobs[job.job_id] = job

    def _persist(self) -> None:
        self.config.job_state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.config.job_state_path.parent, 0o700)
        except OSError:
            pass
        rows = [{**job.public(), "timeout_seconds": job.timeout_seconds} for job in self._jobs.values()]
        temporary = self.config.job_state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(rows[-100:], indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.config.job_state_path)

    def start(
        self,
        command: str,
        *,
        scope: str | None,
        project: str | None,
        cwd: str,
        timeout_seconds: float | None,
        network: bool | None,
        environment: dict[str, str] | None = None,
    ) -> dict[str, object]:
        if not self.config.allow_terminal:
            raise ControlError("TERMINAL_DISABLED", "terminal execution is disabled")
        timeout = self.config.default_timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        if timeout <= 0 or timeout > self.config.max_timeout_seconds:
            raise ControlError("INVALID_TIMEOUT", "timeout exceeds the configured terminal limit")
        resolution = self.policy.resolve_scope(scope=scope, project=project, cwd=cwd)
        argv, network_enabled = self.sandbox.command_argv(
            command, resolution, network=network, environment=environment
        )
        with self._lock:
            running = sum(job.status == "running" for job in self._jobs.values())
            if running >= self.config.max_concurrent_jobs:
                raise ControlError("JOB_LIMIT", "maximum concurrent terminal jobs reached")
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=None,
                    env={},
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError as exc:
                raise ControlError("COMMAND_START_FAILED", str(exc)) from exc
            job = TerminalJob(
                job_id="term-" + secrets.token_hex(12),
                command=command,
                cwd=resolution.sandbox_cwd,
                scope=resolution.scope,
                project=resolution.project,
                network=network_enabled,
                sandbox_backend=self.sandbox.backend,
                timeout_seconds=timeout,
                process=process,
                stdout=_LogBuffer(self.config.max_output_bytes),
                stderr=_LogBuffer(self.config.max_output_bytes),
            )
            self._jobs[job.job_id] = job
            self._persist()
        assert process.stdout is not None and process.stderr is not None
        threading.Thread(target=self._drain, args=(process.stdout, job.stdout), daemon=True).start()
        threading.Thread(target=self._drain, args=(process.stderr, job.stderr), daemon=True).start()
        threading.Thread(target=self._monitor, args=(job,), daemon=True).start()
        return job.public()

    @staticmethod
    def _drain(stream: BinaryIO, buffer: _LogBuffer | None) -> None:
        assert buffer is not None
        reader = getattr(stream, "read1", stream.read)
        while chunk := reader(8192):
            buffer.append(chunk)

    def _monitor(self, job: TerminalJob) -> None:
        assert job.process is not None
        try:
            job.process.wait(timeout=job.timeout_seconds)
        except subprocess.TimeoutExpired:
            job.timed_out = True
            self._signal(job, signal.SIGTERM)
            try:
                job.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._signal(job, signal.SIGKILL)
                job.process.wait()
        with self._lock:
            job.exit_code = job.process.returncode
            job.completed_at = utc_now()
            job.status = "stopped" if job.stopped else "timed_out" if job.timed_out else "completed" if job.exit_code == 0 else "failed"
            self._persist()

    def _get(self, job_id: str) -> TerminalJob:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise ControlError("UNKNOWN_JOB", "job ID is not owned by this MCP service")
        return job

    def status(self, job_id: str) -> dict[str, object]:
        return self._get(job_id).public()

    def output(self, job_id: str, *, stdout_offset: int = 0, stderr_offset: int = 0) -> dict[str, object]:
        job = self._get(job_id)
        if stdout_offset < 0 or stderr_offset < 0:
            raise ControlError("INVALID_INPUT", "output offsets must be non-negative")
        stdout, stdout_next, stdout_lost = job.stdout.read(stdout_offset) if job.stdout else ("", 0, False)
        stderr, stderr_next, stderr_lost = job.stderr.read(stderr_offset) if job.stderr else ("", 0, False)
        return {
            **job.public(),
            "stdout": stdout,
            "stderr": stderr,
            "stdout_next_offset": stdout_next,
            "stderr_next_offset": stderr_next,
            "output_truncated": stdout_lost or stderr_lost,
        }

    def write(self, job_id: str, data: str, *, close: bool = False) -> dict[str, object]:
        job = self._get(job_id)
        if job.status != "running" or job.process is None or job.process.stdin is None:
            raise ControlError("JOB_NOT_RUNNING", "job stdin is not available")
        encoded = data.encode("utf-8")
        if len(encoded) > 65536:
            raise ControlError("INPUT_TOO_LARGE", "terminal input exceeds 65536 bytes")
        try:
            job.process.stdin.write(encoded)
            job.process.stdin.flush()
            if close:
                job.process.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            raise ControlError("TERMINAL_WRITE_FAILED", str(exc)) from exc
        return {"job_id": job_id, "bytes_written": len(encoded), "stdin_closed": close}

    @staticmethod
    def _signal(job: TerminalJob, selected: signal.Signals) -> None:
        if job.process is None:
            return
        try:
            os.killpg(job.process.pid, selected)
        except ProcessLookupError:
            pass

    def stop(self, job_id: str, *, force: bool = False) -> dict[str, object]:
        job = self._get(job_id)
        if job.status != "running":
            return job.public()
        job.stopped = True
        self._signal(job, signal.SIGKILL if force else signal.SIGTERM)
        return job.public()

    def list(self) -> dict[str, object]:
        with self._lock:
            jobs = [job.public() for job in sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)]
        return {"jobs": jobs[:100], "running": sum(item["status"] == "running" for item in jobs)}

    def cleanup(self) -> None:
        with self._lock:
            running = [job for job in self._jobs.values() if job.status == "running"]
        for job in running:
            job.stopped = True
            self._signal(job, signal.SIGTERM)
        deadline = time.monotonic() + 2
        for job in running:
            process = job.process
            if process is None:
                continue
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._signal(job, signal.SIGKILL)

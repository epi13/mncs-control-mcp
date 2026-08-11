from __future__ import annotations

import atexit
import json
import multiprocessing
import os
import secrets
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import BinaryIO

from .config import ControlConfig
from .errors import ControlError
from .sandbox import Sandbox, utc_now
from .security import redact_text
from .workspace import WorkspacePolicy


@dataclass(frozen=True)
class _ExternalOutcome:
    status: str
    result: object
    summary: dict[str, object]


def _external_operation_entry(operation: Callable[[], object], connection: object) -> None:
    """Run one trusted adapter call in a killable child process."""
    try:
        payload = {"ok": True, "result": operation()}
    except Exception as exc:  # the parent owns the public redaction boundary
        payload = {"ok": False, "error": redact_text(str(exc))}
    try:
        connection.send_bytes(json.dumps(payload, default=str).encode("utf-8"))  # type: ignore[attr-defined]
    except (BrokenPipeError, OSError):
        pass
    finally:
        connection.close()  # type: ignore[attr-defined]


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
    kind: str = "terminal"
    upstream_id: str | None = None
    result_summary: dict[str, object] | None = None
    artifacts: list[dict[str, object]] = field(default_factory=list)

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
            "kind": self.kind,
            "upstream_id": self.upstream_id,
            "result_summary": self.result_summary,
            "artifacts": self.artifacts,
        }


class ProcessManager:
    def __init__(self, config: ControlConfig, policy: WorkspacePolicy, sandbox: Sandbox) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox
        self._jobs: dict[str, TerminalJob] = {}
        self._external_futures: dict[str, Future[object]] = {}
        self._external_results: dict[str, object] = {}
        self._external_processes: dict[str, multiprocessing.Process] = {}
        self._external_cancel: dict[str, threading.Event] = {}
        self._external_executor = ThreadPoolExecutor(max_workers=config.max_concurrent_jobs, thread_name_prefix="mncs-control")
        self._lock = threading.RLock()
        self._persist_lock = threading.Lock()
        self._load_metadata()
        atexit.register(self.cleanup)

    def _load_metadata(self) -> None:
        try:
            raw = json.loads(self.config.job_state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        changed = False
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
                status=(
                    "upstream_detached"
                    if item.get("status") in {"running", "queued"} and str(item.get("kind", "terminal")) != "terminal"
                    else "orphaned" if item.get("status") == "running" else str(item.get("status", "unknown"))
                ),
                created_at=str(item.get("created_at", utc_now())),
                started_at=str(item.get("started_at", utc_now())),
                completed_at=item.get("completed_at") if isinstance(item.get("completed_at"), str) else None,
                exit_code=item.get("exit_code") if isinstance(item.get("exit_code"), int) else None,
                timed_out=bool(item.get("timed_out", False)),
                stopped=bool(item.get("stopped", False)),
                kind=str(item.get("kind", "terminal")),
                upstream_id=item.get("upstream_id") if isinstance(item.get("upstream_id"), str) else None,
                result_summary=item.get("result_summary") if isinstance(item.get("result_summary"), dict) else None,
                artifacts=item.get("artifacts") if isinstance(item.get("artifacts"), list) else [],
            )
            if job.status == "upstream_detached" and job.result_summary is None:
                job.result_summary = {"ownership": "upstream", "reconciliation": "local process manager restarted before completion"}
                changed = True
            self._jobs[job.job_id] = job
        if changed:
            self._persist()

    def _persist(self) -> None:
        with self._persist_lock:
            self.config.job_state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.chmod(self.config.job_state_path.parent, 0o700)
            except OSError:
                pass
            rows = [{**job.public(), "timeout_seconds": job.timeout_seconds} for job in self._jobs.values()]
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.config.job_state_path.name}.", suffix=".tmp", dir=self.config.job_state_path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as temporary:
                    temporary.write(json.dumps(rows[-100:], indent=2, sort_keys=True))
                    temporary.flush()
                    os.fsync(temporary.fileno())
                os.chmod(temporary_name, 0o600)
                os.replace(temporary_name, self.config.job_state_path)
            finally:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass

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

    def record_external(
        self,
        kind: str,
        *,
        project: str | None = None,
        node: str | None = None,
        model: str | None = None,
        status: str = "completed",
        upstream_id: str | None = None,
        result_summary: dict[str, object] | None = None,
        artifacts: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        """Record an upstream Fabric/Forge/Harness execution without faking a PID."""
        if not kind or len(kind) > 80 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in kind):
            raise ControlError("INVALID_INPUT", "external job kind is invalid")
        now = utc_now()
        job = TerminalJob(
            job_id="ctrl-" + secrets.token_hex(12),
            command="[upstream execution]",
            cwd="/workspace",
            scope="project" if project else "workspace",
            project=project,
            network=True,
            sandbox_backend="upstream",
            timeout_seconds=0,
            process=None,
            status=status,
            created_at=now,
            started_at=now,
            completed_at=now,
            kind=kind,
            upstream_id=upstream_id or node,
            result_summary=result_summary,
            artifacts=list(artifacts or []),
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._persist()
        return job.public()

    def submit_external(
        self,
        kind: str,
        operation: Callable[[], object],
        *,
        project: str | None = None,
        node: str | None = None,
        model: str | None = None,
        network: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        """Run a bounded upstream operation with a stable control-plane ID.

        The callable is supplied by a trusted adapter, never by an MCP caller.
        Cancellation is honest: a local Future can be cancelled before it
        starts, while a running Fabric request remains owned by Fabric.
        """
        if not callable(operation):
            raise ControlError("INVALID_JOB", "external operation is not callable")
        if not kind or len(kind) > 80 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in kind):
            raise ControlError("INVALID_INPUT", "external job kind is invalid")
        timeout = self.config.max_timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        if timeout <= 0 or timeout > self.config.max_timeout_seconds:
            raise ControlError("INVALID_TIMEOUT", "upstream timeout exceeds the configured limit")
        with self._lock:
            active = sum(job.status in {"running", "queued"} for job in self._jobs.values())
            # Keep one bounded queue slot so cancellation-before-start remains
            # observable without allowing an unbounded executor backlog.
            if active >= self.config.max_concurrent_jobs + 1:
                raise ControlError("JOB_LIMIT", "maximum concurrent jobs reached")
            now = utc_now()
            job = TerminalJob(
                job_id="ctrl-" + secrets.token_hex(12),
                command="[upstream execution]",
                cwd="/workspace",
                scope="project" if project else "workspace",
                project=project,
                network=network,
                sandbox_backend="upstream",
                timeout_seconds=timeout,
                process=None,
                status="queued",
                created_at=now,
                started_at=now,
                kind=kind,
            )
            self._jobs[job.job_id] = job
            cancellation = threading.Event()
            self._external_cancel[job.job_id] = cancellation
            future = self._external_executor.submit(self._run_external_supervised, job.job_id, operation, timeout, cancellation)
            self._external_futures[job.job_id] = future
            self._persist()
        future.add_done_callback(lambda completed: self._finish_external(job.job_id, completed))
        return job.public()

    def _run_external_supervised(
        self,
        job_id: str,
        operation: Callable[[], object],
        timeout: float,
        cancellation: threading.Event,
    ) -> _ExternalOutcome:
        if cancellation.is_set():
            return _ExternalOutcome("stopped", {"cancelled": True}, {"cancelled": True})
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None and job.status == "queued":
                job.status = "running"
                job.started_at = utc_now()
                self._persist()
        if "fork" not in multiprocessing.get_all_start_methods():
            return _ExternalOutcome("failed", None, {"error": "no supervised process start method is available"})
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_external_operation_entry, args=(operation, child), name=f"mncs-control-{job_id}")
        process.start()
        child.close()
        with self._lock:
            self._external_processes[job_id] = process
        deadline = time.monotonic() + timeout
        payload: dict[str, object] | None = None
        while time.monotonic() < deadline:
            if cancellation.is_set():
                self._terminate_external(job_id, process)
                process.join(timeout=1)
                parent.close()
                return _ExternalOutcome(
                    "upstream_detached",
                    {"cancel_requested": True},
                    {"cancel_requested": True, "ownership": "upstream", "cancellation": "local adapter stopped; Fabric abort is not exposed"},
                )
            if parent.poll(0.05):
                try:
                    payload = json.loads(parent.recv_bytes().decode("utf-8"))
                except (OSError, ValueError, UnicodeDecodeError):
                    payload = {"ok": False, "error": "supervised adapter returned malformed output"}
                break
            if not process.is_alive():
                break
        if payload is None and process.is_alive():
            self._terminate_external(job_id, process)
            process.join(timeout=1)
            parent.close()
            return _ExternalOutcome(
                "timed_out",
                {"timed_out": True},
                {"timed_out": True, "ownership": "upstream", "reconciliation": "local adapter stopped; remote ownership is not cancellable through Fabric"},
            )
        process.join(timeout=1)
        parent.close()
        if payload is None:
            return _ExternalOutcome("failed", None, {"error": "supervised adapter exited without a result"})
        if not payload.get("ok"):
            error = redact_text(str(payload.get("error", "upstream operation failed")))
            return _ExternalOutcome("failed", {"error": error}, {"error": error})
        result = payload.get("result")
        summary = result if isinstance(result, dict) else {"result": str(result)}
        return _ExternalOutcome("completed", result, summary)

    def _terminate_external(self, job_id: str, process: multiprocessing.Process) -> None:
        if process.is_alive():
            process.terminate()
            process.join(timeout=0.5)
            if process.is_alive() and process.pid:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        with self._lock:
            self._external_processes.pop(job_id, None)

    def _finish_external(self, job_id: str, future: Future[object]) -> None:
        try:
            outcome = future.result()
            if not isinstance(outcome, _ExternalOutcome):
                outcome = _ExternalOutcome("failed", outcome, {"error": "invalid supervised operation result"})
            result = outcome.result
            status = outcome.status
            summary = outcome.summary
        except CancelledError:
            result = {"cancelled": True}
            status = "stopped"
            summary = result
        except Exception as exc:
            result = {"error": redact_text(str(exc))}
            status = "failed"
            summary = result
        encoded = json.dumps(summary, default=str)
        if len(encoded.encode("utf-8")) > self.config.max_response_bytes:
            summary = {"output_truncated": True, "result_type": type(result).__name__}
            result = summary
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            if job.status not in {"running", "queued"}:
                self._external_futures.pop(job_id, None)
                self._external_cancel.pop(job_id, None)
                self._external_processes.pop(job_id, None)
                self._persist()
                return
            job.status = status
            job.completed_at = utc_now()
            job.result_summary = summary if isinstance(summary, dict) else {"summary": str(summary)}
            self._external_results[job_id] = result
            self._external_futures.pop(job_id, None)
            self._external_cancel.pop(job_id, None)
            self._external_processes.pop(job_id, None)
            self._persist()

    def result(self, job_id: str) -> dict[str, object]:
        job = self._get(job_id)
        if job.process is not None:
            return self.output(job_id)
        if job.status in {"running", "queued"}:
            return {"job": job.public(), "ready": False}
        return {"job": job.public(), "ready": True, "result": self._external_results.get(job_id, job.result_summary)}

    def stop_control(self, job_id: str) -> dict[str, object]:
        job = self._get(job_id)
        if job.process is not None:
            return self.stop(job_id)
        future = self._external_futures.get(job_id)
        if future is None or job.status not in {"running", "queued"}:
            return job.public()
        if future.cancel():
            job.stopped = True
            job.status = "stopped"
            job.completed_at = utc_now()
            self._persist()
            return job.public()
        cancellation = self._external_cancel.get(job_id)
        if cancellation:
            cancellation.set()
        process = self._external_processes.get(job_id)
        if process:
            self._terminate_external(job_id, process)
        job.stopped = True
        job.status = "upstream_detached"
        job.completed_at = utc_now()
        job.result_summary = {"cancel_requested": True, "ownership": "upstream", "cancellation": "local adapter stopped; Fabric abort is not exposed"}
        self._persist()
        return job.public()

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
        for future in tuple(self._external_futures.values()):
            future.cancel()
        for job_id, cancellation in tuple(self._external_cancel.items()):
            cancellation.set()
            process = self._external_processes.get(job_id)
            if process:
                self._terminate_external(job_id, process)
        self._external_executor.shutdown(wait=False, cancel_futures=True)

"""Narrow Environment CLI bridge for protected bwrap consumers.

The host Control MCP process owns this endpoint and invokes Environment with
its configured canonical Store. Clients receive a per-sandbox-run bearer
grant, but never Store paths or filesystem handles.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ControlError

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ARGUMENT_BYTES = 48 * 1024
ALLOWED_COMMANDS = frozenset({
    "enter", "inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims",
    "complete", "store", "invoke", "artifact-read", "campaign-state",
    "retire", "continuation", "campaign-bind", "scope-grant",
})
MAX_CAMPAIGN_EVIDENCE_PAGE = 128
ALLOWED_INVOKE_CAPABILITIES = frozenset({
    "mncs-environment:ambient-projection-coherence",
    "mncs-environment:projection-evidence-inspection",
    "mncs-environment:campaign-state-inspection",
    "mncs-system-monitor:system-resource-sample",
    "mncs-system-monitor:system-observability",
    "mncs-automation:automation-resource-headroom-evaluation",
})
RPC_SANDBOX_SOCKET = "/run/mncs-environment-rpc/environment.sock"
LOGGER = logging.getLogger(__name__)


def _has_option(argv: list[Any], option: str) -> bool:
    return any(
        isinstance(item, str)
        and (item == option or item.startswith(option + "="))
        for item in argv
    )


def _requires_selected_session_for_mutation(command: str, argv: list[Any]) -> bool:
    """Identify session mutations that must match this grant's project selection."""
    if not isinstance(argv, list):
        return False
    if command in {
        "resume", "checkpoint", "handoff", "complete", "scope-grant", "invoke",
    }:
        return True
    if command == "claims":
        return any(_has_option(argv, option) for option in (
            "--acquire", "--release", "--transfer-to",
        ))
    if command == "retire":
        has_target = any(_has_option(argv, option) for option in ("--branch", "--worktree"))
        return has_target and not _has_option(argv, "--dry-run")
    return False


@dataclass(frozen=True)
class EnvironmentRPCGrant:
    token_digest: str
    grant_id: str
    token_file: Path
    sandbox_token_file: str


@dataclass
class _GrantRecord:
    grant_id: str
    principal_id: str
    host_root: Path
    sandbox_root: str
    scope: str
    uid: int
    expires_at: float
    token_file: Path
    bound_session_id: str | None = None
    selection_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


class EnvironmentRPCServer:
    """Authenticated, operation-bounded AF_UNIX transport owned by Control."""

    def __init__(self, config: Any, environment_service: Any, policy: Any) -> None:
        self.config = config
        self.environment_service = environment_service
        self.policy = policy
        self.socket_path = Path(config.environment_rpc_socket).expanduser().resolve()
        self.token_root = self.socket_path.parent / "grants"
        stable = json.dumps(
            {"service": "mncs-control-environment-principal/1",
             "uid": os.getuid(), "state_dir": str(environment_service.state_dir.resolve())},
            sort_keys=True,
        ).encode()
        self.principal_id = "ctrl_" + hashlib.sha256(stable).hexdigest()[:32]
        self._lock = threading.RLock()
        self._grants: dict[str, _GrantRecord] = {}
        self._request_condition = threading.Condition(threading.RLock())
        self._request_records: OrderedDict[str, tuple[str, str, dict[str, Any]]] = OrderedDict()
        self._active_requests: set[str] = set()
        self._session_locks: dict[str, threading.RLock] = {}
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stat_result = self.socket_path.parent.stat()
        if stat_result.st_uid != os.getuid() or stat_result.st_mode & 0o077:
            raise ControlError("ENVIRONMENT_RPC_DIRECTORY_DENIED",
                               "Environment IPC directory must be private and owned by Control")
        self.token_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        token_stat = self.token_root.stat()
        if token_stat.st_uid != os.getuid() or token_stat.st_mode & 0o077:
            raise ControlError("ENVIRONMENT_RPC_DIRECTORY_DENIED",
                               "Environment grant directory must be private and owned by Control")
        self._remove_stale_socket()
        for old_grant in self.token_root.glob("*.grant"):
            try:
                observed = old_grant.lstat()
                if stat.S_ISREG(observed.st_mode) and observed.st_uid == os.getuid():
                    old_grant.unlink()
            except FileNotFoundError:
                continue
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            endpoint.bind(str(self.socket_path))
        finally:
            os.umask(old_umask)
        endpoint.listen(32)
        endpoint.settimeout(0.5)
        self._socket = endpoint
        bound = self.socket_path.lstat()
        self._socket_identity = (bound.st_dev, bound.st_ino)
        self._thread = threading.Thread(target=self._serve, name="mncs-environment-rpc", daemon=True)
        self._thread.start()

    def status(self) -> dict[str, Any]:
        """Report whether the owner-bound endpoint is still the bound socket."""
        available = False
        if (not self._closed and self._socket is not None
                and self._socket.fileno() >= 0 and self._thread is not None
                and self._thread.is_alive() and self._socket_identity is not None):
            try:
                observed = self.socket_path.lstat()
                available = (
                    stat.S_ISSOCK(observed.st_mode)
                    and observed.st_uid == os.getuid()
                    and (observed.st_dev, observed.st_ino) == self._socket_identity
                )
            except OSError:
                available = False
        return {
            "provider": "mncs-control-environment-rpc",
            "available": available,
            "state": "ready" if available else "unavailable",
            "authorization": "per-execution-grant-and-peer-credentials",
            "principal_id": self.principal_id,
            "store_mutation": self._store_mutation_status(),
        }

    def _store_mutation_status(self) -> dict[str, str]:
        """Observe whether this service's mount permits Store publication.

        This checks the service's current mount flags and path permissions;
        it does not attempt a write or claim that Store integrity is healthy.
        Agent-visible status therefore distinguishes an available IPC socket
        from an OS boundary that still prevents the Store owner process from
        publishing.
        """
        store_root = Path(self.environment_service.state_dir).expanduser() / "store"
        try:
            store_root.stat()
            filesystem = os.statvfs(store_root)
        except FileNotFoundError:
            return {"state": "store-missing", "code": "store-missing"}
        except PermissionError:
            return {"state": "unknown", "code": "store-stat-denied"}
        except OSError:
            return {"state": "unknown", "code": "store-stat-unavailable"}
        if filesystem.f_flag & getattr(os, "ST_RDONLY", 1):
            return {"state": "direct-filesystem-read-only",
                    "code": "direct-filesystem-read-only"}
        if not os.access(store_root, os.W_OK | os.X_OK):
            return {"state": "filesystem-write-denied",
                    "code": "filesystem-write-denied"}
        return {"state": "owner-write-path-available",
                "code": "owner-write-path-available"}

    def _remove_stale_socket(self) -> None:
        try:
            observed = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(observed.st_mode) or observed.st_uid != os.getuid():
            raise ControlError("ENVIRONMENT_RPC_ENDPOINT_CONFLICT",
                               "refusing to replace a non-owned Environment endpoint")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.2)
            probe.connect(str(self.socket_path))
        except OSError as error:
            if error.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                raise ControlError("ENVIRONMENT_RPC_ENDPOINT_CONFLICT",
                                   "could not prove the previous Environment endpoint is stale") from error
        else:
            raise ControlError("ENVIRONMENT_RPC_ENDPOINT_CONFLICT",
                               "another Environment publication endpoint is already active")
        finally:
            probe.close()
        self.socket_path.unlink()

    def issue_grant(self, resolution: Any) -> EnvironmentRPCGrant:
        if self._closed or self._socket is None:
            raise ControlError("ENVIRONMENT_PERSISTENCE_UNAVAILABLE",
                               "Control Environment publication endpoint is unavailable")
        token = secrets.token_urlsafe(32)
        grant_id = secrets.token_hex(16)
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        token_file = self.token_root / f"{grant_id}.grant"
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            token_file.unlink(missing_ok=True)
            raise
        sandbox_root = "/workspace" if resolution.scope == "workspace" else f"/workspace/{resolution.project}"
        record = _GrantRecord(
            grant_id=grant_id,
            principal_id=self.principal_id,
            host_root=resolution.host_root.resolve(),
            sandbox_root=sandbox_root,
            scope=resolution.scope,
            uid=os.getuid(),
            expires_at=time.monotonic() + max(30.0, float(self.config.max_timeout_seconds) + 15.0),
            token_file=token_file,
        )
        with self._lock:
            self._grants[token_digest] = record
        return EnvironmentRPCGrant(
            token_digest=token_digest,
            grant_id=grant_id,
            token_file=token_file,
            sandbox_token_file="/run/mncs-environment-rpc/grant",
        )

    def grant_mount_source(self, grant: EnvironmentRPCGrant) -> Path:
        """Return the private host file for an active, Control-issued grant."""
        with self._lock:
            record = self._grants.get(grant.token_digest)
        if record is None or record.grant_id != grant.grant_id:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", "Environment capability is no longer active")
        try:
            observed = record.token_file.lstat()
        except FileNotFoundError as error:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", "Environment capability file is unavailable") from error
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                or observed.st_mode & 0o077 or record.token_file.resolve() != grant.token_file.resolve()):
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", "Environment capability file failed validation")
        return record.token_file

    def revoke_grant(self, grant: EnvironmentRPCGrant | None) -> None:
        if grant is None:
            return
        with self._lock:
            self._grants.pop(grant.token_digest, None)
        grant.token_file.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._closed:
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._closed:
                    break
                continue
            threading.Thread(target=self._serve_connection, args=(connection,), daemon=True).start()

    @staticmethod
    def _peer_uid(connection: socket.socket) -> int | None:
        if not hasattr(socket, "SO_PEERCRED"):
            return None
        try:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            return uid
        except OSError:
            return None

    def _receive_frame(self, connection: socket.socket) -> dict[str, Any]:
        header = self._read_exact(connection, 4)
        size = struct.unpack("!I", header)[0]
        if size < 2 or size > MAX_REQUEST_BYTES:
            raise ValueError("request frame size is invalid")
        value = json.loads(self._read_exact(connection, size).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request frame must contain an object")
        return value

    @staticmethod
    def _read_exact(connection: socket.socket, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            value = connection.recv(count - len(chunks))
            if not value:
                raise ConnectionError("caller disconnected during request")
            chunks.extend(value)
        return bytes(chunks)

    @staticmethod
    def _send_frame(connection: socket.socket, value: dict[str, Any]) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        if len(payload) > MAX_RESPONSE_BYTES:
            payload = json.dumps({
                "ok": False,
                "error": {"code": "ENVIRONMENT_RPC_RESPONSE_TOO_LARGE",
                          "message": "Environment response exceeded the transport limit"},
            }).encode()
        connection.sendall(struct.pack("!I", len(payload)) + payload)

    @staticmethod
    def _test_drop_checkpoint_response_after_commit(
        request: dict[str, Any], response: dict[str, Any],
    ) -> bool:
        """Match and consume one owner-armed post-commit response drop.

        The one-shot environment variable is set only by an owner-controlled
        acceptance run. A protected RPC caller cannot enable it, and normal
        service operation has no response-loss path when it is absent.
        """
        variable = "MNCS_CONTROL_TEST_DROP_CHECKPOINT_RESPONSE_REQUEST_ID"
        request_id = os.environ.get(variable, "")
        if not request_id or request.get("request_id") != request_id:
            return False
        argv = request.get("argv")
        if not isinstance(argv, list) or not argv or argv[0] != "checkpoint":
            return False
        result = response.get("result")
        successful_checkpoint = (
            response.get("ok") is True
            and isinstance(result, dict)
            and result.get("exit_code") == 0
        )
        if successful_checkpoint:
            os.environ.pop(variable, None)
        return successful_checkpoint

    @staticmethod
    def _test_terminate_checkpoint_service_after_commit(
        request: dict[str, Any], response: dict[str, Any],
    ) -> bool:
        """Match and consume one owner-armed post-commit service termination.

        This fault is only enabled by the host service owner for a specific
        request identity. Protected callers cannot arm it. It is deliberately
        limited to a successful checkpoint response, after Environment has
        durably returned, so acceptance can exercise lost-response recovery
        across an actual Control process restart.
        """
        variable = "MNCS_CONTROL_TEST_TERMINATE_CHECKPOINT_SERVICE_REQUEST_ID"
        request_id = os.environ.get(variable, "")
        if not request_id or request.get("request_id") != request_id:
            return False
        argv = request.get("argv")
        if not isinstance(argv, list) or not argv or argv[0] != "checkpoint":
            return False
        result = response.get("result")
        successful_checkpoint = (
            response.get("ok") is True
            and isinstance(result, dict)
            and result.get("exit_code") == 0
        )
        if successful_checkpoint:
            os.environ.pop(variable, None)
        return successful_checkpoint

    def _serve_connection(self, connection: socket.socket) -> None:
        request: dict[str, Any] | None = None
        with connection:
            try:
                connection.settimeout(300.0)
                peer_uid = self._peer_uid(connection)
                if peer_uid is None or peer_uid != os.getuid():
                    raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                                       "Environment IPC peer credentials were not admitted")
                request = self._receive_frame(connection)
                response = self.dispatch(request, peer_uid=peer_uid)
            except ControlError as error:
                response = {"ok": False, "error": {
                    "code": error.code, "message": error.message,
                    "details": error.details,
                }}
            except (OSError, ValueError, UnicodeDecodeError, ConnectionError) as error:
                response = {"ok": False, "error": {
                    "code": "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "message": str(error),
                }}
            if request is not None and self._test_terminate_checkpoint_service_after_commit(
                request, response,
            ):
                LOGGER.critical(
                    "owner-armed Control termination after committed checkpoint request_id=%s",
                    request.get("request_id"),
                )
                # os._exit models loss of the service process before the
                # caller receives a receipt. systemd restarts the owner
                # service, and a fresh authorized caller reconciles by ID.
                os._exit(86)
            if request is not None and self._test_drop_checkpoint_response_after_commit(
                request, response,
            ):
                # Close before sending the committed response. The protected
                # client retries the same request ID and reconciles the cached
                # result without a second authoritative publication.
                LOGGER.info(
                    "owner-armed checkpoint response drop after commit request_id=%s",
                    request.get("request_id"),
                )
                return
            try:
                self._send_frame(connection, response)
            except OSError:
                pass

    def _grant(self, request: dict[str, Any], peer_uid: int) -> _GrantRecord:
        token = request.get("grant")
        if not isinstance(token, str) or len(token) > 128:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", "Environment capability is missing")
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            record = self._grants.get(token_digest)
        if record is None or record.uid != peer_uid or time.monotonic() >= record.expires_at:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED", "Environment capability is expired or unknown")
        return record

    def _map_client_path(self, value: str, record: _GrantRecord, cwd: Path) -> Path:
        if not isinstance(value, str) or "\x00" in value:
            raise ControlError("ENVIRONMENT_WORKSPACE_ESCAPE", "client path is invalid")
        candidate = Path(value)
        if candidate.is_absolute():
            sandbox_path = candidate
        else:
            sandbox_path = Path(record.sandbox_root) / cwd.relative_to(record.host_root).as_posix() / candidate
        try:
            relative = sandbox_path.relative_to(record.sandbox_root)
        except ValueError as error:
            raise ControlError("ENVIRONMENT_WORKSPACE_ESCAPE", "client path escapes its scoped sandbox root") from error
        host_path = (record.host_root / relative).resolve(strict=False)
        if host_path != record.host_root and record.host_root not in host_path.parents:
            raise ControlError("ENVIRONMENT_WORKSPACE_ESCAPE", "client path resolves outside its granted root")
        return host_path

    def _map_retirement_repository(self, value: str) -> Path:
        """Resolve one immediate configured checkout for retirement operations.

        Read-only inventory may name any immediate configured repository.
        Mutation admission separately requires that this is the project's
        exact grant root before Environment sees the operation.
        """
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE", "retirement repository is invalid"
            )
        supplied = Path(value)
        if supplied.is_absolute():
            try:
                relative = supplied.relative_to("/workspace")
            except ValueError as error:
                raise ControlError(
                    "ENVIRONMENT_WORKSPACE_ESCAPE",
                    "retirement repository must be inside the mapped workspace",
                ) from error
        else:
            relative = supplied
        if len(relative.parts) != 1 or relative.name in ("", ".", ".."):
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "retirement inventory accepts one immediate workspace repository",
            )

        workspace_root = self.config.workspace_root.expanduser().resolve(strict=True)
        candidate = workspace_root / relative.name
        if candidate.is_symlink():
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "retirement repository must not be a symbolic link",
            )
        try:
            repository = candidate.resolve(strict=True)
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING",
                "retirement repository is unavailable in the configured workspace",
            ) from error
        if repository.parent != workspace_root or not repository.is_dir():
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "retirement repository must be an immediate workspace directory",
            )
        marker = repository / ".git"
        if not (marker.is_dir() or marker.is_file()):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "retirement target is not a Git checkout",
            )
        return repository

    def _translate_argv(self, argv: Any, cwd: Path, record: _GrantRecord) -> list[str]:
        if (not isinstance(argv, list) or len(argv) > 256
                or not all(isinstance(item, str)
                           and len(item.encode("utf-8")) <= MAX_ARGUMENT_BYTES
                           and "\x00" not in item
                           for item in argv)):
            raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "Environment argv is invalid")
        if any(item == "--state-dir" or item.startswith("--state-dir=")
               or item.startswith("--state-") or item == "--persistence"
               or item.startswith("--persistence=") or item.startswith("--persist")
               or item == "--execution-root" or item.startswith("--execution-root=")
               or item == "--sandbox-root" or item.startswith("--sandbox-root=")
               for item in argv):
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "Environment RPC fixes canonical persistence configuration")
        command = argv[0] if argv else None
        if command not in ALLOWED_COMMANDS:
            raise ControlError(
                "ENVIRONMENT_OPERATION_UNAVAILABLE",
                "Environment operation is not exposed by Control",
                details={
                    "operation": command,
                    "status": "unknown",
                    "next": "use an exposed Environment operation or extend the Control operation contract",
                },
            )
        if command == "store":
            if (len(argv) != 4 or argv[1] != "--session"
                    or not argv[2].startswith("ses_")
                    or argv[3] not in ("--verify", "--generation")):
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "Control exposes only session-authorized read-only Store verification and generation queries",
                    details={"required_forms": [
                        ["store", "--session", "<authorized-session>", "--verify"],
                        ["store", "--session", "<authorized-session>", "--generation"],
                    ]},
                )
        if command == "campaign-state":
            self._authorize_campaign_state_argv(argv, record)
        if command == "artifact-read":
            allowed_artifacts = {
                ("mncs-system-monitor:system-resource-sample",
                 "system-resource-sample.json"),
                ("mncs-system-monitor:system-observability",
                 "system-observability-summary.json"),
                ("mncs-automation:automation-resource-headroom-evaluation",
                 "resource-headroom-decision.json"),
            }
            if (len(argv) != 5
                    or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", argv[1])
                    or (argv[2], argv[4]) not in allowed_artifacts
                    or not re.fullmatch(r"cap_[0-9a-f]{16}", argv[3])):
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "Control exposes only the declared Monitor and Automation artifacts",
                    details={"required": [
                        "artifact-read", "<selected-session>", "<capability>",
                        "<capability-binding-id>", "<declared-artifact-file>",
                    ], "allowed": [
                        {"capability": capability, "path": path}
                        for capability, path in sorted(allowed_artifacts)
                    ]},
                )
            environment_project = self.config.repositories.get(
                "environment", "mncs-environment"
            )
            if (record.scope != "project"
                    or self._project_repository(record) != environment_project):
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "capability artifact reads require the Environment project grant",
                    details={"required_project": environment_project},
                )
            if record.bound_session_id != argv[1]:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "artifact reads require the session selected by this grant's authenticated continuation",
                    details={"next": "run project continuation and use its selected session"},
                )
        if command == "invoke":
            if (len(argv) < 3
                    or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", argv[1])):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "capability invocation requires one Environment session identity and capability",
                )
            if argv[2] not in ALLOWED_INVOKE_CAPABILITIES:
                raise ControlError(
                    "ENVIRONMENT_OPERATION_UNAVAILABLE",
                    "Control does not expose this Environment capability",
                    details={
                        "operation": argv[2],
                        "status": "unknown",
                        "next": "inspect the session capability inventory and extend the Control operation contract",
                    },
                )
            resource_evaluation = (
                argv[2] == "mncs-automation:automation-resource-headroom-evaluation"
            )
            if resource_evaluation:
                self._authorize_resource_headroom_invocation(argv, record)
            elif len(argv) != 3:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "Control exposes this capability only with its session-bound declared invocation",
                    details={"required": [
                        "invoke", "<authorized-session>", argv[2],
                    ]},
                )
            elif (argv[2] == "mncs-system-monitor:system-observability"
                  and record.bound_session_id != argv[1]):
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "System Monitor observability requires the session selected by this grant's authenticated continuation",
                    details={"next": "run project continuation and use its selected session"},
                )
            environment_project = self.config.repositories.get(
                "environment", "mncs-environment"
            )
            if record.scope != "project":
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "this Environment capability is exposed only through the Environment project grant",
                    details={"required_project": environment_project},
                )
            selected_project = self._project_repository(record)
            if selected_project != environment_project:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "this Environment capability is exposed only through the Environment project grant",
                    details={"required_project": environment_project},
                )
        translated = list(argv)

        if command == "scope-grant":
            self._authorize_scope_grant_argv(translated, cwd, record)

        def map_path_option(option: str) -> None:
            index = 0
            while index < len(translated):
                item = translated[index]
                if item == option:
                    if index + 1 >= len(translated):
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST", f"{option} needs a value"
                        )
                    translated[index + 1] = str(
                        self._map_client_path(translated[index + 1], record, cwd)
                    )
                    index += 2
                    continue
                prefix = option + "="
                if item.startswith(prefix):
                    value = item[len(prefix):]
                    translated[index] = prefix + str(
                        self._map_client_path(value, record, cwd)
                    )
                index += 1

        if command == "enter":
            for option in ("--definition", "--workspace"):
                map_path_option(option)
            has_workspace = any(item == "--workspace" or item.startswith("--workspace=")
                                for item in translated)
            has_definition = any(
                item == "--definition" or item.startswith("--definition=")
                for item in translated
            )
            if record.scope == "project" and not has_definition:
                # Project grants have a repository-scoped Environment
                # definition. Keep that choice owner-controlled and explicit
                # when invoking Environment, so its default discovery cannot
                # fall through to the broader workspace definition.
                project_definition = (
                    record.host_root / ".mncs" / "project-environment.json"
                )
                if project_definition.exists() or project_definition.is_symlink():
                    if project_definition.is_symlink() or not project_definition.is_file():
                        raise ControlError(
                            "ENVIRONMENT_WORKSPACE_ESCAPE",
                            "project Environment definition must be a regular file",
                        )
                    try:
                        resolved_definition = project_definition.resolve(strict=True)
                    except OSError as error:
                        raise ControlError(
                            "ENVIRONMENT_WORKSPACE_MISSING",
                            "project Environment definition is unavailable",
                        ) from error
                    if (resolved_definition != record.host_root
                            and record.host_root not in resolved_definition.parents):
                        raise ControlError(
                            "ENVIRONMENT_WORKSPACE_ESCAPE",
                            "project Environment definition exceeds the execution grant",
                        )
                    translated.extend(["--definition", str(resolved_definition)])
            if not has_workspace:
                definition_path = next(
                    (
                        Path(translated[index + 1])
                        for index, item in enumerate(translated[:-1])
                        if item == "--definition"
                    ),
                    next(
                        (
                            Path(item.split("=", 1)[1])
                            for item in translated
                            if item.startswith("--definition=")
                        ),
                        None,
                    ),
                )
                if definition_path is None:
                    current = cwd
                    while current == record.host_root or record.host_root in current.parents:
                        candidate = current / ".mncs" / "environment.json"
                        if candidate.is_file():
                            definition_path = candidate.resolve(strict=True)
                            if (
                                definition_path != record.host_root
                                and record.host_root not in definition_path.parents
                            ):
                                raise ControlError(
                                    "ENVIRONMENT_WORKSPACE_ESCAPE",
                                    "discovered Environment definition exceeds the execution grant",
                                    details={
                                        "next": "select a definition inside the authorized workspace"
                                    },
                                )
                            break
                        if (current / ".git").exists() or current == record.host_root:
                            break
                        current = current.parent

                if definition_path is not None:
                    try:
                        definition = json.loads(definition_path.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        definition = None
                    scope = definition.get("workspace_scope") if isinstance(definition, dict) else None
                    provider_owned = bool(
                        isinstance(definition, dict) and definition.get("workspace_provider")
                    ) or (isinstance(scope, dict) and scope.get("kind") == "campaign")
                    declared_root = (
                        definition.get("workspace_root", ".")
                        if isinstance(definition, dict)
                        else None
                    )
                    if not provider_owned and isinstance(declared_root, str) and declared_root:
                        candidate_root = Path(declared_root)
                        if not candidate_root.is_absolute():
                            candidate_root = definition_path.parent / candidate_root
                        resolved_root = candidate_root.resolve(strict=False)
                        if (
                            resolved_root != record.host_root
                            and record.host_root not in resolved_root.parents
                        ):
                            raise ControlError(
                                "ENVIRONMENT_WORKSPACE_ESCAPE",
                                "configured Environment workspace root exceeds the execution grant",
                                details={
                                    "next": "use an authorized workspace-scoped execution or select a definition inside this project"
                                },
                            )
                    if record.scope == "project":
                        # A project sandbox cannot name its host workspace
                        # parent. Control supplies that path only when the
                        # selected Environment definition itself names exactly
                        # this granted project. Environment then performs its
                        # normal durable principal/campaign/context selection,
                        # whether or not the caller already knows campaign_id.
                        repositories = (
                            scope.get("repositories")
                            if isinstance(scope, dict)
                            else None
                        )
                        if repositories != [record.host_root.name]:
                            raise ControlError(
                                "ENVIRONMENT_AUTHORITY_DENIED",
                                "project-scoped Environment entry must declare only its granted repository",
                                details={"repository": record.host_root.name},
                            )
                        if definition.get("workspace_root", ".") not in (None, "", "."):
                            raise ControlError(
                                "ENVIRONMENT_AUTHORITY_DENIED",
                                "project-scoped Environment entry cannot override the owner-mapped workspace root",
                                details={"repository": record.host_root.name},
                            )
                        configured_root = Path(self.config.workspace_root).expanduser().resolve()
                        project_root = record.host_root.expanduser().resolve(strict=True)
                        if project_root.parent != configured_root:
                            raise ControlError(
                                "ENVIRONMENT_WORKSPACE_ESCAPE",
                                "project grant is not an immediate child of the configured workspace",
                            )
                        translated.extend(["--workspace", str(configured_root)])
        elif command == "claims":
            for option in ("--worktree",):
                map_path_option(option)
        elif command == "retire":
            has_inventory = any(item == "--inventory"
                                or item.startswith("--inventory=") for item in argv)
            has_prune = any(item == "--prune" or item.startswith("--prune=")
                            for item in argv)
            has_targets = any(
                item in {"--branch", "--worktree"}
                or item.startswith("--branch=") or item.startswith("--worktree=")
                for item in argv
            )
            has_dry_run = "--dry-run" in argv
            if (argv.count("--dry-run") > 1
                    or any(item.startswith("--dry-run=") for item in argv)):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "--dry-run is a flag and may appear at most once",
                )
            canonical_values: list[str] = []
            repository_values: list[str] = []
            branch_values: list[str] = []
            worktree_values: list[str] = []
            if has_inventory:
                mutation_targets = has_prune or has_targets
                if (argv.count("--inventory") != 1 or not has_dry_run or mutation_targets
                        or any(item.startswith("--inventory=") for item in argv)):
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "retirement inventory remains read-only and requires --dry-run",
                        details={"required": ["--inventory", "--dry-run"]},
                    )
                allowed = {"--repository", "--canonical", "--inventory", "--dry-run"}
            else:
                if has_prune:
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "Control does not expose worktree metadata pruning",
                    )
                if not has_targets:
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        "retirement requires one or more branch or worktree targets",
                    )
                if record.scope != "project":
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "retirement mutations require an exact project grant",
                    )
                allowed = {"--repository", "--canonical", "--branch", "--worktree", "--dry-run"}

            index = 2
            if (len(argv) < 2
                    or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", argv[1])):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "retirement requires one Environment session identity",
                )
            while index < len(argv):
                item = argv[index]
                if item in {"--dry-run", "--inventory"}:
                    index += 1
                    continue
                option = item.split("=", 1)[0] if item.startswith("--") else ""
                if option in {"--dry-run", "--inventory"}:
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        f"{option} does not accept a value",
                    )
                if option not in allowed:
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "retirement arguments exceed the exposed operation contract",
                    )
                if "=" in item:
                    value = item.split("=", 1)[1]
                    index += 1
                else:
                    if index + 1 >= len(argv):
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST", f"{option} needs a value"
                        )
                    value = argv[index + 1]
                    index += 2
                if not value or value.startswith("--") or "\x00" in value:
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST", f"{option} has an invalid value"
                    )
                {
                    "--repository": repository_values,
                    "--canonical": canonical_values,
                    "--branch": branch_values,
                    "--worktree": worktree_values,
                }[option].append(value)

            if len(repository_values) != 1 or len(canonical_values) > 1:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "retirement requires one repository and at most one canonical ref",
                )
            if len(branch_values) + len(worktree_values) > 16:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "retirement target count exceeds the bounded limit of 16",
                )
            if any(value.startswith("-") for value in branch_values + worktree_values):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "retirement target values cannot be command options",
                )

            canonical = canonical_values[0] if canonical_values else "origin/main"
            if canonical not in {"origin/main", "origin/master", "main", "master"}:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "retirement canonical ref is not exposed",
                )

            repository = self._map_retirement_repository(repository_values[0])
            if not has_inventory:
                scoped_repository = record.host_root.expanduser().resolve(strict=True)
                if repository != scoped_repository:
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "retirement mutation must target the repository granted to this execution",
                        details={"repository": scoped_repository.name},
                    )
                map_path_option("--worktree")
                worktree_paths: list[Path] = []
                index = 0
                while index < len(translated):
                    item = translated[index]
                    if item == "--worktree" and index + 1 < len(translated):
                        worktree_paths.append(Path(translated[index + 1]).resolve(strict=False))
                        index += 2
                        continue
                    if item.startswith("--worktree="):
                        worktree_paths.append(
                            Path(item.split("=", 1)[1]).resolve(strict=False)
                        )
                    index += 1
                for path in worktree_paths:
                    if path != scoped_repository and scoped_repository not in path.parents:
                        raise ControlError(
                            "ENVIRONMENT_WORKSPACE_ESCAPE",
                            "retirement worktree must remain inside the granted project",
                        )

            index = 0
            while index < len(translated):
                item = translated[index]
                if item == "--repository":
                    translated[index + 1] = str(repository)
                    index += 2
                    continue
                if item.startswith("--repository="):
                    translated[index] = "--repository=" + str(repository)
                index += 1
        return translated

    def _authorize_resource_headroom_invocation(
        self, argv: list[str], record: _GrantRecord,
    ) -> None:
        """Admit one typed Monitor-artifact to Automation evaluation request."""
        if record.bound_session_id != argv[1]:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "resource-headroom evaluation requires the session selected by this grant's authenticated continuation",
                details={"next": "run project continuation and use its selected session"},
            )
        required_prefix = [
            "invoke",
            argv[1] if len(argv) > 1 else "",
            "mncs-automation:automation-resource-headroom-evaluation",
            "--input-artifact",
            "monitor-sample",
            "mncs-system-monitor:system-resource-sample",
        ]
        if (len(argv) != 25 or argv[:6] != required_prefix
                or re.fullmatch(r"cap_[0-9a-f]{16}", argv[6]) is None
                or argv[7] != "system-resource-sample.json"
                or argv[8] != "--"):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "resource-headroom evaluation requires the bounded System Monitor Store artifact",
                details={"required": [
                    "invoke", "<selected-session>",
                    "mncs-automation:automation-resource-headroom-evaluation",
                    "--input-artifact monitor-sample",
                    "mncs-system-monitor:system-resource-sample",
                    "<capability-binding-id> system-resource-sample.json",
                    "--", "<bounded resource-evaluation parameters>",
                ]},
            )

        option_names = [
            "--input-name",
            "--measurement-execution",
            "--measurement-subject-identity",
            "--intent-identity",
            "--requested-memory-bytes",
            "--measurement-scale-percent",
            "--minimum-host-headroom-bytes",
            "--max-age-ms",
        ]
        values = argv[10::2]
        if argv[9::2] != option_names or len(values) != len(option_names):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "resource-headroom evaluation arguments exceed the typed operation contract",
            )
        (input_name, measurement_execution, subject_identity, intent_identity,
         requested_memory, scale_percent, minimum_headroom, max_age) = values
        identity_pattern = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}"
        if (input_name != "monitor-sample"
                or re.fullmatch(identity_pattern, measurement_execution) is None
                or re.fullmatch(identity_pattern, subject_identity) is None
                or re.fullmatch(identity_pattern, intent_identity) is None):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "resource-headroom identities are malformed",
            )
        number_pattern = r"(?:0|[1-9][0-9]{0,18})"
        numeric_values: list[int] = []
        for value in (requested_memory, scale_percent, minimum_headroom, max_age):
            if re.fullmatch(number_pattern, value) is None:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "resource-headroom numeric parameters must be bounded unsigned integers",
                )
            numeric_values.append(int(value))
        requested_bytes, scale, host_reserve, maximum_age = numeric_values
        if (not 0 < requested_bytes <= 2**63 - 1
                or not 100 <= scale <= 500
                or not 0 <= host_reserve <= 2**63 - 1
                or not 0 <= maximum_age <= 86_400_000):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "resource-headroom numeric parameters exceed their declared bounds",
            )

    def _authorize_campaign_state_argv(
        self, argv: list[str], record: _GrantRecord,
    ) -> None:
        """Expose only a bounded page read for the authenticated Environment session."""
        if (len(argv) < 2
                or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", argv[1])):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "campaign-state requires one Environment session identity",
            )
        environment_project = self.config.repositories.get(
            "environment", "mncs-environment"
        )
        if (record.scope != "project"
                or self._project_repository(record) != environment_project):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign-state paging is available only through the Environment project grant",
                details={"required_project": environment_project},
            )

        seen: set[str] = set()
        index = 2
        while index < len(argv):
            option = argv[index]
            if option not in {"--evidence-offset", "--evidence-limit"}:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "campaign-state exposes only bounded evidence page arguments",
                    details={"allowed": ["--evidence-offset", "--evidence-limit"]},
                )
            key = option.removeprefix("--evidence-")
            if key in seen or index + 1 >= len(argv):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    f"{option} must be supplied once with an integer value",
                )
            raw_value = argv[index + 1]
            if not re.fullmatch(r"[0-9]{1,10}", raw_value):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    f"{option} must be a nonnegative integer",
                )
            value = int(raw_value)
            if key == "limit" and not 1 <= value <= MAX_CAMPAIGN_EVIDENCE_PAGE:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    f"--evidence-limit must be between 1 and {MAX_CAMPAIGN_EVIDENCE_PAGE}",
                )
            seen.add(key)
            index += 2

    def _authorize_scope_grant_argv(
        self, argv: list[str], cwd: Path, record: _GrantRecord,
    ) -> None:
        """Gate one Environment session's repository-scope admission.

        The Control-owned approval file grants exactly a campaign/repository
        pair. The operation is callable only from the Environment project
        sandbox and can name only one immediate configured workspace checkout.
        Environment performs the independent session, rights, Git, claim, and
        Store-CAS checks before recording the immutable grant.
        """
        required = {
            "--campaign-id", "--repository", "--expected-authority-revision",
            "--approval-reference",
        }
        values: dict[str, str] = {}
        index = 2  # command plus the positional Environment session identity
        if len(argv) < 2 or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", argv[1]):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "scope admission requires one Environment session identity",
            )
        while index < len(argv):
            item = argv[index]
            if item.startswith("--") and "=" in item:
                option, value = item.split("=", 1)
            elif item in required and index + 1 < len(argv):
                option, value = item, argv[index + 1]
                index += 1
            else:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "scope admission arguments are incomplete or contain unsupported options",
                )
            if option not in required or option in values or not value or "\x00" in value:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "scope admission arguments are invalid or repeated",
                )
            values[option] = value
            index += 1
        if set(values) != required:
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "scope admission requires campaign, repository, authority revision, and approval reference",
            )

        environment_name = self.config.repositories.get(
            "environment", "mncs-environment"
        )
        workspace_root = Path(self.config.workspace_root).expanduser().resolve(strict=True)
        environment_root = workspace_root / environment_name
        project_root = record.host_root.resolve(strict=True)
        working_directory = cwd.resolve(strict=True)
        if (record.scope != "project" or project_root != environment_root
                or (working_directory != project_root
                    and project_root not in working_directory.parents)):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "repository scope admission is available only from the Environment project grant",
            )

        campaign_id = values["--campaign-id"]
        repository_name = values["--repository"]
        authority_revision = values["--expected-authority-revision"]
        approval_reference = values["--approval-reference"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", campaign_id):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST", "scope admission campaign identity is invalid"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", authority_revision):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST", "scope admission authority revision is invalid"
            )
        approved = self.config.environment_scope_grants.get(campaign_id, {})
        if approved.get(repository_name) != approval_reference:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "Control has no exact owner-approved campaign/repository scope grant",
                details={"campaign_id": campaign_id, "repository": repository_name},
            )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", repository_name):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST", "scope admission repository identity is invalid"
            )
        target = workspace_root / repository_name
        if target.is_symlink():
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE", "scope admission target cannot be a symbolic link"
            )
        try:
            resolved_target = target.resolve(strict=True)
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING", "scope admission target is unavailable"
            ) from error
        if (resolved_target.parent != workspace_root or not resolved_target.is_dir()
                or not ((resolved_target / ".git").is_dir()
                        or (resolved_target / ".git").is_file())):
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "scope admission target must be an immediate configured Git checkout",
            )

    def _authorize_session(self, session_id: str, principal_id: str) -> None:
        pkg = self.environment_service._pkg()
        store = self.environment_service._store(pkg)
        try:
            snapshot = store.load_snapshot(session_id)
        finally:
            store.close()
        if not isinstance(snapshot, dict):
            raise ControlError("ENVIRONMENT_SESSION_UNKNOWN", "Environment session is not present in canonical Store")
        if snapshot.get("authenticated_principal_id") != principal_id:
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "session has no matching authenticated continuation principal",
                               details={"session_id": session_id,
                                        "next": "request an explicit handoff from the recorded owner"})

    def _authorize_handoff_accept(
        self,
        session_id: str,
        handoff_id: str,
        principal_id: str,
        consumer_id: str,
        consumer_kind: str,
    ) -> None:
        """Admit a receiver only for a current owner-issued transfer.

        A handoff identity and consumer label are not credentials. The
        canonical record must bind this authenticated principal and consumer,
        and its source must still be the session owner.
        """
        pkg = self.environment_service._pkg()
        store = self.environment_service._store(pkg)
        try:
            snapshot = store.load_snapshot(session_id)
            handoff = store.load_handoff(session_id, handoff_id)
        finally:
            store.close()
        if not isinstance(snapshot, dict) or not isinstance(handoff, dict):
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "no current handoff authorizes this continuation")
        source_principal = snapshot.get("authenticated_principal_id")
        pending_id = snapshot.get("pending_handoff_id")
        snapshot_handoffs = snapshot.get("handoffs")
        legacy_pending = (
            "pending_handoff_id" not in snapshot
            and isinstance(snapshot_handoffs, list)
            and snapshot_handoffs[-1:] == [handoff_id]
        )
        if (
            handoff.get("identity") != handoff_id
            or handoff.get("session_id") != session_id
            or not isinstance(snapshot_handoffs, list)
            or handoff_id not in snapshot_handoffs
            or not isinstance(source_principal, str)
            or not source_principal
            or handoff.get("from_authenticated_principal_id") != source_principal
            or handoff.get("from_consumer") != snapshot.get("consumer_id")
            or handoff.get("to_authenticated_principal_id") != principal_id
            or handoff.get("to_consumer") != consumer_id
            or handoff.get("to_consumer_kind", "agent") != consumer_kind
            or snapshot.get("lifecycle") != "handed_off"
            or (pending_id != handoff_id and not legacy_pending)
        ):
            raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                               "no current handoff authorizes this continuation")

    @staticmethod
    def _accept_positionals(argv: list[str], command_index: int = 0) -> list[str]:
        """Extract accept's positionals even when common options come first."""
        result: list[str] = []
        skip_value = False
        value_options = {"--consumer", "--consumer-kind"}
        for item in argv[command_index + 1:]:
            if skip_value:
                skip_value = False
                continue
            if item in value_options:
                skip_value = True
                continue
            if any(item.startswith(option + "=") for option in value_options):
                continue
            if not item.startswith("-"):
                result.append(item)
        return result

    def dispatch(self, request: dict[str, Any], *, peer_uid: int) -> dict[str, Any]:
        try:
            grant = self._grant(request, peer_uid)
            request_id = request.get("request_id")
            if not isinstance(request_id, str) or not request_id.startswith("req_") or len(request_id) > 80:
                raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "stable request identity is invalid")
            content_digest = hashlib.sha256(json.dumps(
                {"argv": request.get("argv"), "cwd": request.get("cwd"),
                 "principal_id": grant.principal_id,
                 "host_root": str(grant.host_root),
                 "sandbox_root": grant.sandbox_root,
                 "scope": grant.scope},
                sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            with self._request_condition:
                while request_id in self._active_requests:
                    finished = self._request_condition.wait(timeout=250.0)
                    if request_id not in self._active_requests:
                        break
                    if not finished:
                        raise ControlError(
                            "ENVIRONMENT_PUBLICATION_AMBIGUOUS",
                            "matching Environment request is still being reconciled",
                        )
                prior = self._request_records.get(request_id)
                if prior is not None:
                    prior_principal, prior_digest, response = prior
                    if prior_principal != grant.principal_id or prior_digest != content_digest:
                        raise ControlError("ENVIRONMENT_RPC_REQUEST_CONFLICT",
                                           "request identity is already bound to another operation")
                    self._request_records.move_to_end(request_id)
                    prior_argv = request.get("argv")
                    if (isinstance(prior_argv, list) and prior_argv
                            and prior_argv[0] == "artifact-read"):
                        with grant.selection_lock:
                            if (len(prior_argv) < 2
                                    or grant.bound_session_id != prior_argv[1]):
                                raise ControlError(
                                    "ENVIRONMENT_AUTHORITY_DENIED",
                                    "cached artifact read no longer matches this grant's selected session",
                                    details={"next": "select the session again through Environment continuation"},
                                )
                            self._authorize_session(prior_argv[1], grant.principal_id)
                            return response
                    return response
                self._active_requests.add(request_id)
            argv = request.get("argv")
            session_id = None
            if isinstance(argv, list) and argv and argv[0] in {
                "inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims", "invoke",
                "retire", "store",
            }:
                if argv[0] == "accept":
                    if all(isinstance(item, str) for item in argv):
                        positional = self._accept_positionals(argv)
                        session_id = positional[0] if positional else None
                else:
                    session_id = next((item for item in argv[1:]
                                       if isinstance(item, str) and not item.startswith("-")), None)
            lock = None
            if session_id:
                with self._lock:
                    lock = self._session_locks.setdefault(session_id, threading.RLock())
            try:
                command = argv[0] if isinstance(argv, list) and argv else None
                selection_lock = (
                    grant.selection_lock
                    if (
                        command in {"enter", "continuation", "campaign-bind", "artifact-read", "retire", "accept"}
                        or _requires_selected_session_for_mutation(command or "", argv)
                    ) else None
                )
                if selection_lock is not None:
                    with selection_lock:
                        if lock is None:
                            response = self._dispatch_once(request, peer_uid=peer_uid)
                        else:
                            with lock:
                                response = self._dispatch_once(request, peer_uid=peer_uid)
                elif lock is None:
                    response = self._dispatch_once(request, peer_uid=peer_uid)
                else:
                    with lock:
                        response = self._dispatch_once(request, peer_uid=peer_uid)
            except ControlError as error:
                response = {"ok": False, "error": {
                    "code": error.code, "message": error.message,
                    "details": error.details,
                }}
            except (OSError, ValueError, UnicodeDecodeError, ConnectionError) as error:
                response = {"ok": False, "error": {
                    "code": "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "message": str(error),
                }}
            except Exception as error:  # keep request waiters from becoming stuck
                store_code = getattr(getattr(error, "code", None), "name", None)
                store_code = store_code or getattr(error, "code", None)
                if type(error).__name__ == "StoreIntegrityFailure" or store_code in {
                    "INTEGRITY_FAILURE", "RECOVERY_REQUIRED", "store-integrity-failure",
                }:
                    error_code = "ENVIRONMENT_STORE_CORRUPTION"
                elif store_code == "direct-filesystem-read-only":
                    error_code = "ENVIRONMENT_DIRECT_READ_ONLY"
                elif store_code in {"CONFLICT", "STALE_GENERATION", "IDENTITY_CONFLICT"}:
                    error_code = "ENVIRONMENT_PUBLICATION_CONFLICT"
                elif type(error).__name__ == "StoreUnavailable":
                    error_code = "ENVIRONMENT_PERSISTENCE_UNAVAILABLE"
                else:
                    error_code = "ENVIRONMENT_RPC_FAILED"
                response = {"ok": False, "error": {
                    "code": error_code,
                    "message": f"{type(error).__name__}: {error}",
                }}
            with self._request_condition:
                self._request_records[request_id] = (
                    grant.principal_id, content_digest, response
                )
                self._request_records.move_to_end(request_id)
                while len(self._request_records) > 2048:
                    self._request_records.popitem(last=False)
                self._active_requests.discard(request_id)
                self._request_condition.notify_all()
            return response
        except ControlError as error:
            return {"ok": False, "error": {
                "code": error.code, "message": error.message,
                "details": error.details,
            }}

    def _dispatch_once(self, request: dict[str, Any], *, peer_uid: int) -> dict[str, Any]:
        record = self._grant(request, peer_uid)
        client_cwd = request.get("cwd")
        if not isinstance(client_cwd, str) or not client_cwd.startswith("/"):
            raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "client cwd must be absolute sandbox path")
        try:
            relative = Path(client_cwd).relative_to(record.sandbox_root)
        except ValueError as error:
            raise ControlError("ENVIRONMENT_WORKSPACE_ESCAPE", "client cwd escapes its scoped sandbox root") from error
        cwd = (record.host_root / relative).resolve(strict=True)
        if cwd != record.host_root and record.host_root not in cwd.parents:
            raise ControlError("ENVIRONMENT_WORKSPACE_ESCAPE", "client cwd escapes its granted host root")
        if not cwd.is_dir():
            raise ControlError("ENVIRONMENT_WORKSPACE_MISSING", "client cwd is unavailable in the host namespace")
        argv = self._translate_argv(request.get("argv"), cwd, record)
        command = argv[0]
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id.startswith("req_") or len(request_id) > 80:
            raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "stable request identity is invalid")
        if command == "enter":
            # Entry may establish a different Environment context. Invalidate
            # any earlier selection until its returned capsule matches again.
            record.bound_session_id = None
        if command == "continuation":
            return self._campaign_continuation(record, argv, request_id, cwd=cwd)
        if command == "campaign-bind":
            return self._campaign_task_bind(record, argv, request_id)
        if command == "retire":
            # The repository path was resolved by Control to one immediate
            # configured workspace checkout. Environment may inspect physical
            # worktrees only within that checkout; other registrations remain
            # classified outside this operation's scope.
            repository = next(
                Path(item.split("=", 1)[1])
                for item in argv
                if item.startswith("--repository=")
            ) if any(item.startswith("--repository=") for item in argv) else Path(
                argv[argv.index("--repository") + 1]
            )
            host_root = record.host_root.expanduser().resolve(strict=True)
            repository = repository.expanduser().resolve(strict=True)
            try:
                repository_relative = repository.relative_to(host_root)
            except ValueError as error:
                raise ControlError(
                    "ENVIRONMENT_WORKSPACE_ESCAPE",
                    "retirement repository escapes its authenticated execution root",
                ) from error
            sandbox_repository = Path(record.sandbox_root) / repository_relative
            argv.extend([
                "--execution-root", str(repository),
                "--sandbox-root", str(sandbox_repository),
            ])
        if command in {"inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims", "complete", "retire", "store", "scope-grant", "invoke", "artifact-read", "campaign-state"}:
            try:
                command_index = argv.index(command)
                if command == "scope-grant":
                    session_id = argv[command_index + 1]
                else:
                    positional = (
                        self._accept_positionals(argv, command_index)
                        if command == "accept"
                        else [item for item in argv[command_index + 1:]
                              if not item.startswith("-")]
                    )
                    session_id = positional[0]
            except (StopIteration, ValueError, IndexError) as error:
                raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "session identity is required") from error
            if command == "accept":
                try:
                    handoff_id = positional[1]
                except IndexError as error:
                    raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST",
                                       "handoff identity is required") from error
                consumer_id = "local-agent"
                consumer_kind = "agent"
                for index, item in enumerate(argv[command_index + 1:], command_index + 1):
                    if item == "--consumer" and index + 1 < len(argv):
                        consumer_id = argv[index + 1]
                    elif item == "--consumer-kind" and index + 1 < len(argv):
                        consumer_kind = argv[index + 1]
                    elif item.startswith("--consumer="):
                        consumer_id = item.split("=", 1)[1]
                    elif item.startswith("--consumer-kind="):
                        consumer_kind = item.split("=", 1)[1]
                self._authorize_handoff_accept(
                    session_id, handoff_id, record.principal_id,
                    consumer_id, consumer_kind,
                )
            else:
                self._authorize_session(session_id, record.principal_id)
                if (_requires_selected_session_for_mutation(command, argv)
                        and record.bound_session_id != session_id):
                    raise ControlError(
                        "ENVIRONMENT_AUTHORITY_DENIED",
                        "session mutation requires the exact session selected by Environment continuation in this execution",
                        details={
                            "session_id": session_id,
                            "selected_session_id": record.bound_session_id,
                            "next": "run project continuation in this protected execution, then target only its selected session",
                        },
                    )
            if command == "claims":
                transfer_target: str | None = None
                transfer_options = 0
                index = 0
                while index < len(argv):
                    item = argv[index]
                    if item == "--transfer-to":
                        transfer_options += 1
                        if index + 1 < len(argv):
                            transfer_target = argv[index + 1]
                        index += 2
                    elif item.startswith("--transfer-to="):
                        transfer_options += 1
                        transfer_target = item.partition("=")[2]
                        index += 1
                    else:
                        index += 1
                if transfer_options:
                    if (transfer_options != 1 or not transfer_target
                            or transfer_target.startswith("--")):
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST",
                            "claim transfer needs exactly one target session",
                        )
                    self._authorize_session(transfer_target, record.principal_id)
        cli_source = self.environment_service.environment_path
        program = "from mncs_env.cli import main; raise SystemExit(main())"
        process_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(Path.home()),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONPATH": str(cli_source),
            "MNCS_ENV_AUTH_PRINCIPAL_ID": record.principal_id,
            "MNCS_ENV_RPC_REQUEST_ID": request_id,
        }
        host_argv = [sys.executable, "-c", program, "--state-dir",
                     str(self.environment_service.state_dir), "--persistence", "store", *argv]
        try:
            completed = subprocess.run(
                host_argv, cwd=cwd, env=process_env, capture_output=True,
                text=True, timeout=240, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ControlError("ENVIRONMENT_PUBLICATION_AMBIGUOUS",
                               "Environment operation exceeded its response window; retry with the same request") from error
        output_limit = (
            MAX_RESPONSE_BYTES - 64 * 1024
            if command == "artifact-read"
            else MAX_RESPONSE_BYTES // 2
        )
        stdout = completed.stdout[:output_limit]
        stderr = completed.stderr[:output_limit]
        if command == "accept" and completed.returncode == 0:
            if not isinstance(session_id, str):
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "successful handoff acceptance did not resolve a session identity",
                )
            # The explicit handoff grant authorizes this transition. Bind the
            # newly accepted session for subsequent work in this execution.
            record.bound_session_id = session_id
        if command == "enter" and completed.returncode in {0, 5}:
            stdout = self._attach_project_continuation(
                record, stdout, cwd=cwd,
                original_stdout_bytes=len(completed.stdout.encode("utf-8")),
                output_limit=output_limit,
            )
        elif command == "enter":
            stdout, stderr = self._attach_project_entry_diagnostic(
                record, stdout, stderr, cwd=cwd,
                original_stdout_bytes=len(completed.stdout.encode("utf-8")),
                original_stderr_bytes=len(completed.stderr.encode("utf-8")),
                output_limit=output_limit,
            )
        return {"ok": True, "result": {
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "request_id": request_id,
            "principal_id": record.principal_id,
        }}

    def _project_repository(
        self, record: _GrantRecord, *, cwd: Path | None = None,
    ) -> str:
        """Resolve one configured project from a project grant or workspace cwd."""
        configured_root = Path(self.config.workspace_root).expanduser().resolve()
        if record.scope == "project":
            try:
                project_root = record.host_root.expanduser().resolve(strict=True)
            except OSError as error:
                raise ControlError(
                    "ENVIRONMENT_PROJECT_UNKNOWN",
                    "project-scoped continuation checkout is unavailable",
                ) from error
            if project_root.parent != configured_root or not project_root.is_dir():
                raise ControlError(
                    "ENVIRONMENT_WORKSPACE_ESCAPE",
                    "project-scoped continuation grant does not identify an immediate configured project",
                )
            return project_root.name

        if record.scope != "workspace" or cwd is None:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "project continuation requires a project grant or a workspace grant with a repository cwd",
            )
        try:
            workspace_root = record.host_root.expanduser().resolve(strict=True)
            working_directory = cwd.expanduser().resolve(strict=True)
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING",
                "workspace-scoped continuation cwd is unavailable",
            ) from error
        if workspace_root != configured_root:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "workspace-scoped continuation must use the configured workspace root",
            )
        if (working_directory != workspace_root
                and workspace_root not in working_directory.parents):
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "workspace-scoped continuation cwd escapes the configured workspace",
            )
        try:
            resolved = subprocess.run(
                ["git", "rev-parse", "--show-toplevel", "--git-common-dir"],
                cwd=working_directory, capture_output=True, text=True,
                timeout=2.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ControlError(
                "ENVIRONMENT_PROJECT_UNKNOWN",
                "workspace cwd could not be resolved to a Git checkout",
            ) from error
        paths = resolved.stdout.splitlines()
        if resolved.returncode != 0 or len(paths) != 2:
            raise ControlError(
                "ENVIRONMENT_PROJECT_UNKNOWN",
                "workspace cwd is not inside a configured Git checkout",
            )
        try:
            checkout_root = Path(paths[0]).expanduser().resolve(strict=True)
            common_dir = Path(paths[1]).expanduser()
            if not common_dir.is_absolute():
                common_dir = checkout_root / common_dir
            common_dir = common_dir.resolve(strict=True)
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_PROJECT_UNKNOWN",
                "workspace cwd has an unavailable Git common directory",
            ) from error
        if common_dir.name != ".git":
            raise ControlError(
                "ENVIRONMENT_PROJECT_UNKNOWN",
                "workspace checkout does not have a configured project Git common directory",
            )
        project_root = common_dir.parent
        if project_root.parent != workspace_root or not project_root.is_dir():
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "workspace checkout Git common directory does not identify one immediate configured project",
            )
        if checkout_root != project_root and project_root not in checkout_root.parents:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "workspace checkout is outside its configured project Git common directory",
            )
        return project_root.name

    def _attach_project_continuation(
        self, record: _GrantRecord, stdout: str, *,
        cwd: Path,
        original_stdout_bytes: int, output_limit: int,
    ) -> str:
        """Add a read-only project capsule to a persisted Environment entry.

        The Environment entry remains the authority for session selection and
        mutation. Control adds its existing read-only continuation projection
        and binds this execution only when that projection selects the exact
        session returned by entry. Readiness-blocked entries still receive the
        capsule; the projection cannot transfer or adopt another context.
        """
        if (record.scope not in {"project", "workspace"}
                or original_stdout_bytes > output_limit):
            return stdout
        try:
            payload = json.loads(stdout)
        except (TypeError, json.JSONDecodeError):
            return stdout
        if (not isinstance(payload, dict)
                or not isinstance(payload.get("session_id"), str)):
            return stdout
        project: str | None = None
        project_error: ControlError | None = None
        try:
            project = self._project_repository(record, cwd=cwd)
        except ControlError as error:
            project_error = error
        continuation = payload.get("continuation")
        campaign_id = continuation.get("identity") if isinstance(continuation, dict) else None
        entry_configuration = payload.get("configuration")
        entry_definition_id = (
            entry_configuration.get("definition_id")
            if isinstance(entry_configuration, dict) else None
        )
        entry_workspace_root = payload.get("workspace_root")
        project_context = None
        if (record.scope in {"project", "workspace"}
                and isinstance(entry_definition_id, str)
                and entry_definition_id.startswith("env_")
                and len(entry_definition_id) == 20
                and all(char in "0123456789abcdef" for char in entry_definition_id[4:])
                and isinstance(entry_workspace_root, str)):
            try:
                configured_root = Path(self.config.workspace_root).expanduser().resolve(strict=True)
            except OSError:
                configured_root = None
            if configured_root is not None and entry_workspace_root == str(configured_root):
                project_context = (entry_definition_id, entry_workspace_root)
        if project_error is not None:
            payload["control_project_continuation"] = {
                "schema_version": "mncs.control.project-entry-continuation/1",
                "campaign_id": campaign_id if isinstance(campaign_id, str) else None,
                "status": "unknown",
                "code": project_error.code,
                "next": (
                    project_error.details.get("next")
                    if isinstance(project_error.details, dict)
                    and isinstance(project_error.details.get("next"), str)
                    else "verify that the grant identifies one configured project"
                ),
            }
        elif project is None:
            payload["control_project_continuation"] = {
                "schema_version": "mncs.control.project-entry-continuation/1",
                "campaign_id": campaign_id if isinstance(campaign_id, str) else None,
                "status": "unknown",
                "code": "ENVIRONMENT_PROJECT_UNKNOWN",
                "next": "select a cwd inside one configured repository before reading its campaign capsule",
            }
        elif (getattr(self.environment_service, "authenticated_principal_id", None)
              != record.principal_id):
            payload["control_project_continuation"] = {
                "schema_version": "mncs.control.project-entry-continuation/1",
                "campaign_id": campaign_id if isinstance(campaign_id, str) else None,
                "repository": project,
                "status": "unknown",
                "code": "ENVIRONMENT_AUTHORITY_DENIED",
                "next": "verify the authenticated Control principal binding",
            }
        elif (not isinstance(campaign_id, str) or not campaign_id.strip()
                or len(campaign_id) > 160 or "\x00" in campaign_id):
            payload["control_project_continuation"] = {
                "schema_version": "mncs.control.project-entry-continuation/1",
                "repository": project,
                "status": "unknown",
                "code": "campaign-identity-unavailable",
                "next": "inspect the Environment entry continuation identity",
            }
        else:
            try:
                capsule = self.environment_service.campaign_continuation(
                    project, campaign_id,
                )
                if not isinstance(capsule, dict):
                    raise TypeError("Environment returned a non-object continuation capsule")
                capsule = self._select_project_campaign_context(
                    capsule, record, project,
                    project_context=project_context,
                    derive_project_context=False,
                )
                payload["control_project_continuation"] = capsule
                if (
                    record.scope in {"project", "workspace"}
                    and capsule.get("status") == "ready"
                    and capsule.get("selection_basis") in {
                        "authenticated-project-environment-definition",
                        "authenticated-task-selector",
                    }
                    and capsule.get("selected_session_id") == payload.get("session_id")
                ):
                    record.bound_session_id = payload["session_id"]
            except ControlError as error:
                next_step = error.details.get("next") if isinstance(error.details, dict) else None
                payload["control_project_continuation"] = {
                    "schema_version": "mncs.control.project-entry-continuation/1",
                    "campaign_id": campaign_id,
                    "repository": project,
                    "status": "unknown",
                    "code": error.code,
                    "next": next_step if isinstance(next_step, str) else (
                        "run the project-scoped Environment continuation lookup"
                    ),
                }
            except Exception:
                # A successful Environment entry is durable already. A
                # supplementary read must not turn it into a failed or
                # ambiguous publication result.
                payload["control_project_continuation"] = {
                    "schema_version": "mncs.control.project-entry-continuation/1",
                    "campaign_id": campaign_id,
                    "repository": project,
                    "status": "unknown",
                    "code": "campaign-lookup-failed",
                    "next": "run the project-scoped Environment continuation lookup",
                }

        rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if len(rendered.encode("utf-8")) <= output_limit:
            return rendered

        payload["control_project_continuation"] = {
            "schema_version": "mncs.control.project-entry-continuation/1",
            "campaign_id": campaign_id if isinstance(campaign_id, str) else None,
            "repository": project,
            "status": "unknown",
            "code": "campaign-capsule-response-limit",
            "next": "run the project-scoped Environment continuation lookup",
        }
        rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        return rendered if len(rendered.encode("utf-8")) <= output_limit else stdout

    def _attach_project_entry_diagnostic(
        self, record: _GrantRecord, stdout: str, stderr: str, *, cwd: Path,
        original_stdout_bytes: int, original_stderr_bytes: int,
        output_limit: int,
    ) -> tuple[str, str]:
        """Add bounded project choices to authenticated campaign-entry errors."""
        if (record.scope not in {"project", "workspace"}
                or original_stdout_bytes > output_limit
                or original_stderr_bytes > output_limit
                or getattr(self.environment_service, "authenticated_principal_id", None)
                != record.principal_id):
            return stdout, stderr

        for stream_name, stream_value in (("stderr", stderr), ("stdout", stdout)):
            try:
                payload = json.loads(stream_value)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict) or not isinstance(payload.get("error"), str):
                continue
            diagnostics = payload.get("diagnostics")
            if not isinstance(diagnostics, dict):
                continue
            if diagnostics.get("code") not in {
                "campaign-continuation-ambiguous",
                "campaign-context-mismatch",
                "campaign-session-active",
            }:
                continue

            try:
                repository = self._project_repository(record, cwd=cwd)
                campaign_id = diagnostics.get("campaign_id")
                capsule = self.environment_service.campaign_continuation(
                    repository,
                    campaign_id if isinstance(campaign_id, str) else None,
                )
                if not isinstance(capsule, dict):
                    raise TypeError("Environment returned a non-object continuation capsule")
                projected = self._compact_entry_continuation(capsule)
            except ControlError as error:
                next_step = error.details.get("next") if isinstance(error.details, dict) else None
                projected = {
                    "schema_version": "mncs.control.project-entry-continuation/1",
                    "status": "unknown",
                    "code": error.code,
                    "next": next_step if isinstance(next_step, str) else (
                        "run the project-scoped Environment continuation lookup"
                    ),
                }
                if record.scope == "project":
                    projected["repository"] = Path(record.host_root).name
            except Exception:
                projected = {
                    "schema_version": "mncs.control.project-entry-continuation/1",
                    "status": "unknown",
                    "code": "campaign-lookup-failed",
                    "next": "run the project-scoped Environment continuation lookup",
                }
                if record.scope == "project":
                    projected["repository"] = Path(record.host_root).name

            if "continuation" not in diagnostics:
                diagnostics["continuation"] = projected
            else:
                prior = diagnostics.get("continuations")
                prior = prior if isinstance(prior, list) else []
                diagnostics["continuations"] = [projected, *prior]
            rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if len(rendered.encode("utf-8")) > output_limit:
                diagnostics["continuation"] = {
                    "schema_version": "mncs.control.project-entry-continuation/1",
                    "repository": Path(record.host_root).name,
                    "campaign_id": diagnostics.get("campaign_id"),
                    "status": "unknown",
                    "code": "campaign-capsule-response-limit",
                    "next": "run the project-scoped Environment continuation lookup",
                }
                diagnostics.pop("continuations", None)
                rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if len(rendered.encode("utf-8")) > output_limit:
                return stdout, stderr
            return (rendered, stderr) if stream_name == "stdout" else (stdout, rendered)
        return stdout, stderr

    @staticmethod
    def _compact_entry_continuation(capsule: dict[str, Any]) -> dict[str, Any]:
        """Flatten selection capsules so the bounded CLI diagnostic retains identities."""
        session_fields = (
            "session_id", "snapshot_version", "lifecycle", "consumer_id",
            "consumer_kind", "current_campaign_consumer", "definition_id",
            "workspace_root", "project_reference", "work_intent", "repositories",
            "authorized_consumers", "campaign_session_ids",
            "repository_facts_source", "claim_ids", "claims", "checkpoint_ids",
            "campaign_state_checkpoint_id",
            "latest_checkpoint", "delivery", "unresolved_pressures", "evidence_count",
            "evidence_truncated", "campaign_charter", "live_repository_observation",
            "recorded_checkout_comparisons",
        )
        campaign_rows = capsule.get("campaigns")
        campaign_rows = campaign_rows if isinstance(campaign_rows, list) else [capsule]
        campaign_statuses: list[dict[str, Any]] = []
        continuations: list[dict[str, Any]] = []
        for campaign in campaign_rows[:8]:
            if not isinstance(campaign, dict):
                continue
            campaign_identity = campaign.get("campaign_id")
            campaign_statuses.append({
                key: campaign[key] for key in
                ("campaign_id", "status", "contexts_count", "continuations_count",
                 "contexts_truncated", "continuations_truncated")
                if key in campaign
            })
            rows = campaign.get("continuations")
            if not isinstance(rows, list):
                continue
            for session in rows[:16]:
                if not isinstance(session, dict):
                    continue
                compact = {
                    **({"campaign_id": campaign_identity}
                       if isinstance(campaign_identity, str) else {}),
                    **{key: session[key] for key in session_fields if key in session},
                }
                evidence = session.get("evidence")
                if isinstance(evidence, list):
                    compact["evidence_refs"] = evidence[-6:]
                    compact["evidence_refs_truncated"] = (
                        bool(session.get("evidence_truncated")) or len(evidence) > 6
                    )
                continuations.append(compact)
                if len(continuations) >= 16:
                    break
        result: dict[str, Any] = {
            "schema_version": "mncs.control.project-entry-continuation/1",
            "repository": capsule.get("repository"),
            "status": capsule.get("status", "unknown"),
            "next": capsule.get("next"),
            "campaign_statuses": campaign_statuses,
            "continuations": continuations,
            "campaigns_count": capsule.get("campaigns_count", len(campaign_rows)),
            "continuations_count": capsule.get(
                "continuations_count", len(continuations)
            ),
        }
        for key in ("campaign_id", "task_selector", "campaigns", "campaigns_count",
                    "campaigns_truncated", "contexts", "contexts_count", "contexts_truncated",
                    "continuations_truncated",
                    "selected_session_id", "selected_context", "selection_basis",
                    "context_conflict_status", "unselected_contexts",
                    "unselected_contexts_count", "unselected_sessions_count",
                    "project_selection"):
            if key in capsule:
                result[key] = capsule[key]
        return result

    def _project_environment_identity(
        self, record: _GrantRecord, repository: str,
    ) -> tuple[str, str] | None:
        """Resolve one repository's owner-controlled Environment definition.

        Project grants use their granted checkout. Workspace grants must
        resolve an exact immediate repository from the supplied cwd before
        selecting its definition. Missing metadata never makes Control guess
        between campaign contexts.
        """
        if record.scope not in {"project", "workspace"}:
            return None
        try:
            workspace_root = Path(self.config.workspace_root).expanduser().resolve(strict=True)
            grant_root = record.host_root.expanduser().resolve(strict=True)
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING",
                "Environment workspace context is unavailable",
            ) from error
        if record.scope == "project":
            project_root = grant_root
        else:
            if grant_root != workspace_root:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "workspace continuation must use the configured workspace root",
                )
            project_root = workspace_root / repository
        if (project_root.parent != workspace_root
                or project_root.name != repository):
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "project continuation is outside its configured immediate workspace",
            )

        definition_path = project_root / ".mncs" / "project-environment.json"
        try:
            observed = definition_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_MISSING",
                "project Environment definition could not be inspected",
            ) from error
        if not stat.S_ISREG(observed.st_mode):
            raise ControlError(
                "ENVIRONMENT_WORKSPACE_ESCAPE",
                "project Environment definition must be a regular file",
            )
        try:
            resolved_definition = definition_path.resolve(strict=True)
            if (resolved_definition != project_root
                    and project_root not in resolved_definition.parents):
                raise ControlError(
                    "ENVIRONMENT_WORKSPACE_ESCAPE",
                    "project Environment definition exceeds its project grant",
                )
            definition = json.loads(resolved_definition.read_text(encoding="utf-8"))
        except ControlError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControlError(
                "ENVIRONMENT_DEFINITION_INVALID",
                "project Environment definition is not readable JSON",
            ) from error
        if not isinstance(definition, dict):
            raise ControlError(
                "ENVIRONMENT_DEFINITION_INVALID",
                "project Environment definition must be an object",
            )
        scope = definition.get("workspace_scope")
        if (not isinstance(scope, dict)
                or scope.get("repositories") != [repository]
                or definition.get("workspace_root", ".") not in (None, "", ".")):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "project continuation definition must remain limited to its granted repository",
                details={"repository": repository},
            )

        package_loader = getattr(self.environment_service, "_pkg", None)
        if not callable(package_loader):
            # Test doubles and alternate adapters without Environment's
            # identity implementation cannot establish this selector.
            return None
        package = package_loader()
        identity_module = getattr(package, "identity", None)
        identity_function = getattr(identity_module, "environment_id", None)
        if not callable(identity_function):
            return None
        definition_id = identity_function(definition)
        if not isinstance(definition_id, str) or not definition_id.startswith("env_"):
            raise ControlError(
                "ENVIRONMENT_DEFINITION_INVALID",
                "Environment returned an invalid project definition identity",
            )
        return definition_id, str(workspace_root)

    def _select_project_campaign_context(
        self, capsule: dict[str, Any], record: _GrantRecord, repository: str,
        *, project_context: tuple[str, str] | None = None,
        derive_project_context: bool = True,
    ) -> dict[str, Any]:
        """Select one exact project context while preserving other capsules.

        Selection is possible only when the authenticated project's canonical
        definition and mapped workspace identify exactly one linked session,
        the bounded result is complete, and no other same-campaign session has
        a claim on this repository. All original continuations remain visible.
        """
        if record.scope not in {"project", "workspace"}:
            return capsule
        selector = project_context
        task_selector = capsule.get("task_selector")
        task_selector_session_id = None
        selection_basis = "authenticated-project-environment-definition"
        if selector is None and isinstance(task_selector, dict):
            task_definition = task_selector.get("definition_id")
            task_workspace = task_selector.get("workspace_root")
            candidate_session_id = task_selector.get("session_id")
            if (
                task_selector.get("status") == "resolved"
                and isinstance(task_definition, str)
                and task_definition.startswith("env_")
                and isinstance(task_workspace, str)
                and task_workspace
                and isinstance(candidate_session_id, str)
                and re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", candidate_session_id)
            ):
                selector = (task_definition, task_workspace)
                task_selector_session_id = candidate_session_id
                selection_basis = "authenticated-task-selector"
        if selector is None and derive_project_context:
            selector = self._project_environment_identity(record, repository)
        if selector is None:
            return capsule
        definition_id, workspace_root = selector
        if capsule.get("repository") not in (None, repository):
            return capsule
        if capsule.get("status") not in {"ready", "context-conflict"}:
            return capsule
        rows = capsule.get("continuations")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            return capsule
        continuation_count = capsule.get("continuations_count", len(rows))
        if (capsule.get("continuations_truncated") is True
                or capsule.get("contexts_truncated") is True
                or type(continuation_count) is not int
                or continuation_count != len(rows)):
            capsule["project_selection"] = {
                "status": "unknown",
                "reason": "continuation-inventory-truncated",
                "definition_id": definition_id,
                "workspace_root": workspace_root,
            }
            return capsule

        exact_context_rows = [
            row for row in rows
            if row.get("definition_id") == definition_id
            and row.get("workspace_root") == workspace_root
        ]
        if task_selector_session_id is not None:
            exact_context_rows = [
                row for row in exact_context_rows
                if row.get("session_id") == task_selector_session_id
            ]
        if not exact_context_rows:
            capsule["project_selection"] = {
                "status": "unmatched",
                "reason": "no-session-matches-project-definition-and-workspace",
                "definition_id": definition_id,
                "workspace_root": workspace_root,
            }
            if capsule.get("status") == "ready":
                capsule["context_conflict_status"] = "ready"
                capsule["status"] = "context-mismatch"
            capsule["next"] = (
                "no same-campaign session matches this project's Environment definition; "
                "review the visible capsules and continue only through an exact context or owner-issued handoff"
            )
            return capsule
        selected_rows = [
            row for row in exact_context_rows
            if (row.get("project_reference") or {}).get("status") == "linked"
            and isinstance(row.get("session_id"), str)
            and row.get("lifecycle") in {
                "active", "blocked", "waiting", "checkpointed", "abandoned",
            }
        ]
        if len(exact_context_rows) != 1:
            capsule["project_selection"] = {
                "status": "ambiguous",
                "reason": "multiple-sessions-match-project-definition-and-workspace",
                "definition_id": definition_id,
                "workspace_root": workspace_root,
                "candidate_sessions": sorted(
                    row.get("session_id") for row in exact_context_rows
                    if isinstance(row.get("session_id"), str)
                ),
            }
            return capsule
        if len(selected_rows) != 1:
            exact = exact_context_rows[0]
            lifecycle = exact.get("lifecycle")
            linked = (exact.get("project_reference") or {}).get("status") == "linked"
            capsule["project_selection"] = {
                "status": "blocked",
                "reason": (
                    "project-context-not-linked" if not linked
                    else "project-session-lifecycle-requires-reconciliation"
                ),
                "definition_id": definition_id,
                "workspace_root": workspace_root,
                "session_id": exact.get("session_id"),
                "lifecycle": lifecycle,
            }
            if linked and capsule.get("status") == "ready":
                capsule["context_conflict_status"] = "ready"
                capsule["status"] = "reconciliation-required"
            capsule["next"] = (
                "reconcile the exact project session lifecycle before continuing; "
                "handed-off sessions require Environment.accept"
            )
            return capsule
        selected = selected_rows[0]
        selected_session = selected["session_id"]

        other_rows = [row for row in rows if row.get("session_id") != selected_session]
        competing_claim_sessions = []
        unknown_claim_sessions = []
        for row in other_rows:
            claims = row.get("claims")
            claim_ids = row.get("claim_ids")
            if not isinstance(claim_ids, list):
                session_id = row.get("session_id")
                if isinstance(session_id, str):
                    unknown_claim_sessions.append(session_id)
                else:
                    unknown_claim_sessions.append("unknown-session")
                continue
            has_repository_claim = bool(claim_ids)
            if isinstance(claims, list):
                has_repository_claim = has_repository_claim or any(
                    isinstance(claim, dict)
                    and claim.get("repository") == repository
                    and claim.get("status") == "held"
                    for claim in claims
                )
            if has_repository_claim:
                session_id = row.get("session_id")
                if isinstance(session_id, str):
                    competing_claim_sessions.append(session_id)
                else:
                    unknown_claim_sessions.append("unknown-session")
        if competing_claim_sessions or unknown_claim_sessions:
            capsule["project_selection"] = {
                "status": "blocked" if competing_claim_sessions else "unknown",
                "reason": (
                    "another-same-campaign-session-holds-a-project-claim"
                    if competing_claim_sessions
                    else "same-campaign-session-claim-projection-is-incomplete"
                ),
                "definition_id": definition_id,
                "workspace_root": workspace_root,
                "competing_claim_sessions": sorted(competing_claim_sessions),
                "unknown_claim_sessions": sorted(set(unknown_claim_sessions)),
            }
            capsule["next"] = (
                "inspect the listed project claims and use the owning session's handoff "
                "or release protocol; Control did not transfer ownership"
                if competing_claim_sessions else
                "refresh the complete claim projection before selecting a project session"
            )
            return capsule

        unselected_contexts: dict[tuple[str, str], list[str]] = {}
        for row in other_rows:
            context = (
                str(row.get("definition_id") or ""),
                str(row.get("workspace_root") or ""),
            )
            session_id = row.get("session_id")
            if isinstance(session_id, str):
                unselected_contexts.setdefault(context, []).append(session_id)
        if capsule.get("status") == "context-conflict":
            capsule["context_conflict_status"] = "context-conflict"
        capsule["status"] = "ready"
        capsule["selected_session_id"] = selected_session
        capsule["selected_context"] = {
            "definition_id": definition_id,
            "workspace_root": workspace_root,
        }
        capsule["selection_basis"] = selection_basis
        capsule["unselected_contexts"] = [
            {
                "definition_id": context[0] or None,
                "workspace_root": context[1] or None,
                "session_ids": sorted(session_ids),
                "session_count": len(session_ids),
            }
            for context, session_ids in sorted(unselected_contexts.items())
        ]
        capsule["unselected_contexts_count"] = len(unselected_contexts)
        capsule["unselected_sessions_count"] = len(other_rows)
        capsule["next"] = (
            "continue the selected project session with Environment revalidation; "
            "other same-campaign contexts remain visible and unchanged"
        )
        return capsule

    def _campaign_task_bind(
        self, record: _GrantRecord, argv: list[str], request_id: str,
    ) -> dict[str, Any]:
        """Bind a task selector to one explicitly named session in this project."""
        record.bound_session_id = None
        if record.scope != "project":
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign task binding requires a project-scoped Control grant",
            )
        project = self._project_repository(record)
        values: dict[str, str] = {}
        allowed = {"--campaign-id", "--session-id", "--task-identity"}
        index = 1
        while index < len(argv):
            item = argv[index]
            if item.startswith("--") and "=" in item:
                option, _, value = item.partition("=")
                if option not in allowed:
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        "campaign-bind accepts only campaign, session, and task identity options",
                    )
                step = 1
            elif item in allowed:
                option = item
                if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        f"{option} needs a value",
                    )
                value = argv[index + 1]
                step = 2
            else:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "campaign-bind accepts only --campaign-id, --session-id, and --task-identity",
                )
            if not value or option in values:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    f"{option} must occur exactly once with a nonempty value",
                )
            values[option] = value
            index += step

        required = {"--campaign-id", "--session-id", "--task-identity"}
        if set(values) != required:
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "campaign-bind requires one explicit campaign, session, and task identity",
            )
        campaign_id = values["--campaign-id"]
        session_id = values["--session-id"]
        task_identity = values["--task-identity"]
        if (len(campaign_id) > 160 or "\x00" in campaign_id
                or not re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", session_id)
                or len(task_identity) > 256 or "\x00" in task_identity):
            raise ControlError(
                "ENVIRONMENT_RPC_INVALID_REQUEST",
                "campaign-bind identity arguments are malformed or exceed their limits",
            )
        if (getattr(self.environment_service, "authenticated_principal_id", None)
                != record.principal_id):
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign task binding is not bound to the Control-authenticated principal",
            )
        binding = self.environment_service.bind_task_identity(
            project, campaign_id, session_id, task_identity, request_id,
        )
        if not isinstance(binding, dict) or binding.get("status") != "bound":
            raise TypeError("Environment returned an unconfirmed task binding")
        record.bound_session_id = session_id
        return {"ok": True, "result": {
            "exit_code": 0,
            "stdout": json.dumps(binding, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            "stderr": "",
            "request_id": request_id,
            "principal_id": record.principal_id,
        }}

    def _campaign_continuation(
        self, record: _GrantRecord, argv: list[str], request_id: str, *, cwd: Path,
    ) -> dict[str, Any]:
        """Return the existing Control-owned capsule for one repository grant.

        Project scope identifies its one immediate checkout. Workspace scope
        uses the cwd already confined by its grant to identify one immediate
        checkout. The caller cannot widen that identity with a repository or
        principal argument; Environment remains the Store lookup authority.
        """
        record.bound_session_id = None
        project = self._project_repository(record, cwd=cwd)
        campaign_id: str | None = None
        task_identity: str | None = None
        index = 1
        while index < len(argv):
            item = argv[index]
            if item in {"--campaign-id", "--task-identity"}:
                option = item
                if index + 1 >= len(argv):
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        f"{option} needs a value",
                    )
                value = argv[index + 1]
                if value.startswith("--"):
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        f"{option} needs a value, not another option",
                    )
                if option == "--campaign-id":
                    if campaign_id is not None:
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST",
                            "continuation accepts at most one --campaign-id",
                        )
                    campaign_id = value
                else:
                    if task_identity is not None:
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST",
                            "continuation accepts at most one --task-identity",
                        )
                    task_identity = value
                index += 2
            elif item.startswith("--campaign-id=") or item.startswith("--task-identity="):
                option, _, value = item.partition("=")
                if option == "--campaign-id":
                    if campaign_id is not None:
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST",
                            "continuation accepts at most one --campaign-id",
                        )
                    campaign_id = value
                else:
                    if task_identity is not None:
                        raise ControlError(
                            "ENVIRONMENT_RPC_INVALID_REQUEST",
                            "continuation accepts at most one --task-identity",
                        )
                    task_identity = value
                index += 1
            else:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "continuation accepts optional --campaign-id and --task-identity",
                )
        if campaign_id is not None and (
            not campaign_id.strip() or campaign_id.startswith("--")
            or len(campaign_id) > 160 or "\x00" in campaign_id
        ):
            raise ControlError(
                "ENVIRONMENT_CAMPAIGN_ID_INVALID",
                "campaign identity must be bounded nonempty text when supplied",
            )
        if task_identity is not None and (
            not task_identity.strip() or len(task_identity) > 256 or "\x00" in task_identity
        ):
            raise ControlError(
                "ENVIRONMENT_TASK_IDENTITY_INVALID",
                "task identity must be bounded nonempty text when supplied",
            )

        if getattr(self.environment_service, "authenticated_principal_id", None) != record.principal_id:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign continuation is not bound to the Control-authenticated principal",
            )
        if task_identity is None:
            capsule = self.environment_service.campaign_continuation(project, campaign_id)
        else:
            capsule = self.environment_service.campaign_continuation(
                project, campaign_id, task_identity,
            )
        if not isinstance(capsule, dict):
            raise TypeError("Environment returned a non-object continuation capsule")
        capsule = self._select_project_campaign_context(capsule, record, project)
        selected_session = capsule.get("selected_session_id")
        task_selector = capsule.get("task_selector")
        if (
            task_identity is not None
            and isinstance(task_selector, dict)
            and task_selector.get("status") == "resolved"
            and capsule.get("status") == "ready"
            and selected_session != task_selector.get("session_id")
        ):
            capsule["status"] = "task-selector-session-mismatch"
            capsule.pop("selected_session_id", None)
            capsule["project_selection"] = {
                "status": "blocked",
                "reason": "selected-project-session-does-not-match-task-selector",
                "task_selector_session_id": task_selector.get("session_id"),
                "project_session_id": selected_session,
            }
            capsule["next"] = (
                "reconcile the task-selector target with the project's exact Environment session; Control did not select either session"
            )
        if (capsule.get("status") == "ready"
                and capsule.get("selection_basis") in {
                    "authenticated-project-environment-definition",
                    "authenticated-task-selector",
                }
                and isinstance(selected_session, str)
                and re.fullmatch(r"ses_[A-Za-z0-9_-]{1,120}", selected_session)):
            record.bound_session_id = selected_session
        capsule = self._compact_entry_continuation(capsule)
        capsule["schema_version"] = "mncs.control.campaign-continuation/2"
        return {"ok": True, "result": {
            "exit_code": 0,
            "stdout": json.dumps(capsule, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            "stderr": "",
            "request_id": request_id,
            "principal_id": record.principal_id,
        }}

    def close(self) -> None:
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with self._lock:
            grants = list(self._grants.values())
            self._grants.clear()
        for record in grants:
            record.token_file.unlink(missing_ok=True)
        try:
            observed = self.socket_path.lstat()
            if (stat.S_ISSOCK(observed.st_mode) and observed.st_uid == os.getuid()
                    and self._socket_identity == (observed.st_dev, observed.st_ino)):
                self.socket_path.unlink()
        except FileNotFoundError:
            pass

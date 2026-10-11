"""Narrow Environment CLI bridge for protected bwrap consumers.

The host Control MCP process owns this endpoint and invokes Environment with
its configured canonical Store. Clients receive a per-sandbox-run bearer
grant, but never Store paths or filesystem handles.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ControlError

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ALLOWED_COMMANDS = frozenset({
    "enter", "inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims",
    "retire", "continuation",
})
RPC_SANDBOX_SOCKET = "/run/mncs-environment-rpc/environment.sock"


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

    def _serve_connection(self, connection: socket.socket) -> None:
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

    def _translate_argv(self, argv: Any, cwd: Path, record: _GrantRecord) -> list[str]:
        if (not isinstance(argv, list) or len(argv) > 256
                or not all(isinstance(item, str) and len(item) <= 8192 and "\x00" not in item
                           for item in argv)):
            raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST", "Environment argv is invalid")
        if any(item == "--state-dir" or item.startswith("--state-dir=")
               or item.startswith("--state-") or item == "--persistence"
               or item.startswith("--persistence=") or item.startswith("--persist")
               or item == "--execution-root" or item.startswith("--execution-root=")
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
        translated = list(argv)

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
            has_campaign_id = False
            for index, item in enumerate(translated):
                if item == "--campaign-id" and index + 1 < len(translated):
                    has_campaign_id = bool(translated[index + 1].strip())
                    break
                if item.startswith("--campaign-id="):
                    has_campaign_id = bool(item.partition("=")[2].strip())
                    break
            has_workspace = any(item == "--workspace" or item.startswith("--workspace=")
                                for item in translated)
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
                    if has_campaign_id and record.scope == "project":
                        # A project sandbox cannot name its host workspace
                        # parent. For a campaign entry, Control may supply
                        # that path only when the selected Environment
                        # definition itself names exactly this granted
                        # project. Environment still performs the durable
                        # principal/campaign/definition/workspace selection.
                        repositories = (
                            scope.get("repositories")
                            if isinstance(scope, dict)
                            else None
                        )
                        if repositories != [record.host_root.name]:
                            raise ControlError(
                                "ENVIRONMENT_AUTHORITY_DENIED",
                                "project-scoped campaign entry must declare only its granted repository",
                                details={"repository": record.host_root.name},
                            )
                        if definition.get("workspace_root", ".") not in (None, "", "."):
                            raise ControlError(
                                "ENVIRONMENT_AUTHORITY_DENIED",
                                "project-scoped campaign entry cannot override the owner-mapped workspace root",
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
            flags = set(argv)
            mutation_targets = any(
                item == "--prune" or item.startswith("--prune=")
                or item == "--branch" or item.startswith("--branch=")
                or item == "--worktree" or item.startswith("--worktree=")
                for item in argv
            )
            if "--inventory" not in flags or "--dry-run" not in flags or mutation_targets:
                raise ControlError(
                    "ENVIRONMENT_AUTHORITY_DENIED",
                    "Control exposes only read-only retirement inventory",
                    details={"required": ["--inventory", "--dry-run"]},
                )
            canonical = "origin/main"
            for index, item in enumerate(translated):
                if item == "--canonical" and index + 1 < len(translated):
                    canonical = translated[index + 1]
                    break
                if item.startswith("--canonical="):
                    canonical = item.split("=", 1)[1]
                    break
            if canonical not in {"origin/main", "origin/master", "main", "master"}:
                raise ControlError("ENVIRONMENT_AUTHORITY_DENIED",
                                   "retirement inventory canonical ref is not exposed")
            map_path_option("--repository")
        return translated

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
                    return response
                self._active_requests.add(request_id)
            argv = request.get("argv")
            session_id = None
            if isinstance(argv, list) and argv and argv[0] in {
                "inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims",
                "retire",
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
                if lock is None:
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
        if command == "continuation":
            return self._campaign_continuation(record, argv, request_id)
        if command == "retire":
            # The client cannot choose this root. Environment must not probe a
            # registered checkout outside the execution grant's namespace.
            argv.extend(["--execution-root", str(record.host_root)])
        if command in {"inspect", "context", "resume", "health", "capabilities", "checkpoint", "handoff", "accept", "claims", "retire"}:
            try:
                command_index = argv.index(command)
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
            if command == "claims" and "--transfer-to" in argv:
                try:
                    target = argv[argv.index("--transfer-to") + 1]
                except (ValueError, IndexError) as error:
                    raise ControlError("ENVIRONMENT_RPC_INVALID_REQUEST",
                                       "claim transfer needs a target session") from error
                self._authorize_session(target, record.principal_id)
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
        output_limit = MAX_RESPONSE_BYTES // 2
        stdout = completed.stdout[:output_limit]
        stderr = completed.stderr[:output_limit]
        return {"ok": True, "result": {
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "request_id": request_id,
            "principal_id": record.principal_id,
        }}

    def _campaign_continuation(
        self, record: _GrantRecord, argv: list[str], request_id: str,
    ) -> dict[str, Any]:
        """Return the existing Control-owned capsule for one project grant.

        A project-scoped grant identifies its one immediate checkout. The
        caller cannot widen that identity with a repository or principal
        argument, and the existing Environment adapter still performs
        authenticated Store lookup and domain filtering.
        """
        if record.scope != "project":
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign continuation requires a project-scoped execution grant",
            )
        campaign_id: str | None = None
        index = 1
        while index < len(argv):
            item = argv[index]
            if item == "--campaign-id":
                if campaign_id is not None or index + 1 >= len(argv):
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        "continuation accepts at most one nonempty --campaign-id",
                    )
                campaign_id = argv[index + 1]
                if campaign_id.startswith("--"):
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        "--campaign-id needs a value, not another option",
                    )
                index += 2
            elif item.startswith("--campaign-id="):
                if campaign_id is not None:
                    raise ControlError(
                        "ENVIRONMENT_RPC_INVALID_REQUEST",
                        "continuation accepts at most one --campaign-id",
                    )
                campaign_id = item.partition("=")[2]
                index += 1
            else:
                raise ControlError(
                    "ENVIRONMENT_RPC_INVALID_REQUEST",
                    "continuation accepts only an optional --campaign-id",
                )
        if campaign_id is not None and (
            not campaign_id.strip() or campaign_id.startswith("--")
            or len(campaign_id) > 160 or "\x00" in campaign_id
        ):
            raise ControlError(
                "ENVIRONMENT_CAMPAIGN_ID_INVALID",
                "campaign identity must be bounded nonempty text when supplied",
            )

        configured_root = Path(self.config.workspace_root).expanduser().resolve()
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
        if getattr(self.environment_service, "authenticated_principal_id", None) != record.principal_id:
            raise ControlError(
                "ENVIRONMENT_AUTHORITY_DENIED",
                "campaign continuation is not bound to the Control-authenticated principal",
            )
        capsule = self.environment_service.campaign_continuation(
            project_root.name, campaign_id,
        )
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

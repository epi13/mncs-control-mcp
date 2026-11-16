"""Regression tests for EnvironmentRPCServer, EnvironmentService, and MCP lifecycle ownership."""
from __future__ import annotations

import atexit
import gc
import os
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import EnvironmentRPCServer
from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.local_environment_mcp import _rpc
from mncs_control_mcp.server import build_server
from mncs_control_mcp.workspace import WorkspacePolicy

_CONTROL_COMMON_DIRECTORY = Path(
    subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=Path(__file__).resolve().parent,
        text=True,
    ).strip()
).resolve()
_PROJECTS_ROOT = _CONTROL_COMMON_DIRECTORY.parent.parent
_ENVIRONMENT_ROOT = _PROJECTS_ROOT / "mncs-environment"


def _track_atexit(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    active_hooks: list[object] = []
    real_register = atexit.register
    real_unregister = atexit.unregister

    def track_register(func, *args, **kwargs):
        if getattr(func, "__module__", "").startswith("mncs_control_mcp"):
            active_hooks.append(func)
        return real_register(func, *args, **kwargs)

    def track_unregister(func):
        active_hooks[:] = [item for item in active_hooks if item != func]
        return real_unregister(func)

    monkeypatch.setattr(atexit, "register", track_register)
    monkeypatch.setattr(atexit, "unregister", track_unregister)
    return active_hooks


def _open_fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def _lifecycle_config(tmp_path: Path, socket_path: Path) -> ControlConfig:
    workspace = tmp_path / "projects"
    workspace.mkdir(parents=True, exist_ok=True)
    return ControlConfig(
        workspace_root=workspace,
        repositories={"environment": str(_ENVIRONMENT_ROOT)},
        sandbox_home=tmp_path / "sandbox-home",
        job_state_path=tmp_path / "state" / "jobs.json",
        audit_path=tmp_path / "state" / "audit.jsonl",
        fabric_registry=tmp_path / "state" / "workers.json",
        fabric_state=tmp_path / "state" / "fabric.jsonl",
        environment_rpc_socket=socket_path,
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
        environment_state_dir=tmp_path / "env-state",
    )


def _create_git_project(workspace: Path, name: str) -> Path:
    project = workspace / name
    project.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    return project


def _fake_store_package(created: list[object] | None = None, *, gate: dict[str, threading.Event] | None = None):
    package = ModuleType("test_lifecycle_env")
    stores = created if created is not None else []

    class Store:
        def __init__(self, path: Path) -> None:
            self.path = path
            self.closes = 0

        def close(self) -> None:
            self.closes += 1

    def open_store(path: Path, backend: str) -> Store:
        assert backend == "store"
        if gate is not None:
            gate["entered"].set()
            gate["proceed"].wait(timeout=5.0)
        instance = Store(path)
        stores.append(instance)
        return instance

    open_store.__module__ = "mncs_env.session_store"
    package.session_store = SimpleNamespace(open_store=open_store)
    return package, stores


def test_borrowed_service_survives_rpc_close_and_keeps_serving_after_restart(
    tmp_path: Path, environment_rpc_socket: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not (_ENVIRONMENT_ROOT / "mncs_env" / "sessions.py").is_file():
        pytest.skip("sibling mncs-environment checkout is unavailable")

    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    project = _create_git_project(cfg.workspace_root, "alpha")
    policy = WorkspacePolicy(cfg)
    environment = EnvironmentService(cfg)
    first_rpc = EnvironmentRPCServer(cfg, environment, policy)
    first_rpc.start()
    second_rpc: EnvironmentRPCServer | None = None
    try:
        environment.authenticated_principal_id = first_rpc.principal_id
        monkeypatch.setattr(first_rpc, "_peer_process_cwd", lambda _pid: project)

        first_bootstrap = _rpc(first_rpc.socket_path, {
            "action": "local-project-grant", "project": "alpha", "cwd": ".",
        })
        assert first_bootstrap["ok"] is True
        first_token = first_bootstrap["result"]["grant"]
        assert list(first_rpc.token_root.glob("*.grant"))

        # Borrowed service must stay open and operational across non-owner RPC close.
        first_rpc.close()
        first_rpc.close()  # Idempotent repeat close.
        assert first_rpc.status()["available"] is False
        assert not environment_rpc_socket.exists()
        assert not list(first_rpc.token_root.glob("*.grant"))
        assert environment.status()["available"] is True
        continuation = environment.campaign_continuation("alpha")
        assert continuation["repository"] == "alpha"

        with pytest.raises(ControlError, match="closed"):
            first_rpc.start()

        second_rpc = EnvironmentRPCServer(cfg, environment, policy)
        second_rpc.start()
        assert second_rpc.principal_id == first_rpc.principal_id
        assert second_rpc.status()["available"] is True
        monkeypatch.setattr(second_rpc, "_peer_process_cwd", lambda _pid: project)

        # Prior grant cannot authorize requests on the restarted server.
        stale_reply = _rpc(second_rpc.socket_path, {
            "grant": first_token,
            "request_id": "req_stale_grant",
            "argv": ["continuation"],
        })
        assert stale_reply["ok"] is False
        assert stale_reply["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"

        second_bootstrap = _rpc(second_rpc.socket_path, {
            "action": "local-project-grant", "project": "alpha", "cwd": ".",
        })
        assert second_bootstrap["ok"] is True
    finally:
        first_rpc.close()
        if second_rpc is not None:
            second_rpc.close()
        environment.close()
        assert environment.status()["available"] is False


def test_closing_rpc_client_connection_leaves_server_and_service_active(
    tmp_path: Path, environment_rpc_socket: Path,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    project = _create_git_project(cfg.workspace_root, "alpha")
    service = EnvironmentService(cfg)
    policy = WorkspacePolicy(cfg)
    rpc = EnvironmentRPCServer(cfg, service, policy)
    rpc.start()
    try:
        # Abruptly disconnect a raw socket mid-frame without sending a full request.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as abrupt_client:
            abrupt_client.connect(str(rpc.socket_path))
            abrupt_client.sendall(struct.pack("!I", 64))

        # Abrupt EOF with zero payload.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as empty_client:
            empty_client.connect(str(rpc.socket_path))

        response = _rpc(rpc.socket_path, {
            "action": "local-project-grant", "project": "alpha", "cwd": ".",
        })
        assert response["ok"] is True
        assert Path(response["result"]["working_directory"]) == project.resolve()
        assert rpc.status()["available"] is True
    finally:
        rpc.close()
        service.close()


def test_owned_service_shuts_down_after_draining_inflight_requests(
    tmp_path: Path, environment_rpc_socket: Path,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    _create_git_project(cfg.workspace_root, "alpha")
    entered = threading.Event()
    release = threading.Event()
    created: list[object] = []
    package, stores = _fake_store_package(created)
    service = EnvironmentService(cfg)
    loan = service._store(package)
    loan.close()  # Return Store handle to _store_pool so shutdown must close it.
    assert len(service._store_pool) == 1

    rpc = EnvironmentRPCServer(
        cfg, service, WorkspacePolicy(cfg), owns_environment_service=True,
    )
    rpc.start()
    grant_reply = _rpc(rpc.socket_path, {
        "action": "local-project-grant", "project": "alpha", "cwd": ".",
    })
    assert grant_reply["ok"] is True
    token = grant_reply["result"]["grant"]

    def slow_dispatch_once(request, *, peer_uid, peer_pid=None):
        entered.set()
        assert release.wait(timeout=5.0)
        # Borrow and release pooled Store while owned service must still remain open.
        active_loan = service._store(package)
        active_loan.close()
        return {"ok": True, "result": {"exit_code": 0, "stdout": "{}", "stderr": ""}}

    rpc._dispatch_once = slow_dispatch_once  # type: ignore[method-assign]

    responses: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def run_request() -> None:
        try:
            responses.append(_rpc(rpc.socket_path, {
                "grant": token,
                "request_id": "req_inflight_owned_drain",
                "argv": ["continuation"],
            }))
        except BaseException as exc:  # pragma: no cover - assertion target
            errors.append(exc)

    request_thread = threading.Thread(target=run_request)
    close_thread = threading.Thread(target=rpc.close)
    request_thread.start()
    assert entered.wait(timeout=3.0)

    close_thread.start()
    # Close must wait for the active connection thread before closing the owned service.
    time.sleep(0.05)
    assert close_thread.is_alive()
    assert service._closed is False
    assert stores[0].closes == 0

    release.set()
    request_thread.join(timeout=5.0)
    close_thread.join(timeout=5.0)

    assert not errors
    assert responses and responses[0]["ok"] is True
    assert rpc.status()["available"] is False
    assert service._closed is True
    assert len(stores) == 1 and stores[0].closes == 1
    assert not service._store_pool
    assert not environment_rpc_socket.exists()
    with pytest.raises(ControlError, match="closed"):
        service._store(package)


def test_reentrant_handler_close_and_concurrent_closes_are_safe_and_idempotent(
    tmp_path: Path, environment_rpc_socket: Path,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    _create_git_project(cfg.workspace_root, "alpha")
    entered_close = threading.Event()
    finish_close = threading.Event()

    class SlowCloseService:
        def __init__(self) -> None:
            self.state_dir = tmp_path / "state"
            self.close_calls = 0
            self.finished = False
            self._lock = threading.Lock()

        def close(self) -> None:
            with self._lock:
                self.close_calls += 1
            entered_close.set()
            assert finish_close.wait(timeout=5.0)
            self.finished = True

    service = SlowCloseService()

    class ReentrantCloseRPC(EnvironmentRPCServer):
        def _send_frame(self, connection, value):
            # Model DropNextResponseRPC: closing from inside _serve_connection must not
            # attempt to self-join the current worker thread or deadlock.
            self.close()
            super()._send_frame(connection, value)

    rpc = ReentrantCloseRPC(
        cfg, service, WorkspacePolicy(cfg), owns_environment_service=True,
    )
    rpc.start()

    client_thread = threading.Thread(target=lambda: _rpc(rpc.socket_path, {
        "action": "local-project-grant", "project": "alpha", "cwd": ".",
    }))
    client_thread.start()
    assert entered_close.wait(timeout=3.0)

    # Concurrent second close must block until the first completes teardown.
    concurrent_done = threading.Event()

    def concurrent_close() -> None:
        rpc.close()
        concurrent_done.set()

    other_closer = threading.Thread(target=concurrent_close)
    other_closer.start()
    time.sleep(0.05)
    assert not concurrent_done.is_set()

    finish_close.set()
    client_thread.join(timeout=5.0)
    other_closer.join(timeout=5.0)
    rpc.close()

    assert concurrent_done.is_set()
    assert service.close_calls == 1
    assert service.finished is True
    assert rpc.status()["available"] is False


def test_concurrent_requests_on_shared_service_survive_sibling_rpc_teardown(
    tmp_path: Path,
) -> None:
    cfg_a = _lifecycle_config(tmp_path, tmp_path / "rpc-a" / "environment.sock")
    cfg_b = _lifecycle_config(tmp_path, tmp_path / "rpc-b" / "environment.sock")
    _create_git_project(cfg_a.workspace_root, "alpha")
    service = EnvironmentService(cfg_a)
    policy = WorkspacePolicy(cfg_a)

    server_a = EnvironmentRPCServer(cfg_a, service, policy)
    server_b = EnvironmentRPCServer(cfg_b, service, policy)
    server_a.start()
    server_b.start()
    package, stores = _fake_store_package()

    def exercise_b(_index: int) -> dict[str, object]:
        reply = _rpc(server_b.socket_path, {
            "action": "local-project-grant", "project": "alpha", "cwd": ".",
        })
        loan = service._store(package)
        loan.close()
        return reply

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(exercise_b, idx) for idx in range(12)]
            server_a.close()
            results = [future.result(timeout=10.0) for future in futures]
        assert all(item["ok"] is True for item in results)
        assert service._closed is False
        assert server_b.status()["available"] is True
        with pytest.raises(ControlError, match="unavailable"):
            server_a.issue_grant(policy.resolve_scope(scope="project", project="alpha", cwd="."))
    finally:
        server_a.close()
        server_b.close()
        service.close()
        assert all(store.closes == 1 for store in stores)


def test_failed_start_and_failed_build_server_clean_up_without_fd_leaks(
    tmp_path: Path, environment_rpc_socket: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    service = EnvironmentService(cfg)
    policy = WorkspacePolicy(cfg)

    def fail_listen(self, *_args, **_kwargs):
        raise OSError("simulated listen failure")

    monkeypatch.setattr(socket.socket, "listen", fail_listen)

    gc.collect()
    baseline_fds = _open_fd_count()
    for _ in range(3):
        rpc = EnvironmentRPCServer(cfg, service, policy)
        with pytest.raises(OSError, match="simulated listen failure"):
            rpc.start()
        assert rpc._socket is None
        assert rpc._thread is None
        assert not environment_rpc_socket.exists()
    gc.collect()
    assert _open_fd_count() == baseline_fds
    service.close()

    # Now verify build_server cleans up processes, service, and atexit hooks on start failure.
    active_hooks = _track_atexit(monkeypatch)
    server_cfg = replace(
        _lifecycle_config(tmp_path, tmp_path / "server-rpc" / "environment.sock"),
    )
    monkeypatch.setattr(
        "mncs_control_mcp.server.EnvironmentRPCServer.start",
        lambda self: (_ for _ in ()).throw(ControlError("ENVIRONMENT_RPC_FAILURE", "boom")),
    )
    closed_services: list[EnvironmentService] = []
    real_service_close = EnvironmentService.close

    def track_service_close(self: EnvironmentService) -> None:
        closed_services.append(self)
        real_service_close(self)

    monkeypatch.setattr(EnvironmentService, "close", track_service_close)
    with pytest.raises(ControlError, match="boom"):
        build_server(server_cfg)
    assert not active_hooks
    assert {id(item) for item in closed_services} == {id(closed_services[0])}
    assert closed_services[0]._closed is True


def test_build_server_shutdown_releases_store_pool_socket_grants_and_atexit(
    tmp_path: Path, environment_rpc_socket: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    _create_git_project(cfg.workspace_root, "alpha")
    active_hooks = _track_atexit(monkeypatch)
    # Keep background ExperimentManager resume timer out of FD measurements.
    monkeypatch.setattr(
        "mncs_control_mcp.server.ExperimentManager",
        lambda config: SimpleNamespace(config=config),
    )
    gc.collect()
    baseline_fds = _open_fd_count()

    server = build_server(cfg)
    package, stores = _fake_store_package()
    try:
        assert active_hooks
        service = server._control_environment_sessions
        rpc = server._control_environment_rpc
        assert service.authenticated_principal_id == rpc.principal_id

        loan = service._store(package)
        loan.close()
        assert len(service._store_pool) == 1

        bootstrap = _rpc(rpc.socket_path, {
            "action": "local-project-grant", "project": "alpha", "cwd": ".",
        })
        assert bootstrap["ok"] is True
        assert list(rpc.token_root.glob("*.grant"))
    finally:
        server._control_close()
        server._control_close()  # Idempotent repeat shutdown.

    assert server._control_environment_rpc.status()["available"] is False
    assert server._control_environment_sessions._closed is True
    assert not server._control_environment_sessions._store_pool
    assert stores and stores[0].closes == 1
    assert not environment_rpc_socket.exists()
    assert not list(server._control_environment_rpc.token_root.glob("*.grant"))
    assert not active_hooks
    gc.collect()
    assert _open_fd_count() == baseline_fds


def test_store_open_racing_with_service_close_closes_new_backend(tmp_path: Path) -> None:
    cfg = _lifecycle_config(tmp_path, tmp_path / "rpc" / "environment.sock")
    service = EnvironmentService(cfg)
    gate = {"entered": threading.Event(), "proceed": threading.Event()}
    stores: list[object] = []
    package, stores = _fake_store_package(stores, gate=gate)

    captured_error: list[BaseException] = []

    def borrow() -> None:
        try:
            service._store(package)
        except BaseException as exc:
            captured_error.append(exc)

    opener = threading.Thread(target=borrow)
    opener.start()
    assert gate["entered"].wait(timeout=3.0)

    service.close()
    gate["proceed"].set()
    opener.join(timeout=5.0)

    assert len(stores) == 1
    assert stores[0].closes == 1
    assert len(captured_error) == 1
    assert isinstance(captured_error[0], ControlError)
    assert "closed" in captured_error[0].message


def test_principal_isolation_preserved_across_rpc_restart(tmp_path: Path) -> None:
    cfg_first = _lifecycle_config(tmp_path / "one", tmp_path / "shared-rpc" / "environment.sock")
    cfg_second = _lifecycle_config(tmp_path / "two", tmp_path / "shared-rpc" / "environment.sock")
    _create_git_project(cfg_first.workspace_root, "alpha")
    _create_git_project(cfg_second.workspace_root, "alpha")
    first_service = EnvironmentService(cfg_first)
    second_service = EnvironmentService(cfg_second)
    first_rpc = EnvironmentRPCServer(cfg_first, first_service, WorkspacePolicy(cfg_first))
    second_rpc = EnvironmentRPCServer(cfg_second, second_service, WorkspacePolicy(cfg_second))
    try:
        assert first_rpc.principal_id != second_rpc.principal_id
        first_rpc.start()
        res = WorkspacePolicy(cfg_first).resolve_scope(scope="project", project="alpha", cwd=".")
        stale_grant = first_rpc.issue_grant(res)
        stale_token = stale_grant.token_file.read_text(encoding="ascii")
        first_rpc.close()

        second_rpc.start()
        denied = _rpc(second_rpc.socket_path, {
            "grant": stale_token,
            "request_id": "req_cross_principal",
            "argv": ["continuation"],
        })
        assert denied["ok"] is False
        assert denied["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    finally:
        first_rpc.close()
        second_rpc.close()
        first_service.close()
        second_service.close()


def test_socket_unlink_does_not_remove_successor_socket_inode(
    tmp_path: Path, environment_rpc_socket: Path,
) -> None:
    cfg = _lifecycle_config(tmp_path, environment_rpc_socket)
    service = EnvironmentService(cfg)
    policy = WorkspacePolicy(cfg)
    first_rpc = EnvironmentRPCServer(cfg, service, policy)
    second_rpc = EnvironmentRPCServer(cfg, service, policy)
    first_rpc.start()
    try:
        first_inode = environment_rpc_socket.lstat().st_ino
        # Simulate another server replacing the socket path while first_rpc still
        # remembers the original (st_dev, st_ino) identity before first_rpc.close().
        environment_rpc_socket.unlink()
        second_rpc.start()
        second_inode = environment_rpc_socket.lstat().st_ino
        assert second_inode != first_inode

        first_rpc.close()
        assert environment_rpc_socket.exists()
        assert environment_rpc_socket.lstat().st_ino == second_inode
        assert second_rpc.status()["available"] is True
    finally:
        first_rpc.close()
        second_rpc.close()
        service.close()

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import EnvironmentRPCServer, _GrantRecord
from mncs_control_mcp.errors import ControlError


def test_path_options_are_mapped_in_split_and_equals_forms(tmp_path: Path) -> None:
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    host_root = tmp_path / "project"
    host_root.mkdir()
    grant = _GrantRecord(
        grant_id="grant-path-test",
        principal_id="principal-test",
        host_root=host_root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    split = server._translate_argv(
        ["enter", "--workspace", "/workspace/project/nested"],
        host_root,
        grant,
    )
    equals = server._translate_argv(
        ["enter", "--workspace=/workspace/project/nested"],
        host_root,
        grant,
    )
    assert split == ["enter", "--workspace", str(host_root / "nested")]
    assert equals == ["enter", "--workspace=" + str(host_root / "nested")]


def test_project_grant_returns_authenticated_campaign_capsule(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    calls: list[tuple[str, str | None]] = []

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            calls.append((repository, campaign_id))
            return {
                "schema_version": "mncs.control.campaign-continuation/1",
                "repository": repository,
                "campaign_id": campaign_id,
                "status": "ambiguous",
                "continuations": [
                    {"session_id": "ses_one", "campaign_id": "cmp_test"},
                    {"session_id": "ses_two", "campaign_id": "cmp_test"},
                ],
            }

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    token = "project-continuation-capability"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="project-continuation-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    request = {
        "grant": token,
        "request_id": "req_project_campaign_capsule",
        "argv": ["continuation"],
        "cwd": "/workspace/mncs-environment",
    }

    response = server.dispatch(request, peer_uid=0)
    replay = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert response == replay
    assert response["result"]["exit_code"] == 0
    capsule = json.loads(response["result"]["stdout"])
    assert capsule["status"] == "ambiguous"
    assert [item["session_id"] for item in capsule["continuations"]] == [
        "ses_one", "ses_two",
    ]
    assert calls == [("mncs-environment", None)]

    selected = server.dispatch({
        **request,
        "request_id": "req_project_campaign_selected",
        "argv": ["continuation", "--campaign-id=cmp_test"],
    }, peer_uid=0)
    assert json.loads(selected["result"]["stdout"])["campaign_id"] == "cmp_test"
    assert calls == [("mncs-environment", None), ("mncs-environment", "cmp_test")]


def test_campaign_capsule_rejects_wider_or_unbound_requests(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def __init__(self) -> None:
            self.calls = 0

        def campaign_continuation(self, _repository: str, _campaign_id: str | None = None):
            self.calls += 1
            return {"status": "not-found", "continuations": []}

    environment = Environment()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=environment,
        policy=object(),
    )
    token = "project-continuation-boundary"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="project-continuation-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    def request(identity: str, argv: list[str]):
        return server.dispatch({
            "grant": token,
            "request_id": identity,
            "argv": argv,
            "cwd": "/workspace/mncs-environment",
        }, peer_uid=0)

    wider = request("req_continuation_wider", ["continuation", "--repository", "another-project"])
    assert wider["error"]["code"] == "ENVIRONMENT_RPC_INVALID_REQUEST"
    assert environment.calls == 0

    environment.authenticated_principal_id = "different-principal"
    unbound = request("req_continuation_unbound", ["continuation"])
    assert unbound["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert environment.calls == 0

    environment.authenticated_principal_id = "principal-test"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="workspace-continuation-grant",
        principal_id="principal-test",
        host_root=workspace,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    broad_scope = request("req_continuation_workspace_scope", ["continuation"])
    assert broad_scope["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert environment.calls == 0


def test_retire_rpc_exposes_only_scoped_read_only_inventory(tmp_path: Path) -> None:
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    host_root = tmp_path / "project"
    host_root.mkdir()
    grant = _GrantRecord(
        grant_id="grant-retire-test",
        principal_id="principal-test",
        host_root=host_root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    translated = server._translate_argv(
        ["retire", "ses_test", "--repository", "/workspace/project",
         "--inventory", "--dry-run"],
        host_root,
        grant,
    )
    assert translated == ["retire", "ses_test", "--repository", str(host_root),
                          "--inventory", "--dry-run"]

    for argv in (
        ["retire", "ses_test", "--repository", "/workspace/project", "--inventory"],
        ["retire", "ses_test", "--repository", "/workspace/project",
         "--inventory", "--dry-run", "--branch", "main"],
        ["retire", "ses_test", "--repository", "/workspace/project",
         "--inventory", "--dry-run", "--execution-root", "/"],
        ["retire", "ses_test", "--repository", "/workspace/project",
         "--inventory", "--dry-run", "--canonical=refs/heads/private"],
    ):
        with pytest.raises(ControlError):
            server._translate_argv(argv, host_root, grant)


def test_entry_preserves_and_bounds_configured_workspace_root(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    project = projects / "mncs-environment"
    definition_dir = project / ".mncs"
    definition_dir.mkdir(parents=True)
    definition = definition_dir / "environment.json"
    definition.write_text(
        json.dumps({"workspace_root": "../..", "workspace_scope": {"kind": "workspace"}}),
        encoding="utf-8",
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    workspace_grant = _GrantRecord(
        grant_id="workspace-grant",
        principal_id="principal-test",
        host_root=projects,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    translated = server._translate_argv(
        ["enter"], project, workspace_grant
    )

    assert translated == ["enter"]

    project_grant = _GrantRecord(
        grant_id="project-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "project-grant",
    )
    with pytest.raises(ControlError, match="exceeds the execution grant") as raised:
        server._translate_argv(["enter"], project, project_grant)
    assert raised.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"

    outside_definition = tmp_path / "outside-environment.json"
    outside_definition.write_text(json.dumps({"workspace_root": "."}), encoding="utf-8")
    definition.unlink()
    definition.symlink_to(outside_definition)
    with pytest.raises(ControlError, match="discovered Environment definition") as raised:
        server._translate_argv(["enter"], project, workspace_grant)
    assert raised.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"


def test_retry_identity_replays_across_fresh_execution_grants(tmp_path: Path) -> None:
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "shared-sandbox-home",
            environment_rpc_socket=tmp_path / "private-control-state" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    root = tmp_path / "project"
    root.mkdir()
    token_one = "execution-one-capability"
    token_two = "execution-two-capability"
    for token, grant_id in ((token_one, "grant-one"), (token_two, "grant-two")):
        server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
            grant_id=grant_id,
            principal_id="same-control-principal",
            host_root=root,
            sandbox_root="/workspace/project",
            scope="project",
            uid=0,
            expires_at=time.monotonic() + 60,
            token_file=tmp_path / f"{grant_id}.grant",
        )
    calls = 0

    def dispatch_once(request, *, peer_uid):
        nonlocal calls
        calls += 1
        return {"ok": True, "result": {"checkpoint": "chk_retry"}}

    server._dispatch_once = dispatch_once
    request = {
        "request_id": "req_retry_new_execution_grant",
        "argv": ["checkpoint", "ses_test", "--progress", "retry"],
        "cwd": "/workspace/project",
    }
    assert server.dispatch({**request, "grant": token_one}, peer_uid=0)["ok"]
    assert server.dispatch({**request, "grant": token_two}, peer_uid=0)["ok"]
    assert calls == 1


def test_grant_files_live_outside_shared_sandbox_home(tmp_path: Path) -> None:
    sandbox_home = tmp_path / "shared-sandbox-home"
    private_root = Path(tempfile.mkdtemp(prefix="mncsr-", dir="/tmp"))
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=sandbox_home,
            environment_rpc_socket=private_root / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    assert server.status()["available"] is False
    server.start()
    try:
        assert server.status() == {
            "provider": "mncs-control-environment-rpc",
            "available": True,
            "state": "ready",
            "authorization": "per-execution-grant-and-peer-credentials",
            "principal_id": server.principal_id,
            "store_mutation": {"state": "store-missing", "code": "store-missing"},
        }
        resolution = SimpleNamespace(
            scope="project", project="alpha", host_root=tmp_path / "projects" / "alpha"
        )
        grant = server.issue_grant(resolution)
        assert not grant.token_file.is_relative_to(sandbox_home)
        assert grant.token_file.stat().st_mode & 0o777 == 0o600
        assert server.grant_mount_source(grant) == grant.token_file
    finally:
        server.close()
        assert server.status()["available"] is False
        shutil.rmtree(private_root)


def test_status_reports_store_mount_read_only_without_attempting_a_write(
    tmp_path: Path, monkeypatch,
) -> None:
    state_dir = tmp_path / "state"
    (state_dir / "store").mkdir(parents=True)
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=state_dir),
        policy=object(),
    )
    monkeypatch.setattr(
        "mncs_control_mcp.environment_rpc.os.statvfs",
        lambda _path: SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1)),
    )
    monkeypatch.setattr("mncs_control_mcp.environment_rpc.os.access", lambda *_args: True)

    status = server.status()

    assert status["available"] is False
    assert status["store_mutation"] == {
        "state": "direct-filesystem-read-only",
        "code": "direct-filesystem-read-only",
    }
    assert str(state_dir / "store") not in json.dumps(status)


def test_same_request_is_serialized_and_replayed_once(tmp_path: Path) -> None:
    token = "one-time-test-capability"
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="grant-test",
        principal_id="principal-test",
        host_root=tmp_path.resolve(),
        sandbox_root="/workspace/test-project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    calls = 0
    call_lock = threading.Lock()

    def dispatch_once(request, *, peer_uid):
        nonlocal calls
        with call_lock:
            calls += 1
        time.sleep(0.05)
        return {"ok": True, "result": {"checkpoint": "chk_test"}}

    server._dispatch_once = dispatch_once
    request = {
        "grant": token,
        "request_id": "req_same_request_test",
        "argv": ["checkpoint", "ses_test", "--progress", "reconcile"],
        "cwd": "/workspace/test-project",
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _: server.dispatch(request, peer_uid=0), range(2)
        ))
    assert results[0] == results[1]
    assert calls == 1


def test_request_identity_cannot_be_reused_for_different_operation(tmp_path: Path) -> None:
    token = "one-time-test-capability"
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="grant-test",
        principal_id="principal-test",
        host_root=tmp_path.resolve(),
        sandbox_root="/workspace/test-project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._dispatch_once = lambda request, *, peer_uid: {"ok": True, "result": {}}
    base = {
        "grant": token,
        "request_id": "req_operation_binding_test",
        "cwd": "/workspace/test-project",
    }
    assert server.dispatch(
        {**base, "argv": ["inspect", "ses_one"]}, peer_uid=0
    )["ok"]
    rejected = server.dispatch(
        {**base, "argv": ["checkpoint", "ses_one"]}, peer_uid=0
    )
    assert rejected["error"]["code"] == "ENVIRONMENT_RPC_REQUEST_CONFLICT"


def test_foreign_session_inspection_requires_authenticated_owner(tmp_path: Path) -> None:
    token = "read-only-session-capability"

    class Store:
        def load_snapshot(self, session_id: str):
            assert session_id == "ses_foreign"
            return {"authenticated_principal_id": "principal-owner"}

        def close(self) -> None:
            pass

    class Environment:
        state_dir = tmp_path / "state"

        def _pkg(self):
            return object()

        def _store(self, _pkg):
            return Store()

    root = tmp_path / "project"
    root.mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="grant-read-only-test",
        principal_id="principal-agent",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    response = server.dispatch({
        "grant": token,
        "request_id": "req_foreign_read_is_denied",
        "argv": ["inspect", "ses_foreign"],
        "cwd": "/workspace/project",
    }, peer_uid=0)

    assert response["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"


def test_accept_requires_current_receiver_bound_owner_handoff(tmp_path: Path, monkeypatch) -> None:
    token = "receiver-handoff-capability"
    root = tmp_path / "project"
    root.mkdir()
    session_id = "ses_handoff"
    handoff_id = "hff_receiver"
    snapshot = {
        "authenticated_principal_id": "ctrl_source",
        "consumer_id": "owner-agent",
        "lifecycle": "handed_off",
        "pending_handoff_id": handoff_id,
        "handoffs": [handoff_id],
    }
    handoff = {
        "identity": handoff_id,
        "session_id": session_id,
        "from_consumer": "owner-agent",
        "from_authenticated_principal_id": "ctrl_source",
        "to_authenticated_principal_id": "ctrl_receiver",
        "to_consumer": "agent-receiver",
        "to_consumer_kind": "agent",
    }

    class Store:
        def load_snapshot(self, identity):
            assert identity == session_id
            return snapshot

        def load_handoff(self, identity, transfer_id):
            assert identity == session_id
            assert transfer_id == handoff_id
            return handoff

        def close(self):
            pass

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"

        def _pkg(self):
            return object()

        def _store(self, _pkg):
            return Store()

    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="receiver-grant",
        principal_id="ctrl_receiver",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    called = []

    def run(*args, **kwargs):
        called.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="{}\n", stderr="")

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    response = server.dispatch({
        "grant": token,
        "request_id": "req_accept_current_handoff",
        "argv": ["accept", "--consumer", "agent-receiver", session_id, handoff_id],
        "cwd": "/workspace/project",
    }, peer_uid=0)
    assert response["ok"] is True
    assert response["result"]["exit_code"] == 0
    assert len(called) == 1

    handoff["to_authenticated_principal_id"] = "ctrl_someone_else"
    rejected = server.dispatch({
        "grant": token,
        "request_id": "req_reject_foreign_handoff",
        "argv": ["accept", "--consumer", "agent-receiver", session_id, handoff_id],
        "cwd": "/workspace/project",
    }, peer_uid=0)
    assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(called) == 1


def test_store_corruption_during_authorization_is_structured(tmp_path: Path) -> None:
    token = "store-corruption-capability"

    class StoreIntegrityFailure(Exception):
        pass

    class Environment:
        state_dir = tmp_path / "state"

        def _pkg(self):
            return object()

        def _store(self, _pkg):
            raise StoreIntegrityFailure("canonical Store recovery is required")

    root = tmp_path / "project"
    root.mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="grant-corruption-test",
        principal_id="principal-agent",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    response = server.dispatch({
        "grant": token,
        "request_id": "req_store_corruption_is_reported",
        "argv": ["inspect", "ses_test"],
        "cwd": "/workspace/project",
    }, peer_uid=0)

    assert response["error"]["code"] == "ENVIRONMENT_STORE_CORRUPTION"

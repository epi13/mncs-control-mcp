from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from mncs_control_mcp import environment_rpc as environment_rpc_module
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import (
    MAX_ARGUMENT_BYTES,
    MAX_RESPONSE_BYTES,
    EnvironmentRPCServer,
    _GrantRecord,
)
from mncs_control_mcp.errors import ControlError


def test_post_commit_response_drop_requires_exact_successful_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = "req_post_commit_crash_test"
    request = {"request_id": request_id, "argv": ["checkpoint", "ses_test"]}
    response = {"ok": True, "result": {"exit_code": 0}}
    variable = "MNCS_CONTROL_TEST_DROP_CHECKPOINT_RESPONSE_REQUEST_ID"
    monkeypatch.delenv(variable, raising=False)
    assert not EnvironmentRPCServer._test_drop_checkpoint_response_after_commit(
        request, response,
    )

    monkeypatch.setenv(variable, request_id)
    assert EnvironmentRPCServer._test_drop_checkpoint_response_after_commit(
        request, response,
    )
    assert variable not in os.environ

    monkeypatch.setenv(variable, request_id)
    assert not EnvironmentRPCServer._test_drop_checkpoint_response_after_commit(
        {**request, "request_id": "req_other"}, response,
    )
    assert not EnvironmentRPCServer._test_drop_checkpoint_response_after_commit(
        {**request, "argv": ["inspect", "ses_test"]}, response,
    )
    assert not EnvironmentRPCServer._test_drop_checkpoint_response_after_commit(
        request, {"ok": True, "result": {"exit_code": 1}},
    )


def test_post_commit_service_termination_requires_exact_successful_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = "req_post_commit_terminate_test"
    request = {"request_id": request_id, "argv": ["checkpoint", "ses_test"]}
    response = {"ok": True, "result": {"exit_code": 0}}
    variable = "MNCS_CONTROL_TEST_TERMINATE_CHECKPOINT_SERVICE_REQUEST_ID"
    monkeypatch.delenv(variable, raising=False)
    assert not EnvironmentRPCServer._test_terminate_checkpoint_service_after_commit(
        request, response,
    )

    monkeypatch.setenv(variable, request_id)
    assert EnvironmentRPCServer._test_terminate_checkpoint_service_after_commit(
        request, response,
    )
    assert variable not in os.environ

    monkeypatch.setenv(variable, request_id)
    assert not EnvironmentRPCServer._test_terminate_checkpoint_service_after_commit(
        {**request, "request_id": "req_other"}, response,
    )
    assert not EnvironmentRPCServer._test_terminate_checkpoint_service_after_commit(
        {**request, "argv": ["inspect", "ses_test"]}, response,
    )
    assert not EnvironmentRPCServer._test_terminate_checkpoint_service_after_commit(
        request, {"ok": True, "result": {"exit_code": 1}},
    )


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


def test_scope_grant_rpc_requires_exact_campaign_approval_and_environment_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    environment = workspace / "mncs-environment"
    target = workspace / "mncs-control-mcp"
    for checkout in (environment, target):
        (checkout / ".git").mkdir(parents=True)
    approval = "user-approval:campaign-scope-test"
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
            environment_scope_grants={
                "cmp_scope_test": {"mncs-control-mcp": approval},
            },
        ),
        environment_service=SimpleNamespace(
            state_dir=tmp_path / "state", environment_path=tmp_path / "environment-source",
        ),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="scope-grant-test",
        principal_id="principal-test",
        host_root=environment,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_scope_test",
    )
    args = [
        "scope-grant", "ses_scope_test",
        "--campaign-id", "cmp_scope_test",
        "--repository", "mncs-control-mcp",
        "--expected-authority-revision", "a" * 64,
        "--approval-reference", approval,
    ]

    assert server._translate_argv(args, environment, grant) == args
    for changed in (
        args[:-1] + ["user-approval:other"],
        args[:3] + ["cmp_other"] + args[4:],
        args[:5] + ["mncs-language"] + args[6:],
    ):
        with pytest.raises(ControlError) as raised:
            server._translate_argv(changed, environment, grant)
        assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"

    authorized_sessions: list[str] = []
    monkeypatch.setattr(server, "_grant", lambda _request, _peer: grant)
    monkeypatch.setattr(
        server, "_authorize_session", lambda session_id, _principal:
        authorized_sessions.append(session_id),
    )
    monkeypatch.setattr(
        environment_rpc_module.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="{}\n", stderr="",
        ),
    )
    response = server._dispatch_once(
        {
            "cwd": "/workspace/mncs-environment",
            "argv": args,
            "request_id": "req_scope_grant_dispatch_test",
        },
        peer_uid=grant.uid,
    )
    assert response["ok"] is True
    assert authorized_sessions == ["ses_scope_test"]

    workspace_grant = _GrantRecord(
        **{**grant.__dict__, "scope": "workspace", "host_root": workspace},
    )
    with pytest.raises(ControlError) as raised:
        server._translate_argv(args, environment, workspace_grant)
    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"

    linked_target = workspace / "mncs-other-control"
    linked_target.symlink_to(target, target_is_directory=True)
    server.config.environment_scope_grants["cmp_scope_test"] = {
        "mncs-other-control": approval,
    }
    linked_args = args[:5] + ["mncs-other-control"] + args[6:]
    with pytest.raises(ControlError) as raised:
        server._translate_argv(linked_args, environment, grant)
    assert raised.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"


def test_claim_recovery_rpc_requires_exact_owner_approval_generation_and_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    environment = workspace / "mncs-environment"
    environment.mkdir(parents=True)
    approval = "user-approval:compiler-claim-recovery"
    approved = {
        "repository": "mncs-compiler",
        "claim_version": 63,
        "owner_session_id": "ses_old_compiler",
        "owner_consumer_id": "luna-compiler-self-consumption-admission-20261009",
        "requester_session_id": "ses_new_campaign",
        "approval_reference": approval,
    }

    class Store:
        def load_snapshot(self, _session_id: str) -> dict:
            return {
                "authenticated_principal_id": "principal-test",
                "campaign": {"identity": "cmp_mncs_continuity_20261010"},
            }

        def close(self) -> None:
            pass

    service = SimpleNamespace(
        state_dir=tmp_path / "state",
        environment_path=tmp_path / "environment-source",
        _pkg=lambda: object(),
        _store=lambda _pkg: Store(),
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
            environment_claim_recovery_grants={
                "cmp_mncs_continuity_20261010": {
                    "claim:mncs-compiler": approved,
                },
            },
        ),
        environment_service=service,
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="claim-recovery-test",
        principal_id="principal-test",
        host_root=environment,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_new_campaign",
    )
    args = [
        "claim-recover", "ses_new_campaign",
        "--campaign-id", "cmp_mncs_continuity_20261010",
        "--claim-id", "claim:mncs-compiler",
        "--repository", "mncs-compiler",
        "--owner-session-id", "ses_old_compiler",
        "--expected-version", "63",
        "--approval-reference", approval,
        "--reason", "operator-approved recovery after host reboot",
    ]
    authorized_sessions: list[str] = []
    monkeypatch.setattr(
        server, "_authorize_session",
        lambda session_id, _principal: authorized_sessions.append(session_id),
    )

    result = server._authorize_claim_recovery_argv(args, environment, grant)

    assert result["claim_id"] == "claim:mncs-compiler"
    assert result["expected_version"] == 63
    assert result["owner_consumer_id"] == approved["owner_consumer_id"]
    assert authorized_sessions == ["ses_new_campaign"]
    for changed in (
        args[:11] + ["64"] + args[12:],
        args[:-3] + ["user-approval:other", "--reason", "operator-approved recovery"],
    ):
        with pytest.raises(ControlError) as raised:
            server._authorize_claim_recovery_argv(changed, environment, grant)
        assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"
    wrong_session = _GrantRecord(
        **{**grant.__dict__, "bound_session_id": "ses_other"},
    )
    with pytest.raises(ControlError) as raised:
        server._authorize_claim_recovery_argv(args, environment, wrong_session)
    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


def test_claim_recovery_liveness_correlates_jobs_and_excludes_only_current_grant() -> None:
    from mncs_control_mcp.processes import ProcessManager

    manager = ProcessManager.__new__(ProcessManager)
    manager._lock = threading.RLock()
    manager._claim_recovery_repositories = set()
    manager._jobs = {
        "old-session": SimpleNamespace(
            job_id="old-session", status="running", command="python task.py", cwd="/workspace/other",
            scope="project", project="mncs-language", kind="terminal",
            process=SimpleNamespace(pid=101),
        ),
        "repository": SimpleNamespace(
            job_id="repository", status="queued", command="python build.py", cwd="/workspace/compiler",
            scope="project", project="mncs-compiler", kind="terminal",
            process=None,
        ),
        "current-recovery": SimpleNamespace(
            job_id="current-recovery", status="running", command="mncs-env claim-recover", cwd="/workspace/environment",
            scope="project", project="mncs-environment", kind="terminal",
            process=SimpleNamespace(pid=103),
        ),
        "unrelated": SimpleNamespace(
            job_id="unrelated", status="running", command="python task.py", cwd="/workspace/language",
            scope="project", project="mncs-language", kind="terminal",
            process=SimpleNamespace(pid=104),
        ),
        "unbound-environment": SimpleNamespace(
            job_id="unbound-environment", status="running", command="python continuation.py", cwd="/workspace/environment",
            scope="project", project="mncs-environment", kind="terminal",
            process=SimpleNamespace(pid=105),
        ),
    }
    manager._environment_grants = {
        "old-session": SimpleNamespace(grant_id="grant-old"),
        "repository": SimpleNamespace(grant_id="grant-compiler"),
        "current-recovery": SimpleNamespace(grant_id="grant-current"),
        "unrelated": SimpleNamespace(grant_id="grant-unrelated"),
    }
    rows = manager.claim_recovery_job_candidates(
        "mncs-compiler",
        owner_session_id="ses_old_owner",
        current_grant_id="grant-current",
        environment_project="mncs-environment",
        grant_sessions={
            "grant-old": "ses_old_owner",
            "grant-compiler": "ses_current",
            "grant-current": "ses_requester",
            "grant-unrelated": "ses_other",
        },
    )
    assert {item["job_id"] for item in rows} == {
        "old-session", "repository", "unbound-environment",
    }


def test_process_manager_pauses_project_jobs_during_claim_recovery() -> None:
    from mncs_control_mcp.processes import ProcessManager

    manager = ProcessManager.__new__(ProcessManager)
    manager.config = SimpleNamespace(
        allow_terminal=True,
        default_timeout_seconds=30,
        max_timeout_seconds=60,
    )
    manager.policy = SimpleNamespace(resolve_scope=lambda **_kwargs: SimpleNamespace(
        scope="project", project="mncs-compiler",
    ))
    manager._lock = threading.RLock()
    manager._claim_recovery_repositories = {"mncs-compiler"}

    with pytest.raises(ControlError) as raised:
        manager.start(
            "python compile_fixture.py",
            scope="project",
            project="mncs-compiler",
            cwd="/workspace/mncs-compiler",
            timeout_seconds=30,
            network=False,
        )
    assert raised.value.code == "ENVIRONMENT_OWNER_RECOVERY_ACTIVE"


def test_claim_recovery_request_tracks_selected_continuation_session() -> None:
    assert EnvironmentRPCServer._request_session(
        ["continuation", "--repository", "mncs-environment"],
        bound_session_id="ses_selected",
    ) == "ses_selected"
    assert EnvironmentRPCServer._request_session(
        ["campaign-bind", "--session-id", "ses_old_owner", "--task-identity", "task-1"],
    ) == "ses_old_owner"
    assert EnvironmentRPCServer._request_session(
        ["complete", "ses_old_owner", "--outcome", "done"],
    ) == "ses_old_owner"


def test_claim_recovery_refuses_a_live_former_owner_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim = {
        "claim_id": "claim:mncs-compiler",
        "version": 63,
        "status": "held",
        "repository": "mncs-compiler",
        "session_id": "ses_old_compiler",
        "consumer_id": "old-compiler-consumer",
        "scope": {"kind": "repository", "exclusive": True},
        "acquired_at": "2026-10-13T00:00:00+00:00",
        "expires_at": "2026-10-20T00:00:00+00:00",
    }

    class Store:
        def load_snapshot(self, session_id: str) -> dict:
            if session_id == "ses_new_campaign":
                return {
                    "authenticated_principal_id": "principal-test",
                    "campaign": {"identity": "cmp_recovery_test"},
                }
            return {"session_id": session_id}

        def read_claims(self) -> list[dict]:
            return [claim]

        def close(self) -> None:
            pass

    service = SimpleNamespace(
        state_dir=tmp_path / "state",
        _pkg=lambda: SimpleNamespace(claims=SimpleNamespace(
            active_claims=lambda _records: {claim["claim_id"]: claim},
            _alive=lambda _claim: True,
        )),
        _store=lambda _pkg: Store(),
        recover_claim=mock.Mock(),
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=tmp_path,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=service,
        policy=object(),
        process_manager=SimpleNamespace(
            begin_claim_recovery=mock.Mock(),
            end_claim_recovery=mock.Mock(),
        ),
    )
    observation = {
        "jobs": [], "grants": [], "active_requests": 0,
        "processes": [{"pid": 777, "reason": "former-session-environment"}],
        "processes_examined": 4, "same_uid_processes_examined": 2,
        "host_boot_id": "00000000-0000-0000-0000-000000000000",
        "process_complete": True, "services": [], "user_units_examined": 1,
        "services_complete": True,
    }
    monkeypatch.setattr(
        server, "_recovery_liveness_snapshot",
        lambda **_kwargs: observation,
    )
    grant = _GrantRecord(
        grant_id="recovery-live-owner-test",
        principal_id="principal-test",
        host_root=tmp_path,
        sandbox_root="/workspace/environment",
        scope="project",
        uid=os.getuid(),
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    with pytest.raises(ControlError) as raised:
        server._perform_claim_recovery(
            {
                "session_id": "ses_new_campaign",
                "campaign_id": "cmp_recovery_test",
                "claim_id": "claim:mncs-compiler",
                "repository": "mncs-compiler",
                "owner_session_id": "ses_old_compiler",
                "owner_consumer_id": "old-compiler-consumer",
                "expected_version": 63,
                "approval_reference": "user-approval:test",
                "reason": "test blocked live owner",
            },
            record=grant,
            request_id="req_live_owner_recovery_test",
        )

    assert raised.value.code == "ENVIRONMENT_OWNER_EXECUTION_ACTIVE"
    service.recover_claim.assert_not_called()
    server.process_manager.end_claim_recovery.assert_called_once_with("mncs-compiler")
    assert "ses_old_compiler" not in server._fenced_sessions


def test_rpc_accepts_bounded_campaign_metadata_and_rejects_oversized_arguments(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="campaign-metadata-bound",
        principal_id="principal-test",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    evidence = json.dumps(
        [
            {
                "identity": f"ev_rpc_{index:02d}",
                "repository": "mncs-environment",
                "commit": f"{index + 1:040x}",
                "path": f"tests/{'x' * 120}_evidence_{index:03d}.json",
                "sha256": f"{index + 1:064x}",
            }
            for index in range(100)
        ],
        separators=(",", ":"),
    )
    assert 32 * 1024 < len(evidence.encode("utf-8")) <= MAX_ARGUMENT_BYTES

    translated = server._translate_argv(
        ["checkpoint", "ses_test", "--campaign-evidence-json", evidence],
        root,
        grant,
    )

    assert translated[-1] == evidence
    with pytest.raises(ControlError, match="Environment argv is invalid"):
        server._translate_argv(
            [
                "checkpoint",
                "ses_test",
                "--campaign-evidence-json",
                "x" * (MAX_ARGUMENT_BYTES + 1),
            ],
            root,
            grant,
        )


def test_project_campaign_entry_maps_only_the_granted_repository_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_path = project / "tests" / "fixtures" / "entry.json"
    definition_path.parent.mkdir(parents=True)
    definition_path.write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-campaign-entry-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    translated = server._translate_argv(
        ["enter", "--definition", "tests/fixtures/entry.json",
         "--campaign-id", "cmp_test"],
        project,
        grant,
    )

    assert translated == [
        "enter", "--definition", str(definition_path), "--campaign-id", "cmp_test",
        "--workspace", str(workspace),
    ]


def test_project_entry_selects_project_default_definition(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    config = project / ".mncs"
    config.mkdir(parents=True)
    (config / "environment.json").write_text(json.dumps({
        "workspace_root": "../..",
        "workspace_scope": {
            "kind": "workspace",
            "repositories": ["mncs-environment", "mncs-language"],
        },
    }), encoding="utf-8")
    project_definition = config / "project-environment.json"
    project_definition.write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-default-entry-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    translated = server._translate_argv(
        ["enter", "--campaign-id", "cmp_test"], project, grant,
    )

    assert translated == [
        "enter", "--campaign-id", "cmp_test",
        "--definition", str(project_definition),
        "--workspace", str(workspace),
    ]


def test_project_default_environment_definition_rejects_symlink(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    config = project / ".mncs"
    config.mkdir(parents=True)
    outside_definition = tmp_path / "outside.json"
    outside_definition.write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    (config / "project-environment.json").symlink_to(outside_definition)
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-default-entry-symlink-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    with pytest.raises(ControlError, match="must be a regular file") as raised:
        server._translate_argv(["enter"], project, grant)

    assert raised.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"


def test_project_campaign_entry_rejects_definition_scope_widening(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_path = project / "entry.json"
    project.mkdir(parents=True)
    definition_path.write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment", "mncs-language"]},
    }), encoding="utf-8")
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-campaign-entry-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    with pytest.raises(ControlError, match="must declare only its granted repository") as raised:
        server._translate_argv(
            ["enter", "--definition", "entry.json", "--campaign-id", "cmp_test"],
            project,
            grant,
        )

    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


def test_project_grant_returns_authenticated_campaign_capsule(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    calls: list[tuple[str, str | None, str | None]] = []

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def campaign_continuation(
            self, repository: str, campaign_id: str | None = None,
            task_identity: str | None = None,
        ):
            calls.append((repository, campaign_id, task_identity))
            return {
                "schema_version": "mncs.control.campaign-continuation/1",
                "repository": repository,
                "campaign_id": campaign_id,
                "status": "ready" if task_identity is not None else "ambiguous",
                **({"task_selector": {"status": "resolved",
                                      "campaign_id": "cmp_test",
                                      "session_id": "ses_one"},
                    "selected_session_id": "ses_two",
                    "selection_basis": "authenticated-project-environment-definition"}
                   if task_identity is not None else {}),
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
    assert calls == [("mncs-environment", None, None)]

    selected = server.dispatch({
        **request,
        "request_id": "req_project_campaign_selected",
        "argv": ["continuation", "--campaign-id=cmp_test"],
    }, peer_uid=0)
    assert json.loads(selected["result"]["stdout"])["campaign_id"] == "cmp_test"
    assert calls == [
        ("mncs-environment", None, None),
        ("mncs-environment", "cmp_test", None),
    ]

    selected_by_task = server.dispatch({
        **request,
        "request_id": "req_project_campaign_task_selector",
        "argv": ["continuation", "--task-identity=durable-task-key"],
    }, peer_uid=0)
    assert selected_by_task["ok"] is True
    task_capsule = json.loads(selected_by_task["result"]["stdout"])
    assert task_capsule["status"] == "task-selector-session-mismatch"
    assert "selected_session_id" not in task_capsule
    assert task_capsule["task_selector"] == {
        "status": "resolved",
        "campaign_id": "cmp_test",
        "session_id": "ses_one",
    }
    assert calls[-1] == ("mncs-environment", None, "durable-task-key")


def test_artifact_read_is_bound_to_environment_selected_project_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    authorized_sessions: list[tuple[str, str]] = []

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-agent"

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            assert repository == "mncs-environment"
            assert campaign_id == "cmp_test"
            return {"status": "ready", "campaign_id": campaign_id}

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            repositories={"environment": "mncs-environment"},
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    token = "artifact-read-session-bound-grant"
    record = _GrantRecord(
        grant_id="artifact-read-session-bound-grant",
        principal_id="principal-agent",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = record
    selected_session = ["ses_selected"]
    monkeypatch.setattr(
        server, "_select_project_campaign_context",
        lambda _capsule, _record, _project: {
            "status": "ready",
            "campaign_id": "cmp_test",
            "selected_session_id": selected_session[0],
            "selection_basis": "authenticated-project-environment-definition",
        },
    )
    monkeypatch.setattr(
        server, "_authorize_session",
        lambda session_id, principal_id: authorized_sessions.append(
            (session_id, principal_id)
        ),
    )
    calls = []
    monkeypatch.setattr(
        "mncs_control_mcp.environment_rpc.subprocess.run",
        lambda argv, **kwargs: calls.append((argv, kwargs)) or SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"content_base64": "A" * 1_398_104}) + "\n",
            stderr="",
        ),
    )
    base = {
        "grant": token,
        "cwd": "/workspace/mncs-environment",
    }
    capability = "mncs-system-monitor:system-resource-sample"
    binding_id = "cap_" + "a" * 16
    before_selection = server.dispatch({
        **base,
        "request_id": "req_artifact_read_before_selection",
        "argv": ["artifact-read", "ses_selected", capability, binding_id,
                 "system-resource-sample.json"],
    }, peer_uid=0)
    assert before_selection["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert not calls

    continuation = server.dispatch({
        **base,
        "request_id": "req_artifact_read_select_session",
        "argv": ["continuation", "--campaign-id=cmp_test"],
    }, peer_uid=0)
    assert continuation["ok"] is True
    assert record.bound_session_id == "ses_selected"
    assert authorized_sessions == []

    wrong_session = server.dispatch({
        **base,
        "request_id": "req_artifact_read_wrong_session",
        "argv": ["artifact-read", "ses_other", capability, binding_id,
                 "system-resource-sample.json"],
    }, peer_uid=0)
    assert wrong_session["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert not calls

    read_result = server.dispatch({
        **base,
        "request_id": "req_artifact_read_selected_session",
        "argv": ["artifact-read", "ses_selected", capability, binding_id,
                 "system-resource-sample.json"],
    }, peer_uid=0)
    assert read_result["ok"] is True
    assert read_result["result"]["exit_code"] == 0
    assert len(read_result["result"]["stdout"].encode()) > MAX_RESPONSE_BYTES // 2
    assert len(json.dumps(read_result, separators=(",", ":")).encode()) < MAX_RESPONSE_BYTES
    assert calls[0][0][-5:] == [
        "artifact-read", "ses_selected", capability, binding_id,
        "system-resource-sample.json",
    ]
    assert authorized_sessions[-1] == ("ses_selected", "principal-agent")

    decision_capability = (
        "mncs-automation:automation-resource-headroom-evaluation"
    )
    decision_binding_id = "cap_" + "b" * 16
    decision_read = server.dispatch({
        **base,
        "request_id": "req_artifact_read_automation_decision",
        "argv": ["artifact-read", "ses_selected", decision_capability,
                 decision_binding_id, "resource-headroom-decision.json"],
    }, peer_uid=0)
    assert decision_read["ok"] is True
    assert calls[1][0][-5:] == [
        "artifact-read", "ses_selected", decision_capability,
        decision_binding_id, "resource-headroom-decision.json",
    ]
    assert authorized_sessions[-1] == ("ses_selected", "principal-agent")

    summary_capability = "mncs-system-monitor:system-observability"
    summary_binding_id = "cap_" + "c" * 16
    summary_path = "system-observability-summary.json"
    wrong_summary_session = server.dispatch({
        **base,
        "request_id": "req_artifact_read_summary_wrong_session",
        "argv": ["artifact-read", "ses_other", summary_capability,
                 summary_binding_id, summary_path],
    }, peer_uid=0)
    assert wrong_summary_session["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 2

    extra_summary_argument = server.dispatch({
        **base,
        "request_id": "req_artifact_read_summary_extra_argument",
        "argv": ["artifact-read", "ses_selected", summary_capability,
                 summary_binding_id, summary_path, "unexpected"],
    }, peer_uid=0)
    assert extra_summary_argument["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 2

    summary_read = server.dispatch({
        **base,
        "request_id": "req_artifact_read_summary_selected_session",
        "argv": ["artifact-read", "ses_selected", summary_capability,
                 summary_binding_id, summary_path],
    }, peer_uid=0)
    assert summary_read["ok"] is True
    assert summary_read["result"]["exit_code"] == 0
    assert calls[2][0][-5:] == [
        "artifact-read", "ses_selected", summary_capability,
        summary_binding_id, summary_path,
    ]
    assert authorized_sessions[-1] == ("ses_selected", "principal-agent")

    selected_session[0] = "ses_other"
    server.dispatch({
        **base,
        "request_id": "req_artifact_read_reselect_session",
        "argv": ["continuation", "--campaign-id=cmp_test"],
    }, peer_uid=0)
    assert record.bound_session_id == "ses_other"
    stale_replay = server.dispatch({
        **base,
        "request_id": "req_artifact_read_selected_session",
        "argv": ["artifact-read", "ses_selected", capability, binding_id,
                 "system-resource-sample.json"],
    }, peer_uid=0)
    assert stale_replay["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"

    for index, argv in enumerate((
        ["artifact-read", "ses_selected", capability, binding_id, "../secret"],
        ["artifact-read", "ses_selected", "mncs-language:compile", binding_id,
         "system-resource-sample.json"],
        ["artifact-read", "ses_selected", capability, "not-a-binding",
         "system-resource-sample.json"],
        ["artifact-read", "ses_selected", decision_capability, decision_binding_id,
         "system-resource-sample.json"],
    )):
        rejected = server.dispatch({
            **base,
            "request_id": f"req_artifact_read_invalid_{index}",
            "argv": argv,
        }, peer_uid=0)
        assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 3


def test_project_session_mutations_require_exact_continuation_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    capsule = {
        "schema_version": "mncs.control.campaign-continuation/1",
        "campaign_id": "cmp_mutation_binding",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "contexts_count": 2,
        "continuations_count": 2,
        "contexts_truncated": False,
        "continuations_truncated": False,
        "continuations": [
            {
                "session_id": "ses_selected",
                "definition_id": "env_selected",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
            {
                "session_id": "ses_other_context",
                "definition_id": "env_other",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "same_campaign_only"},
                "claim_ids": [],
                "claims": [],
            },
        ],
    }

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            assert repository == "mncs-environment"
            assert campaign_id == "cmp_mutation_binding"
            return capsule

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    token = "project-session-mutation-grant"
    record = _GrantRecord(
        grant_id="project-session-mutation-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = record
    monkeypatch.setattr(
        server, "_project_environment_identity",
        lambda _record, _repository: ("env_selected", str(workspace)),
    )
    authorized_sessions: list[str] = []
    monkeypatch.setattr(
        server, "_authorize_session",
        lambda session_id, _principal: authorized_sessions.append(session_id),
    )
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        "mncs_control_mcp.environment_rpc.subprocess.run",
        lambda argv, **kwargs: calls.append((argv, kwargs)) or SimpleNamespace(
            returncode=0, stdout='{"identity":"chk_selected"}\n', stderr="",
        ),
    )

    def request(request_id: str, argv: list[str]) -> dict[str, object]:
        return server.dispatch({
            "grant": token,
            "request_id": request_id,
            "argv": argv,
            "cwd": "/workspace/mncs-environment",
        }, peer_uid=0)

    unselected = request(
        "req_mutation_binding_before_selection",
        ["checkpoint", "ses_selected", "--progress=before-selection"],
    )
    assert unselected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert calls == []

    selected = request(
        "req_mutation_binding_select",
        ["continuation", "--campaign-id", "cmp_mutation_binding"],
    )
    assert selected["ok"] is True
    assert record.bound_session_id == "ses_selected"

    allowed = request(
        "req_mutation_binding_allowed",
        ["checkpoint", "ses_selected", "--progress=selected"],
    )
    assert allowed["ok"] is True

    acquired = request(
        "req_mutation_binding_claim_acquire",
        ["claims", "ses_selected", "--acquire=mncs-environment"],
    )
    assert acquired["ok"] is True
    released = request(
        "req_mutation_binding_claim_release",
        ["claims", "ses_selected", "--release=mncs-environment"],
    )
    assert released["ok"] is True
    assert len(calls) == 3
    assert authorized_sessions == ["ses_selected"] * 4
    transferred = request(
        "req_mutation_binding_claim_transfer_equals",
        ["claims", "ses_selected", "--claim-id=claim-test",
         "--transfer-to=ses_transfer_recipient"],
    )
    assert transferred["ok"] is True
    assert authorized_sessions[-2:] == ["ses_selected", "ses_transfer_recipient"]
    assert len(calls) == 4

    for index, argv in enumerate((
        ["checkpoint", "ses_other_context", "--progress=unselected"],
        ["resume", "ses_other_context"],
        ["claims", "ses_other_context", "--acquire=mncs-other-project"],
    )):
        rejected = request(f"req_mutation_binding_wrong_{index}", argv)
        assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
        assert rejected["error"]["details"]["selected_session_id"] == "ses_selected"
        assert rejected["error"]["details"]["session_id"] == "ses_other_context"

    assert len(calls) == 4


def test_project_entry_returns_campaign_capsule_without_changing_entry_authority(
    tmp_path: Path, monkeypatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    (project / "entry.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    entry_result = {
        "session_id": "ses_selected",
        "lifecycle": "active",
        "configuration": {"definition_id": "env_3333333333333333"},
        "workspace_root": str(workspace),
        "continuation": {"identity": "cmp_test"},
        "readiness": {"status": "ready"},
    }
    capsule = {
        "schema_version": "mncs.control.campaign-continuation/1",
        "campaign_id": "cmp_test",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "continuations": [
            {
                "session_id": "ses_selected",
                "lifecycle": "active",
                "definition_id": "env_3333333333333333",
                "workspace_root": str(workspace),
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
            {
                "session_id": "ses_other_context",
                "lifecycle": "active",
                "definition_id": "env_4444444444444444",
                "workspace_root": str(workspace),
                "project_reference": {"status": "same_campaign_only"},
                "claim_ids": [],
                "claims": [],
            },
        ],
        "next": "select the exact recorded Environment context",
    }
    calls: list[tuple[str, str | None]] = []

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            calls.append((repository, campaign_id))
            return capsule

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    token = "project-entry-continuation"
    record = _GrantRecord(
        grant_id="project-entry-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = record

    def run(argv, **_kwargs):
        assert argv[-2:] == ["--workspace", str(workspace)]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(entry_result) + "\n",
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    request = {
        "grant": token,
        "request_id": "req_project_entry_continuation",
        "argv": ["enter", "--definition", "entry.json", "--campaign-id", "cmp_test"],
        "cwd": "/workspace/mncs-environment",
    }

    response = server.dispatch(request, peer_uid=0)
    replay = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert response == replay
    assert response["result"]["exit_code"] == 0
    result = json.loads(response["result"]["stdout"])
    assert result["session_id"] == "ses_selected"
    assert result["continuation"] == {"identity": "cmp_test"}
    assert result["control_project_continuation"]["status"] == "ready"
    assert result["control_project_continuation"]["selected_session_id"] == "ses_selected"
    assert result["control_project_continuation"]["selection_basis"] == (
        "authenticated-project-environment-definition"
    )
    assert record.bound_session_id == "ses_selected"
    assert result["control_project_continuation"] == capsule
    assert [item["session_id"] for item in
            result["control_project_continuation"]["continuations"]] == [
                "ses_selected", "ses_other_context",
            ]
    assert calls == [("mncs-environment", "cmp_test")]


def test_ambiguous_project_entry_returns_bounded_campaign_choices(
    tmp_path: Path, monkeypatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    (project / "entry.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
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
                "status": "ambiguous-campaigns",
                "campaigns_count": 2,
                "campaigns": [
                    {
                        "campaign_id": "cmp_alpha",
                        "status": "ready",
                        "continuations": [{
                            "session_id": "ses_alpha",
                            "lifecycle": "active",
                            "definition_id": "env_alpha",
                            "workspace_root": "/projects",
                            "project_reference": {"status": "linked"},
                            "claim_ids": ["claim-alpha"],
                            "checkpoint_ids": ["chk-alpha"],
                            "repositories": [{
                                "repository": repository,
                                "branch": "campaign/alpha",
                                "head": "a" * 40,
                            }],
                        }],
                    },
                    {
                        "campaign_id": "cmp_beta",
                        "status": "context-conflict",
                        "continuations": [{
                            "session_id": "ses_beta",
                            "lifecycle": "active",
                            "definition_id": "env_beta",
                            "workspace_root": "/projects",
                            "project_reference": {"status": "linked"},
                            "claim_ids": [],
                            "checkpoint_ids": [],
                            "repositories": [],
                        }],
                    },
                ],
                "next": "select a campaign identity",
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
    token = "project-entry-ambiguity"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="project-entry-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    def run(_argv, **_kwargs):
        return SimpleNamespace(
            returncode=2,
            stdout=json.dumps({
                "error": "multiple durable campaigns match this environment",
                "diagnostics": {
                    "code": "campaign-continuation-ambiguous",
                    "campaigns": ["cmp_alpha", "cmp_beta"],
                    "sessions": ["ses_alpha", "ses_beta"],
                    "next": "select the intended campaign identity",
                },
            }) + "\n",
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    request = {
        "grant": token,
        "request_id": "req_entry_ambiguity_capsule",
        "argv": ["enter", "--definition", "entry.json"],
        "cwd": "/workspace/mncs-environment",
    }

    response = server.dispatch(request, peer_uid=0)
    retry = server.dispatch(request, peer_uid=0)

    assert response == retry
    assert response["ok"] is True
    result = response["result"]
    assert result["exit_code"] == 2
    diagnostic = json.loads(result["stdout"])["diagnostics"]
    assert diagnostic["code"] == "campaign-continuation-ambiguous"
    assert diagnostic["campaigns"] == ["cmp_alpha", "cmp_beta"]
    capsule = diagnostic["continuation"]
    assert capsule["schema_version"] == "mncs.control.project-entry-continuation/1"
    assert capsule["status"] == "ambiguous-campaigns"
    assert capsule["campaigns_count"] == 2
    assert [item["campaign_id"] for item in capsule["campaign_statuses"]] == [
        "cmp_alpha", "cmp_beta",
    ]
    assert [item["session_id"] for item in capsule["continuations"]] == [
        "ses_alpha", "ses_beta",
    ]
    assert capsule["continuations"][0]["project_reference"] == {"status": "linked"}
    assert calls == [("mncs-environment", None)]


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

    def request(
        identity: str, argv: list[str], *, cwd: str = "/workspace/mncs-environment",
    ):
        return server.dispatch({
            "grant": token,
            "request_id": identity,
            "argv": argv,
            "cwd": cwd,
        }, peer_uid=0)

    wider = request("req_continuation_wider", ["continuation", "--repository", "another-project"])
    assert wider["error"]["code"] == "ENVIRONMENT_RPC_INVALID_REQUEST"
    assert environment.calls == 0

    environment.authenticated_principal_id = "different-principal"
    unbound = request("req_continuation_unbound", ["continuation"])
    assert unbound["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert environment.calls == 0

    environment.authenticated_principal_id = "principal-test"
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
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
    assert broad_scope["ok"] is True
    assert environment.calls == 1
    assert request(
        "req_continuation_workspace_root_only", ["continuation"], cwd="/workspace",
    )["error"]["code"] == "ENVIRONMENT_PROJECT_UNKNOWN"
    assert environment.calls == 1


def test_workspace_continuation_binds_one_repository_session_for_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_dir = project / ".mncs"
    definition_dir.mkdir(parents=True)
    (definition_dir / "project-environment.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    workspace_root = str(workspace.resolve())
    capsule = {
        "schema_version": "mncs.control.campaign-continuation/1",
        "campaign_id": "cmp_workspace_binding",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "continuations_count": 1,
        "continuations_truncated": False,
        "contexts_truncated": False,
        "continuations": [{
            "session_id": "ses_workspace_selected",
            "definition_id": "env_workspace_definition",
            "workspace_root": workspace_root,
            "lifecycle": "active",
            "project_reference": {"status": "linked"},
            "claim_ids": [],
            "claims": [],
        }],
    }

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-workspace"

        @staticmethod
        def _pkg():
            return SimpleNamespace(identity=SimpleNamespace(
                environment_id=lambda definition: (
                    "env_workspace_definition"
                    if definition["workspace_scope"]["repositories"]
                    == ["mncs-environment"] else "env_unexpected"
                ),
            ))

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            assert repository == "mncs-environment"
            assert campaign_id == "cmp_workspace_binding"
            return json.loads(json.dumps(capsule))

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    token = "workspace-session-mutation-grant"
    record = _GrantRecord(
        grant_id="workspace-session-mutation-grant",
        principal_id="principal-workspace",
        host_root=workspace,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = record
    authorized_sessions: list[str] = []
    monkeypatch.setattr(
        server, "_authorize_session",
        lambda session_id, _principal: authorized_sessions.append(session_id),
    )
    real_run = subprocess.run
    cli_calls: list[list[str]] = []

    def run(argv: list[str], *args: object, **kwargs: object):
        if argv and argv[0] == "git":
            return real_run(argv, *args, **kwargs)
        cli_calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, stdout='{"identity":"chk_workspace_selected"}\n', stderr="",
        )

    monkeypatch.setattr(environment_rpc_module.subprocess, "run", run)

    def request(request_id: str, argv: list[str]) -> dict[str, object]:
        return server.dispatch({
            "grant": token,
            "request_id": request_id,
            "argv": argv,
            "cwd": "/workspace/mncs-environment",
        }, peer_uid=0)

    selected = request(
        "req_workspace_mutation_select",
        ["continuation", "--campaign-id", "cmp_workspace_binding"],
    )
    assert selected["ok"] is True
    assert json.loads(selected["result"]["stdout"])["selected_session_id"] == (
        "ses_workspace_selected"
    )
    assert record.bound_session_id == "ses_workspace_selected"

    authorized = request(
        "req_workspace_mutation_allowed",
        ["checkpoint", "ses_workspace_selected", "--progress=selected"],
    )
    assert authorized["ok"] is True
    assert authorized_sessions == ["ses_workspace_selected"]
    assert len(cli_calls) == 1

    rejected = request(
        "req_workspace_mutation_cross_session",
        ["checkpoint", "ses_other_workspace_context", "--progress=wrong-session"],
    )
    assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert rejected["error"]["details"]["selected_session_id"] == (
        "ses_workspace_selected"
    )
    assert len(cli_calls) == 1


def test_project_continuation_cli_returns_compact_duplicate_session_capsule(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_dir = project / ".mncs"
    definition_dir.mkdir(parents=True)
    (definition_dir / "project-environment.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")
    evidence = [
        {
            "identity": f"ev_{index:02d}",
            "repository": "mncs-environment",
            "commit": f"{index + 1:040x}",
            "path": f"evidence/{index:02d}.json",
            "sha256": f"{index + 1:064x}",
        }
        for index in range(64)
    ]
    observation = {
        "status": "current",
        "observed_at": "2026-10-11T14:00:00Z",
        "source": "mncs-environment.workspace.discover_workspace",
        "workspace_root": str(workspace),
        "repository": "mncs-environment",
        "scan_status": "complete",
        "checkout": {
            "path": str(project),
            "branch": "main",
            "head": "a" * 40,
            "clean": True,
        },
        "worktree_registrations": [{
            "registered_path": str(project),
            "branch": "main",
            "head": "a" * 40,
            "detached": False,
            "physical_checkout_status": "not_checked; Git registration only",
        }],
        "worktree_registrations_count": 1,
        "worktree_registrations_truncated": False,
    }
    capsule = {
        "schema_version": "mncs.control.campaign-continuation/1",
        "campaign_id": "cmp_continuation_fixture",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "contexts_count": 2,
        "continuations_count": 2,
        "continuations": [
            {
                "session_id": "ses_linked",
                "lifecycle": "active",
                "consumer_id": "consumer-a",
                    "definition_id": "env_1111111111111111",
                "workspace_root": str(workspace),
                "project_reference": {"status": "linked", "basis": ["active_claim.repository"]},
                "claim_ids": ["claim:mncs-environment"],
                "claims": [{"claim_id": "claim:mncs-environment", "version": 4}],
                "checkpoint_ids": ["chk_1", "chk_2"],
                "campaign_state_checkpoint_id": "chk_campaign_state",
                "latest_checkpoint": {"identity": "chk_2", "sequence": 2},
                "evidence": evidence,
                "evidence_count": 64,
                "evidence_truncated": False,
                "delivery": {"status": "partial"},
                "unresolved_pressures": [{"identity": "CP-0011"}],
                "repositories": [{"repository": "mncs-environment", "head": "a" * 40}],
                "live_repository_observation": observation,
                "recorded_checkout_comparisons": [{"status": "checkout_head_changed"}],
            },
            {
                "session_id": "ses_other_context",
                "lifecycle": "active",
                "consumer_id": "consumer-b",
                "definition_id": "env-other",
                "workspace_root": str(workspace),
                "project_reference": {"status": "same_campaign_only", "basis": []},
                "claim_ids": [],
                "claims": [],
                "checkpoint_ids": [],
                "evidence": [],
                "evidence_count": 0,
                "evidence_truncated": False,
            },
        ],
        "next": "review the project-linked session and select its exact Environment context",
    }

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        def __init__(self) -> None:
            self.calls: list[tuple[str, str | None]] = []

        @staticmethod
        def _pkg():
            return SimpleNamespace(identity=SimpleNamespace(
                environment_id=lambda _definition: "env_1111111111111111",
            ))

        def campaign_continuation(self, repository: str, campaign_id: str | None = None):
            self.calls.append((repository, campaign_id))
            return capsule

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
    token = "compact-project-continuation"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="compact-project-continuation-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    response = server.dispatch({
        "grant": token,
        "request_id": "req_compact_project_continuation",
        "argv": ["continuation", "--campaign-id", "cmp_continuation_fixture"],
        "cwd": "/workspace/mncs-environment",
    }, peer_uid=0)

    assert response["ok"] is True
    result = json.loads(response["result"]["stdout"])
    assert result["schema_version"] == "mncs.control.campaign-continuation/2"
    assert result["status"] == "ready"
    assert result["context_conflict_status"] == "context-conflict"
    assert result["campaign_id"] == "cmp_continuation_fixture"
    assert result["selected_session_id"] == "ses_linked"
    assert result["selected_context"] == {
        "definition_id": "env_1111111111111111",
        "workspace_root": str(workspace),
    }
    assert result["selection_basis"] == "authenticated-project-environment-definition"
    assert result["unselected_contexts_count"] == 1
    assert result["unselected_sessions_count"] == 1
    assert [item["session_id"] for item in result["continuations"]] == [
        "ses_linked", "ses_other_context",
    ]
    linked, other = result["continuations"]
    assert linked["project_reference"]["basis"] == ["active_claim.repository"]
    assert linked["claim_ids"] == ["claim:mncs-environment"]
    assert linked["campaign_state_checkpoint_id"] == "chk_campaign_state"
    assert linked["latest_checkpoint"]["identity"] == "chk_2"
    assert linked["evidence_count"] == 64
    assert [item["identity"] for item in linked["evidence_refs"]] == [
        f"ev_{index:02d}" for index in range(58, 64)
    ]
    assert linked["evidence_refs_truncated"] is True
    assert "evidence" not in linked
    assert other["project_reference"]["status"] == "same_campaign_only"
    assert linked["live_repository_observation"]["checkout"]["path"] == str(project)
    assert linked["live_repository_observation"]["workspace_root"] == str(workspace)
    assert linked["recorded_checkout_comparisons"] == [
        {"status": "checkout_head_changed"},
    ]
    assert len(response["result"]["stdout"].encode()) < len(
        json.dumps(capsule).encode()
    )
    assert environment.calls == [("mncs-environment", "cmp_continuation_fixture")]


def test_project_continuation_refuses_selection_when_other_context_holds_claim(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_dir = project / ".mncs"
    definition_dir.mkdir(parents=True)
    (definition_dir / "project-environment.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"
        authenticated_principal_id = "principal-test"

        @staticmethod
        def _pkg():
            return SimpleNamespace(identity=SimpleNamespace(
                environment_id=lambda _definition: "env_2222222222222222",
            ))

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    record = _GrantRecord(
        grant_id="project-claim-selection-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    capsule = {
        "campaign_id": "cmp_test",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "continuations_count": 2,
        "continuations": [
            {
                "session_id": "ses_project",
                    "definition_id": "env_2222222222222222",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
            {
                "session_id": "ses_other",
                "definition_id": "env-workspace",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": ["claim:mncs-environment"],
                "claims": [{
                    "claim_id": "claim:mncs-environment",
                    "repository": "mncs-environment",
                    "status": "held",
                }],
            },
        ],
    }

    result = server._select_project_campaign_context(
        capsule, record, "mncs-environment",
    )

    assert result["status"] == "context-conflict"
    assert "selected_session_id" not in result
    assert result["project_selection"]["status"] == "blocked"
    assert result["project_selection"]["competing_claim_sessions"] == ["ses_other"]


def test_project_continuation_does_not_select_from_truncated_inventory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    definition_dir = project / ".mncs"
    definition_dir.mkdir(parents=True)
    (definition_dir / "project-environment.json").write_text(json.dumps({
        "workspace_scope": {"repositories": ["mncs-environment"]},
    }), encoding="utf-8")

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"

        @staticmethod
        def _pkg():
            return SimpleNamespace(identity=SimpleNamespace(
                environment_id=lambda _definition: "env_2222222222222222",
            ))

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    record = _GrantRecord(
        grant_id="project-truncated-selection-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    capsule = {
        "campaign_id": "cmp_test",
        "repository": "mncs-environment",
        "status": "context-conflict",
        "continuations_count": 3,
        "continuations_truncated": True,
        "continuations": [{
            "session_id": "ses_project",
            "definition_id": "env_2222222222222222",
            "workspace_root": str(workspace),
            "lifecycle": "active",
            "project_reference": {"status": "linked"},
            "claim_ids": [],
            "claims": [],
        }],
    }

    result = server._select_project_campaign_context(
        capsule, record, "mncs-environment",
    )

    assert result["status"] == "context-conflict"
    assert "selected_session_id" not in result
    assert result["project_selection"]["status"] == "unknown"
    assert result["project_selection"]["reason"] == "continuation-inventory-truncated"


def test_project_rpc_exposes_session_authorized_read_operations_and_reports_unknown_operations(
    tmp_path: Path, monkeypatch,
) -> None:
    token = "project-health-capability"
    root = tmp_path / "project"
    root.mkdir()
    snapshot = {"authenticated_principal_id": "principal-agent"}

    class Store:
        def load_snapshot(self, session_id):
            assert session_id == "ses_health"
            return snapshot

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
            workspace_root=tmp_path,
            repositories={"environment": "project"},
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    project_grant = _GrantRecord(
        grant_id="project-health-grant",
        principal_id="principal-agent",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_health",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = project_grant
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        stdout = (
            '{"providers":[{"provider_id":"forge","status":"unknown"}]}\n'
            if "capabilities" in argv else
            '{"evidence_count":129,"evidence_offset":64,"evidence_limit":32}\n'
            if "campaign-state" in argv else
            '{"evidence_count":3,"delivery":{"status":"delivered"}}\n'
            if any("campaign-state-inspection" in arg for arg in argv) else
            '{"schema":"mncs.system-monitor.resource-sample.v1",'
            '"execution_records":{"schema":"mncs.system-monitor.execution-records.v1",'
            '"records":[]}}\n'
            if any("mncs-system-monitor:system-resource-sample" in arg for arg in argv) else
            '{"capability":"mncs-environment:ambient-projection-coherence",'
            '"status":"ok","returncode":0}\n'
            if "invoke" in argv else
            '{"outcome":"done","claims_released":[]}\n'
            if "complete" in argv else
            '{"overall":"unknown","providers":{"forge":"unknown"}}\n'
        )
        return SimpleNamespace(
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    request = {
        "grant": token,
        "request_id": "req_project_health",
        "argv": ["health", "ses_health", "--consumer", "agent", "--live"],
        "cwd": "/workspace/project",
    }
    response = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert response["result"]["exit_code"] == 0
    assert json.loads(response["result"]["stdout"])["overall"] == "unknown"
    assert len(calls) == 1
    assert calls[0][0][-5:] == [
        "health", "ses_health", "--consumer", "agent", "--live",
    ]
    assert calls[0][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[0][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_health"

    capabilities = server.dispatch({
        **request,
        "request_id": "req_project_capabilities",
        "argv": ["capabilities", "ses_health"],
    }, peer_uid=0)
    assert capabilities["ok"] is True
    assert json.loads(capabilities["result"]["stdout"])["providers"][0]["status"] == "unknown"
    assert calls[1][0][-2:] == ["capabilities", "ses_health"]
    assert calls[1][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[1][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_capabilities"

    completion = server.dispatch({
        **request,
        "request_id": "req_project_complete",
        "argv": ["complete", "ses_health", "--outcome", "done",
                 "--summary", "campaign closed"],
    }, peer_uid=0)
    assert completion["ok"] is True
    assert json.loads(completion["result"]["stdout"])["outcome"] == "done"
    assert calls[2][0][-6:] == [
        "complete", "ses_health", "--outcome", "done", "--summary", "campaign closed",
    ]
    assert calls[2][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[2][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_complete"

    invocation_request = {
        **request,
        "request_id": "req_project_projection_invoke",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:ambient-projection-coherence"],
    }
    invocation = server.dispatch(invocation_request, peer_uid=0)
    assert invocation["ok"] is True
    assert json.loads(invocation["result"]["stdout"])["status"] == "ok"
    assert calls[3][0][-3:] == [
        "invoke", "ses_health", "mncs-environment:ambient-projection-coherence",
    ]
    assert calls[3][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[3][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_projection_invoke"

    evidence_read = server.dispatch({
        **request,
        "request_id": "req_project_projection_evidence_read",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:projection-evidence-inspection"],
    }, peer_uid=0)
    assert evidence_read["ok"] is True
    assert json.loads(evidence_read["result"]["stdout"])["status"] == "ok"
    assert calls[4][0][-3:] == [
        "invoke", "ses_health", "mncs-environment:projection-evidence-inspection",
    ]
    assert calls[4][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[4][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_projection_evidence_read"

    campaign_state_read = server.dispatch({
        **request,
        "request_id": "req_project_campaign_state_read",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:campaign-state-inspection"],
    }, peer_uid=0)
    assert campaign_state_read["ok"] is True
    assert json.loads(campaign_state_read["result"]["stdout"])["evidence_count"] == 3
    assert calls[5][0][-3:] == [
        "invoke", "ses_health", "mncs-environment:campaign-state-inspection",
    ]
    assert calls[5][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[5][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_campaign_state_read"

    resource_sample_request = {
        **request,
        "request_id": "req_project_system_resource_sample",
        "argv": ["invoke", "ses_health",
                 "mncs-system-monitor:system-resource-sample"],
    }
    resource_sample = server.dispatch(resource_sample_request, peer_uid=0)
    assert resource_sample["ok"] is True
    sample_output = json.loads(resource_sample["result"]["stdout"])
    assert sample_output["schema"] == "mncs.system-monitor.resource-sample.v1"
    assert sample_output["execution_records"]["records"] == []
    assert calls[6][0][-3:] == [
        "invoke", "ses_health", "mncs-system-monitor:system-resource-sample",
    ]
    assert calls[6][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[6][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == (
        "req_project_system_resource_sample"
    )
    assert server.dispatch(resource_sample_request, peer_uid=0) == resource_sample
    assert len(calls) == 7

    campaign_state_page = server.dispatch({
        **request,
        "request_id": "req_project_campaign_state_page",
        "argv": ["campaign-state", "ses_health", "--evidence-offset", "64",
                 "--evidence-limit", "32"],
    }, peer_uid=0)
    assert campaign_state_page["ok"] is True
    assert json.loads(campaign_state_page["result"]["stdout"]) == {
        "evidence_count": 129, "evidence_offset": 64, "evidence_limit": 32,
    }
    assert calls[7][0][-6:] == [
        "campaign-state", "ses_health", "--evidence-offset", "64",
        "--evidence-limit", "32",
    ]
    assert calls[7][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[7][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_project_campaign_state_page"

    for invalid_argv in (
        ["campaign-state", "ses_health", "--evidence-limit", "129"],
        ["campaign-state", "ses_health", "--evidence-offset", "0",
         "--evidence-offset", "1"],
        ["campaign-state", "ses_health", "--workspace", "/workspace"],
    ):
        with pytest.raises(ControlError):
            server._translate_argv(invalid_argv, root, project_grant)
    workspace_grant = _GrantRecord(
        grant_id="workspace-health-grant",
        principal_id="principal-agent",
        host_root=tmp_path,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "workspace-grant",
    )
    with pytest.raises(ControlError):
        server._authorize_campaign_state_argv(
            ["campaign-state", "ses_health"], workspace_grant,
        )

    # A retry with the same stable identity returns the admitted result and
    # does not invoke the capability twice within one Control process.
    replay = server.dispatch(invocation_request, peer_uid=0)
    assert replay == invocation
    assert len(calls) == 8

    unsupported = server.dispatch({
        **request,
        "request_id": "req_project_unknown_capability",
        "argv": ["invoke", "ses_health", "mncs-language:compile"],
    }, peer_uid=0)
    assert unsupported["error"]["code"] == "ENVIRONMENT_OPERATION_UNAVAILABLE"
    assert unsupported["error"]["details"]["status"] == "unknown"
    assert len(calls) == 8

    unbounded_invocation = server.dispatch({
        **request,
        "request_id": "req_project_projection_invoke_args",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:ambient-projection-coherence",
                 "--cwd", "/workspace/project"],
    }, peer_uid=0)
    assert unbounded_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 8

    unbounded_resource_sample = server.dispatch({
        **request,
        "request_id": "req_project_resource_sample_args",
        "argv": ["invoke", "ses_health",
                 "mncs-system-monitor:system-resource-sample", "--executions",
                 "/workspace/project/receipt.json"],
    }, peer_uid=0)
    assert unbounded_resource_sample["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 8

    other_root = tmp_path / "other"
    other_root.mkdir()
    other_token = "other-project-invocation"
    server._grants[hashlib.sha256(other_token.encode()).hexdigest()] = _GrantRecord(
        grant_id="other-project-grant",
        principal_id="principal-agent",
        host_root=other_root,
        sandbox_root="/workspace/other",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "other-grant",
    )
    other_project_invocation = server.dispatch({
        **resource_sample_request,
        "grant": other_token,
        "request_id": "req_other_project_invoke",
        "cwd": "/workspace/other",
    }, peer_uid=0)
    assert other_project_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 8

    snapshot["authenticated_principal_id"] = "different-principal"
    foreign_invocation = server.dispatch({
        **request,
        "request_id": "req_project_invoke_foreign",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:ambient-projection-coherence"],
    }, peer_uid=0)
    assert foreign_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 8

    foreign = server.dispatch({
        **request,
        "request_id": "req_project_health_foreign",
        "argv": ["complete", "ses_health", "--outcome", "done"],
    }, peer_uid=0)
    assert foreign["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 8

    unsupported = server.dispatch({
        **request,
        "request_id": "req_project_doctor_unavailable",
        "argv": ["doctor", "ses_health"],
    }, peer_uid=0)
    assert unsupported["error"]["code"] == "ENVIRONMENT_OPERATION_UNAVAILABLE"
    assert unsupported["error"]["details"]["status"] == "unknown"
    assert unsupported["error"]["details"]["operation"] == "doctor"
    assert len(calls) == 8


def test_project_rpc_exposes_session_bound_system_observability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    token = "test-environment-grant"
    calls: list[tuple[list[str], dict[str, object]]] = []
    loaded_sessions: list[str] = []

    class Store:
        def load_snapshot(self, session_id: str) -> dict[str, str]:
            loaded_sessions.append(session_id)
            return {"authenticated_principal_id": "principal-agent"}

        def close(self) -> None:
            pass

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"

        def _pkg(self) -> object:
            return object()

        def _store(self, _pkg: object) -> Store:
            return Store()

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            repositories={"environment": "mncs-environment"},
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-observability-grant",
        principal_id="principal-agent",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_selected",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = grant

    def run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout='{"schema":"mncs.system-monitor.observability.v1","status":"ok"}\n',
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    request = {
        "grant": token,
        "request_id": "req_project_system_observability",
        "argv": [
            "invoke", "ses_selected", "mncs-system-monitor:system-observability",
        ],
        "cwd": "/workspace/mncs-environment",
    }
    admitted = server.dispatch(request, peer_uid=0)
    assert admitted["ok"] is True
    assert json.loads(admitted["result"]["stdout"])["status"] == "ok"
    assert calls[0][0][-3:] == request["argv"]
    assert calls[0][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[0][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == request["request_id"]
    assert loaded_sessions == ["ses_selected"]

    wrong_session = server.dispatch({
        **request,
        "request_id": "req_project_system_observability_wrong_session",
        "argv": [
            "invoke", "ses_other", "mncs-system-monitor:system-observability",
        ],
    }, peer_uid=0)
    assert wrong_session["ok"] is False
    assert wrong_session["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 1
    assert loaded_sessions == ["ses_selected"]

    extra_arguments = server.dispatch({
        **request,
        "request_id": "req_project_system_observability_extra_arguments",
        "argv": [
            "invoke", "ses_selected", "mncs-system-monitor:system-observability",
            "--include-process-details",
        ],
    }, peer_uid=0)
    assert extra_arguments["ok"] is False
    assert extra_arguments["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 1
    assert loaded_sessions == ["ses_selected"]


def test_project_rpc_exposes_only_typed_resource_headroom_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    token = "project-resource-headroom"
    calls: list[tuple[list[str], dict[str, object]]] = []

    class Store:
        def load_snapshot(self, session_id: str) -> dict[str, str]:
            assert session_id == "ses_resource"
            return {"authenticated_principal_id": "principal-agent"}

        def close(self) -> None:
            pass

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"

        def _pkg(self) -> object:
            return object()

        def _store(self, _pkg: object) -> Store:
            return Store()

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            repositories={"environment": "mncs-environment"},
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-resource-grant",
        principal_id="principal-agent",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_resource",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = grant

    def run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                '{"schema_version":"mncs.automation.resource-headroom-evaluation/1",'
                '"condition":"unknown"}\n'
            ),
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    invocation_argv = [
        "invoke", "ses_resource",
        "mncs-automation:automation-resource-headroom-evaluation",
        "--input-artifact", "monitor-sample",
        "mncs-system-monitor:system-resource-sample",
        "cap_0123456789abcdef", "system-resource-sample.json", "--",
        "--input-name", "monitor-sample",
        "--measurement-execution", "pending-forge-execution",
        "--measurement-subject-identity", "pending-forge-subject",
        "--intent-identity", "compiler-resource-loop-next",
        "--requested-memory-bytes", "1073741824",
        "--measurement-scale-percent", "125",
        "--minimum-host-headroom-bytes", "268435456",
        "--max-age-ms", "60000",
    ]
    request = {
        "grant": token,
        "request_id": "req_resource_headroom_invoke",
        "argv": invocation_argv,
        "cwd": "/workspace/mncs-environment",
    }
    response = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert json.loads(response["result"]["stdout"])["condition"] == "unknown"
    assert calls[0][0][-len(invocation_argv):] == invocation_argv
    assert calls[0][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[0][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_resource_headroom_invoke"
    assert server.dispatch(request, peer_uid=0) == response
    assert len(calls) == 1

    bad_requests = [
        invocation_argv[:6] + ["cap_invalid"] + invocation_argv[7:],
        invocation_argv[:5] + ["mncs-forge:execution-receipts"] + invocation_argv[6:],
        invocation_argv[:7] + ["../system-resource-sample.json"] + invocation_argv[8:],
        invocation_argv[:-2] + ["--max-age-ms", "86400001"],
        invocation_argv + ["--mncs", "/bin/false"],
    ]
    for index, argv in enumerate(bad_requests):
        rejected = server.dispatch({
            **request,
            "request_id": f"req_resource_headroom_rejected_{index}",
            "argv": argv,
        }, peer_uid=0)
        assert rejected["ok"] is False
    assert len(calls) == 1

    grant.bound_session_id = "ses_other"
    wrong_session = server.dispatch({
        **request,
        "request_id": "req_resource_headroom_wrong_session",
    }, peer_uid=0)
    assert wrong_session["ok"] is False
    assert wrong_session["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 1


def test_store_verify_rpc_is_session_bound_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "store-verify-capability"
    root = tmp_path / "project"
    root.mkdir()
    snapshot = {"authenticated_principal_id": "principal-agent"}

    class Store:
        def load_snapshot(self, session_id: str):
            assert session_id in {"ses_store_verify", "ses_foreign"}
            return snapshot

        def close(self) -> None:
            pass

    class Environment:
        state_dir = tmp_path / "canonical-environment-state"
        environment_path = tmp_path / "environment-source"

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
        grant_id="grant-store-verify-test",
        principal_id="principal-agent",
        host_root=root,
        sandbox_root="/workspace/project",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        stdout = (
            '{"generation":7}\n'
            if argv[-1] == "--generation"
            else '{"generation":7,"objects_verified":43000}\n'
        )
        return SimpleNamespace(
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)

    request = {
        "grant": token,
        "request_id": "req_store_verify_authorized",
        "argv": ["store", "--session", "ses_store_verify", "--verify"],
        "cwd": "/workspace/project",
    }
    response = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert response["result"]["exit_code"] == 0
    assert json.loads(response["result"]["stdout"]) == {
        "generation": 7, "objects_verified": 43000,
    }
    assert len(calls) == 1
    assert calls[0][0][3:7] == [
        "--state-dir", str(Environment.state_dir), "--persistence", "store",
    ]
    assert calls[0][0][-4:] == [
        "store", "--session", "ses_store_verify", "--verify",
    ]
    assert calls[0][1]["cwd"] == root
    assert calls[0][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"
    assert calls[0][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == "req_store_verify_authorized"

    generation_query = server.dispatch({
        **request,
        "request_id": "req_store_generation_authorized",
        "argv": ["store", "--session", "ses_store_verify", "--generation"],
    }, peer_uid=0)
    assert generation_query["ok"] is True
    assert generation_query["result"]["exit_code"] == 0
    assert json.loads(generation_query["result"]["stdout"]) == {
        "generation": 7,
    }
    assert len(calls) == 2
    assert calls[1][0][-4:] == [
        "store", "--session", "ses_store_verify", "--generation",
    ]
    assert calls[1][1]["env"]["MNCS_ENV_RPC_REQUEST_ID"] == (
        "req_store_generation_authorized"
    )

    for index, argv in enumerate((
        ["store"],
        ["store", "--verify"],
        ["store", "--session=ses_store_verify", "--verify"],
        ["store", "--session", "not-a-session", "--verify"],
        ["store", "--session", "ses_store_verify", "--verify", "--write"],
        ["store", "--session", "ses_store_verify", "--generation", "--write"],
        ["store", "--session", "ses_store_verify", "--generation", "--verify"],
        ["store", "--session", "ses_store_verify", "--verify",
         "--state-dir", str(tmp_path / "other-store")],
    )):
        rejected = server.dispatch({
            **request,
            "request_id": f"req_store_verify_rejected_{index}",
            "argv": argv,
        }, peer_uid=0)
        assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 2

    snapshot["authenticated_principal_id"] = "different-principal"
    foreign = server.dispatch({
        **request,
        "request_id": "req_store_verify_foreign_session",
        "argv": ["store", "--session", "ses_foreign", "--verify"],
    }, peer_uid=0)
    assert foreign["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 2

    foreign_generation = server.dispatch({
        **request,
        "request_id": "req_store_generation_foreign_session",
        "argv": ["store", "--session", "ses_foreign", "--generation"],
    }, peer_uid=0)
    assert foreign_generation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 2


def test_retire_rpc_scopes_inventory_and_project_mutation(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    host_root = projects / "mncs-environment"
    host_root.mkdir()
    (host_root / ".git").mkdir()
    compiler_root = projects / "mncs-compiler"
    compiler_root.mkdir()
    (compiler_root / ".git").mkdir()
    non_repository = projects / "not-a-repository"
    non_repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".git").mkdir()
    (projects / "linked-repository").symlink_to(outside, target_is_directory=True)
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=projects,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="grant-retire-test",
        principal_id="principal-test",
        host_root=host_root,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    translated = server._translate_argv(
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run"],
        host_root,
        grant,
    )
    assert translated == ["retire", "ses_test", "--repository", str(host_root),
                          "--inventory", "--dry-run"]

    cross_project = server._translate_argv(
        ["retire", "ses_test", "--repository", "mncs-compiler",
         "--inventory", "--dry-run"],
        host_root,
        grant,
    )
    assert cross_project == [
        "retire", "ses_test", "--repository", str(compiler_root),
        "--inventory", "--dry-run",
    ]
    equals = server._translate_argv(
        ["retire", "ses_test", "--repository=/workspace/mncs-compiler",
         "--inventory", "--dry-run"],
        host_root,
        grant,
    )
    assert equals == [
        "retire", "ses_test", "--repository=" + str(compiler_root),
        "--inventory", "--dry-run",
    ]

    scoped_worktree = server._translate_argv(
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--worktree", "/workspace/mncs-environment/.worktrees/reviewed",
         "--canonical", "origin/main"],
        host_root,
        grant,
    )
    assert scoped_worktree == [
        "retire", "ses_test", "--repository", str(host_root),
        "--worktree", str(host_root / ".worktrees" / "reviewed"),
        "--canonical", "origin/main",
    ]
    scoped_branch = server._translate_argv(
        ["retire", "ses_test", "--repository=mncs-environment",
         "--branch=campaign/finished", "--dry-run"],
        host_root,
        grant,
    )
    assert scoped_branch == [
        "retire", "ses_test", "--repository=" + str(host_root),
        "--branch=campaign/finished", "--dry-run",
    ]

    for argv in (
        ["retire", "ses_test", "--repository", "mncs-compiler",
         "--branch", "campaign/foreign"],
        ["retire", "ses_test", "--repository", "mncs-environment", "--prune"],
        ["retire", "ses_test", "--repository", "mncs-environment",
         "--worktree", "/tmp/foreign-worktree"],
        ["retire", "ses_test", "--repository", "mncs-environment",
         "--worktree", "../outside"],
        ["retire", "ses_test", "--repository", "mncs-environment",
         "--branch", "campaign/finished", "--dry-run=false"],
    ):
        with pytest.raises(ControlError):
            server._translate_argv(argv, host_root, grant)

    workspace_grant = _GrantRecord(
        grant_id="workspace-retire-test", principal_id="principal-test",
        host_root=projects, sandbox_root="/workspace", scope="workspace", uid=0,
        expires_at=time.monotonic() + 60, token_file=tmp_path / "workspace-grant",
    )
    with pytest.raises(ControlError):
        server._translate_argv(
            ["retire", "ses_test", "--repository", "mncs-environment",
             "--branch", "campaign/finished"],
            host_root,
            workspace_grant,
        )

    for argv in (
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment", "--inventory"],
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run", "--execution-root", "/"],
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run", "--sandbox-root", "/workspace"],
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run", "--canonical=refs/heads/private"],
    ):
        with pytest.raises(ControlError):
            server._translate_argv(argv, host_root, grant)

    for repository in (
        "../outside",
        "nested/repository",
        "/home/agent/mncs-compiler",
        "/workspace/../outside",
        "linked-repository",
        "not-a-repository",
        "missing-repository",
    ):
        with pytest.raises(ControlError):
            server._translate_argv(
                ["retire", "ses_test", "--repository", repository,
                 "--inventory", "--dry-run"],
                host_root,
                grant,
            )


def test_retire_rpc_maps_sibling_inventory_to_project_sandbox_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects = tmp_path / "projects"
    host_root = projects / "mncs-control-mcp"
    compiler_root = projects / "mncs-compiler"
    for checkout in (host_root, compiler_root):
        (checkout / ".git").mkdir(parents=True)
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=projects,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(
            state_dir=tmp_path / "state", environment_path=tmp_path / "environment-source",
        ),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="grant-retire-inventory-dispatch-test",
        principal_id="principal-test",
        host_root=host_root,
        sandbox_root="/workspace/mncs-control-mcp",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    monkeypatch.setattr(server, "_grant", lambda _request, _peer: grant)
    monkeypatch.setattr(server, "_authorize_session", lambda *_args: None)
    invocations: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        invocations.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="{}\n", stderr="")

    monkeypatch.setattr(environment_rpc_module.subprocess, "run", run)
    response = server._dispatch_once(
        {
            "cwd": "/workspace/mncs-control-mcp",
            "argv": [
                "retire", "ses_test", "--repository", "mncs-compiler",
                "--inventory", "--dry-run",
            ],
            "request_id": "req_retire_sibling_inventory_dispatch_test",
        },
        peer_uid=grant.uid,
    )

    assert response["ok"] is True
    assert len(invocations) == 1
    argv, kwargs = invocations[0]
    assert kwargs["cwd"] == host_root
    assert argv[argv.index("--repository") + 1] == str(compiler_root)
    assert argv[argv.index("--execution-root") + 1] == str(compiler_root)
    assert argv[argv.index("--sandbox-root") + 1] == "/workspace/mncs-compiler"


def test_retire_rpc_requires_continuation_selected_session_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    host_root = projects / "mncs-environment"
    host_root.mkdir()
    (host_root / ".git").mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=projects,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(
            state_dir=tmp_path / "state", environment_path=tmp_path / "environment-source",
        ),
        policy=object(),
    )
    token = "retire-selection-fence"
    grant = _GrantRecord(
        grant_id="retire-selection-grant", principal_id="principal-test",
        host_root=host_root, sandbox_root="/workspace/mncs-environment",
        scope="project", uid=0, expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = grant
    monkeypatch.setattr(server, "_authorize_session", lambda *_args: None)
    run = mock.Mock(return_value=subprocess.CompletedProcess(
        args=[], returncode=0, stdout="{}\n", stderr="",
    ))
    monkeypatch.setattr(environment_rpc_module.subprocess, "run", run)

    def request(identity: str):
        return server.dispatch({
            "grant": token,
            "request_id": identity,
            "argv": ["retire", "ses_test", "--repository", "mncs-environment",
                     "--branch", "campaign/finished"],
            "cwd": "/workspace/mncs-environment",
        }, peer_uid=0)

    unselected = request("req_retire_unselected")
    assert unselected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert run.call_count == 0

    grant.bound_session_id = "ses_test"
    selected = request("req_retire_selected")
    assert selected["ok"] is True
    assert selected["result"]["exit_code"] == 0
    assert run.call_count == 1
    forwarded = run.call_args.args[0]
    assert "--execution-root" in forwarded
    assert str(host_root) in forwarded
    assert "--sandbox-root" in forwarded
    assert "/workspace/mncs-environment" in forwarded


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


def test_project_entry_maps_workspace_without_campaign_id(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    project = projects / "mncs-environment"
    project.mkdir(parents=True)
    definition = project / "environment.json"
    definition.write_text(
        json.dumps({"workspace_scope": {"repositories": ["mncs-environment"]}}),
        encoding="utf-8",
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=projects,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="project-entry-no-campaign",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    translated = server._translate_argv(
        ["enter", "--definition", "/workspace/mncs-environment/environment.json"],
        project,
        grant,
    )

    assert translated == [
        "enter", "--definition", str(definition), "--workspace", str(projects),
    ]

    definition.write_text(
        json.dumps({"workspace_scope": {"repositories": [
            "mncs-environment", "mncs-compiler",
        ]}}),
        encoding="utf-8",
    )
    with pytest.raises(ControlError) as raised:
        server._translate_argv(
            ["enter", "--definition", "/workspace/mncs-environment/environment.json"],
            project,
            grant,
        )
    assert raised.value.code == "ENVIRONMENT_AUTHORITY_DENIED"


def test_workspace_project_resolution_uses_git_common_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    (project / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(project), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(project), "-c", "user.name=MNCS Test",
         "-c", "user.email=mncs-test@example.invalid", "commit", "--quiet", "-m", "fixture"],
        check=True,
    )
    worktree = project / ".worktrees" / "continuation"
    worktree.parent.mkdir()
    subprocess.run(
        ["git", "-C", str(project), "worktree", "add", "--quiet", "--detach",
         str(worktree), "HEAD"],
        check=True,
    )
    nested_cwd = worktree / "src"
    nested_cwd.mkdir()

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    grant = _GrantRecord(
        grant_id="workspace-project-resolution",
        principal_id="principal-test",
        host_root=workspace,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )

    assert server._project_repository(grant, cwd=nested_cwd) == "mncs-environment"

    outside = tmp_path / "outside"
    outside.mkdir()
    subprocess.run(["git", "init", "--quiet", str(outside)], check=True)
    with pytest.raises(ControlError) as escaped:
        server._project_repository(grant, cwd=outside)
    assert escaped.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"

    nested_repo = project / "nested" / "independent"
    nested_repo.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(nested_repo)], check=True)
    with pytest.raises(ControlError) as nested:
        server._project_repository(grant, cwd=nested_repo)
    assert nested.value.code == "ENVIRONMENT_WORKSPACE_ESCAPE"


def test_workspace_entry_attaches_capsule_after_readiness_block(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    calls: list[tuple[str, str | None]] = []

    def campaign_continuation(repository: str, campaign_id: str | None = None):
        calls.append((repository, campaign_id))
        return {
            "schema_version": "mncs.control.campaign-continuation/1",
            "repository": repository,
            "campaign_id": campaign_id,
            "status": "context-conflict",
            "continuations": [
                {"session_id": "ses_project_context"},
                {"session_id": "ses_workspace_context"},
            ],
        }

    environment = SimpleNamespace(
        state_dir=tmp_path / "environment-state",
        environment_path=tmp_path / "environment-source",
        authenticated_principal_id="principal-test",
        campaign_continuation=campaign_continuation,
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=environment,
        policy=object(),
    )
    token = "workspace-entry-capsule"
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="workspace-entry-capsule-grant",
        principal_id="principal-test",
        host_root=workspace,
        sandbox_root="/workspace",
        scope="workspace",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    grant = server._grants[hashlib.sha256(token.encode()).hexdigest()]
    server._translate_argv = lambda argv, _cwd, _record: argv
    entry_result = {
        "session_id": "ses_project_context",
        "continuation": {"identity": "cmp_workspace_entry"},
        "entry": {"reused": True},
        "readiness": {"status": "blocked"},
    }
    real_run = subprocess.run

    def run_with_blocked_entry(command, *args, **kwargs):
        if isinstance(command, list) and len(command) > 2 and command[1] == "-c":
            return subprocess.CompletedProcess(
                command, 5, stdout=json.dumps(entry_result), stderr="",
            )
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(environment_rpc_module.subprocess, "run", run_with_blocked_entry)
    response = server.dispatch({
        "grant": token,
        "request_id": "req_workspace_entry_capsule",
        "argv": ["enter"],
        "cwd": "/workspace/mncs-environment",
    }, peer_uid=0)

    assert response["ok"] is True
    result = response["result"]
    assert result["exit_code"] == 5
    returned = json.loads(result["stdout"])
    assert returned["readiness"]["status"] == "blocked"
    assert returned["control_project_continuation"]["status"] == "context-conflict"
    assert [item["session_id"] for item in
            returned["control_project_continuation"]["continuations"]] == [
                "ses_project_context", "ses_workspace_context",
            ]
    assert grant.bound_session_id is None
    assert calls == [("mncs-environment", "cmp_workspace_entry")]


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
    grant = server._grants[hashlib.sha256(token.encode()).hexdigest()]
    assert grant.bound_session_id == session_id

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


def test_campaign_task_bind_rpc_selects_one_exact_project_session(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-control-mcp"
    project.mkdir(parents=True)
    calls = []

    class Environment:
        authenticated_principal_id = "principal-test"
        state_dir = tmp_path / "state"

        def bind_task_identity(self, repository, campaign_id, session_id,
                               task_identity, request_id):
            calls.append((repository, campaign_id, session_id, task_identity, request_id))
            return {
                "status": "bound",
                "campaign_id": campaign_id,
                "session_id": session_id,
                "selector_identity": "tsel_fixture",
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
    token = "campaign-task-bind-grant"
    record = _GrantRecord(
        grant_id="campaign-task-bind-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-control-mcp",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = record
    response = server.dispatch({
        "grant": token,
        "request_id": "req_campaign_task_bind_rpc",
        "argv": [
            "campaign-bind",
            "--campaign-id=cmp_task_binding",
            "--session-id", "ses_task_binding",
            "--task-identity", "durable-task-binding-identity",
        ],
        "cwd": "/workspace/mncs-control-mcp",
    }, peer_uid=0)

    assert response["ok"] is True
    assert response["result"]["exit_code"] == 0
    payload = json.loads(response["result"]["stdout"])
    assert payload["status"] == "bound"
    assert record.bound_session_id == "ses_task_binding"
    assert calls == [(
        "mncs-control-mcp",
        "cmp_task_binding",
        "ses_task_binding",
        "durable-task-binding-identity",
        "req_campaign_task_bind_rpc",
    )]

    malformed = server.dispatch({
        "grant": token,
        "request_id": "req_campaign_task_bind_missing_session",
        "argv": [
            "campaign-bind",
            "--campaign-id", "cmp_task_binding",
            "--task-identity", "durable-task-binding-identity",
        ],
        "cwd": "/workspace/mncs-control-mcp",
    }, peer_uid=0)
    assert malformed["error"]["code"] == "ENVIRONMENT_RPC_INVALID_REQUEST"
    assert len(calls) == 1


def test_task_selector_selects_saved_project_context_over_current_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-control-mcp"
    project.mkdir(parents=True)
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    record = _GrantRecord(
        grant_id="task-selector-context-grant",
        principal_id="principal-test",
        host_root=project,
        sandbox_root="/workspace/mncs-control-mcp",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
    )
    monkeypatch.setattr(
        server,
        "_project_environment_identity",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("resolved task selector must take precedence over the current default")
        ),
    )
    capsule = {
        "schema_version": "mncs.control.campaign-continuation/1",
        "repository": "mncs-control-mcp",
        "status": "context-conflict",
        "campaign_id": "cmp_context_precedence",
        "task_selector": {
            "status": "resolved",
            "campaign_id": "cmp_context_precedence",
            "session_id": "ses_saved_context",
            "definition_id": "env_saved_context",
            "workspace_root": str(workspace),
        },
        "continuations_count": 3,
        "continuations_truncated": False,
        "continuations": [
            {
                "session_id": "ses_saved_context",
                "definition_id": "env_saved_context",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
            {
                "session_id": "ses_saved_context_duplicate",
                "definition_id": "env_saved_context",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
            {
                "session_id": "ses_current_default",
                "definition_id": "env_current_default",
                "workspace_root": str(workspace),
                "lifecycle": "active",
                "project_reference": {"status": "linked"},
                "claim_ids": [],
                "claims": [],
            },
        ],
    }

    selected = server._select_project_campaign_context(
        capsule, record, "mncs-control-mcp",
    )
    assert selected["status"] == "ready"
    assert selected["selected_session_id"] == "ses_saved_context"
    assert selected["selection_basis"] == "authenticated-task-selector"
    assert selected["context_conflict_status"] == "context-conflict"
    assert selected["unselected_sessions_count"] == 2

    server.environment_service = SimpleNamespace(
        authenticated_principal_id="principal-test",
        campaign_continuation=lambda *_args: json.loads(json.dumps(capsule)),
    )
    response = server._campaign_continuation(
        record,
        ["continuation", "--task-identity", "stable-task-selector"],
        "req_task_selector_context_route",
        cwd=project,
    )
    assert response["ok"] is True
    projected = json.loads(response["result"]["stdout"])
    assert projected["status"] == "ready"
    assert projected["selected_session_id"] == "ses_saved_context"
    assert projected["selection_basis"] == "authenticated-task-selector"
    assert record.bound_session_id == "ses_saved_context"


@pytest.mark.parametrize(
    "capability",
    [
        "mncs-compiler:compiler-producer",
        "mncs-compiler:compiler-build",
        "mncs-forge:canonical-vm-work",
    ],
)
def test_project_rpc_exposes_recovered_compiler_and_forge_capabilities(
    capability: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-environment"
    project.mkdir(parents=True)
    token = "recovered-compiler-forge-capability"

    class Store:
        def load_snapshot(self, session_id: str) -> dict[str, str]:
            assert session_id == "ses_recovered"
            return {"authenticated_principal_id": "principal-agent"}

        def close(self) -> None:
            pass

    class Environment:
        state_dir = tmp_path / "state"
        environment_path = tmp_path / "environment"

        def _pkg(self) -> object:
            return object()

        def _store(self, _pkg: object) -> Store:
            return Store()

    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            repositories={"environment": "mncs-environment"},
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=Environment(),
        policy=object(),
    )
    project_grant = _GrantRecord(
        grant_id="recovered-project-grant",
        principal_id="principal-agent",
        host_root=project,
        sandbox_root="/workspace/mncs-environment",
        scope="project",
        uid=0,
        expires_at=time.monotonic() + 60,
        token_file=tmp_path / "grant",
        bound_session_id="ses_recovered",
    )
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = project_grant
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"status":"ok"}\n', stderr="")

    monkeypatch.setattr("mncs_control_mcp.environment_rpc.subprocess.run", run)
    request = {
        "grant": token,
        "request_id": "req_recovered_capability_" + capability.split(":", 1)[0],
        "argv": ["invoke", "ses_recovered", capability],
        "cwd": "/workspace/mncs-environment",
    }

    response = server.dispatch(request, peer_uid=0)

    assert response["ok"] is True
    assert json.loads(response["result"]["stdout"]) == {"status": "ok"}
    assert calls[0][0][-3:] == ["invoke", "ses_recovered", capability]
    assert calls[0][1]["env"]["MNCS_ENV_AUTH_PRINCIPAL_ID"] == "principal-agent"

    unsupported = server.dispatch({
        **request,
        "request_id": "req_unapproved_language_compile",
        "argv": ["invoke", "ses_recovered", "mncs-language:compile"],
    }, peer_uid=0)
    assert unsupported["ok"] is False
    assert unsupported["error"]["code"] == "ENVIRONMENT_OPERATION_UNAVAILABLE"
    assert len(calls) == 1

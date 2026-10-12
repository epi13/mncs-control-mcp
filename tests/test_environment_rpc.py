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

import pytest

from mncs_control_mcp import environment_rpc as environment_rpc_module
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import (
    MAX_ARGUMENT_BYTES,
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
                "path": f"tests/{'x' * 80}_evidence_{index:02d}.json",
                "sha256": f"{index + 1:064x}",
            }
            for index in range(64)
        ],
        separators=(",", ":"),
    )
    assert 8192 < len(evidence.encode("utf-8")) <= MAX_ARGUMENT_BYTES

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
    server._grants[hashlib.sha256(token.encode()).hexdigest()] = _GrantRecord(
        grant_id="project-health-grant",
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
            '{"providers":[{"provider_id":"forge","status":"unknown"}]}\n'
            if "capabilities" in argv else
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

    # A retry with the same stable identity returns the admitted result and
    # does not invoke the capability twice within one Control process.
    replay = server.dispatch(invocation_request, peer_uid=0)
    assert replay == invocation
    assert len(calls) == 5

    unsupported = server.dispatch({
        **request,
        "request_id": "req_project_unknown_capability",
        "argv": ["invoke", "ses_health", "mncs-language:compile"],
    }, peer_uid=0)
    assert unsupported["error"]["code"] == "ENVIRONMENT_OPERATION_UNAVAILABLE"
    assert unsupported["error"]["details"]["status"] == "unknown"
    assert len(calls) == 5

    unbounded_invocation = server.dispatch({
        **request,
        "request_id": "req_project_projection_invoke_args",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:ambient-projection-coherence",
                 "--cwd", "/workspace/project"],
    }, peer_uid=0)
    assert unbounded_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 5

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
        **invocation_request,
        "grant": other_token,
        "request_id": "req_other_project_invoke",
        "cwd": "/workspace/other",
    }, peer_uid=0)
    assert other_project_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 5

    snapshot["authenticated_principal_id"] = "different-principal"
    foreign_invocation = server.dispatch({
        **request,
        "request_id": "req_project_invoke_foreign",
        "argv": ["invoke", "ses_health",
                 "mncs-environment:ambient-projection-coherence"],
    }, peer_uid=0)
    assert foreign_invocation["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 5

    foreign = server.dispatch({
        **request,
        "request_id": "req_project_health_foreign",
        "argv": ["complete", "ses_health", "--outcome", "done"],
    }, peer_uid=0)
    assert foreign["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 5

    unsupported = server.dispatch({
        **request,
        "request_id": "req_project_doctor_unavailable",
        "argv": ["doctor", "ses_health"],
    }, peer_uid=0)
    assert unsupported["error"]["code"] == "ENVIRONMENT_OPERATION_UNAVAILABLE"
    assert unsupported["error"]["details"]["status"] == "unknown"
    assert unsupported["error"]["details"]["operation"] == "doctor"
    assert len(calls) == 5


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
        return SimpleNamespace(
            returncode=0,
            stdout='{"generation":7,"objects_verified":43000}\n',
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

    for index, argv in enumerate((
        ["store"],
        ["store", "--verify"],
        ["store", "--session=ses_store_verify", "--verify"],
        ["store", "--session", "not-a-session", "--verify"],
        ["store", "--session", "ses_store_verify", "--verify", "--write"],
        ["store", "--session", "ses_store_verify", "--verify",
         "--state-dir", str(tmp_path / "other-store")],
    )):
        rejected = server.dispatch({
            **request,
            "request_id": f"req_store_verify_rejected_{index}",
            "argv": argv,
        }, peer_uid=0)
        assert rejected["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 1

    snapshot["authenticated_principal_id"] = "different-principal"
    foreign = server.dispatch({
        **request,
        "request_id": "req_store_verify_foreign_session",
        "argv": ["store", "--session", "ses_foreign", "--verify"],
    }, peer_uid=0)
    assert foreign["error"]["code"] == "ENVIRONMENT_AUTHORITY_DENIED"
    assert len(calls) == 1


def test_retire_rpc_exposes_only_scoped_read_only_inventory(tmp_path: Path) -> None:
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
        sandbox_root="/workspace/project",
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

    for argv in (
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment", "--inventory"],
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run", "--branch", "main"],
        ["retire", "ses_test", "--repository", "/workspace/mncs-environment",
         "--inventory", "--dry-run", "--execution-root", "/"],
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

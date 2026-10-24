from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import mncs_control_mcp.local_environment_mcp as local_environment_mcp
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_rpc import EnvironmentRPCServer
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.local_environment_mcp import (
    MAX_TOOL_RESULT_BYTES,
    LocalEnvironmentMCP,
    _build_argv,
    _ProjectContext,
    _rpc,
)


def test_stable_tool_maps_only_named_environment_operations() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler/.worktrees/run")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "checkpoint",
        {"progress": "verified", "remaining": ["push"], "session_id": "ses_selected"},
        context, "mncs-compiler",
    )
    assert selected is True
    assert argv == [
        "checkpoint", "ses_selected", "--progress", "verified", "--remaining", "push",
    ]

    argv, selected = _build_argv(
        "complete",
        {"retry_pending": True, "session_id": "ses_selected"},
        context, "mncs-compiler",
    )
    assert selected is True
    assert argv == ["complete", "ses_selected", "--retry-pending"]

    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "enter", {"argv": ["terminal_exec", "rm -rf"]}, context,
            "mncs-compiler",
        )


def test_environmental_capability_maps_to_one_bounded_read_projection() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-environment")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "environmental_capability",
        {
            "session_id": "ses_selected",
            "history_pages": 4,
            "evidence_offset": 16,
            "evidence_limit": 8,
        },
        context,
        "mncs-environment",
    )

    assert selected is True
    assert argv == [
        "projections", "ses_selected", "--interpret", "environmental-capability",
        "--history-pages", "4", "--evidence-limit", "8",
        "--evidence-offset", "16",
    ]

    default_argv, _selected = _build_argv(
        "environmental_capability", {"session_id": "ses_selected"},
        context, "mncs-environment",
    )
    assert default_argv == [
        "projections", "ses_selected", "--interpret", "environmental-capability",
        "--history-pages", "1", "--evidence-limit", "32",
    ]

    with pytest.raises(ValueError, match="history_pages"):
        _build_argv(
            "environmental_capability",
            {"session_id": "ses_selected", "history_pages": 5},
            context,
            "mncs-environment",
        )
    with pytest.raises(ValueError, match="evidence_limit"):
        _build_argv(
            "environmental_capability",
            {"session_id": "ses_selected", "evidence_limit": 33},
            context,
            "mncs-environment",
        )
    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "environmental_capability",
            {"session_id": "ses_selected", "apply": "unbounded"},
            context,
            "mncs-environment",
        )


def test_scope_grant_maps_only_the_owner_checked_scope_admission_contract() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    context.selected_session_id = "ses_selected"
    revision = "a" * 64

    argv, selected = _build_argv(
        "scope_grant",
        {
            "campaign_id": "cmp_selected",
            "repository": "mncs-environment",
            "expected_authority_revision": revision,
            "approval_reference": "user-authorization:environment-integration",
        },
        context,
        "mncs-compiler",
    )

    assert selected is True
    assert argv == [
        "scope-grant", "ses_selected",
        "--campaign-id", "cmp_selected",
        "--repository", "mncs-environment",
        "--expected-authority-revision", revision,
        "--approval-reference", "user-authorization:environment-integration",
    ]

    checkout_argv, _selected = _build_argv(
        "scope_grant",
        {
            "campaign_id": "cmp_selected",
            "repository": "mncs-environment",
            "expected_authority_revision": revision,
            "approval_reference": "user-authorization:environment-integration",
            "checkout_path": ".worktrees/compiler/mncs-environment",
        },
        context,
        "mncs-compiler",
    )
    assert checkout_argv[-2:] == [
        "--checkout", ".worktrees/compiler/mncs-environment",
    ]

    workspace_checkout_argv, _selected = _build_argv(
        "scope_grant",
        {
            "campaign_id": "cmp_selected",
            "repository": "mncs-vm",
            "expected_authority_revision": revision,
            "approval_reference": "user-authorization:compiler-vm-runtime",
            "workspace_checkout": (
                "mncs-compiler/.worktrees/native-app-readiness/mncs-vm"
            ),
        },
        context,
        "mncs-compiler",
    )
    assert workspace_checkout_argv[-2:] == [
        "--workspace-checkout",
        "mncs-compiler/.worktrees/native-app-readiness/mncs-vm",
    ]

    with pytest.raises(ValueError, match="only one"):
        _build_argv(
            "scope_grant",
            {
                "campaign_id": "cmp_selected",
                "repository": "mncs-vm",
                "expected_authority_revision": revision,
                "approval_reference": "user-authorization:compiler-vm-runtime",
                "checkout_path": ".worktrees/vm",
                "workspace_checkout": "mncs-compiler/.worktrees/vm",
            },
            context,
            "mncs-compiler",
        )

    with pytest.raises(ValueError, match="revision"):
        _build_argv(
            "scope_grant",
            {"campaign_id": "cmp_selected", "repository": "mncs-environment",
             "expected_authority_revision": "stale",
             "approval_reference": "user-authorization:environment-integration"},
            context,
            "mncs-compiler",
        )

    with pytest.raises(ValueError, match="inside the configured repository"):
        _build_argv(
            "scope_grant",
            {
                "campaign_id": "cmp_selected",
                "repository": "mncs-environment",
                "expected_authority_revision": revision,
                "approval_reference": "user-authorization:environment-integration",
                "checkout_path": "../outside",
            },
            context,
            "mncs-compiler",
        )

    with pytest.raises(ValueError, match="inside the configured workspace"):
        _build_argv(
            "scope_grant",
            {
                "campaign_id": "cmp_selected",
                "repository": "mncs-vm",
                "expected_authority_revision": revision,
                "approval_reference": "user-authorization:compiler-vm-runtime",
                "workspace_checkout": "mncs-compiler/../outside",
            },
            context,
            "mncs-compiler",
        )


def test_scope_grant_bridge_preserves_the_campaign_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = LocalEnvironmentMCP()
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    bridge._contexts[("mncs-compiler", "")] = context
    captured: list[dict] = []

    def select_session(selected_context, _project, values, _cwd=""):
        assert values["campaign_id"] == "cmp_selected"
        selected_context.selected_session_id = "ses_selected"
        return None

    monkeypatch.setattr(bridge, "_context", lambda _project, _cwd: context)
    monkeypatch.setattr(bridge, "_select_session", select_session)
    monkeypatch.setattr(
        local_environment_mcp,
        "_rpc",
        lambda _socket, request: captured.append(request) or {
            "ok": True,
            "result": {"exit_code": 0, "stdout": "{}", "stderr": ""},
        },
    )

    response = bridge.invoke(
        "mncs-compiler",
        "scope_grant",
        {
            "campaign_id": "cmp_selected",
            "repository": "mncs-environment",
            "expected_authority_revision": "a" * 64,
            "approval_reference": "user-authorization:environment-integration",
            "checkout_path": ".worktrees/compiler/mncs-environment",
        },
    )

    assert response["ok"] is True
    assert captured[0]["argv"][2:4] == ["--campaign-id", "cmp_selected"]
    assert captured[0]["argv"][-2:] == [
        "--checkout", ".worktrees/compiler/mncs-environment",
    ]

    workspace_response = bridge.invoke(
        "mncs-compiler",
        "scope_grant",
        {
            "campaign_id": "cmp_selected",
            "repository": "mncs-vm",
            "expected_authority_revision": "a" * 64,
            "approval_reference": "user-authorization:compiler-vm-runtime",
            "workspace_checkout": "mncs-compiler/.worktrees/native-app/vm",
        },
    )
    assert workspace_response["ok"] is True
    assert captured[1]["argv"][-2:] == [
        "--workspace-checkout", "mncs-compiler/.worktrees/native-app/vm",
    ]


def test_resume_revalidates_the_selected_session() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler/.worktrees/run")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "resume", {"session_id": "ses_selected"}, context, "mncs-compiler",
    )

    assert selected is True
    assert argv == ["resume", "ses_selected", "--revalidate"]


def test_verify_maps_a_project_capability_to_its_fixed_invocation() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler/.worktrees/run")
    context.selected_session_id = "ses_selected"
    capability = "mncs-compiler:verification-executor/mncs-compiler.frontend-differential"

    argv, selected = _build_argv(
        "verify",
        {"session_id": "ses_selected", "capability": capability},
        context,
        "mncs-compiler",
    )

    assert selected is True
    assert argv == ["invoke", "ses_selected", capability]

    language_context = _ProjectContext(
        "secret", "/workspace/mncs-compiler/.worktrees/run/mncs-language",
    )
    language_context.selected_session_id = "ses_selected"
    language_test = "mncs-language:test/language-tests-mncs-model"
    argv, selected = _build_argv(
        "verify",
        {"session_id": "ses_selected", "capability": language_test},
        language_context,
        "mncs-language",
    )
    assert selected is True
    assert argv == ["invoke", "ses_selected", language_test]


def test_verify_rejects_other_projects_and_caller_supplied_arguments() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    context.selected_session_id = "ses_selected"
    with pytest.raises(ValueError, match="selected project"):
        _build_argv(
            "verify", {"session_id": "ses_selected", "capability": "../../shell"},
            context, "mncs-compiler",
        )
    with pytest.raises(ValueError, match="selected project"):
        _build_argv(
            "verify",
            {"session_id": "ses_selected",
             "capability": "mncs-language:test/language-tests-mncs-model"},
            context, "mncs-compiler",
        )
    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "verify",
            {"session_id": "ses_selected",
             "capability": "mncs-compiler:verification-executor/test",
             "argv": ["rm", "-rf"]},
            context, "mncs-compiler",
        )


def test_claim_release_mapping_is_explicit_and_bounded() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    context.selected_session_id = "ses_selected"
    argv, selected = _build_argv(
        "claims",
        {"mode": "release", "claim_id": "claim:mncs-language:worktree:123"}, context,
        "mncs-compiler",
    )
    assert selected is True
    assert argv == [
        "claims", "ses_selected", "--release", "mncs-language",
        "--claim-id", "claim:mncs-language:worktree:123",
    ]

    # Older noncanonical claim IDs use the selected project as their target;
    # an explicit repository can identify them when the caller has one.
    legacy, _ = _build_argv(
        "claims", {"mode": "release", "claim_id": "claim_123"}, context,
        "mncs-compiler",
    )
    assert legacy == [
        "claims", "ses_selected", "--release", "mncs-compiler",
        "--claim-id", "claim_123",
    ]
    explicit, _ = _build_argv(
        "claims",
        {"mode": "release", "claim_id": "claim_123", "repository": "mncs-language"},
        context,
        "mncs-compiler",
    )
    assert explicit == [
        "claims", "ses_selected", "--release", "mncs-language",
        "--claim-id", "claim_123",
    ]

    with pytest.raises(ValueError, match="unsupported arguments"):
        _build_argv(
            "claims",
            {"mode": "acquire", "repository": "mncs-compiler", "argv": ["raw"]},
            context, "mncs-compiler",
        )

    with pytest.raises(ValueError, match="supported only when acquiring a claim"):
        _build_argv(
            "claims",
            {"mode": "release", "claim_id": "claim_123",
             "expected_store_generation": 17},
            context, "mncs-compiler",
        )

    with pytest.raises(ValueError, match="valid repository identifier"):
        _build_argv(
            "claims",
            {"mode": "release", "claim_id": "claim_123", "repository": "../mncs-language"},
            context, "mncs-compiler",
        )


def test_claim_targets_forward_to_authenticated_selected_session() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-environment/.worktrees/gatec")
    context.selected_session_id = "ses_selected"
    argv, selected = _build_argv(
        "claims",
        {"mode": "acquire", "repository": "mncs-compiler", "reason": "Gate C",
         "basis": "explicit-claim"},
        context,
        "mncs-environment",
    )
    assert selected is True
    assert argv == [
        "claims", "ses_selected", "--acquire", "mncs-compiler",
        "--reason", "Gate C", "--basis", "explicit-claim",
    ]

    compiler_argv, compiler_selected = _build_argv(
        "claims",
        {"mode": "acquire", "repository": "mncs-language", "reason": "Language fact implementation",
         "basis": "intent-scope"},
        context,
        "mncs-compiler",
    )
    assert compiler_selected is True
    assert compiler_argv == [
        "claims", "ses_selected", "--acquire", "mncs-language",
        "--reason", "Language fact implementation", "--basis", "intent-scope",
    ]

    fenced_argv, fenced_selected = _build_argv(
        "claims",
        {"mode": "acquire", "repository": "mncs-compiler",
         "expected_store_generation": 61},
        context,
        "mncs-environment",
    )
    assert fenced_selected is True
    assert fenced_argv == [
        "claims", "ses_selected", "--acquire", "mncs-compiler",
        "--expected-store-generation", "61",
    ]

    with pytest.raises(ValueError, match="valid repository identifier"):
        _build_argv(
            "claims",
            {"mode": "acquire", "repository": "../mncs-forge"},
            context,
            "mncs-environment",
        )


def test_claim_target_accepts_canonical_absolute_checkout_inside_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "Projects"
    checkout = workspace / "mncs-compiler" / ".worktrees" / "main"
    checkout.mkdir(parents=True)
    monkeypatch.setattr(
        local_environment_mcp,
        "load_config",
        lambda: SimpleNamespace(workspace_root=workspace),
    )
    context = _ProjectContext("secret", "/workspace/mncs-compiler/.worktrees/campaign")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "claims",
        {
            "mode": "acquire",
            "repository": "mncs-compiler",
            "worktree": str(checkout),
            "branch": "main",
        },
        context,
        "mncs-compiler",
    )

    assert selected is True
    assert argv[-4:] == [
        "--worktree", "/workspace/mncs-compiler/.worktrees/main", "--branch", "main",
    ]


def test_claim_target_maps_an_absolute_checkout_from_another_project_by_workspace_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "Projects"
    language_project = workspace / "mncs-language"
    language_project.mkdir(parents=True)
    checkout = (
        workspace / "mncs-compiler" / ".worktrees" / "native-app"
        / "mncs-language" / ".worktrees" / "verified-facts"
    )
    checkout.mkdir(parents=True)
    monkeypatch.setattr(
        local_environment_mcp,
        "load_config",
        lambda: SimpleNamespace(workspace_root=workspace),
    )
    context = _ProjectContext("secret", "/workspace/mncs-language")
    context.selected_session_id = "ses_selected"

    argv, selected = _build_argv(
        "claims",
        {
            "mode": "acquire",
            "repository": "mncs-language",
            "worktree": str(checkout),
            "branch": "campaign/language-verified-fact-reuse",
        },
        context,
        "mncs-language",
    )

    assert selected is True
    assert argv[-4:] == [
        "--worktree",
        "/workspace/mncs-compiler/.worktrees/native-app/mncs-language/.worktrees/verified-facts",
        "--branch",
        "campaign/language-verified-fact-reuse",
    ]


def test_claim_target_rejects_absolute_escape_and_symlinked_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "Projects"
    workspace.mkdir()
    (workspace / "mncs-compiler").mkdir()
    outside_workspace = tmp_path / "outside-projects"
    outside_workspace.mkdir(parents=True)
    outside = outside_workspace / ".worktrees" / "feature"
    outside.mkdir(parents=True)
    link = workspace / "escape"
    link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        local_environment_mcp,
        "load_config",
        lambda: SimpleNamespace(workspace_root=workspace),
    )
    context = _ProjectContext("secret", "/workspace/mncs-compiler")
    context.selected_session_id = "ses_selected"

    for target, message in (
        (outside, "authorized workspace"),
        (link, "symbolic link"),
    ):
        with pytest.raises(ValueError, match=message):
            _build_argv(
                "claims",
                {"mode": "acquire", "repository": "mncs-compiler",
                 "worktree": str(target), "branch": "main"},
                context,
                "mncs-compiler",
            )


def test_native_application_invocations_map_to_fixed_typed_contracts() -> None:
    context = _ProjectContext("secret", "/workspace/mncs-environment/.worktrees/gatec")
    context.selected_session_id = "ses_selected"
    build, selected = _build_argv(
        "invoke",
        {
            "capability": "mncs-compiler:native-application-build",
            "request_file": "build/gatec/request.json",
        },
        context,
        "mncs-environment",
    )
    assert selected is True
    assert build == [
        "invoke", "ses_selected", "mncs-compiler:native-application-build",
        "--", "--request-file", "build/gatec/request.json",
    ]

    execution, selected = _build_argv(
        "invoke",
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {
                "name": "native-application-build",
                "capability": "mncs-compiler:native-application-build",
                "binding_id": "cap_0123456789abcdef",
                "path": "native-application-build.json",
            },
            "call": {"arguments": [{
                "record": {
                    "type_identity": (
                        "mncs:0.2:record-type:tests.native_readiness::ReadinessRequest::"
                        "case_index%3Au64%3Bexpected_tests%3Au64%3Bseed%3Au64%3B"
                    ),
                    "name": "ReadinessRequest",
                    "fields": [
                        ["case_index", {"integer": {"type": {"bits": 64, "signed": False}, "value": 7}}],
                        ["expected_tests", {"integer": {"type": {"bits": 64, "signed": False}, "value": 4}}],
                        ["seed", {"integer": {"type": {"bits": 64, "signed": False}, "value": 42}}],
                    ],
                },
            }]},
        },
        context,
        "mncs-environment",
    )
    assert selected is True
    assert execution[:9] == [
        "invoke", "ses_selected", "mncs-forge:native-application-execution",
        "--input-artifact", "native-application-build",
        "mncs-compiler:native-application-build", "cap_0123456789abcdef",
        "native-application-build.json", "--",
    ]
    assert execution[9] == "--call-json"
    forwarded_call = {"arguments": [{
        "record": {
            "type_identity": (
                "mncs:0.2:record-type:tests.native_readiness::ReadinessRequest::"
                "case_index%3Au64%3Bexpected_tests%3Au64%3Bseed%3Au64%3B"
            ),
            "name": "ReadinessRequest",
            "fields": [
                ["case_index", {"integer": {"type": {"bits": 64, "signed": False}, "value": 7}}],
                ["expected_tests", {"integer": {"type": {"bits": 64, "signed": False}, "value": 4}}],
                ["seed", {"integer": {"type": {"bits": 64, "signed": False}, "value": 42}}],
            ],
        },
    }]}
    assert json.loads(execution[10]) == forwarded_call

    structured_provider = {
        "schema_version": "mncs.forge.structured-file-capability/1",
        "capability_identity": (
            "mncs:0.2:capability:mncs.test.digest::digest_app::test_artifact"
        ),
        "input_schema": "mncs.test.digest-request/1",
        "input_value": {"record": {"name": "DigestRequest", "fields": []}},
        "output_schema": "mncs.test.digest/1",
    }
    provider_execution, selected = _build_argv(
        "invoke",
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {
                "name": "native-application-build",
                "capability": "mncs-compiler:native-application-build",
                "binding_id": "cap_0123456789abcdef",
                "path": "native-application-build.json",
            },
            "call": {
                **forwarded_call,
                "capability_providers": [structured_provider],
            },
        },
        context,
        "mncs-environment",
    )
    assert selected is True
    assert json.loads(provider_execution[10]) == {
        **forwarded_call,
        "capability_providers": [structured_provider],
    }

    for arguments in (
        {"capability": "mncs-compiler:compiler-build", "request_file": "request.json"},
        {"capability": "mncs-compiler:native-application-build", "request_file": "../request.json"},
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {"name": "arbitrary", "capability": "x", "binding_id": "bad", "path": "x"},
            "call": {"arguments": {}},
        },
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {
                "name": "native-application-build",
                "capability": "mncs-compiler:native-application-build",
                "binding_id": "cap_0123456789abcdef",
                "path": "native-application-build.json",
            },
            "call": {"arguments": {}, "callable": "arbitrary"},
        },
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {
                "name": "native-application-build",
                "capability": "mncs-compiler:native-application-build",
                "binding_id": "cap_0123456789abcdef",
                "path": "native-application-build.json",
            },
            "call": {"arguments": [], "capability_providers": [
                structured_provider, structured_provider,
            ]},
        },
        {
            "capability": "mncs-forge:native-application-execution",
            "input_artifact": {
                "name": "native-application-build",
                "capability": "mncs-compiler:native-application-build",
                "binding_id": "cap_0123456789abcdef",
                "path": "native-application-build.json",
            },
            "call": {"arguments": [], "capability_providers": [{
                **structured_provider, "schema_version": "mncs.forge.structured-file-capability/0",
            }]},
        },
    ):
        with pytest.raises(ValueError):
            _build_argv("invoke", arguments, context, "mncs-environment")


def test_campaign_continuation_trusts_only_control_selected_session() -> None:
    assert LocalEnvironmentMCP._selected_session({
        "status": "ready",
        "selected_session_id": "ses_selected",
    }) == "ses_selected"
    assert LocalEnvironmentMCP._selected_session({
        "status": "ready",
        "continuations": [{"campaign_session_ids": ["ses_selected"]}],
    }) is None
    assert LocalEnvironmentMCP._selected_session({
        "status": "ready",
        "continuations": [{"campaign_session_ids": ["ses_one", "ses_two"]}],
    }) is None


def test_continuation_response_omits_large_workspace_inventory() -> None:
    payload = {
        "status": "ready",
        "repository": "mncs-compiler",
        "selected_session_id": "ses_selected",
        "continuations": [{
            "campaign_id": "cmp_compiler",
            "campaign_session_ids": ["ses_selected"],
            "latest_checkpoint": {"identity": "chk_latest", "progress": "verified"},
            "live_repository_observation": {
                "worktree_registrations": [{"path": f"/tmp/worktree-{index}"}
                                            for index in range(1000)],
            },
        }],
    }
    response = LocalEnvironmentMCP._present("continuation", {
        "ok": True,
        "result": {"exit_code": 0, "stdout": json.dumps(payload), "stderr": ""},
    })
    encoded = json.dumps(response).encode("utf-8")
    assert len(encoded) < MAX_TOOL_RESULT_BYTES
    assert response["result"]["selected_session_id"] == "ses_selected"
    assert "live_repository_observation" not in response["result"]["continuations"][0]


def test_artifact_read_result_fits_the_bounded_tool_response() -> None:
    artifact = base64.b64encode(b"x" * 55_747).decode("ascii")
    payload = {
        "schema_version": "mncs.environment.artifact-read/1",
        "session_id": "ses_selected",
        "capability": "mncs-forge:native-application-execution",
        "binding_id": "cap_07ea8bcfb58ff902",
        "store_reference": "mncs-store:ses_selected:capability-invocation-artifacts:result",
        "path": "native-application-execution.json",
        "byte_count": 55_747,
        "sha256": "a" * 64,
        "content_base64": artifact,
    }
    response = LocalEnvironmentMCP._present("artifact_read", {
        "ok": True,
        "result": {"exit_code": 0, "stdout": json.dumps(payload), "stderr": ""},
    })

    assert response["ok"] is True
    assert response["result"]["byte_count"] == 55_747
    assert response["result"]["content_base64"] == artifact
    assert len(json.dumps(response).encode("utf-8")) < MAX_TOOL_RESULT_BYTES


def test_project_context_reuses_one_selected_worktree_when_cwd_is_omitted(
    tmp_path: Path,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    selected = _ProjectContext(
        "secret", "/workspace/mncs-compiler/.worktrees/selected",
        selected_session_id="ses_selected",
    )
    bridge._contexts = {("mncs-compiler", ".worktrees/selected"): selected}
    bridge.socket_path = tmp_path / "unused.sock"

    assert bridge._context("mncs-compiler", "") is selected


def test_expired_context_refresh_preserves_omitted_worktree_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    bridge.socket_path = tmp_path / "unused.sock"
    selected = _ProjectContext(
        "expired", "/workspace/mncs-compiler/.worktrees/selected",
        selected_session_id="ses_selected", expires_at=0,
    )
    bridge._contexts = {("mncs-compiler", ".worktrees/selected"): selected}
    requests: list[dict[str, object]] = []

    def fake_rpc(_socket_path: Path, request: dict[str, object]) -> dict[str, object]:
        requests.append(request)
        return {"ok": True, "result": {
            "grant": "n" * 40,
            "sandbox_cwd": "/workspace/mncs-compiler/.worktrees/selected",
            "expires_in_seconds": 315,
        }}

    monkeypatch.setattr(local_environment_mcp, "_rpc", fake_rpc)
    refreshed = bridge._context("mncs-compiler", "")

    assert refreshed is selected
    assert requests == [{
        "action": "local-project-grant",
        "project": "mncs-compiler",
        "cwd": ".worktrees/selected",
    }]
    assert refreshed.grant == "n" * 40
    assert refreshed.sandbox_cwd == "/workspace/mncs-compiler/.worktrees/selected"
    assert refreshed.selected_session_id == "ses_selected"
    assert refreshed.expires_at is not None and refreshed.expires_at > 0


def test_project_context_requires_cwd_when_multiple_contexts_exist(
    tmp_path: Path,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    bridge._contexts = {
        ("mncs-compiler", "."): _ProjectContext("root", "/workspace/mncs-compiler"),
        ("mncs-compiler", ".worktrees/selected"): _ProjectContext(
            "worktree", "/workspace/mncs-compiler/.worktrees/selected",
        ),
    }
    bridge.socket_path = tmp_path / "unused.sock"

    with pytest.raises(ValueError, match="cwd is required"):
        bridge._context("mncs-compiler", "")


def test_session_operation_reselects_through_campaign_on_a_fresh_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    bridge.socket_path = tmp_path / "unused.sock"
    context = _ProjectContext("grant", "/workspace/mncs-compiler")
    bridge._contexts = {}
    monkeypatch.setattr(bridge, "_context", lambda _project, _cwd: context)
    requests: list[dict[str, object]] = []
    replies = [
        {"status": "ready", "selected_session_id": "ses_selected"},
        {"session_id": "ses_selected", "lifecycle": "active"},
    ]

    def fake_rpc(_socket_path: Path, request: dict[str, object]) -> dict[str, object]:
        requests.append(request)
        return {"ok": True, "result": {
            "stdout": json.dumps(replies.pop(0)), "stderr": "", "exit_code": 0,
        }}

    monkeypatch.setattr(local_environment_mcp, "_rpc", fake_rpc)
    response = bridge.invoke(
        "mncs-compiler", "context", {"campaign_id": "cmp_current"},
    )

    assert response["ok"] is True
    assert response["result"]["session_id"] == "ses_selected"
    assert requests[0]["argv"] == ["continuation", "--campaign-id", "cmp_current"]
    assert requests[1]["argv"] == ["context", "ses_selected"]


def test_campaign_selection_refreshes_a_stale_local_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    bridge.socket_path = tmp_path / "unused.sock"
    context = _ProjectContext(
        "stale-grant", "/workspace/mncs-compiler/.worktrees/selected",
        expires_at=10**12,
    )
    bridge._contexts = {("mncs-compiler", ".worktrees/selected"): context}
    requests: list[dict[str, object]] = []

    def fake_rpc(_socket_path: Path, request: dict[str, object]) -> dict[str, object]:
        requests.append(dict(request))
        if request.get("action") == "local-project-grant":
            assert request == {
                "action": "local-project-grant",
                "project": "mncs-compiler",
                "cwd": ".worktrees/selected",
            }
            return {"ok": True, "result": {
                "grant": "f" * 40,
                "sandbox_cwd": "/workspace/mncs-compiler/.worktrees/selected",
                "expires_in_seconds": 315,
            }}
        if request.get("grant") == "stale-grant":
            return {"ok": False, "error": {
                "code": "ENVIRONMENT_AUTHORITY_DENIED",
                "message": "Environment capability is expired or unknown",
            }}
        argv = request.get("argv")
        if isinstance(argv, list) and argv[0] == "continuation":
            return {"ok": True, "result": {
                "stdout": json.dumps({"status": "ready", "selected_session_id": "ses_selected"}),
                "stderr": "", "exit_code": 0,
            }}
        if isinstance(argv, list) and argv[0] == "resume":
            return {"ok": True, "result": {
                "stdout": json.dumps({"session_id": "ses_selected", "lifecycle": "active"}),
                "stderr": "", "exit_code": 0,
            }}
        raise AssertionError(f"unexpected Environment RPC request: {request}")

    monkeypatch.setattr(local_environment_mcp, "_rpc", fake_rpc)
    response = bridge.invoke(
        "mncs-compiler", "resume",
        {"task_identity": "mncs_native_application_readiness_gate_c_20261014"},
        cwd=".worktrees/selected",
    )

    assert response["ok"] is True
    assert response["result"]["session_id"] == "ses_selected"
    assert [request.get("action") for request in requests] == [
        None, "local-project-grant", None, None,
    ]
    assert requests[0]["argv"] == [
        "continuation", "--task-identity",
        "mncs_native_application_readiness_gate_c_20261014",
    ]
    assert requests[2]["grant"] == "f" * 40
    assert requests[2]["argv"] == requests[0]["argv"]
    assert requests[3]["grant"] == "f" * 40
    assert requests[3]["argv"] == ["resume", "ses_selected", "--revalidate"]


def test_campaign_and_task_identity_jointly_reselect_exact_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    bridge.socket_path = Path("unused.sock")
    context = _ProjectContext(
        "authenticated-grant", "/workspace/mncs-compiler/.worktrees/selected",
    )
    bridge._contexts = {("mncs-compiler", ".worktrees/selected"): context}
    requests: list[dict[str, object]] = []

    def fake_rpc(_socket_path: Path, request: dict[str, object]) -> dict[str, object]:
        requests.append(dict(request))
        argv = request.get("argv")
        if argv == [
            "continuation", "--campaign-id", "cmp_compiler",
            "--task-identity", "int_compiler_task",
        ]:
            return {"ok": True, "result": {
                "stdout": json.dumps({
                    "status": "ready", "selected_session_id": "ses_exact",
                }),
                "stderr": "", "exit_code": 0,
            }}
        if argv == ["resume", "ses_exact", "--revalidate"]:
            return {"ok": True, "result": {
                "stdout": json.dumps({
                    "session_id": "ses_exact", "lifecycle": "active",
                }),
                "stderr": "", "exit_code": 0,
            }}
        raise AssertionError(f"unexpected Environment RPC request: {request}")

    monkeypatch.setattr(local_environment_mcp, "_rpc", fake_rpc)
    response = bridge.invoke(
        "mncs-compiler", "resume",
        {"campaign_id": "cmp_compiler", "task_identity": "int_compiler_task"},
        cwd=".worktrees/selected",
    )

    assert response["ok"] is True
    assert response["result"]["session_id"] == "ses_exact"
    assert [request["argv"] for request in requests] == [
        ["continuation", "--campaign-id", "cmp_compiler",
         "--task-identity", "int_compiler_task"],
        ["resume", "ses_exact", "--revalidate"],
    ]


def test_selection_error_is_bounded_and_keeps_campaign_choices() -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    campaigns = [
        {
            "campaign_id": f"cmp_campaign_{index}",
            "continuations": [{
                "campaign_session_ids": [f"ses_session_{index}"],
                "lifecycle": "active",
                "live_repository_observation": {
                    "worktree_registrations": [
                        {"path": f"/workspace/tree-{item}"} for item in range(1000)
                    ],
                },
            }],
        }
        for index in range(5)
    ]
    response = bridge._response_error({"error": {
        "code": "ENVIRONMENT_SESSION_SELECTION_REQUIRED",
        "message": "Environment continuation did not select one session",
        "details": {
            "status": "ambiguous-campaigns",
            "repository": "mncs-compiler",
            "campaigns_count": len(campaigns),
            "continuations_count": len(campaigns),
            "campaign_statuses": [
                {"campaign_id": campaign["campaign_id"], "status": "ready"}
                for campaign in campaigns
            ],
            "campaigns": campaigns,
        },
    }})

    assert len(json.dumps(response, ensure_ascii=False).encode("utf-8")) < MAX_TOOL_RESULT_BYTES
    details = response["error"]["details"]
    assert details["campaign_statuses"][0] == {
        "campaign_id": "cmp_campaign_0", "status": "ready",
    }
    assert details["continuations"][0] == {
        "campaign_session_ids": ["ses_session_0"],
        "lifecycle": "active",
        "campaign_id": "cmp_campaign_0",
    }


def test_generic_owner_error_details_are_bounded() -> None:
    bridge = object.__new__(LocalEnvironmentMCP)
    response = bridge._response_error({"error": {
        "code": "ENVIRONMENT_OWNER_LIVENESS_UNKNOWN",
        "message": "liveness is unknown",
        "details": {"large_inventory": "x" * (MAX_TOOL_RESULT_BYTES * 2)},
    }})

    assert len(json.dumps(response).encode("utf-8")) < MAX_TOOL_RESULT_BYTES
    assert response["error"]["details"] == {"details_truncated": True}


def test_local_rpc_bootstrap_binds_capability_to_process_and_working_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-compiler"
    checkout = project / ".worktrees" / "selected"
    checkout.mkdir(parents=True)
    (project / ".git").mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "state" / "environment.sock",
            repositories={"environment": "mncs-environment"},
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "canonical"),
        policy=object(),
    )
    server.start()
    monkeypatch.setattr(server, "_peer_process_cwd", lambda _pid: checkout)
    try:
        response = _rpc(server.socket_path, {
            "action": "local-project-grant",
            "project": "mncs-compiler",
            "cwd": ".worktrees/selected",
        })
        assert response["ok"] is True
        grant = response["result"]
        assert grant["scope"] == "project"
        assert grant["sandbox_cwd"] == "/workspace/mncs-compiler/.worktrees/selected"
        record = server._grant(
            {"grant": grant["grant"]}, os.getuid(), os.getpid(),
        )
        assert record.host_root == project
        assert record.working_root == checkout
        assert record.client_pid == os.getpid()
        with pytest.raises(ControlError, match="belongs to another MCP process"):
            server._grant({"grant": grant["grant"]}, os.getuid(), os.getpid() + 1)

        with pytest.raises(ControlError, match="working directory"):
            server._dispatch_once({
                "grant": grant["grant"],
                "request_id": "req_wrong_context_test",
                "cwd": "/workspace/mncs-compiler",
                "argv": ["inspect", "ses_selected"],
            }, peer_uid=os.getuid(), peer_pid=os.getpid())
    finally:
        server.close()


def test_current_request_liveness_uses_only_verified_codex_ancestor(
    tmp_path: Path,
) -> None:
    assert EnvironmentRPCServer._looks_like_codex_process(
        "/usr/bin/codex", ["codex", "exec"],
    )
    assert not EnvironmentRPCServer._looks_like_codex_process(
        "/usr/bin/python3", ["python3", "-m", "mncs_control_mcp.local_environment_mcp"],
    )

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
    )
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=tmp_path,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    try:
        identity = server._current_request_process_identity(process.pid)
        assert identity is not None
        assert identity["start_ticks"] == server._proc_start_ticks(identity["pid"])
        if identity["pid"] == process.pid:
            assert identity["start_ticks"] == server._proc_start_ticks(process.pid)
        else:
            executable = os.readlink(f"/proc/{identity['pid']}/exe")
            argv = [item.decode("utf-8", errors="replace") for item in
                    Path(f"/proc/{identity['pid']}/cmdline").read_bytes().split(b"\x00") if item]
            assert EnvironmentRPCServer._looks_like_codex_process(executable, argv)
    finally:
        process.terminate()
        process.wait(timeout=3)


def test_current_request_liveness_walks_hidden_executable_to_codex_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=tmp_path,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "state"),
        policy=object(),
    )
    parents = {101: 102, 102: 103, 103: 1}
    command_lines = {
        102: b"codex\x00exec\x00--json\x00",
        103: b"node\x00/home/user/.local/bin/codex\x00--yolo\x00exec\x00",
    }

    def proc_status(path: Path, *, encoding: str = "utf-8") -> str:
        pid = int(path.parent.name)
        if path.name == "status" and pid in parents:
            return f"Name:\ttest\nUid:\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\t{os.getuid()}\nPPid:\t{parents[pid]}\n"
        raise FileNotFoundError(path)

    def proc_cmdline(path: Path) -> bytes:
        pid = int(path.parent.name)
        if path.name == "cmdline" and pid in command_lines:
            return command_lines[pid]
        raise FileNotFoundError(path)

    def proc_executable(path: str) -> str:
        if path == "/proc/102/exe":
            raise PermissionError(path)
        if path == "/proc/103/exe":
            return "/usr/bin/node-22"
        raise FileNotFoundError(path)

    monkeypatch.setattr(server, "_proc_start_ticks", lambda pid: str(pid))
    monkeypatch.setattr(Path, "read_text", proc_status)
    monkeypatch.setattr(Path, "read_bytes", proc_cmdline)
    monkeypatch.setattr(os, "readlink", proc_executable)

    identity = server._current_request_process_identity(101)

    assert identity == {"pid": 103, "start_ticks": "103"}


def test_local_bridge_uses_owner_resolved_context_without_leaking_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "projects"
    project = workspace / "mncs-compiler"
    project.mkdir(parents=True)
    (project / ".git").mkdir()
    server = EnvironmentRPCServer(
        ControlConfig(
            workspace_root=workspace,
            sandbox_home=tmp_path / "home",
            environment_rpc_socket=tmp_path / "rpc" / "environment.sock",
            repositories={"compiler": "mncs-compiler"},
        ),
        environment_service=SimpleNamespace(state_dir=tmp_path / "canonical"),
        policy=object(),
    )
    server.start()
    monkeypatch.setattr(server, "_peer_process_cwd", lambda _pid: project)
    bridge = LocalEnvironmentMCP()
    monkeypatch.setattr(bridge, "socket_path", server.socket_path)
    try:
        context = bridge._context("mncs-compiler", "")
        assert context.sandbox_cwd == "/workspace/mncs-compiler"
        assert context.grant
    finally:
        server.close()


def test_compact_context_preserves_the_environment_rights_projection() -> None:
    rights_context = {
        "schema_version": "mncs.rights-provenance.agent-context/1",
        "identity": "sha256:" + "a" * 64,
        "status": "review",
        "sources": {
            "rights_manifest": {
                "reference": "RIGHTS.json",
                "sha256": "sha256:" + "b" * 64,
            },
            "governance_profile": {"reference": "governance/agent-governance.json"},
            "license_resolver": {
                "reference": "mncs_rights_provenance.license_resolution/1",
            },
        },
        "rights": {
            "distribution_license": "Apache-2.0",
            "compatibility": {"status": "unknown"},
        },
        "provenance": {"evidence_state": "declared-unverified"},
        "governance": {"status": "authorized", "profile_id": "native-open@0.1.0"},
        "diagnostics": [{"code": "rights-basis-unknown"}],
    }

    compact = LocalEnvironmentMCP._compact_context({
        "schema_version": "mncs.environment.entry-context/1",
        "session_id": "ses_rights_context",
        "lifecycle": "active",
        "authority": {"readable": ["workspace"], "writable": ["mncs-language"],
                      "revision": "c" * 64},
        "rights_context": rights_context,
        "unrelated_full_workspace_detail": {"large": "omitted"},
    })

    assert compact["rights_context"] == rights_context
    assert compact["authority"]["revision"] == "c" * 64
    assert "unrelated_full_workspace_detail" not in compact


def test_compact_context_keeps_bounded_checkout_composition_diagnostics() -> None:
    compact = LocalEnvironmentMCP._compact_context({
        "schema_version": "mncs.environment.entry-context/1",
        "session_id": "ses_checkout_context",
        "revalidation": {
            "scope_composition": {
                "status": "partial",
                "composed": ["mncs-language"],
                "retained": ["mncs-compiler"],
                "removed": [],
                "skipped": [{
                    "repository": "mncs-forge",
                    "reason": "selected-checkout-identity-conflict",
                    "path": "/private/path",
                }],
                "base_intent_skipped": [{
                    "repository": "mncs-compiler",
                    "reason": "ambiguous-base-intent-checkout",
                    "claim_id": "private-claim-id",
                }],
                "unrelated": {"secret": "omitted"},
            },
        },
    })

    assert compact["revalidation"] == {
        "scope_composition": {
            "status": "partial",
            "composed": ["mncs-language"],
            "retained": ["mncs-compiler"],
            "removed": [],
            "skipped": [{
                "repository": "mncs-forge",
                "reason": "selected-checkout-identity-conflict",
            }],
            "base_intent_skipped": [{
                "repository": "mncs-compiler",
                "reason": "ambiguous-base-intent-checkout",
            }],
        },
    }

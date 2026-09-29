from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mncs_control_mcp import campaign_launcher


def _git(path: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _fixture_repo(path: Path, name: str) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    _git(path, "config", "user.name", "campaign-test")
    _git(path, "config", "user.email", "campaign-test@example.invalid")
    (path / f"{name}.txt").write_text("selected\n", encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "fixture")
    return _git(path, "rev-parse", "HEAD")


def _definition(path: Path, *, provider_revision: str) -> dict:
    definition = {
        "name": "fixture-compiler-campaign",
        "managed_checkouts": [{
            "repository": "fixture-repo",
            "name": "selected",
            "branch": "campaign/fixture",
            "source_ref": "refs/heads/main",
        }],
        "workspace_provider": {
            "repository": "mncs-control-mcp",
            "checkout": ".worktrees/provider",
            "capability": "mncs-control-mcp:workspace.worktree.prepare",
            "revision": provider_revision,
        },
        "session_checkout": {
            "repository": "mncs-environment",
            "checkout": ".worktrees/environment",
        },
    }
    path.write_text(json.dumps(definition), encoding="utf-8")
    return definition


def test_assembly_requires_every_explicit_source_without_touching_target(tmp_path: Path) -> None:
    definition_path = tmp_path / "environment.json"
    _definition(definition_path, provider_revision="deadbeef")
    target = tmp_path / "campaign"

    with pytest.raises(campaign_launcher.AssemblyError) as raised:
        campaign_launcher.assemble(
            definition_path=definition_path,
            workspace_root=target,
            state_dir=tmp_path / "state",
            sources={},
        )

    assert raised.value.code == "campaign-source-closure-invalid"
    assert not target.exists()


def test_assembly_creates_exact_provider_managed_closure(tmp_path: Path) -> None:
    control_source = Path(__file__).resolve().parents[1]
    fixture_source = tmp_path / "fixture-repo"
    fixture_head = _fixture_repo(fixture_source, "fixture")
    provider_head = _git(control_source, "rev-parse", "HEAD")
    definition_path = tmp_path / "environment.json"
    _definition(definition_path, provider_revision=provider_head)
    target = tmp_path / "campaign"
    state = tmp_path / "state"

    result = campaign_launcher.assemble(
        definition_path=definition_path,
        workspace_root=target,
        state_dir=state,
        sources={
            "fixture-repo": fixture_source,
            "mncs-control-mcp": control_source,
            "mncs-environment": control_source,
        },
        timeout_seconds=30,
    )

    selected = result["selected_checkouts"]
    assert set(selected) == {"fixture-repo", "mncs-control-mcp", "mncs-environment"}
    assert selected["fixture-repo"]["path"] == "fixture-repo/.worktrees/selected"
    assert selected["fixture-repo"]["head"] == fixture_head
    assert selected["fixture-repo"]["branch"] == "campaign/fixture"
    assert selected["fixture-repo"]["clean"] is True
    assert selected["mncs-control-mcp"]["path"] == "mncs-control-mcp/.worktrees/provider"
    assert selected["mncs-control-mcp"]["head"] == provider_head
    assert selected["mncs-environment"]["path"] == "mncs-environment/.worktrees/environment"
    assert selected["mncs-environment"]["head"] == provider_head
    assert result["entry_context"] is None
    assert not state.exists()

    assert _git(fixture_source, "status", "--porcelain=v1", "-uall") == ""
    assert (target / "mncs-control-mcp" / ".worktrees" / "provider" / "src" / "mncs_control_mcp" / "worktree_cli.py").is_file()


def test_shared_environment_state_is_rejected_before_assembly(tmp_path: Path) -> None:
    control_source = Path(__file__).resolve().parents[1]
    fixture_source = tmp_path / "fixture-repo"
    _fixture_repo(fixture_source, "fixture")
    provider_head = _git(control_source, "rev-parse", "HEAD")
    definition_path = tmp_path / "environment.json"
    _definition(definition_path, provider_revision=provider_head)
    with pytest.raises(campaign_launcher.AssemblyError) as raised:
        campaign_launcher.assemble(
            definition_path=definition_path,
            workspace_root=tmp_path / "campaign",
            state_dir=campaign_launcher.DEFAULT_SHARED_ENVIRONMENT_STATE,
            sources={
                "fixture-repo": fixture_source,
                "mncs-control-mcp": control_source,
                "mncs-environment": control_source,
            },
        )
    assert raised.value.code == "campaign-shared-state-forbidden"

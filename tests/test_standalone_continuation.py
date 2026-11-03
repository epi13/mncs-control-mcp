"""Standalone project entry must remain selectable through Control after restart."""
import json
import subprocess

import pytest

from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.local_environment_mcp import LocalEnvironmentMCP
from test_environment_sessions import _config


def test_standalone_orientation_exact_session_recovery(tmp_path):
    config = _config(tmp_path)
    root = config.workspace_root / "mncs-actions"
    root.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    git("init", "-b", "main")
    git("config", "user.name", "Continuation proof")
    git("config", "user.email", "proof@example.invalid")
    (root / ".mncs").mkdir()
    (root / ".mncs/project.json").write_text(json.dumps({"repository": "mncs-actions"}))
    git("add", ".mncs/project.json")
    git("commit", "-m", "isolated identity")
    service = EnvironmentService(config)
    service.authenticated_principal_id = "principal-standalone"
    pkg = service._pkg()
    definition, _ = pkg.entry.select_definition(None, str(root))
    context = service.enter(definition, "consumer", workspace="mncs-actions",
                            campaign_id="cmp_standalone")
    session_id = context["session_id"]
    checkout = pkg.workspace.verify_registered_checkout(root)
    # Model the exact historical incident record: root refs were discarded.
    store = service._store(pkg)
    session = pkg.sessions.Session(store, session_id)
    session.snapshot["campaign"]["repository_refs"] = []
    session._save()
    store.close()
    fresh = EnvironmentService(config)
    fresh.authenticated_principal_id = "principal-standalone"
    capsule = fresh.campaign_continuation("mncs-actions", session_id=session_id,
                                          working_checkout=checkout)
    assert capsule["status"] == "ready"
    assert capsule["continuations"][0]["session_id"] == session_id
    assert capsule["continuations"][0]["work_intent"]["repositories"] == []
    assert capsule["continuations"][0]["repositories"][0]["observed_path"] == str(root)
    assert LocalEnvironmentMCP._compact_context(context)["development_entry"]["status"] == "orientation-only"
    foreign = EnvironmentService(config)
    foreign.authenticated_principal_id = "other-principal"
    with pytest.raises(ControlError) as denied:
        foreign.campaign_continuation("mncs-actions", session_id=session_id,
                                      working_checkout=checkout)
    assert denied.value.code == "ENVIRONMENT_AUTHORITY_DENIED"

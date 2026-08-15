from __future__ import annotations

import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from mncs_control_mcp.actions import run_bounded
from mncs_control_mcp.adapters import (
    FabricAdapter,
    ForgeAdapter,
    HarnessAdapter,
    OllamaAdapter,
    SystemAdapter,
)
from mncs_control_mcp.config import ControlConfig, load_config
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.filesystem import FileService
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.runtime import effective_fabric_registry, prepare_fabric_runtime
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.security import filtered_environment, resolve_repository, validate_environment
from mncs_control_mcp.workspace import WorkspacePolicy


def test_configuration_loads_new_model_and_legacy_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "control.toml"
    config_path.write_text(
        """
[server]
name = "test-control"
[workspace]
root = "./projects"
default_scope = "project"
terminal_network_default = false
[sandbox]
backend = "bwrap"
require_real_sandbox = true
[terminal]
max_concurrent_jobs = 2
[mncs.repos]
fixture = "fixture"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MNCS_PROJECTS_ROOT", str(tmp_path / "legacy-override"))
    config = load_config(config_path)
    assert config.name == "test-control"
    assert config.workspace_root == (tmp_path / "legacy-override").resolve()
    assert config.projects_root == config.workspace_root
    assert config.repositories["fixture"] == "fixture"
    assert config.max_concurrent_jobs == 2


def test_new_workspace_environment_takes_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MNCS_PROJECTS_ROOT", str(tmp_path / "old"))
    monkeypatch.setenv("MNCS_CONTROL_WORKSPACE_ROOT", str(tmp_path / "new"))
    assert load_config(tmp_path / "missing.toml").workspace_root == (tmp_path / "new").resolve()


def test_workspace_policy_rejects_traversal_absolute_and_symlink_escape(config, tmp_path: Path) -> None:
    policy = WorkspacePolicy(config)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (config.workspace_root / "project").mkdir()
    (config.workspace_root / "escape").symlink_to(outside, target_is_directory=True)
    (config.workspace_root / "project" / "nested").symlink_to(outside, target_is_directory=True)

    for value in (
        "../outside/secret",
        "/etc/passwd",
        "project/../../outside",
        "escape/secret",
        "project/nested/secret",
        "project\\windows-style",
        "project/secret\x00suffix",
    ):
        with pytest.raises(ControlError) as error:
            policy.resolve(value, must_exist=True)
        assert error.value.code in {"PATH_ESCAPE", "INVALID_PATH"}


def test_terminal_cwd_uses_relative_abstraction_not_sandbox_internal_path(config) -> None:
    policy = WorkspacePolicy(config)
    (config.workspace_root / "mncs-control-mcp").mkdir()
    with pytest.raises(ControlError, match="workspace-relative/project-relative"):
        policy.resolve_scope(
            scope="project",
            project="mncs-control-mcp",
            cwd="/workspace/mncs-control-mcp",
        )
    resolution = policy.resolve_scope(scope="project", project="mncs-control-mcp", cwd=".")
    assert resolution.sandbox_cwd == "/workspace/mncs-control-mcp"


def test_file_service_blocks_root_deletion_and_symlink_writes(config, tmp_path: Path) -> None:
    policy = WorkspacePolicy(config)
    files = FileService(config, policy)
    outside = tmp_path / "outside.txt"
    outside.write_text("original", encoding="utf-8")
    (config.workspace_root / "link").symlink_to(outside)
    with pytest.raises(ControlError) as error:
        files.write("link", "changed")
    assert error.value.code in {"SYMLINK_MUTATION", "PATH_ESCAPE"}
    assert outside.read_text(encoding="utf-8") == "original"
    with pytest.raises(ControlError) as error:
        files.delete(".", recursive=True)
    assert error.value.code == "WORKSPACE_ROOT_PROTECTED"
    with pytest.raises(ControlError) as error:
        files.move(".", "renamed-workspace")
    assert error.value.code == "WORKSPACE_ROOT_PROTECTED"


def test_file_round_trip_search_patch_move_copy_and_delete(config) -> None:
    files = FileService(config, WorkspacePolicy(config))
    files.mkdir("demo")
    files.write("demo/hello.txt", "hello\n")
    assert files.read("demo/hello.txt")["content"] == "hello\n"
    assert files.search("hello", path="demo")["matches"][0]["line"] == 1
    files.patch("--- a/demo/hello.txt\n+++ b/demo/hello.txt\n@@ -1 +1 @@\n-hello\n+world\n")
    assert files.read("demo/hello.txt")["content"] == "world\n"
    files.copy("demo/hello.txt", "demo/copy.txt")
    files.move("demo/copy.txt", "demo/moved.txt")
    assert "demo/moved.txt" in files.glob("demo/*.txt")["matches"]
    files.delete("demo/moved.txt")
    assert not (config.workspace_root / "demo" / "moved.txt").exists()


def test_patch_error_explains_required_unified_headers(config) -> None:
    with pytest.raises(ControlError) as error:
        FileService(config, WorkspacePolicy(config)).patch("@@ -1 +1 @@\n-old\n+new\n")
    assert error.value.code == "INVALID_PATCH"
    assert "--- a/path" in error.value.message
    assert error.value.details["expected_format"].startswith("standard unified")


def test_legacy_fabric_registry_is_migrated_into_private_control_state(tmp_path: Path) -> None:
    legacy = tmp_path / ".local" / "state" / "mncs-fabric" / "workers.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"schema_version":"test"}\n', encoding="utf-8")
    config = ControlConfig(
        workspace_root=tmp_path / "projects",
        fabric_registry=legacy,
        fabric_state=tmp_path / "control-state" / "fabric.jsonl",
        job_state_path=tmp_path / "control-state" / "jobs.json",
        audit_path=tmp_path / "control-state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )
    target = effective_fabric_registry(config)
    assert target != legacy
    assert target.parent == tmp_path / "control-state" / "fabric"
    assert prepare_fabric_runtime(config) == target
    assert target.read_text(encoding="utf-8") == legacy.read_text(encoding="utf-8")
    assert (target.parent.stat().st_mode & 0o777) == 0o700
    assert (target.stat().st_mode & 0o777) == 0o600



def test_legacy_fabric_trust_state_is_relocated_into_private_control_state(tmp_path: Path) -> None:
    legacy = tmp_path / ".local" / "state" / "mncs-fabric" / "workers.json"
    trust_state = (
        tmp_path
        / ".local"
        / "state"
        / "epi13-local-harness"
        / "fabric-enrollment"
        / "worker-01-windows"
        / "trust"
        / "controller-trust.jsonl"
    )
    trust_state.parent.mkdir(parents=True)
    trust_state.write_text('{"record":{"identity":"worker-01-windows"}}\n', encoding="utf-8")
    legacy.parent.mkdir(parents=True)
    registry = {
        "schema_version": "mncs-fabric.worker-registry.v0.1",
        "controller_id": "epi13-local-harness",
        "workers": [
            {
                "worker_id": "worker-01-windows",
                "trust_state": str(trust_state),
            }
        ],
    }
    legacy.write_text(json.dumps(registry) + "\n", encoding="utf-8")
    config = ControlConfig(
        workspace_root=tmp_path / "projects",
        fabric_registry=legacy,
        fabric_state=tmp_path / "control-state" / "fabric.jsonl",
        job_state_path=tmp_path / "control-state" / "jobs.json",
        audit_path=tmp_path / "control-state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )

    target = prepare_fabric_runtime(config)
    migrated = json.loads(target.read_text(encoding="utf-8"))
    private_trust = Path(migrated["workers"][0]["trust_state"])
    assert private_trust != trust_state
    assert private_trust.parent == target.parent / "trust"
    assert private_trust.read_text(encoding="utf-8") == trust_state.read_text(encoding="utf-8")
    assert (private_trust.stat().st_mode & 0o777) == 0o600


def test_fabric_registry_migration_is_idempotent_under_concurrency(tmp_path: Path) -> None:
    legacy = tmp_path / ".local" / "state" / "mncs-fabric" / "workers.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"workers": [1, 2]}\n', encoding="utf-8")
    config = ControlConfig(
        workspace_root=tmp_path / "projects",
        fabric_registry=legacy,
        fabric_state=tmp_path / "control-state" / "fabric.jsonl",
        job_state_path=tmp_path / "control-state" / "jobs.json",
        audit_path=tmp_path / "control-state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _item: prepare_fabric_runtime(config), range(8)))
    assert all(item == results[0] for item in results)
    assert results[0].read_text(encoding="utf-8") == legacy.read_text(encoding="utf-8")
    assert not (results[0].parent / "workers.json.lock").exists()


@pytest.mark.parametrize("kind", ["source_symlink", "target_symlink"])
def test_fabric_registry_migration_rejects_symlinks(tmp_path: Path, kind: str) -> None:
    legacy = tmp_path / ".local" / "state" / "mncs-fabric" / "workers.json"
    legacy.parent.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    if kind == "source_symlink":
        legacy.symlink_to(outside)
    config = ControlConfig(
        workspace_root=tmp_path / "projects",
        fabric_registry=legacy,
        fabric_state=tmp_path / "control-state" / "fabric.jsonl",
        job_state_path=tmp_path / "control-state" / "jobs.json",
        audit_path=tmp_path / "control-state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )
    if kind == "target_symlink":
        target = effective_fabric_registry(config)
        target.parent.mkdir(parents=True)
        target.symlink_to(outside)
    with pytest.raises(ControlError):
        prepare_fabric_runtime(config)


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_runtime_mount_accepts_only_control_state_and_keeps_home_unmounted(config, tmp_path: Path) -> None:
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    runtime = config.fabric_state.parent / "fabric"
    runtime.mkdir(parents=True)
    argv, _ = sandbox.command_argv(
        "touch /home/developer/should-not-exist; touch /home/developer/.local/state/fabric/ok",
        policy.resolve_scope(scope="workspace", project=None, cwd="."),
        network=False,
        runtime_mounts=((runtime, "/home/developer/.local/state/fabric"),),
    )
    assert "--bind" in argv
    assert str(runtime) in argv
    with pytest.raises(ControlError) as error:
        sandbox.command_argv(
            "true",
            policy.resolve_scope(scope="workspace", project=None, cwd="."),
            network=False,
            runtime_mounts=((tmp_path, "/home/developer/.local/state/other"),),
        )
    assert error.value.code == "INVALID_RUNTIME_MOUNT"


@pytest.mark.requires_bwrap_namespace
def test_harness_config_is_deliberately_projected_into_sandbox(config, tmp_path: Path) -> None:
    harness_config = tmp_path / "harness.toml"
    harness_config.write_text("[fabric]\nenabled = true\n", encoding="utf-8")
    projected = replace(config, harness_config=harness_config)
    policy = WorkspacePolicy(projected)
    sandbox = Sandbox(projected, policy)
    result = sandbox.run(
        "test \"$MNCS_HARNESS_CONFIG\" = /home/developer/.config/mncs-harness/config.toml "
        "&& test \"$EPI13_HARNESS_CONFIG\" = /home/developer/.config/mncs-harness/config.toml "
        "&& grep -q 'enabled = true' \"$MNCS_HARNESS_CONFIG\"",
        scope="workspace",
        project=None,
        cwd=".",
        timeout_seconds=10,
        network=False,
    )
    assert result.exit_code == 0, result.stderr


def test_harness_projection_rejects_symlink_mountpoint(config, tmp_path: Path) -> None:
    harness_config = tmp_path / "harness.toml"
    harness_config.write_text("[fabric]\nenabled = true\n", encoding="utf-8")
    projected = replace(config, harness_config=harness_config)
    target = projected.sandbox_home / ".config"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(tmp_path / "outside", target_is_directory=True)
    sandbox = Sandbox(projected, WorkspacePolicy(projected))
    with pytest.raises(ControlError) as error:
        sandbox.command_argv(
            "true",
            WorkspacePolicy(projected).resolve_scope(scope="workspace", project=None, cwd="."),
            network=False,
        )
    assert error.value.code == "SANDBOX_MOUNTPOINT_UNSAFE"


def test_fabric_status_uses_migrated_registry_lock_in_private_state(tmp_path: Path) -> None:
    legacy = tmp_path / ".local" / "state" / "mncs-fabric" / "workers.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")
    config = ControlConfig(
        workspace_root=tmp_path / "projects",
        repositories={"fabric": "mncs-fabric"},
        fabric_registry=legacy,
        fabric_state=tmp_path / "control-state" / "fabric.jsonl",
        job_state_path=tmp_path / "control-state" / "jobs.json",
        audit_path=tmp_path / "control-state" / "audit.jsonl",
        fabric_mode="embedded",
        fabric_execution_mode="embedded-direct",
    )

    class FakeClient:
        refresh_calls = 0

        def __init__(self, _controller: str, _state: Path) -> None:
            pass

        def load_registry(self, path: Path) -> dict[str, object]:
            lock = path.with_name(path.name + ".lock")
            lock.touch()
            return {"outcome": "PASS", "registry_path": str(path)}

        def workers(self, *, apply_lease: bool = True) -> list[dict[str, object]]:
            del apply_lease
            return []

        def refresh_workers(self) -> list[dict[str, object]]:
            FakeClient.refresh_calls += 1
            return []

    class FakeFabric:
        FabricClient = FakeClient
        __version__ = "test"

    adapter = FabricAdapter(config)
    adapter._module = lambda: FakeFabric  # type: ignore[method-assign]
    result = adapter.status()
    assert result["available"] is True
    assert result["registry_path"].endswith("control-state/fabric/workers.json")
    assert Path(str(result["registry_path"] + ".lock")).is_file()
    assert FakeClient.refresh_calls == 1


def test_approved_mncs_alias_remains_specialization_not_general_authorization(config) -> None:
    with pytest.raises(ControlError) as unauthorized:
        resolve_repository(config, "not_approved")
    assert unauthorized.value.code == "UNAUTHORIZED_REPOSITORY"
    with pytest.raises(ControlError) as traversal:
        resolve_repository(config, "../../etc/passwd")
    assert traversal.value.code == "UNAUTHORIZED_REPOSITORY"


def test_environment_filter_and_overrides_drop_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MNCS_TEST_SECRET", "must-not-pass")
    monkeypatch.setenv("PATH", "/safe/path")
    environment = filtered_environment()
    assert environment["PATH"] == "/safe/path"
    assert "MNCS_TEST_SECRET" not in environment
    with pytest.raises(ControlError):
        validate_environment({"GITHUB_TOKEN": "nope"})
    assert validate_environment({"CFLAGS": "-O2"}) == {"CFLAGS": "-O2"}


def test_bounded_subprocess_timeout_and_output_limit() -> None:
    timeout = run_bounded((sys.executable, "-c", "import time; time.sleep(2)"), timeout_seconds=0.1, output_limit_bytes=4096)
    assert timeout.timed_out is True
    output = run_bounded((sys.executable, "-c", "print('x' * 20000)"), timeout_seconds=5, output_limit_bytes=512)
    assert len(output.stdout.encode()) <= 512
    assert output.output_truncated is True


def test_optional_integrations_fail_gracefully(config) -> None:
    actions = __import__("mncs_control_mcp.server", fromlist=["_register_actions"])._register_actions()
    system = SystemAdapter(config, actions, OllamaAdapter(config, actions)).status()
    assert "hostname" in system
    assert HarnessAdapter(config).status()["available"] in {True, False}
    assert FabricAdapter(config).status()["status"] in {"available", "empty", "unavailable"}
    assert ForgeAdapter(config).evaluate("missing", "case")["status"] == "not_supported_yet"


@pytest.mark.requires_bwrap_namespace
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_repo_status_uses_only_approved_alias(tmp_path: Path, config) -> None:
    repo = config.workspace_root / "fixture-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "MNCS Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    policy = WorkspacePolicy(config)
    result = GitService(config, policy, Sandbox(config, policy)).status("fixture-repo")
    assert result["clean"] is True
    assert result["branch_summary"]

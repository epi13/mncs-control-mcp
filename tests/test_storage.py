from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.storage import StorageService, _Process, _ProcessSnapshot
from mncs_control_mcp.workspace import WorkspacePolicy


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def cargo_worktree(root: Path) -> Path:
    root.mkdir(parents=True)
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Storage Tests")
    git(root, "config", "user.email", "storage-tests@example.invalid")
    (root / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n")
    (root / "src").mkdir()
    (root / "src" / "main.rs").write_text("fn main() {}\n")
    (root / ".gitignore").write_text("/target/\n")
    git(root, "add", "Cargo.toml", ".gitignore", "src/main.rs")
    git(root, "commit", "-m", "fixture")
    target = root / "target"
    (target / "debug" / ".fingerprint" / "fixture").mkdir(parents=True)
    (target / ".rustc_info.json").write_text("{}\n")
    (target / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n# Cache directory\n")
    (target / "debug" / ".fingerprint" / "fixture" / "lib-fixture.json").write_text("{}\n")
    (target / "debug" / "fixture").write_bytes(b"reconstructable build output")
    return target


def service(workspace: Path) -> StorageService:
    return StorageService(WorkspacePolicy(ControlConfig(workspace_root=workspace)))


def idle_process_scan() -> _ProcessSnapshot:
    return _ProcessSnapshot((), False, 0)


def test_plan_only_marks_clean_default_single_worktree_cargo_target_reclaimable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)
    monkeypatch.setattr(storage, "_open_target_handles", lambda _path: False)

    result = storage.plan()

    assert result["eligible_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["path"] == "fixture/target"
    assert candidate["state"] == "reclaimable"
    assert candidate["reconstructability"] == "known"
    assert candidate["reasons"] == []
    assert target.exists()


def test_reclaim_requires_confirmation_and_consumes_a_fresh_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)
    monkeypatch.setattr(storage, "_open_target_handles", lambda _path: False)
    plan = storage.plan()
    plan_id = str(plan["plan_id"])

    with pytest.raises(ControlError, match="confirm=true"):
        storage.reclaim(plan_id, confirm=False)
    assert target.exists()

    result = storage.reclaim(plan_id, confirm=True)
    assert result["allocated_bytes_removed"] > 0
    assert result["reclaimed"] == [{"path": "fixture/target", "allocated_bytes_removed": plan["eligible_bytes"]}]
    assert not target.exists()
    with pytest.raises(ControlError, match="absent, already used, or expired"):
        storage.reclaim(plan_id, confirm=True)


def test_reclaim_rejects_target_changed_after_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)
    monkeypatch.setattr(storage, "_open_target_handles", lambda _path: False)
    plan = storage.plan()
    (target / "debug" / "new-output").write_text("changed after planning")

    with pytest.raises(ControlError, match="changed after inspection"):
        storage.reclaim(str(plan["plan_id"]), confirm=True)
    assert target.exists()
    assert (target / "debug" / "new-output").exists()


def test_plan_preserves_dirty_and_multi_worktree_repositories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    dirty_target = cargo_worktree(workspace / "dirty")
    (workspace / "dirty" / "src" / "main.rs").write_text("fn main() { println!(\"work\"); }\n")

    multi_target = cargo_worktree(workspace / "multi")
    second_worktree = workspace / "multi-feature"
    git(workspace / "multi", "worktree", "add", "-b", "feature", str(second_worktree))

    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)
    monkeypatch.setattr(storage, "_open_target_handles", lambda _path: False)
    result = storage.plan()
    by_path = {item["path"]: item for item in result["candidates"]}

    assert result["eligible_count"] == 0
    assert "repository_has_uncommitted_work" in by_path["dirty/target"]["reasons"]
    assert "repository_has_multiple_worktrees" in by_path["multi/target"]["reasons"]
    assert dirty_target.exists() and multi_target.exists()


def test_plan_preserves_target_without_cargo_cache_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    (target / "CACHEDIR.TAG").unlink()
    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)

    result = storage.plan()

    assert result["eligible_count"] == 0
    assert result["candidates"] == []
    assert target.exists()
    roots, complete, errors = storage._discover_roots()
    assert complete and not errors
    assert {item["path"].name: item["kind"] for item in roots}["target"] == "unrecognized-cargo-target"


def test_known_protected_reason_takes_precedence_over_unknown_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    (workspace / "fixture" / "Cargo.toml").unlink()
    storage = service(workspace)
    monkeypatch.setattr(storage, "_process_snapshot", idle_process_scan)
    monkeypatch.setattr(storage, "_open_target_handles", lambda _path: False)

    result = storage.plan()
    candidate = result["candidates"][0]

    assert "cargo_manifest_unavailable" in candidate["reasons"]
    assert "repository_has_uncommitted_work" in candidate["reasons"]
    assert candidate["state"] == "protected"
    assert target.exists()


def test_plan_preserves_a_target_referenced_by_a_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    storage = service(workspace)
    process = _Process(
        pid=4242,
        argv=("cargo", "build"),
        cwd=str(workspace / "fixture"),
        references=(str(target / "debug" / "fixture"),),
        build_context=True,
    )
    monkeypatch.setattr(storage, "_process_snapshot", lambda: _ProcessSnapshot((process,), False, 0))

    result = storage.plan()

    assert result["eligible_count"] == 0
    assert "referenced_by_running_process" in result["candidates"][0]["reasons"]
    assert target.exists()


def test_inventory_reports_workspace_and_preserved_runtime_state(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    cargo_worktree(workspace / "fixture")
    state = workspace / "fixture" / ".mncs"
    state.mkdir()
    (state / "state.json").write_text("unique")

    result = service(workspace).inventory()

    assert result["schema_version"] == "mncs.workspace-storage-inventory/1"
    assert result["btrfs"]["status"] in {"observed", "partial", "unavailable", "not_applicable"}
    assert result["workspace"]["allocated_bytes"] > 0
    categories = {item["kind"]: item for item in result["categories"]}
    assert categories["cargo-target"]["root_count"] == 1
    assert categories["cargo-target"]["reconstructability"] == "known"
    assert categories["cargo-target"]["reclamation_supported"] is True
    assert categories["mncs-runtime-state"]["root_count"] == 1


def test_non_btrfs_inventory_skips_btrfs_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    storage = service(workspace)
    monkeypatch.setattr(storage, "_mount_for_path", lambda _root: {
        "status": "observed",
        "mount": {"target": "/", "filesystem_type": "ext4", "source": "/dev/test"},
        "errors": [],
    })

    def unexpected_command(_args: list[str], _timeout: int) -> dict[str, object]:
        raise AssertionError("Btrfs commands must not run for a non-Btrfs workspace")

    monkeypatch.setattr(storage, "_run_btrfs_command", unexpected_command)

    result = storage._btrfs_observation()

    assert result["status"] == "not_applicable"
    assert result["device_stats"] == {"status": "not_applicable", "devices": []}


def test_mountinfo_selects_the_most_specific_mount_and_decodes_escaped_paths(tmp_path: Path) -> None:
    mountpoint = tmp_path / "projects and data"
    root = mountpoint / "mncs"
    root.mkdir(parents=True)
    escaped_mountpoint = str(mountpoint).replace(" ", r"\040")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "24 1 0:1 / / rw - ext4 /dev/root rw\n"
        f"36 24 8:3 /home {escaped_mountpoint} rw,relatime - btrfs /dev/sda3 rw,compress=zstd\n"
    )

    result = StorageService._mount_for_path(root, mountinfo)

    assert result["status"] == "observed"
    assert result["mount"] == {
        "target": str(mountpoint),
        "filesystem_type": "btrfs",
        "source": "/dev/sda3",
    }


def test_btrfs_inventory_exposes_pool_metadata_and_device_error_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    storage = service(workspace)
    monkeypatch.setattr(
        storage,
        "_mount_for_path",
        lambda _root: {
            "status": "observed",
            "mount": {"target": "/home", "filesystem_type": "btrfs", "source": "/dev/sda3"},
            "errors": [],
        },
    )
    outputs = {
        "filesystem": """Overall:
    Device size: 10000
    Device allocated: 9000
    Device unallocated: 1000
    Device missing: 0
    Device slack: 0
    Used: 7000
    Free (estimated): 3000 (min: 2000)
    Free (statfs, df): 2500
    Data ratio: 1.00
    Metadata ratio: 2.00
    Global reserve: 500 (used: 20)
Data,single: Size:7000, Used:6000 (85.71%)
Metadata,DUP: Size:2000, Used:1000 (50.00%)
System,DUP: Size:1000, Used:0 (0.00%)
""",
        "device": """[/dev/sda3].write_io_errs 0
[/dev/sda3].read_io_errs 0
[/dev/sda3].flush_io_errs 0
[/dev/sda3].corruption_errs 0
[/dev/sda3].generation_errs 0
""",
    }

    def run(args: list[str], _timeout: int) -> dict[str, object]:
        return {"status": "observed", "stdout": outputs[args[0]]}

    monkeypatch.setattr(storage, "_run_btrfs_command", run)

    result = storage._btrfs_observation()

    assert result["status"] == "observed"
    usage = result["usage"]
    assert isinstance(usage, dict)
    assert usage["device_unallocated_bytes"] == 1000
    assert usage["free_estimated_min_bytes"] == 2000
    assert usage["metadata_ratio"] == 2.0
    assert usage["global_reserve_used_bytes"] == 20
    assert usage["block_groups"] == [
        {"kind": "data", "profile": "single", "size_bytes": 7000, "used_bytes": 6000},
        {"kind": "metadata", "profile": "DUP", "size_bytes": 2000, "used_bytes": 1000},
        {"kind": "system", "profile": "DUP", "size_bytes": 1000, "used_bytes": 0},
    ]
    stats = result["device_stats"]
    assert isinstance(stats, dict)
    assert stats["devices"] == [{
        "device": "/dev/sda3",
        "counters": {
            "write_io_errs": 0,
            "read_io_errs": 0,
            "flush_io_errs": 0,
            "corruption_errs": 0,
            "generation_errs": 0,
        },
    }]


def test_btrfs_observation_keeps_partial_results_when_a_command_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "projects"
    workspace.mkdir()
    storage = service(workspace)
    monkeypatch.setattr(
        storage,
        "_mount_for_path",
        lambda _root: {
            "status": "observed",
            "mount": {"target": "/", "filesystem_type": "btrfs", "source": "/dev/sda3"},
            "errors": [],
        },
    )
    usage = """Device size: 10000
Device allocated: 9000
Device unallocated: 1000
Used: 7000
Data,single: Size:7000, Used:6000
"""
    monkeypatch.setattr(storage, "_run_btrfs_command", lambda args, _timeout: {
        "status": "timed_out" if args[0] == "device" else "observed",
        "stdout": usage,
    })

    result = storage._btrfs_observation()

    assert result["status"] == "partial"
    assert result["usage"]["device_unallocated_bytes"] == 1000
    assert result["device_stats"] == {"status": "timed_out", "devices": []}
    assert result["errors"] == ["device_stats_timed_out"]


def test_manifest_allows_hardlinks_contained_in_target_but_rejects_escaping_links(tmp_path: Path) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    output = target / "debug" / "fixture"
    internal_alias = target / "debug" / "fixture-alias"
    os.link(output, internal_alias)
    storage = service(workspace)

    assert "contains_hardlink_outside_tree" not in storage._manifest(target).unsafe_reasons
    external_alias = workspace / "unique-output"
    os.link(output, external_alias)
    assert "contains_hardlink_outside_tree" in storage._manifest(target).unsafe_reasons


def test_manifest_rejects_target_mountpoints_and_prunes_nested_mounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "projects"
    target = cargo_worktree(workspace / "fixture")
    storage = service(workspace)
    monkeypatch.setattr(os.path, "ismount", lambda path: Path(path) == target)

    assert "target_is_mountpoint" in storage._manifest(target).unsafe_reasons

    nested = target / "debug" / ".fingerprint"
    monkeypatch.setattr(os.path, "ismount", lambda path: Path(path) == nested)
    manifest = storage._manifest(target)
    assert "contains_mountpoint" in manifest.unsafe_reasons
    assert manifest.entries == 5

from __future__ import annotations

import errno
import io
import json
import os
import stat
from pathlib import Path

from mncs_control_mcp import processes as processes_module
from mncs_control_mcp.processes import ProcessManager, TerminalJob
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.workspace import WorkspacePolicy


def test_terminal_job_state_falls_back_to_private_tmpfs_on_enospc(
    config, tmp_path: Path, monkeypatch,
) -> None:
    temporary_root = tmp_path / "tmp"
    monkeypatch.setattr(
        processes_module.tempfile, "gettempdir", lambda: str(temporary_root)
    )
    policy = WorkspacePolicy(config)
    manager = ProcessManager(config, policy, Sandbox(config, policy))
    job = TerminalJob(
        job_id="term_fallback_fixture",
        command="true",
        cwd="/workspace/mncs-compiler",
        scope="project",
        project="mncs-compiler",
        network=False,
        sandbox_backend="bwrap",
        timeout_seconds=30,
        status="completed",
        completed_at="2026-10-23T00:00:00Z",
        exit_code=0,
    )
    manager._jobs[job.job_id] = job

    replace = os.replace

    def fail_primary_replace(source: str | bytes | os.PathLike, target: str | bytes | os.PathLike) -> None:
        if Path(target) == config.job_state_path:
            raise OSError(errno.ENOSPC, "simulated Btrfs metadata exhaustion")
        replace(source, target)

    monkeypatch.setattr(processes_module.os, "replace", fail_primary_replace)
    manager._persist()

    fallback = manager._fallback_job_state_path
    assert not config.job_state_path.exists()
    assert fallback.is_file()
    assert stat.S_IMODE(fallback.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(fallback.stat().st_mode) == 0o600
    document = json.loads(fallback.read_text(encoding="utf-8"))
    assert document["schema_version"] == "mncs.control.terminal-job-state-fallback/1"
    assert document["jobs"][0]["job_id"] == job.job_id
    assert document["jobs"][0]["state_persistence"] == "temporary-fallback"
    assert manager.status(job.job_id)["state_persistence"] == "temporary-fallback"

    monkeypatch.setattr(processes_module.os, "replace", replace)
    restarted = ProcessManager(config, policy, Sandbox(config, policy))
    restored = restarted.status(job.job_id)
    assert restored["status"] == "completed"
    assert restored["state_persistence"] == "temporary-fallback"

    restarted._persist()
    assert config.job_state_path.is_file()
    assert not fallback.exists()
    primary_rows = json.loads(config.job_state_path.read_text(encoding="utf-8"))
    assert primary_rows[0]["state_persistence"] == "persistent"
    assert restarted.status(job.job_id)["state_persistence"] == "persistent"


def test_terminal_job_is_reaped_if_both_state_destinations_fail(
    config, monkeypatch,
) -> None:
    project = config.workspace_root / "fixture"
    project.mkdir()
    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    monkeypatch.setattr(sandbox, "command_argv", lambda *_args, **_kwargs: (["true"], False))

    class FakeProcess:
        pid = 12345
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        stdin = io.BytesIO()
        returncode = 0
        waited = False

        def wait(self, timeout: float | None = None) -> int:
            self.waited = True
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(processes_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    manager = ProcessManager(config, policy, sandbox)
    monkeypatch.setattr(
        manager, "_persist",
        lambda: (_ for _ in ()).throw(OSError(errno.ENOSPC, "both destinations are full")),
    )
    monkeypatch.setattr(manager, "_signal", lambda *_args, **_kwargs: None)

    try:
        manager.start(
            "true", scope="project", project="fixture", cwd=".",
            timeout_seconds=30, network=False,
        )
    except OSError as error:
        assert error.errno == errno.ENOSPC
    else:
        raise AssertionError("terminal start should report when all state persistence fails")

    assert process.waited
    assert manager._jobs == {}

from __future__ import annotations

import json
import time

import pytest

from mncs_control_mcp.errors import ControlError
from mncs_control_mcp.processes import ProcessManager, TerminalJob, _LogBuffer
from mncs_control_mcp.sandbox import Sandbox
from mncs_control_mcp.workspace import WorkspacePolicy


def manager(config):
    policy = WorkspacePolicy(config)
    return ProcessManager(config, policy, Sandbox(config, policy))


def fixture_job(*, lifecycle="live"):
    return TerminalJob(
        job_id="term-capture-fixture", command="fixture", cwd="/workspace/fixture",
        scope="project", project="fixture", network=False,
        sandbox_backend="fixture", timeout_seconds=10, status="completed",
        exit_code=0, stdout=_LogBuffer(8), stderr=_LogBuffer(8),
        capture_lifecycle=lifecycle,
    )


@pytest.mark.parametrize("data, expected", [(b"", "available-empty"), (b"ok", "available-content")])
def test_actual_process_empty_and_nonempty_capture(config, monkeypatch, data, expected):
    m = manager(config)
    (config.workspace_root / "fixture").mkdir()
    # Exercise the real process/drain/persistence path; sandbox policy has its
    # own existing regression suite. This fixed fixture executes no user input.
    monkeypatch.setattr(m.sandbox, "command_argv", lambda *a, **k: (
        ["/usr/bin/python3", "-c", f"import sys;sys.stdout.buffer.write({data!r})"], False,
    ))
    started = m.start("fixture", scope="project", project="fixture", cwd=".",
                      timeout_seconds=10, network=False)
    deadline = time.monotonic() + 5
    while m.status(started["job_id"])["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.005)
    output = m.output(started["job_id"])
    assert output["status"] == "completed"
    assert output["stdout"] == data.decode()
    assert output["output_capture"]["stdout"]["status"] == expected
    assert output["output_capture"]["stderr"]["status"] == "available-empty"
    assert output["output_capture"]["process_complete"] is True


def test_retained_output_survives_metadata_persistence_in_same_process(config):
    m = manager(config)
    job = fixture_job()
    job.stdout.append(b"hello")
    m._jobs[job.job_id] = job
    m._persist()
    assert m.output(job.job_id)["stdout"] == "hello"
    assert m.output(job.job_id)["output_capture"]["stdout"]["retained_bytes"] == 5
    persisted = config.job_state_path.read_text()
    assert "hello" not in persisted  # No new raw-output persistence.


def test_restart_never_misreports_lost_capture_as_genuinely_empty(config):
    m = manager(config)
    job = fixture_job()
    job.stdout.append(b"hello")
    m._jobs[job.job_id] = job
    m._persist()
    restarted = manager(config)
    output = restarted.output(job.job_id)
    assert output["stdout"] == "" and output["output_truncated"] is False
    for stream in ("stdout", "stderr"):
        capture = output["output_capture"][stream]
        assert capture["status"] == "unavailable-restored"
        assert capture["available"] is False and capture["retained_bytes"] is None
    restarted._persist()
    assert manager(config).output(job.job_id)["output_capture"]["stdout"]["status"] == "unavailable-restored"


def test_truncation_and_incremental_read_ranges_are_distinct(config):
    m = manager(config)
    job = fixture_job()
    job.stdout.append(b"abcdefghijkl")
    m._jobs[job.job_id] = job
    output = m.output(job.job_id)
    assert output["stdout"] == "efghijkl" and output["output_truncated"] is True
    capture = output["output_capture"]["stdout"]
    assert capture == {"status": "truncated", "available": True,
                       "start_offset": 4, "end_offset": 12, "retained_bytes": 8, "limit_bytes": 8}
    end = m.output(job.job_id, stdout_offset=12)
    assert end["stdout"] == "" and end["output_truncated"] is False
    assert end["output_capture"]["stdout"]["status"] == "truncated"


@pytest.mark.parametrize("capture, expected", [
    (None, "unknown"), ({"schema_version": "unrecognized"}, "unknown"),
    ({"schema_version": "mncs.control.output-capture/1", "lifecycle": "expired"}, "expired"),
])
def test_legacy_and_owner_recorded_retention_states(config, capture, expected):
    row = fixture_job().public()
    row.pop("output_capture")
    if capture is not None:
        row["output_capture"] = capture
    config.job_state_path.parent.mkdir(parents=True, exist_ok=True)
    config.job_state_path.write_text(json.dumps([row]))
    output = manager(config).output(row["job_id"])
    assert output["output_capture"]["stdout"]["status"] == expected
    assert output["output_capture"]["stdout"]["available"] is False


def test_running_empty_is_not_a_completed_output_and_access_stays_owned(config):
    m = manager(config)
    job = fixture_job()
    job.status = "running"
    m._jobs[job.job_id] = job
    assert m.output(job.job_id)["output_capture"]["process_complete"] is False
    with pytest.raises(ControlError):
        m.output("foreign-job")
    with pytest.raises(ControlError):
        m.output(job.job_id, stdout_offset=-1)
    job.status = "completed"  # No running fixture remains for cleanup.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mncs_control_mcp.adapters import CommonsAdapter
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.errors import ControlError


def _config(tmp_path: Path, *, with_cli: bool = True) -> ControlConfig:
    workspace = tmp_path / "projects"
    harness = workspace / "epi13-local-harness"
    harness.mkdir(parents=True)
    (workspace / "MNCS-Commons").mkdir()
    harness_config = tmp_path / "harness.toml"
    harness_config.write_text("[commons]\nenabled = true\n", encoding="utf-8")
    if with_cli:
        executable = harness / ".venv" / "bin" / "elh"
        executable.parent.mkdir(parents=True)
        executable.write_text(
            """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
operation = args[args.index('commons') + 1]
if operation == 'status':
    payload = {
        'code': 'COMMONS_READY',
        'enabled': True,
        'ready': True,
        'record_count': 11,
        'store_healthy': True,
        'content_trust': 'UNTRUSTED',
    }
else:
    payload = {
        'outcome': 'PASS',
        'result': {'operation': operation, 'argv': args},
        'content_trust': 'UNTRUSTED',
    }
print(json.dumps(payload, separators=(',', ':')))
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)
    return ControlConfig(
        workspace_root=workspace,
        repositories={
            "local_harness": "epi13-local-harness",
            "commons": "MNCS-Commons",
        },
        harness_config=harness_config,
        sandbox_backend="none",
        require_real_sandbox=False,
    )


def test_commons_adapter_routes_read_only_operations_through_harness_cli(tmp_path: Path) -> None:
    adapter = CommonsAdapter(_config(tmp_path))

    status = adapter.status()
    assert status["available"] is True
    assert status["reachable"] is True
    assert status["code"] == "COMMONS_READY"
    assert status["record_count"] == 11
    assert status["transport"] == "harness-stdio-mcp"

    work = adapter.work(5)
    assert work["outcome"] == "PASS"
    assert work["content_trust"] == "UNTRUSTED"
    work_args = work["result"]["argv"]
    assert work_args[-4:] == ["work", "--limit", "5", "--json"]

    query = adapter.query(
        kind="WorkRequest",
        subject="test:commons-control",
        limit=7,
        open_work=True,
    )
    query_args = query["result"]["argv"]
    assert "--kind" in query_args and "WorkRequest" in query_args
    assert "--subject" in query_args and "test:commons-control" in query_args
    assert "--open-work" in query_args
    assert query_args[-1] == "--json"

    digest = "sha256:" + "a" * 64
    assert adapter.get(digest)["result"]["operation"] == "get"
    assert adapter.conversation(digest)["result"]["operation"] == "conversation"
    assert adapter.evidence(digest)["result"]["operation"] == "evidence"
    sync = adapter.sync({"offset": 4}, limit=10)
    sync_args = sync["result"]["argv"]
    assert "--cursor" in sync_args
    cursor = sync_args[sync_args.index("--cursor") + 1]
    assert json.loads(cursor) == {"offset": 4}

    assert not hasattr(adapter, "publish")


def test_commons_adapter_bounds_inputs_and_fails_closed(tmp_path: Path) -> None:
    adapter = CommonsAdapter(_config(tmp_path))
    with pytest.raises(ControlError, match="limit must be between"):
        adapter.work(0)
    with pytest.raises(ControlError, match="subject must be bounded"):
        adapter.query(subject="x" * 5000)
    with pytest.raises(ControlError, match="cursor exceeds"):
        adapter.sync({"cursor": "x" * (65 * 1024)})

    missing = CommonsAdapter(_config(tmp_path / "missing", with_cli=False)).status()
    assert missing["available"] is False
    assert missing["reachable"] is False
    assert missing["ready"] is False
    assert missing["code"] == "COMMONS_HARNESS_UNAVAILABLE"

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mncs_control_mcp.adapters import CommonsAdapter
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.errors import ControlError


class FakeCommonsClient:
    def __init__(self) -> None:
        self.closed = False
        self.calls: list[tuple[str, object]] = []

    def close(self) -> None:
        self.closed = True

    def status(self) -> dict[str, object]:
        self.calls.append(("status", None))
        return {
            "serviceProtocol": "commons.mncs.dev/local-service/v0alpha1",
            "storeHealthy": True,
            "recordCount": 11,
            "contentTrust": "UNTRUSTED",
        }

    def work(self, *, limit: int) -> dict[str, object]:
        self.calls.append(("work", limit))
        return {"records": [], "limit": limit}

    def query(self, **filters: object) -> dict[str, object]:
        self.calls.append(("query", filters))
        return {"records": [], "filters": filters}

    def get(self, digest: str) -> dict[str, object]:
        self.calls.append(("get", digest))
        return {"contentDigest": digest}

    def conversation(self, digest: str) -> dict[str, object]:
        self.calls.append(("conversation", digest))
        return {"root": digest, "records": []}

    def evidence(self, digest: str) -> dict[str, object]:
        self.calls.append(("evidence", digest))
        return {"root": digest, "records": []}

    def sync(
        self, cursor: dict[str, object] | None, *, limit: int
    ) -> dict[str, object]:
        self.calls.append(("sync", {"cursor": cursor, "limit": limit}))
        return {"entries": [], "cursor": cursor}


def _config(tmp_path: Path) -> ControlConfig:
    workspace = tmp_path / "projects"
    workspace.mkdir(parents=True)
    return ControlConfig(
        workspace_root=workspace,
        repositories={"commons": "MNCS-Commons"},
        commons_socket=tmp_path / "commons.sock",
        sandbox_backend="none",
        require_real_sandbox=False,
    )


def test_commons_adapter_uses_only_read_only_service_client(tmp_path: Path) -> None:
    adapter = CommonsAdapter(_config(tmp_path))
    clients: list[FakeCommonsClient] = []

    def client() -> FakeCommonsClient:
        result = FakeCommonsClient()
        clients.append(result)
        return result

    adapter._client = client  # type: ignore[method-assign]
    status = adapter.status()
    assert status["available"] is True
    assert status["reachable"] is True
    assert status["recordCount"] == 11
    assert status["transport"] == "local-unix-service"

    assert adapter.work(5)["limit"] == 5
    query = adapter.query(
        kind="WorkRequest",
        subject="test:commons-control",
        limit=7,
        open_work=True,
    )
    assert query["filters"] == {
        "kind": "WorkRequest",
        "state": None,
        "subject": "test:commons-control",
        "related": None,
        "limit": 7,
        "openWorkRequests": True,
    }

    digest = "sha256:" + "a" * 64
    assert adapter.get(digest)["contentDigest"] == digest
    assert adapter.conversation(digest)["root"] == digest
    assert adapter.evidence(digest)["root"] == digest
    assert adapter.sync({"sequence": 4}, limit=10)["cursor"] == {"sequence": 4}
    assert all(item.closed for item in clients)
    assert not hasattr(adapter, "publish")


def test_commons_adapter_bounds_inputs_and_fails_closed(tmp_path: Path) -> None:
    adapter = CommonsAdapter(_config(tmp_path))
    adapter._client = FakeCommonsClient  # type: ignore[method-assign]
    with pytest.raises(ControlError, match="limit must be between"):
        adapter.work(0)
    with pytest.raises(ControlError, match="subject must be bounded"):
        adapter.query(subject="x" * 5000)
    with pytest.raises(ControlError, match="cursor exceeds"):
        adapter.sync({"cursor": "x" * (65 * 1024)})

    unavailable = CommonsAdapter(_config(tmp_path / "missing"))
    unavailable._client = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ControlError("COMMONS_SERVICE_UNAVAILABLE", "not running")
    )
    missing = unavailable.status()
    assert missing["available"] is False
    assert missing["reachable"] is False
    assert missing["ready"] is False
    assert missing["code"] == "COMMONS_SERVICE_UNAVAILABLE"


def test_real_persistent_commons_service_read_surface(tmp_path: Path) -> None:
    pytest.importorskip("mncs_commons")
    from mncs_commons.local_service import (
        CommonsService,
        CommonsServiceConfig,
        CommonsServiceServer,
    )
    from mncs_commons.store import CommonsStore

    projects_root = Path(__file__).resolve().parents[2]
    control_config = ControlConfig(
        workspace_root=projects_root,
        repositories={"commons": "MNCS-Commons"},
        commons_socket=tmp_path / "commons.sock",
        sandbox_backend="none",
        require_real_sandbox=False,
    )
    example = control_config.commons_path / "examples" / "observation.example.yaml"
    if not example.is_file():
        pytest.skip("sibling Commons checkout is unavailable")
    store = CommonsStore(tmp_path / "store")
    store.init()
    record = json.loads(example.read_text(encoding="utf-8"))
    added = store.add_record(record)
    service_config = CommonsServiceConfig(
        store.root,
        control_config.commons_socket,
        tmp_path / "commons-operator.sock",
        domain="control:test",
    )
    server = CommonsServiceServer(CommonsService(service_config))
    server.start()
    try:
        adapter = CommonsAdapter(control_config)
        assert adapter.status()["available"] is True
        assert adapter.get(added.content_digest)["content_trust"] == "UNTRUSTED"
        assert adapter.query(limit=10)["content_trust"] == "UNTRUSTED"
        assert adapter.work(10)["content_trust"] == "UNTRUSTED"
        assert adapter.sync(limit=10)["content_trust"] == "UNTRUSTED"
        assert not hasattr(adapter, "publish")
    finally:
        server.close()

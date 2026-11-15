"""Bounded regression coverage for immutable reads and leased Store lifetime."""
from __future__ import annotations

import gc
import os
import weakref
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from test_environment_sessions import _config

from mncs_control_mcp import environment_sessions as implementation
from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.errors import ControlError


def package_with_stores():
    package = ModuleType("test_environment_package")
    created = []

    class Store:
        def __init__(self, path):
            self.path = path
            self.closes = 0
            self.failure = None

        def read(self):
            if self.failure is not None:
                raise self.failure
            return "authoritative data"

        def close(self):
            self.closes += 1

    def open_store(path, backend):
        assert backend == "store"
        result = Store(path)
        created.append(result)
        return result

    open_store.__module__ = "mncs_env.session_store"
    package.session_store = SimpleNamespace(open_store=open_store)
    return package, created


def test_store_leases_are_exclusive_bounded_and_closed_on_shutdown(tmp_path, monkeypatch):
    monkeypatch.setattr(implementation, "_POOL_MAX_STORES", 2)
    service = EnvironmentService(_config(tmp_path))
    package, created = package_with_stores()
    loans = [service._store(package) for _ in range(3)]
    assert len({id(loan._wrapped_store) for loan in loans}) == 3
    for loan in loans:
        loan.close()
        loan.close()
    assert len(service._store_pool) == 2
    assert sum(store.closes for store in created) == 1
    outstanding = service._store(package)
    service.close()
    assert sum(store.closes for store in created) == 2
    outstanding.close()
    assert all(store.closes == 1 for store in created)
    with pytest.raises(ControlError, match="closed"):
        service._store(package)


@pytest.mark.parametrize("failure", [OSError("provider unavailable"), KeyboardInterrupt()])
def test_failed_or_interrupted_store_is_not_reused(tmp_path, failure):
    service = EnvironmentService(_config(tmp_path))
    package, created = package_with_stores()
    loan = service._store(package)
    created[0].failure = failure
    with pytest.raises(type(failure)):
        loan.read()
    loan.close()
    healthy = service._store(package)
    assert len(created) == 2 and created[0].closes == 1
    assert healthy.read() == "authoritative data"
    healthy.close()
    service.close()


def test_package_and_state_changes_invalidate_pool_and_pin_outstanding_package(tmp_path):
    service = EnvironmentService(_config(tmp_path))
    old_package, old_stores = package_with_stores()
    new_package, new_stores = package_with_stores()
    old = service._store(old_package)
    retained = weakref.ref(old_package)
    new = service._store(new_package)
    del old_package
    gc.collect()
    assert retained() is not None
    old.close()
    gc.collect()
    assert retained() is None
    assert old_stores[0].closes == 1
    new.close()
    service._config = replace(service._config, environment_state_dir=tmp_path / "other-state")
    other = service._store(new_package)
    assert new_stores[0].closes == 1
    assert other.path == tmp_path / "other-state"
    other.close()
    service.close()


def test_metadata_is_bound_to_the_actual_revision_and_cleared_at_close(tmp_path, monkeypatch):
    monkeypatch.setattr(implementation, "_SNAPSHOT_META_CACHE_MAX", 2)
    service = EnvironmentService(_config(tmp_path))
    for ordinal in range(3):
        service._record_snapshot_meta("state", str(ordinal), ordinal,
                                      {"snapshot_sequence": ordinal})
    assert service._get_snapshot_meta("state", "0", 0) is None
    assert service._get_snapshot_meta("state", "1", 1) is not None
    service._record_snapshot_meta("state", "raced", 1, {"snapshot_sequence": 2})
    service._record_snapshot_meta("state", "invalid", 0, {"snapshot_sequence": False})
    assert service._get_snapshot_meta("state", "raced", 1) is None
    assert service._get_snapshot_meta("state", "invalid", 0) is None
    service.close()
    service._record_snapshot_meta("state", "late", 1, {"snapshot_sequence": 1})
    assert not service._snapshot_meta_cache


def test_source_digest_reuses_only_unchanged_content_and_detects_metadata_restoration(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    source = package / "__init__.py"
    source.write_text("VALUE = 1\n")
    original = Path.read_bytes
    reads = []

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    first = implementation._package_source_identity(package)
    count = len(reads)
    assert implementation._package_source_identity(package) == first
    assert len(reads) == count
    metadata = source.stat()
    source.write_text("VALUE = 2\n")
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert implementation._package_source_identity(package) != first
    added = package / "added.py"
    added.write_text("NEW = True\n")
    with_added = implementation._package_source_identity(package)
    added.unlink()
    assert implementation._package_source_identity(package) != with_added
    source.unlink()
    source.symlink_to(tmp_path / "missing")
    with pytest.raises(ControlError, match="symbolic links"):
        implementation._package_source_identity(package)


@pytest.mark.parametrize("historical_count", [0, 100])
def test_warm_selection_skips_history_but_rechecks_claims_principal_and_failures(tmp_path, historical_count):
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "owner"
    repository = "mncs-control-mcp"
    (service._config.workspace_root / repository).mkdir()

    def snapshot(sid, lifecycle="active", campaign="current"):
        return {"session_id": sid, "snapshot_sequence": 1, "lifecycle": lifecycle,
                "authenticated_principal_id": "owner",
                "campaign": {"identity": campaign, "work_intent": {"repositories": [repository]}},
                "readiness": {"status": "unknown", "unknown_count": 1},
                "incomplete_operations": ["interrupted-verification"]}

    class Store:
        def __init__(self):
            self.snapshots = {"ses_active": snapshot("ses_active")}
            self.snapshots.update({f"ses_history_{i}": snapshot(f"ses_history_{i}", "completed", "history")
                                   for i in range(historical_count)})
            self.loads = []
            self.claims = []
            self.failure = False

        def generation(self):
            return 1

        def domain_bindings_at(self, generation):
            return [(implementation._SNAPSHOT_SCHEMA, f"{sid}:snap:{snap['snapshot_sequence']:010d}".encode())
                    for sid, snap in self.snapshots.items()]

        def load_snapshot(self, sid):
            self.loads.append(sid)
            if sid == "ses_active" and self.failure:
                raise StoreUnavailable("provider down")
            return self.snapshots[sid]

        def read_claims(self):
            return self.claims

        def close(self):
            pass

    class StoreUnavailable(RuntimeError):
        pass

    store = Store()
    package = SimpleNamespace(claims=SimpleNamespace(
        active_claims=lambda records: {str(i): value for i, value in enumerate(records)}))
    service._pkg = lambda: package
    service._store = lambda _pkg: store
    service._observe_project_checkout = lambda _repo: {"status": "unknown"}
    service._continuation_capsule = lambda _pkg, _store, sid, snap, *_args, **_kwargs: {
        "session_id": sid, "lifecycle": snap["lifecycle"], "readiness": snap["readiness"],
        "incomplete_operations": snap["incomplete_operations"]}
    cold = service.campaign_continuation(repository)
    assert cold["continuations"][0]["readiness"]["status"] == "unknown"
    assert cold["continuations"][0]["incomplete_operations"] == ["interrupted-verification"]
    store.loads.clear()
    warm = service.campaign_continuation(repository)
    assert warm == cold and store.loads == ["ses_active"]
    store.failure = True
    with pytest.raises(ControlError) as failure:
        service.campaign_continuation(repository)
    assert failure.value.code == "ENVIRONMENT_PERSISTENCE_UNAVAILABLE"
    store.failure = False
    store.snapshots["ses_active"]["readiness"] = {"status": "unavailable"}
    assert service.campaign_continuation(repository)["continuations"][0]["readiness"]["status"] == "unavailable"
    service.authenticated_principal_id = "other-principal"
    with pytest.raises(ControlError) as foreign:
        service.campaign_continuation(repository)
    assert foreign.value.code == "ENVIRONMENT_AUTHORITY_DENIED"
    service.authenticated_principal_id = "owner"
    store.snapshots["ses_active"]["snapshot_sequence"] = 2
    store.snapshots["ses_active"]["campaign"]["work_intent"]["repositories"] = ["mncs-language"]
    store.claims = [{"session_id": "ses_active", "repository": repository, "status": "held"}]
    assert service.campaign_continuation(repository)["status"] == "ready"
    store.claims.clear()
    assert service.campaign_continuation(repository)["status"] == "not-found"
    store.snapshots["ses_active"]["snapshot_sequence"] = 3
    store.snapshots["ses_active"]["lifecycle"] = "completed"
    assert service.campaign_continuation(repository)["status"] == "not-found"

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


def test_definition_workspace_discovery_skips_unrelated_and_observes_new_scope_grants(tmp_path):
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "owner"
    repository = "mncs-control-mcp"
    repo_dir = service._config.workspace_root / repository
    repo_dir.mkdir()
    checkout = {
        "repository": repository,
        "path": str(repo_dir),
        "branch": "main",
        "checkout_identity": "chk_1",
        "git_common_directory_identity": "git_1",
    }

    def snapshot(sid, campaign="cmp_other"):
        return {
            "session_id": sid,
            "snapshot_sequence": 1,
            "lifecycle": "active",
            "authenticated_principal_id": "owner",
            "provenance": {"definition_id": "def_1"},
            "workspace": {"root": str(service._config.workspace_root)},
            "authority": {"writable": [], "protected_repositories": []},
            "campaign": {"identity": campaign, "work_intent": {"repositories": ["mncs-other"]}},
            "readiness": {"status": "ready"},
            "incomplete_operations": [],
        }

    class Store:
        def __init__(self):
            self.snapshots = {f"ses_other_{i:02d}": snapshot(f"ses_other_{i:02d}", f"cmp_{i:02d}")
                              for i in range(40)}
            self.events = {}
            self.grant_events = {}
            self.gen = 1
            self.loads = []
            self.scope_grant_reads = []
            self.latest_claim_reads = 0
            self.full_claim_reads = 0

        def generation(self):
            return self.gen

        def domain_bindings_at(self, generation):
            bindings = [
                (implementation._SNAPSHOT_SCHEMA, f"{sid}:snap:{snap['snapshot_sequence']:010d}".encode())
                for sid, snap in self.snapshots.items()
            ]
            for sid, ev_ids in self.events.items():
                for ev_id in ev_ids:
                    bindings.append((b"mncs.environment.session-event/1", f"{sid}:ev:{ev_id}".encode()))
            return bindings

        def load_snapshot(self, sid):
            self.loads.append(sid)
            return self.snapshots[sid]

        def read_claims(self):
            self.full_claim_reads += 1
            return []

        def read_latest_claims(self):
            self.latest_claim_reads += 1
            return []

        def read_scope_grant_events(self, sid):
            self.scope_grant_reads.append(sid)
            return list(self.grant_events.get(sid, []))

        def close(self):
            pass

    store = Store()

    class FakeSession:
        __module__ = "mncs_env.sessions"

        def __init__(self, store_arg, session_id, *, _initial_snapshot=None):
            self.store = store_arg
            self.session_id = session_id
            self._snapshot = _initial_snapshot

        @classmethod
        def open(cls, *, state_dir, session_id, backend, store):
            return cls(store, session_id)

        def authority_scope_grants(self):
            return [
                ev["grant"] for ev in self.store.read_scope_grant_events(self.session_id)
                if isinstance(ev.get("grant"), dict)
            ]

        def effective_authority(self):
            grants = self.authority_scope_grants()
            return {
                "writable": sorted({g["repository"] for g in grants}),
                "scope_grants": grants,
            }

        def continuation_capsule_projection(self):
            return {
                "authority": self.effective_authority(),
                "continuation": {"repositories": [], "recent_evidence": [], "unresolved_pressures": []},
            }

    package = SimpleNamespace(
        claims=SimpleNamespace(
            read_latest_records=lambda st: st.read_latest_claims(),
            active_claims=lambda records: {str(i): v for i, v in enumerate(records)},
        ),
        sessions=SimpleNamespace(Session=FakeSession),
        campaign_selector=SimpleNamespace(
            selector_identity=lambda *a, **kw: "sel",
            read_binding=lambda _store, _sel: None,
        ),
    )
    service._pkg = lambda: package
    service._store = lambda _pkg: store
    service._observe_project_checkout = lambda _repo: {"status": "ready"}
    service._continuation_capsule = lambda _pkg, _store, sid, snap, *_args, **_kwargs: {
        "session_id": sid, "lifecycle": snap["lifecycle"], "readiness": snap["readiness"],
        "incomplete_operations": snap["incomplete_operations"],
    }

    cold = service.campaign_continuation(
        repository, definition_id="def_1", workspace_root=str(service._config.workspace_root),
        working_checkout=checkout,
    )
    assert cold["status"] == "not-found"
    assert store.full_claim_reads == 0 and store.latest_claim_reads == 1

    store.loads.clear()
    store.scope_grant_reads.clear()
    warm = service.campaign_continuation(
        repository, definition_id="def_1", workspace_root=str(service._config.workspace_root),
        working_checkout=checkout,
    )
    assert warm["status"] == "not-found"
    assert store.loads == []
    assert store.scope_grant_reads == []

    warm_task = service.campaign_continuation(
        repository, task_identity="task_missing", definition_id="def_1",
        workspace_root=str(service._config.workspace_root), working_checkout=checkout,
    )
    assert warm_task["status"] == "task-selector-unbound"
    assert store.loads == []
    assert store.scope_grant_reads == []

    # Grant scope for `repository` on ses_other_05 without changing its snapshot revision.
    target_sid = "ses_other_05"
    store.gen = 2
    store.events[target_sid] = ["00000001"]
    store.grant_events[target_sid] = [{
        "event_type": "authority.scope-granted",
        "grant": {
            "schema_version": "mncs.environment.authority-scope-grant/1",
            "campaign_id": "cmp_05",
            "session_id": target_sid,
            "repository": repository,
            "authorized_by_principal_id": "owner",
            "scope": {"kind": "repository", "repository": repository},
            "repository_identity": {
                "path": str(repo_dir),
                "branch": "main",
                "checkout_identity": "chk_1",
                "git_common_directory_identity": "git_1",
            },
        },
    }]
    store.loads.clear()
    store.scope_grant_reads.clear()
    found = service.campaign_continuation(
        repository, definition_id="def_1", workspace_root=str(service._config.workspace_root),
        working_checkout=checkout,
    )
    assert found["status"] == "ready"
    assert found["campaign_id"] == "cmp_05"
    assert store.loads == [target_sid]
    assert set(store.scope_grant_reads) == {target_sid}


def test_ambiguous_campaigns_caps_capsules_and_uses_projection_with_legacy_fallback(tmp_path):
    service = EnvironmentService(_config(tmp_path))
    service.authenticated_principal_id = "owner"
    repository = "mncs-control-mcp"
    (service._config.workspace_root / repository).mkdir()

    def make_store(count):
        snapshots = {
            f"ses_{i:02d}": {
                "session_id": f"ses_{i:02d}",
                "snapshot_sequence": 1,
                "lifecycle": "active",
                "authenticated_principal_id": "owner",
                "provenance": {"definition_id": "def_1"},
                "workspace": {"root": str(service._config.workspace_root)},
                "authority": {"writable": [repository], "protected_repositories": []},
                "campaign": {"identity": f"cmp_{i:02d}", "work_intent": {"repositories": [repository]}},
                "readiness": {"status": "ready"},
                "incomplete_operations": [],
            }
            for i in range(count)
        }
        return SimpleNamespace(
            snapshots=snapshots,
            read_claims_calls=0,
            read_latest_claims_calls=0,
            generation=lambda: 1,
            domain_bindings_at=lambda _g: [
                (implementation._SNAPSHOT_SCHEMA, f"{sid}:snap:0000000001".encode())
                for sid in snapshots
            ],
            load_snapshot=lambda sid: snapshots[sid],
            read_latest_claims=lambda: [],
            read_claims=lambda: [],
            close=lambda: None,
        )

    store = make_store(25)

    def counted_latest(_st):
        store.read_latest_claims_calls += 1
        return []

    def counted_full():
        store.read_claims_calls += 1
        return []

    store.read_claims = counted_full
    counts = {"open": 0, "context": 0, "projection": 0}

    class FastSession:
        __module__ = "mncs_env.sessions"

        def __init__(self, st, sid, *, _initial_snapshot=None):
            assert _initial_snapshot is st.snapshots[sid]

        @classmethod
        def open(cls, **kw):
            counts["open"] += 1
            return cls(kw["store"], kw["session_id"], _initial_snapshot=kw["store"].snapshots[kw["session_id"]])

        def context(self):
            counts["context"] += 1
            return {"authority": {"writable": [repository], "scope_grants": []}, "continuation": {}}

        def continuation_capsule_projection(self):
            counts["projection"] += 1
            return {
                "authority": {"writable": [repository], "scope_grants": []},
                "continuation": {"recent_evidence": [], "unresolved_pressures": []},
            }

    package = SimpleNamespace(
        claims=SimpleNamespace(
            read_latest_records=counted_latest,
            active_claims=lambda records: {},
        ),
        sessions=SimpleNamespace(Session=FastSession),
    )
    service._pkg = lambda: package
    service._store = lambda _pkg: store
    service._observe_project_checkout = lambda _repo: {"status": "ready"}

    result = service.campaign_continuation(repository)
    assert result["status"] == "ambiguous-campaigns"
    assert len(result["campaigns"]) == 16
    assert result["campaigns_truncated"] is True
    assert store.read_claims_calls == 0
    assert store.read_latest_claims_calls == 1
    assert counts["projection"] == 16
    assert counts["open"] == 0 and counts["context"] == 0

    # Non-mncs_env.sessions Session test double falls back to Session.open().context()
    legacy_counts = {"open": 0, "context": 0}

    class LegacySession:
        @classmethod
        def open(cls, **kw):
            legacy_counts["open"] += 1
            return cls()

        def context(self):
            legacy_counts["context"] += 1
            return {"authority": {"writable": [repository], "scope_grants": []}, "continuation": {}}

    store_legacy = make_store(1)
    package.sessions = SimpleNamespace(Session=LegacySession)
    service._store = lambda _pkg: store_legacy
    single = service.campaign_continuation(repository)
    assert single["status"] == "ready"
    assert legacy_counts == {"open": 1, "context": 1}

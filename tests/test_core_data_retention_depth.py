# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_data_retention_depth.py
# REM: Depth coverage for core/data_retention.py
# REM: RetentionPolicy, DeletionRequest, RetentionManager — in-memory.

import pytest
from datetime import datetime, timedelta, timezone

from core.data_retention import (
    RetentionPolicy,
    DeletionRequest,
    RetentionManager,
)


# ─── Patch Redis so audit.log() uses in-memory path ────────────────────────────
@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def manager():
    """Reuse the module-level singleton but reset its in-memory state."""
    from core.data_retention import RetentionManager as _RM
    m = object.__new__(_RM)
    m._policies = {}
    m._deletion_requests = {}
    m._data_registry = {}
    m._legal_hold_checker = None
    return m


def _create_policy(manager, name="7yr_rule", tenant_id=None, days=365 * 7,
                   data_types=None, auto_delete=False, created_by="admin"):
    return manager.create_policy(
        name=name,
        tenant_id=tenant_id,
        retention_days=days,
        data_types=data_types or ["client_data"],
        auto_delete=auto_delete,
        created_by=created_by,
    )


def _request_deletion(manager, tenant_id="tenant-001", matter_id=None,
                      requested_by="admin", reason="ccpa_deletion"):
    return manager.request_deletion(tenant_id, matter_id, requested_by, reason)


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionPolicy.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRetentionPolicyToDict:
    def _make_policy(self, **kwargs):
        defaults = dict(
            policy_id="rpol_abc",
            name="test_policy",
            tenant_id="tenant-001",
            retention_days=365,
            data_types=["client_data"],
            auto_delete=False,
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            created_by="admin",
        )
        defaults.update(kwargs)
        return RetentionPolicy(**defaults)

    def test_returns_dict(self):
        p = self._make_policy()
        assert isinstance(p.to_dict(), dict)

    def test_has_policy_id(self):
        p = self._make_policy(policy_id="rpol_xyz")
        assert p.to_dict()["policy_id"] == "rpol_xyz"

    def test_has_name(self):
        p = self._make_policy(name="my_policy")
        assert p.to_dict()["name"] == "my_policy"

    def test_has_tenant_id(self):
        p = self._make_policy(tenant_id="tenant-001")
        assert p.to_dict()["tenant_id"] == "tenant-001"

    def test_tenant_id_none_allowed(self):
        p = self._make_policy(tenant_id=None)
        assert p.to_dict()["tenant_id"] is None

    def test_has_retention_days(self):
        p = self._make_policy(retention_days=365)
        assert p.to_dict()["retention_days"] == 365

    def test_has_data_types(self):
        p = self._make_policy(data_types=["a", "b"])
        assert p.to_dict()["data_types"] == ["a", "b"]

    def test_has_auto_delete(self):
        p = self._make_policy(auto_delete=True)
        assert p.to_dict()["auto_delete"] is True

    def test_has_created_at_isoformat(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        p = self._make_policy(created_at=ts)
        assert p.to_dict()["created_at"] == ts.isoformat()

    def test_has_created_by(self):
        p = self._make_policy(created_by="alice")
        assert p.to_dict()["created_by"] == "alice"

    def test_all_eight_keys_present(self):
        p = self._make_policy()
        expected = {
            "policy_id", "name", "tenant_id", "retention_days",
            "data_types", "auto_delete", "created_at", "created_by"
        }
        assert set(p.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# DeletionRequest.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeletionRequestToDict:
    def _make_request(self, **kwargs):
        defaults = dict(
            request_id="del_abc",
            tenant_id="tenant-001",
            matter_id="matter-001",
            requested_by="admin",
            reason="ccpa_deletion",
            status="pending",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        defaults.update(kwargs)
        return DeletionRequest(**defaults)

    def test_returns_dict(self):
        r = self._make_request()
        assert isinstance(r.to_dict(), dict)

    def test_has_request_id(self):
        r = self._make_request(request_id="del_xyz")
        assert r.to_dict()["request_id"] == "del_xyz"

    def test_has_tenant_id(self):
        r = self._make_request(tenant_id="tenant-999")
        assert r.to_dict()["tenant_id"] == "tenant-999"

    def test_has_matter_id(self):
        r = self._make_request(matter_id="matter-abc")
        assert r.to_dict()["matter_id"] == "matter-abc"

    def test_matter_id_none_allowed(self):
        r = self._make_request(matter_id=None)
        assert r.to_dict()["matter_id"] is None

    def test_has_requested_by(self):
        r = self._make_request(requested_by="alice")
        assert r.to_dict()["requested_by"] == "alice"

    def test_has_reason(self):
        r = self._make_request(reason="ccpa_deletion")
        assert r.to_dict()["reason"] == "ccpa_deletion"

    def test_has_status(self):
        r = self._make_request(status="pending")
        assert r.to_dict()["status"] == "pending"

    def test_has_created_at_isoformat(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        r = self._make_request(created_at=ts)
        assert r.to_dict()["created_at"] == ts.isoformat()

    def test_completed_at_none_when_not_completed(self):
        r = self._make_request()
        assert r.to_dict()["completed_at"] is None

    def test_completed_at_isoformat_when_set(self):
        ts = datetime(2026, 2, 1, tzinfo=timezone.utc)
        r = self._make_request(completed_at=ts)
        assert r.to_dict()["completed_at"] == ts.isoformat()

    def test_has_deleted_keys(self):
        r = self._make_request(deleted_keys=["key1", "key2"])
        assert r.to_dict()["deleted_keys"] == ["key1", "key2"]

    def test_all_nine_keys_present(self):
        r = self._make_request()
        expected = {
            "request_id", "tenant_id", "matter_id", "requested_by",
            "reason", "status", "created_at", "completed_at", "deleted_keys"
        }
        assert set(r.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.create_policy()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreatePolicy:
    def test_returns_retention_policy(self, manager):
        p = _create_policy(manager)
        assert isinstance(p, RetentionPolicy)

    def test_policy_id_has_prefix(self, manager):
        p = _create_policy(manager)
        assert p.policy_id.startswith("rpol_")

    def test_name_stored(self, manager):
        p = _create_policy(manager, name="ccpa_rule")
        assert p.name == "ccpa_rule"

    def test_tenant_id_stored(self, manager):
        p = _create_policy(manager, tenant_id="tenant-001")
        assert p.tenant_id == "tenant-001"

    def test_global_policy_tenant_none(self, manager):
        p = _create_policy(manager, tenant_id=None)
        assert p.tenant_id is None

    def test_retention_days_stored(self, manager):
        p = _create_policy(manager, days=730)
        assert p.retention_days == 730

    def test_data_types_stored(self, manager):
        p = _create_policy(manager, data_types=["a", "b"])
        assert p.data_types == ["a", "b"]

    def test_auto_delete_stored(self, manager):
        p = _create_policy(manager, auto_delete=True)
        assert p.auto_delete is True

    def test_created_by_stored(self, manager):
        p = _create_policy(manager, created_by="alice")
        assert p.created_by == "alice"

    def test_created_at_is_datetime(self, manager):
        p = _create_policy(manager)
        assert isinstance(p.created_at, datetime)

    def test_policy_stored_in_manager(self, manager):
        p = _create_policy(manager)
        assert p.policy_id in manager._policies

    def test_unique_policy_ids(self, manager):
        p1 = _create_policy(manager)
        p2 = _create_policy(manager)
        assert p1.policy_id != p2.policy_id


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.get_policies()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetPolicies:
    def test_returns_list(self, manager):
        assert isinstance(manager.get_policies(), list)

    def test_empty_initially(self, manager):
        assert manager.get_policies() == []

    def test_returns_all_policies(self, manager):
        _create_policy(manager, name="p1")
        _create_policy(manager, name="p2")
        assert len(manager.get_policies()) == 2

    def test_filter_by_tenant_returns_tenant_policies(self, manager):
        _create_policy(manager, tenant_id="tenant-A")
        _create_policy(manager, tenant_id="tenant-B")
        result = manager.get_policies(tenant_id="tenant-A")
        assert len(result) == 1
        assert result[0].tenant_id == "tenant-A"

    def test_filter_by_tenant_includes_global_policies(self, manager):
        _create_policy(manager, tenant_id=None, name="global")
        _create_policy(manager, tenant_id="tenant-A", name="specific")
        result = manager.get_policies(tenant_id="tenant-A")
        # Should include both: the global (tenant_id=None) and tenant-specific
        assert len(result) == 2

    def test_no_match_for_unknown_tenant(self, manager):
        _create_policy(manager, tenant_id="tenant-B")
        result = manager.get_policies(tenant_id="tenant-Z")
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.request_deletion()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequestDeletion:
    def test_returns_deletion_request(self, manager):
        r = _request_deletion(manager)
        assert isinstance(r, DeletionRequest)

    def test_request_id_has_prefix(self, manager):
        r = _request_deletion(manager)
        assert r.request_id.startswith("del_")

    def test_tenant_id_stored(self, manager):
        r = _request_deletion(manager, tenant_id="tenant-ABC")
        assert r.tenant_id == "tenant-ABC"

    def test_matter_id_stored(self, manager):
        r = _request_deletion(manager, matter_id="matter-001")
        assert r.matter_id == "matter-001"

    def test_matter_id_none_allowed(self, manager):
        r = _request_deletion(manager, matter_id=None)
        assert r.matter_id is None

    def test_requested_by_stored(self, manager):
        r = _request_deletion(manager, requested_by="alice")
        assert r.requested_by == "alice"

    def test_reason_stored(self, manager):
        r = _request_deletion(manager, reason="ccpa_deletion")
        assert r.reason == "ccpa_deletion"

    def test_initial_status_pending(self, manager):
        r = _request_deletion(manager)
        assert r.status == "pending"

    def test_stored_in_manager(self, manager):
        r = _request_deletion(manager)
        assert r.request_id in manager._deletion_requests

    def test_unique_request_ids(self, manager):
        r1 = _request_deletion(manager)
        r2 = _request_deletion(manager)
        assert r1.request_id != r2.request_id


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.approve_deletion()
# ═══════════════════════════════════════════════════════════════════════════════

class TestApproveDeletion:
    def test_returns_true_for_pending_request(self, manager):
        r = _request_deletion(manager)
        assert manager.approve_deletion(r.request_id, "admin") is True

    def test_status_becomes_approved(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        assert manager._deletion_requests[r.request_id].status == "approved"

    def test_returns_false_for_unknown_id(self, manager):
        assert manager.approve_deletion("nonexistent", "admin") is False

    def test_returns_false_if_not_pending(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")  # Now "approved"
        assert manager.approve_deletion(r.request_id, "admin") is False


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.execute_deletion()
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecuteDeletion:
    def test_returns_dict(self, manager):
        r = _request_deletion(manager)
        result = manager.execute_deletion(r.request_id)
        assert isinstance(result, dict)

    def test_unknown_request_returns_error(self, manager):
        result = manager.execute_deletion("nonexistent")
        assert result["status"] == "error"

    def test_not_approved_returns_error(self, manager):
        r = _request_deletion(manager)
        result = manager.execute_deletion(r.request_id)
        assert result["status"] == "error"

    def test_approved_request_completes(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        result = manager.execute_deletion(r.request_id)
        assert result["status"] == "completed"

    def test_completed_request_keys_deleted_zero_when_empty_registry(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        result = manager.execute_deletion(r.request_id)
        assert result["keys_deleted"] == 0

    def test_data_registry_keys_deleted(self, manager):
        # Register some data in the registry
        manager._data_registry["key1"] = {"tenant_id": "tenant-001", "matter_id": None, "data_type": "client_data"}
        manager._data_registry["key2"] = {"tenant_id": "tenant-001", "matter_id": None, "data_type": "client_data"}
        manager._data_registry["key3"] = {"tenant_id": "tenant-999", "matter_id": None, "data_type": "client_data"}  # different tenant

        r = _request_deletion(manager, tenant_id="tenant-001")
        manager.approve_deletion(r.request_id, "admin")
        result = manager.execute_deletion(r.request_id)
        assert result["keys_deleted"] == 2
        assert "key3" in manager._data_registry  # Different tenant unaffected

    def test_completed_status_in_request(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        manager.execute_deletion(r.request_id)
        assert manager._deletion_requests[r.request_id].status == "completed"

    def test_completed_at_set(self, manager):
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        manager.execute_deletion(r.request_id)
        assert manager._deletion_requests[r.request_id].completed_at is not None

    def test_legal_hold_blocks_deletion(self, manager):
        manager._legal_hold_checker = lambda tenant_id, matter_id: True  # Always holds
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        result = manager.execute_deletion(r.request_id)
        assert result["status"] == "blocked_by_hold"

    def test_legal_hold_updates_status(self, manager):
        manager._legal_hold_checker = lambda t, m: True
        r = _request_deletion(manager)
        manager.approve_deletion(r.request_id, "admin")
        manager.execute_deletion(r.request_id)
        assert manager._deletion_requests[r.request_id].status == "blocked_by_hold"


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.get_deletion_requests()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetDeletionRequests:
    def test_returns_list(self, manager):
        assert isinstance(manager.get_deletion_requests(), list)

    def test_empty_initially(self, manager):
        assert manager.get_deletion_requests() == []

    def test_returns_all_requests(self, manager):
        _request_deletion(manager)
        _request_deletion(manager)
        assert len(manager.get_deletion_requests()) == 2

    def test_filter_by_tenant_id(self, manager):
        _request_deletion(manager, tenant_id="tenant-A")
        _request_deletion(manager, tenant_id="tenant-B")
        result = manager.get_deletion_requests(tenant_id="tenant-A")
        assert len(result) == 1

    def test_filter_by_status(self, manager):
        r = _request_deletion(manager)
        _request_deletion(manager)  # Also pending
        manager.approve_deletion(r.request_id, "admin")
        pending = manager.get_deletion_requests(status="pending")
        assert len(pending) == 1
        approved = manager.get_deletion_requests(status="approved")
        assert len(approved) == 1

    def test_filter_by_both_tenant_and_status(self, manager):
        r1 = _request_deletion(manager, tenant_id="tenant-A")
        r2 = _request_deletion(manager, tenant_id="tenant-A")
        _request_deletion(manager, tenant_id="tenant-B")
        manager.approve_deletion(r1.request_id, "admin")
        result = manager.get_deletion_requests(tenant_id="tenant-A", status="pending")
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# RetentionManager.check_retention_expiry()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckRetentionExpiry:
    def test_returns_list(self, manager):
        assert isinstance(manager.check_retention_expiry(), list)

    def test_empty_registry_empty_result(self, manager):
        _create_policy(manager, days=365)
        assert manager.check_retention_expiry() == []

    def test_expired_data_detected(self, manager):
        _create_policy(manager, days=30, data_types=["client_data"], tenant_id="tenant-001")
        # Add data created 60 days ago
        old_time = datetime.now(timezone.utc) - timedelta(days=60)
        manager._data_registry["old_key"] = {
            "tenant_id": "tenant-001",
            "data_type": "client_data",
            "created_at": old_time,
        }
        result = manager.check_retention_expiry()
        assert len(result) == 1
        assert result[0]["key"] == "old_key"

    def test_non_expired_data_not_included(self, manager):
        _create_policy(manager, days=365, data_types=["client_data"], tenant_id="tenant-001")
        manager._data_registry["fresh_key"] = {
            "tenant_id": "tenant-001",
            "data_type": "client_data",
            "created_at": datetime.now(timezone.utc),
        }
        assert manager.check_retention_expiry() == []

    def test_expired_item_has_required_keys(self, manager):
        _create_policy(manager, days=1, data_types=["client_data"], tenant_id="tenant-001")
        old_time = datetime.now(timezone.utc) - timedelta(days=10)
        manager._data_registry["key1"] = {
            "tenant_id": "tenant-001",
            "data_type": "client_data",
            "created_at": old_time,
        }
        result = manager.check_retention_expiry()
        assert len(result) == 1
        item = result[0]
        assert "key" in item
        assert "tenant_id" in item
        assert "data_type" in item
        assert "expired_at" in item
        assert "policy_id" in item
        assert "auto_delete" in item

    def test_global_policy_applies_to_all_tenants(self, manager):
        # Global policy (tenant_id=None)
        _create_policy(manager, days=5, tenant_id=None, data_types=["client_data"])
        old_time = datetime.now(timezone.utc) - timedelta(days=10)
        manager._data_registry["key1"] = {
            "tenant_id": "any_tenant",
            "data_type": "client_data",
            "created_at": old_time,
        }
        result = manager.check_retention_expiry()
        assert len(result) == 1

    def test_wrong_data_type_not_expired(self, manager):
        _create_policy(manager, days=1, data_types=["client_data"], tenant_id="tenant-001")
        old_time = datetime.now(timezone.utc) - timedelta(days=10)
        manager._data_registry["key1"] = {
            "tenant_id": "tenant-001",
            "data_type": "other_type",  # Not in policy's data_types
            "created_at": old_time,
        }
        assert manager.check_retention_expiry() == []

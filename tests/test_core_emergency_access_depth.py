# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_emergency_access_depth.py
# REM: Depth tests for core/emergency_access.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from core.emergency_access import EmergencyAccessRequest, EmergencyAccessManager
from core.rbac import Permission


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(EmergencyAccessManager)
    m._requests = {}
    m._active_by_user = {}
    return m


def _now():
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════════
# EmergencyAccessRequest dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmergencyAccessRequest:
    def test_to_dict_keys(self):
        now = _now()
        req = EmergencyAccessRequest(
            request_id="emerg_abc123",
            user_id="user-1",
            reason="Patient emergency",
            timestamp=now,
            approved_by="admin-1",
            expires_at=now + timedelta(hours=1),
            permissions_granted={"read", "write"},
            is_active=True
        )
        d = req.to_dict()
        assert set(d.keys()) == {
            "request_id", "user_id", "reason", "timestamp",
            "approved_by", "expires_at", "permissions_granted", "is_active"
        }

    def test_to_dict_request_id(self):
        req = EmergencyAccessRequest(
            request_id="emerg_xyz",
            user_id="u1",
            reason="test",
            timestamp=_now()
        )
        assert req.to_dict()["request_id"] == "emerg_xyz"

    def test_to_dict_user_id(self):
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="nurse-007",
            reason="test",
            timestamp=_now()
        )
        assert req.to_dict()["user_id"] == "nurse-007"

    def test_to_dict_permissions_sorted(self):
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="u1",
            reason="test",
            timestamp=_now(),
            permissions_granted={"z_perm", "a_perm", "m_perm"}
        )
        d = req.to_dict()
        assert d["permissions_granted"] == sorted(["z_perm", "a_perm", "m_perm"])

    def test_to_dict_no_expires_at(self):
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="u1",
            reason="test",
            timestamp=_now(),
            expires_at=None
        )
        assert req.to_dict()["expires_at"] is None

    def test_to_dict_expires_at_iso(self):
        now = _now()
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="u1",
            reason="test",
            timestamp=now,
            expires_at=now + timedelta(minutes=60)
        )
        assert isinstance(req.to_dict()["expires_at"], str)

    def test_to_dict_is_active_false_by_default(self):
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="u1",
            reason="test",
            timestamp=_now()
        )
        assert req.to_dict()["is_active"] is False

    def test_to_dict_timestamp_iso(self):
        now = _now()
        req = EmergencyAccessRequest(
            request_id="r1",
            user_id="u1",
            reason="test",
            timestamp=now
        )
        assert req.to_dict()["timestamp"] == now.isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# request_emergency_access
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequestEmergencyAccess:
    def test_returns_request(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert isinstance(req, EmergencyAccessRequest)

    def test_not_active_initially(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert req.is_active is False

    def test_no_permissions_initially(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert len(req.permissions_granted) == 0

    def test_stored_in_requests(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert req.request_id in mgr._requests

    def test_not_in_active_by_user(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert "nurse-1" not in mgr._active_by_user

    def test_request_id_has_emerg_prefix(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert req.request_id.startswith("emerg_")

    def test_expires_at_set(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue", duration_minutes=30)
        assert req.expires_at is not None

    def test_expires_at_is_future(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue", duration_minutes=60)
        assert req.expires_at > _now()

    def test_custom_duration(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue", duration_minutes=120)
        diff = req.expires_at - _now()
        assert diff.total_seconds() > 7000  # ~120 minutes minus a few seconds of test time

    def test_user_id_stored(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert req.user_id == "nurse-1"

    def test_reason_stored(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Patient deteriorating")
        assert req.reason == "Patient deteriorating"


# ═══════════════════════════════════════════════════════════════════════════════
# approve_emergency_access
# ═══════════════════════════════════════════════════════════════════════════════

class TestApproveEmergencyAccess:
    def test_returns_true_on_success(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert mgr.approve_emergency_access(req.request_id, "admin-1") is True

    def test_is_active_after_approval(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert req.is_active is True

    def test_approved_by_set(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert req.approved_by == "admin-1"

    def test_all_permissions_granted(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        all_perms = {p.value for p in Permission}
        assert req.permissions_granted == all_perms

    def test_active_by_user_updated(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert mgr._active_by_user.get("nurse-1") == req.request_id

    def test_returns_false_for_unknown_request(self, mgr):
        assert mgr.approve_emergency_access("nonexistent", "admin-1") is False

    def test_returns_false_if_already_active(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert mgr.approve_emergency_access(req.request_id, "admin-2") is False


# ═══════════════════════════════════════════════════════════════════════════════
# revoke_emergency_access
# ═══════════════════════════════════════════════════════════════════════════════

class TestRevokeEmergencyAccess:
    def test_returns_true_on_success(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert mgr.revoke_emergency_access(req.request_id, "security-1") is True

    def test_is_inactive_after_revoke(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        mgr.revoke_emergency_access(req.request_id, "security-1")
        assert req.is_active is False

    def test_permissions_cleared_after_revoke(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        mgr.revoke_emergency_access(req.request_id, "security-1")
        assert len(req.permissions_granted) == 0

    def test_active_by_user_cleared(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        mgr.revoke_emergency_access(req.request_id, "security-1")
        assert "nurse-1" not in mgr._active_by_user

    def test_returns_false_for_unknown_request(self, mgr):
        assert mgr.revoke_emergency_access("nonexistent", "security-1") is False

    def test_returns_false_if_not_active(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert mgr.revoke_emergency_access(req.request_id, "security-1") is False


# ═══════════════════════════════════════════════════════════════════════════════
# is_emergency_active
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsEmergencyActive:
    def test_false_before_approval(self, mgr):
        mgr.request_emergency_access("nurse-1", "Code blue")
        assert mgr.is_emergency_active("nurse-1") is False

    def test_true_after_approval(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        assert mgr.is_emergency_active("nurse-1") is True

    def test_false_after_revoke(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        mgr.revoke_emergency_access(req.request_id, "security-1")
        assert mgr.is_emergency_active("nurse-1") is False

    def test_false_for_unknown_user(self, mgr):
        assert mgr.is_emergency_active("nobody") is False

    def test_auto_expires_when_past_expiry(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue", duration_minutes=60)
        mgr.approve_emergency_access(req.request_id, "admin-1")
        # Set expiry to the past
        req.expires_at = _now() - timedelta(minutes=1)
        assert mgr.is_emergency_active("nurse-1") is False

    def test_auto_expire_clears_active_by_user(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue", duration_minutes=60)
        mgr.approve_emergency_access(req.request_id, "admin-1")
        req.expires_at = _now() - timedelta(minutes=1)
        mgr.is_emergency_active("nurse-1")
        assert "nurse-1" not in mgr._active_by_user


# ═══════════════════════════════════════════════════════════════════════════════
# get_active_emergencies
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetActiveEmergencies:
    def test_empty_initially(self, mgr):
        assert mgr.get_active_emergencies() == []

    def test_no_active_before_approval(self, mgr):
        mgr.request_emergency_access("nurse-1", "Code blue")
        assert mgr.get_active_emergencies() == []

    def test_one_active_after_approval(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        active = mgr.get_active_emergencies()
        assert len(active) == 1

    def test_correct_request_returned(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        active = mgr.get_active_emergencies()
        assert active[0].request_id == req.request_id

    def test_revoked_not_in_active(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.approve_emergency_access(req.request_id, "admin-1")
        mgr.revoke_emergency_access(req.request_id, "security-1")
        assert mgr.get_active_emergencies() == []

    def test_multiple_active(self, mgr):
        req1 = mgr.request_emergency_access("nurse-1", "Code blue")
        req2 = mgr.request_emergency_access("nurse-2", "Trauma")
        mgr.approve_emergency_access(req1.request_id, "admin-1")
        mgr.approve_emergency_access(req2.request_id, "admin-1")
        assert len(mgr.get_active_emergencies()) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# get_request / list_all_requests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetRequest:
    def test_returns_none_for_unknown(self, mgr):
        assert mgr.get_request("nonexistent") is None

    def test_returns_request(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        assert mgr.get_request(req.request_id) is req


class TestListAllRequests:
    def test_empty_initially(self, mgr):
        assert mgr.list_all_requests() == []

    def test_returns_all_as_dicts(self, mgr):
        mgr.request_emergency_access("nurse-1", "Code blue")
        mgr.request_emergency_access("nurse-2", "Trauma")
        result = mgr.list_all_requests()
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)

    def test_dict_has_request_id(self, mgr):
        req = mgr.request_emergency_access("nurse-1", "Code blue")
        result = mgr.list_all_requests()
        ids = [r["request_id"] for r in result]
        assert req.request_id in ids

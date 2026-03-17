# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_legal_hold_depth.py
# REM: Depth tests for core/legal_hold.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timezone

from core.legal_hold import LegalHold, HoldManager


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(HoldManager)
    m._holds = {}
    return m


def _now():
    return datetime.now(timezone.utc)


def _make_hold(mgr, tenant_id="t1", matter_id="m1", name="Hold A",
               reason="Litigation", scope=None, created_by="admin-1"):
    if scope is None:
        scope = ["all"]
    return mgr.create_hold(
        tenant_id=tenant_id,
        matter_id=matter_id,
        name=name,
        reason=reason,
        scope=scope,
        created_by=created_by
    )


# ═══════════════════════════════════════════════════════════════════════════════
# LegalHold dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestLegalHoldDataclass:
    def test_to_dict_key_count(self, mgr):
        hold = _make_hold(mgr)
        d = hold.to_dict()
        assert len(d) == 13

    def test_to_dict_all_keys(self, mgr):
        hold = _make_hold(mgr)
        d = hold.to_dict()
        assert set(d.keys()) == {
            "hold_id", "tenant_id", "matter_id", "name", "reason",
            "scope", "status", "created_at", "created_by",
            "released_at", "released_by", "custodians", "acknowledgments"
        }

    def test_to_dict_status_active(self, mgr):
        hold = _make_hold(mgr)
        assert hold.to_dict()["status"] == "active"

    def test_to_dict_released_at_none(self, mgr):
        hold = _make_hold(mgr)
        assert hold.to_dict()["released_at"] is None

    def test_to_dict_released_by_none(self, mgr):
        hold = _make_hold(mgr)
        assert hold.to_dict()["released_by"] is None

    def test_to_dict_created_at_iso(self, mgr):
        hold = _make_hold(mgr)
        assert isinstance(hold.to_dict()["created_at"], str)

    def test_to_dict_custodians_empty(self, mgr):
        hold = _make_hold(mgr)
        assert hold.to_dict()["custodians"] == []

    def test_to_dict_acknowledgments_empty(self, mgr):
        hold = _make_hold(mgr)
        assert hold.to_dict()["acknowledgments"] == {}

    def test_to_dict_scope(self, mgr):
        hold = _make_hold(mgr, scope=["communications", "documents"])
        assert hold.to_dict()["scope"] == ["communications", "documents"]

    def test_to_dict_matter_id(self, mgr):
        hold = _make_hold(mgr, matter_id="matter-99")
        assert hold.to_dict()["matter_id"] == "matter-99"

    def test_to_dict_matter_id_none(self, mgr):
        hold = _make_hold(mgr, matter_id=None)
        assert hold.to_dict()["matter_id"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# create_hold
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateHold:
    def test_returns_legal_hold(self, mgr):
        hold = _make_hold(mgr)
        assert isinstance(hold, LegalHold)

    def test_status_active(self, mgr):
        hold = _make_hold(mgr)
        assert hold.status == "active"

    def test_hold_id_prefix(self, mgr):
        hold = _make_hold(mgr)
        assert hold.hold_id.startswith("hold_")

    def test_stored_in_holds(self, mgr):
        hold = _make_hold(mgr)
        assert hold.hold_id in mgr._holds

    def test_tenant_id_stored(self, mgr):
        hold = _make_hold(mgr, tenant_id="tenant-abc")
        assert hold.tenant_id == "tenant-abc"

    def test_name_stored(self, mgr):
        hold = _make_hold(mgr, name="Smith v Jones")
        assert hold.name == "Smith v Jones"

    def test_created_by_stored(self, mgr):
        hold = _make_hold(mgr, created_by="legal-counsel")
        assert hold.created_by == "legal-counsel"

    def test_created_at_set(self, mgr):
        hold = _make_hold(mgr)
        assert hold.created_at is not None


# ═══════════════════════════════════════════════════════════════════════════════
# get_hold / list_holds
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetHold:
    def test_returns_none_for_unknown(self, mgr):
        assert mgr.get_hold("nonexistent") is None

    def test_returns_hold(self, mgr):
        hold = _make_hold(mgr)
        assert mgr.get_hold(hold.hold_id) is hold


class TestListHolds:
    def test_empty_initially(self, mgr):
        assert mgr.list_holds() == []

    def test_returns_active_holds(self, mgr):
        _make_hold(mgr)
        assert len(mgr.list_holds(status="active")) == 1

    def test_no_released_in_active_filter(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert mgr.list_holds(status="active") == []

    def test_released_in_released_filter(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert len(mgr.list_holds(status="released")) == 1

    def test_tenant_filter(self, mgr):
        _make_hold(mgr, tenant_id="t1")
        _make_hold(mgr, tenant_id="t2")
        assert len(mgr.list_holds(tenant_id="t1")) == 1
        assert len(mgr.list_holds(tenant_id="t2")) == 1

    def test_no_tenant_filter_returns_all(self, mgr):
        _make_hold(mgr, tenant_id="t1")
        _make_hold(mgr, tenant_id="t2")
        assert len(mgr.list_holds()) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# release_hold
# ═══════════════════════════════════════════════════════════════════════════════

class TestReleaseHold:
    def test_returns_true_on_success(self, mgr):
        hold = _make_hold(mgr)
        assert mgr.release_hold(hold.hold_id, "admin-1", "settled") is True

    def test_status_becomes_released(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert hold.status == "released"

    def test_released_by_set(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert hold.released_by == "admin-1"

    def test_released_at_set(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert hold.released_at is not None

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.release_hold("nonexistent", "admin-1", "settled") is False

    def test_returns_false_if_already_released(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert mgr.release_hold(hold.hold_id, "admin-2", "again") is False


# ═══════════════════════════════════════════════════════════════════════════════
# is_data_held
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsDataHeld:
    def test_false_with_no_holds(self, mgr):
        assert mgr.is_data_held("t1") is False

    def test_true_with_tenant_wide_hold(self, mgr):
        _make_hold(mgr, tenant_id="t1", matter_id=None)
        assert mgr.is_data_held("t1") is True

    def test_true_with_matching_matter(self, mgr):
        _make_hold(mgr, tenant_id="t1", matter_id="m1")
        assert mgr.is_data_held("t1", matter_id="m1") is True

    def test_false_for_different_tenant(self, mgr):
        _make_hold(mgr, tenant_id="t1", matter_id=None)
        assert mgr.is_data_held("t2") is False

    def test_false_after_release(self, mgr):
        hold = _make_hold(mgr, tenant_id="t1", matter_id=None)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert mgr.is_data_held("t1") is False

    def test_matter_specific_hold_blocks_tenant_wide_query(self, mgr):
        # matter_id=None in query → any hold for that tenant matches
        _make_hold(mgr, tenant_id="t1", matter_id="m99")
        assert mgr.is_data_held("t1", matter_id=None) is True

    def test_matter_mismatch(self, mgr):
        # hold is for m1, query is for m2 — should NOT block
        _make_hold(mgr, tenant_id="t1", matter_id="m1")
        assert mgr.is_data_held("t1", matter_id="m2") is False


# ═══════════════════════════════════════════════════════════════════════════════
# add_custodian
# ═══════════════════════════════════════════════════════════════════════════════

class TestAddCustodian:
    def test_returns_true(self, mgr):
        hold = _make_hold(mgr)
        assert mgr.add_custodian(hold.hold_id, "user-1") is True

    def test_custodian_appended(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        assert "user-1" in hold.custodians

    def test_idempotent(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.add_custodian(hold.hold_id, "user-1")
        assert hold.custodians.count("user-1") == 1

    def test_returns_false_for_unknown_hold(self, mgr):
        assert mgr.add_custodian("nonexistent", "user-1") is False

    def test_returns_false_for_released_hold(self, mgr):
        hold = _make_hold(mgr)
        mgr.release_hold(hold.hold_id, "admin-1", "settled")
        assert mgr.add_custodian(hold.hold_id, "user-1") is False

    def test_multiple_custodians(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.add_custodian(hold.hold_id, "user-2")
        assert len(hold.custodians) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# acknowledge_hold
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcknowledgeHold:
    def test_returns_true(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        assert mgr.acknowledge_hold(hold.hold_id, "user-1") is True

    def test_acknowledgment_recorded(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.acknowledge_hold(hold.hold_id, "user-1")
        assert "user-1" in hold.acknowledgments

    def test_acknowledgment_is_datetime(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.acknowledge_hold(hold.hold_id, "user-1")
        assert isinstance(hold.acknowledgments["user-1"], datetime)

    def test_returns_false_for_unknown_hold(self, mgr):
        assert mgr.acknowledge_hold("nonexistent", "user-1") is False

    def test_returns_false_if_not_custodian(self, mgr):
        hold = _make_hold(mgr)
        assert mgr.acknowledge_hold(hold.hold_id, "non-custodian") is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_unacknowledged
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetUnacknowledged:
    def test_empty_for_unknown_hold(self, mgr):
        assert mgr.get_unacknowledged("nonexistent") == []

    def test_all_unacked_initially(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.add_custodian(hold.hold_id, "user-2")
        assert len(mgr.get_unacknowledged(hold.hold_id)) == 2

    def test_empty_after_all_ack(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.acknowledge_hold(hold.hold_id, "user-1")
        assert mgr.get_unacknowledged(hold.hold_id) == []

    def test_partial_ack(self, mgr):
        hold = _make_hold(mgr)
        mgr.add_custodian(hold.hold_id, "user-1")
        mgr.add_custodian(hold.hold_id, "user-2")
        mgr.acknowledge_hold(hold.hold_id, "user-1")
        unacked = mgr.get_unacknowledged(hold.hold_id)
        assert unacked == ["user-2"]

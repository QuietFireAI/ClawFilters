# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_baa_tracking_depth.py
# REM: Depth tests for core/baa_tracking.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone

from core.baa_tracking import BAAManager, BAAStatus, BusinessAssociate


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(BAAManager)
    m._associates = {}
    return m


def _now():
    return datetime.now(timezone.utc)


def _register(mgr, name="Acme Corp", email="acme@example.com",
              services=None, phi_access="limited"):
    if services is None:
        services = ["billing"]
    return mgr.register_ba(
        name=name,
        email=email,
        services=services,
        phi_access_level=phi_access
    )


# ═══════════════════════════════════════════════════════════════════════════════
# BAAStatus enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestBAAStatus:
    def test_draft(self):
        assert BAAStatus.DRAFT.value == "draft"

    def test_active(self):
        assert BAAStatus.ACTIVE.value == "active"

    def test_expired(self):
        assert BAAStatus.EXPIRED.value == "expired"

    def test_terminated(self):
        assert BAAStatus.TERMINATED.value == "terminated"

    def test_under_review(self):
        assert BAAStatus.UNDER_REVIEW.value == "under_review"

    def test_five_statuses(self):
        assert len(BAAStatus) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# BusinessAssociate dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestBusinessAssociate:
    def test_to_dict_keys(self, mgr):
        ba = _register(mgr)
        d = ba.to_dict()
        assert set(d.keys()) == {
            "ba_id", "name", "contact_email", "services_provided",
            "phi_access_level", "baa_status", "effective_date",
            "expiration_date", "last_reviewed", "reviewed_by", "notes"
        }

    def test_to_dict_ba_id(self, mgr):
        ba = _register(mgr)
        assert ba.to_dict()["ba_id"] == ba.ba_id

    def test_to_dict_name(self, mgr):
        ba = _register(mgr, name="MedBill Inc")
        assert ba.to_dict()["name"] == "MedBill Inc"

    def test_to_dict_baa_status_draft(self, mgr):
        ba = _register(mgr)
        assert ba.to_dict()["baa_status"] == "draft"

    def test_to_dict_effective_date_none(self, mgr):
        ba = _register(mgr)
        assert ba.to_dict()["effective_date"] is None

    def test_to_dict_expiration_date_none(self, mgr):
        ba = _register(mgr)
        assert ba.to_dict()["expiration_date"] is None

    def test_to_dict_services_provided(self, mgr):
        ba = _register(mgr, services=["billing", "coding"])
        assert ba.to_dict()["services_provided"] == ["billing", "coding"]

    def test_to_dict_phi_access_level(self, mgr):
        ba = _register(mgr, phi_access="full")
        assert ba.to_dict()["phi_access_level"] == "full"

    def test_to_dict_notes_none_initially(self, mgr):
        ba = _register(mgr)
        assert ba.to_dict()["notes"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# register_ba
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegisterBa:
    def test_returns_business_associate(self, mgr):
        ba = _register(mgr)
        assert isinstance(ba, BusinessAssociate)

    def test_draft_status(self, mgr):
        ba = _register(mgr)
        assert ba.baa_status == BAAStatus.DRAFT

    def test_ba_id_prefix(self, mgr):
        ba = _register(mgr)
        assert ba.ba_id.startswith("ba_")

    def test_stored_in_associates(self, mgr):
        ba = _register(mgr)
        assert ba.ba_id in mgr._associates

    def test_name_stored(self, mgr):
        ba = _register(mgr, name="Healthcare AI Ltd")
        assert ba.name == "Healthcare AI Ltd"

    def test_email_stored(self, mgr):
        ba = _register(mgr, email="vendor@health.com")
        assert ba.contact_email == "vendor@health.com"

    def test_no_effective_date(self, mgr):
        ba = _register(mgr)
        assert ba.effective_date is None

    def test_no_expiration_date(self, mgr):
        ba = _register(mgr)
        assert ba.expiration_date is None


# ═══════════════════════════════════════════════════════════════════════════════
# activate_baa
# ═══════════════════════════════════════════════════════════════════════════════

class TestActivateBaa:
    def test_returns_true(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        assert mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer") is True

    def test_status_becomes_active(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer")
        assert ba.baa_status == BAAStatus.ACTIVE

    def test_effective_date_set(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer")
        assert ba.effective_date == eff

    def test_expiration_date_set(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer")
        assert ba.expiration_date == exp

    def test_reviewed_by_set(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer")
        assert ba.reviewed_by == "legal-officer"

    def test_last_reviewed_set(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-officer")
        assert ba.last_reviewed is not None

    def test_returns_false_for_unknown_ba(self, mgr):
        eff = _now()
        exp = eff + timedelta(days=365)
        assert mgr.activate_baa("nonexistent", eff, exp, "legal-officer") is False


# ═══════════════════════════════════════════════════════════════════════════════
# review_baa
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewBaa:
    def test_returns_true(self, mgr):
        ba = _register(mgr)
        assert mgr.review_baa(ba.ba_id, "compliance-officer", "Annual review") is True

    def test_status_under_review(self, mgr):
        ba = _register(mgr)
        mgr.review_baa(ba.ba_id, "compliance-officer", "Annual review")
        assert ba.baa_status == BAAStatus.UNDER_REVIEW

    def test_reviewed_by_set(self, mgr):
        ba = _register(mgr)
        mgr.review_baa(ba.ba_id, "compliance-officer", "Annual review")
        assert ba.reviewed_by == "compliance-officer"

    def test_notes_set(self, mgr):
        ba = _register(mgr)
        mgr.review_baa(ba.ba_id, "compliance-officer", "All controls met")
        assert ba.notes == "All controls met"

    def test_last_reviewed_set(self, mgr):
        ba = _register(mgr)
        mgr.review_baa(ba.ba_id, "compliance-officer", "Annual review")
        assert ba.last_reviewed is not None

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.review_baa("nonexistent", "officer", "notes") is False


# ═══════════════════════════════════════════════════════════════════════════════
# terminate_baa
# ═══════════════════════════════════════════════════════════════════════════════

class TestTerminateBaa:
    def test_returns_true(self, mgr):
        ba = _register(mgr)
        assert mgr.terminate_baa(ba.ba_id, "legal-1", "Contract breach") is True

    def test_status_terminated(self, mgr):
        ba = _register(mgr)
        mgr.terminate_baa(ba.ba_id, "legal-1", "Contract breach")
        assert ba.baa_status == BAAStatus.TERMINATED

    def test_notes_set(self, mgr):
        ba = _register(mgr)
        mgr.terminate_baa(ba.ba_id, "legal-1", "Contract breach")
        assert "Contract breach" in ba.notes

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.terminate_baa("nonexistent", "legal-1", "reason") is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_expiring_baas
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetExpiringBaas:
    def _activate(self, mgr, ba, days_until_expiry):
        eff = _now()
        exp = eff + timedelta(days=days_until_expiry)
        mgr.activate_baa(ba.ba_id, eff, exp, "admin-1")

    def test_empty_with_no_associates(self, mgr):
        assert mgr.get_expiring_baas() == []

    def test_active_expiring_within_90_days(self, mgr):
        ba = _register(mgr)
        self._activate(mgr, ba, 30)
        result = mgr.get_expiring_baas(within_days=90)
        assert ba in result

    def test_active_not_expiring_within_90_days(self, mgr):
        ba = _register(mgr)
        self._activate(mgr, ba, 200)
        result = mgr.get_expiring_baas(within_days=90)
        assert ba not in result

    def test_draft_not_included(self, mgr):
        ba = _register(mgr)
        # Not activated → no expiration_date, stays DRAFT
        result = mgr.get_expiring_baas(within_days=90)
        assert ba not in result

    def test_terminated_not_included(self, mgr):
        ba = _register(mgr)
        self._activate(mgr, ba, 30)
        mgr.terminate_baa(ba.ba_id, "legal-1", "reason")
        result = mgr.get_expiring_baas(within_days=90)
        assert ba not in result


# ═══════════════════════════════════════════════════════════════════════════════
# get_all_baas
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetAllBaas:
    def test_empty_initially(self, mgr):
        assert mgr.get_all_baas() == []

    def test_returns_all(self, mgr):
        _register(mgr, name="Acme")
        _register(mgr, name="BetaCo")
        assert len(mgr.get_all_baas()) == 2

    def test_filter_by_draft(self, mgr):
        _register(mgr)
        assert len(mgr.get_all_baas(status_filter=BAAStatus.DRAFT)) == 1

    def test_filter_by_active_empty(self, mgr):
        _register(mgr)
        assert mgr.get_all_baas(status_filter=BAAStatus.ACTIVE) == []

    def test_filter_after_activate(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-1")
        assert len(mgr.get_all_baas(status_filter=BAAStatus.ACTIVE)) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# is_baa_active
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsBaaActive:
    def test_false_for_unknown(self, mgr):
        assert mgr.is_baa_active("nonexistent") is False

    def test_false_for_draft(self, mgr):
        ba = _register(mgr)
        assert mgr.is_baa_active(ba.ba_id) is False

    def test_true_after_activate(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-1")
        assert mgr.is_baa_active(ba.ba_id) is True

    def test_false_after_terminate(self, mgr):
        ba = _register(mgr)
        eff = _now()
        exp = eff + timedelta(days=365)
        mgr.activate_baa(ba.ba_id, eff, exp, "legal-1")
        mgr.terminate_baa(ba.ba_id, "legal-1", "breach")
        assert mgr.is_baa_active(ba.ba_id) is False

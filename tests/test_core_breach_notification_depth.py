# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_breach_notification_depth.py
# REM: Depth tests for core/breach_notification.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone

from core.breach_notification import (
    BreachAssessment,
    BreachManager,
    BreachSeverity,
    NotificationRecord,
    NOTIFICATION_RULES,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(BreachManager)
    m._assessments = {}
    m._notifications = {}
    return m


def _now():
    return datetime.now(timezone.utc)


def _assess(mgr, severity=BreachSeverity.HIGH, data_types=None,
            assessed_by="security-1", description="Test breach",
            affected_tenants=None, records_count=100, attack_vector="phishing"):
    if data_types is None:
        data_types = ["pii"]
    if affected_tenants is None:
        affected_tenants = ["t1"]
    return mgr.create_assessment(
        detected_at=_now(),
        assessed_by=assessed_by,
        severity=severity,
        description=description,
        affected_tenants=affected_tenants,
        affected_records_count=records_count,
        data_types_exposed=data_types,
        attack_vector=attack_vector
    )


# ═══════════════════════════════════════════════════════════════════════════════
# BreachSeverity enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestBreachSeverity:
    def test_critical(self):
        assert BreachSeverity.CRITICAL.value == "critical"

    def test_high(self):
        assert BreachSeverity.HIGH.value == "high"

    def test_medium(self):
        assert BreachSeverity.MEDIUM.value == "medium"

    def test_low(self):
        assert BreachSeverity.LOW.value == "low"

    def test_four_levels(self):
        assert len(BreachSeverity) == 4


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION_RULES
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotificationRules:
    def test_ssn_required(self):
        assert NOTIFICATION_RULES["ssn"]["required"] is True

    def test_ssn_deadline_30_days(self):
        assert NOTIFICATION_RULES["ssn"]["deadline_days"] == 30

    def test_financial_required(self):
        assert NOTIFICATION_RULES["financial"]["required"] is True

    def test_pii_required(self):
        assert NOTIFICATION_RULES["pii"]["required"] is True

    def test_medical_required(self):
        assert NOTIFICATION_RULES["medical"]["required"] is True

    def test_privileged_required(self):
        assert NOTIFICATION_RULES["privileged"]["required"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# BreachAssessment dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestBreachAssessment:
    def test_to_dict_keys(self, mgr):
        ba = _assess(mgr)
        d = ba.to_dict()
        assert set(d.keys()) == {
            "assessment_id", "detected_at", "assessed_by", "severity",
            "description", "affected_tenants", "affected_records_count",
            "data_types_exposed", "attack_vector", "containment_status",
            "notification_required", "notification_deadline", "status"
        }

    def test_to_dict_severity_is_string(self, mgr):
        ba = _assess(mgr, severity=BreachSeverity.CRITICAL)
        assert ba.to_dict()["severity"] == "critical"

    def test_to_dict_detected_at_iso(self, mgr):
        ba = _assess(mgr)
        assert isinstance(ba.to_dict()["detected_at"], str)

    def test_to_dict_notification_required_true(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        assert ba.to_dict()["notification_required"] is True

    def test_to_dict_notification_required_false(self, mgr):
        ba = _assess(mgr, data_types=["logs"])
        assert ba.to_dict()["notification_required"] is False

    def test_to_dict_notification_deadline_none_for_no_trigger(self, mgr):
        ba = _assess(mgr, data_types=["logs"])
        assert ba.to_dict()["notification_deadline"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# NotificationRecord dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotificationRecord:
    def test_to_dict_keys(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        d = notif.to_dict()
        assert set(d.keys()) == {
            "notification_id", "assessment_id", "recipient_type",
            "recipient", "sent_at", "method", "status"
        }

    def test_to_dict_status_pending(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        assert notif.to_dict()["status"] == "pending"

    def test_to_dict_sent_at_none_initially(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        assert notif.to_dict()["sent_at"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# determine_notification_requirement
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetermineNotificationRequirement:
    def test_no_trigger_types_not_required(self, mgr):
        result = mgr.determine_notification_requirement(["logs", "metrics"])
        assert result["required"] is False

    def test_ssn_required(self, mgr):
        result = mgr.determine_notification_requirement(["ssn"])
        assert result["required"] is True

    def test_pii_required(self, mgr):
        result = mgr.determine_notification_requirement(["pii"])
        assert result["required"] is True

    def test_financial_required(self, mgr):
        result = mgr.determine_notification_requirement(["financial"])
        assert result["required"] is True

    def test_medical_required(self, mgr):
        result = mgr.determine_notification_requirement(["medical"])
        assert result["required"] is True

    def test_privileged_required(self, mgr):
        result = mgr.determine_notification_requirement(["privileged"])
        assert result["required"] is True

    def test_ssn_deadline_is_30_days(self, mgr):
        result = mgr.determine_notification_requirement(["ssn"])
        assert result["deadline_days"] == 30

    def test_pii_deadline_is_60_days(self, mgr):
        result = mgr.determine_notification_requirement(["pii"])
        assert result["deadline_days"] == 60

    def test_ssn_plus_pii_uses_shortest_deadline(self, mgr):
        # ssn=30 days, pii=60 days → should pick 30 (shortest)
        result = mgr.determine_notification_requirement(["ssn", "pii"])
        assert result["deadline_days"] == 30

    def test_empty_list_not_required(self, mgr):
        result = mgr.determine_notification_requirement([])
        assert result["required"] is False
        assert result["deadline_days"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# create_assessment
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateAssessment:
    def test_returns_breach_assessment(self, mgr):
        ba = _assess(mgr)
        assert isinstance(ba, BreachAssessment)

    def test_assessment_id_prefix(self, mgr):
        ba = _assess(mgr)
        assert ba.assessment_id.startswith("breach_")

    def test_stored_in_assessments(self, mgr):
        ba = _assess(mgr)
        assert ba.assessment_id in mgr._assessments

    def test_containment_status_investigating(self, mgr):
        ba = _assess(mgr)
        assert ba.containment_status == "investigating"

    def test_status_assessing(self, mgr):
        ba = _assess(mgr)
        assert ba.status == "assessing"

    def test_notification_required_for_pii(self, mgr):
        ba = _assess(mgr, data_types=["pii"])
        assert ba.notification_required is True

    def test_notification_not_required_for_unknown(self, mgr):
        ba = _assess(mgr, data_types=["logs"])
        assert ba.notification_required is False

    def test_notification_deadline_set_for_ssn(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        assert ba.notification_deadline is not None

    def test_notification_deadline_30_days_for_ssn(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        diff = ba.notification_deadline - ba.detected_at
        assert diff.days == 30

    def test_no_deadline_for_no_trigger(self, mgr):
        ba = _assess(mgr, data_types=["system_logs"])
        assert ba.notification_deadline is None

    def test_severity_stored(self, mgr):
        ba = _assess(mgr, severity=BreachSeverity.CRITICAL)
        assert ba.severity == BreachSeverity.CRITICAL

    def test_records_count_stored(self, mgr):
        ba = _assess(mgr, records_count=5000)
        assert ba.affected_records_count == 5000


# ═══════════════════════════════════════════════════════════════════════════════
# update_containment
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpdateContainment:
    def test_returns_true(self, mgr):
        ba = _assess(mgr)
        assert mgr.update_containment(ba.assessment_id, "contained", "admin-1") is True

    def test_status_updated(self, mgr):
        ba = _assess(mgr)
        mgr.update_containment(ba.assessment_id, "remediated", "admin-1")
        assert ba.containment_status == "remediated"

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.update_containment("nonexistent", "contained", "admin-1") is False


# ═══════════════════════════════════════════════════════════════════════════════
# create_notification / mark_notification_sent
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateNotification:
    def test_returns_notification_record(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "portal")
        assert isinstance(notif, NotificationRecord)

    def test_notification_id_prefix(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "portal")
        assert notif.notification_id.startswith("notif_")

    def test_stored_in_notifications(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "portal")
        assert notif.notification_id in mgr._notifications

    def test_status_pending(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        assert notif.status == "pending"


class TestMarkNotificationSent:
    def test_returns_true(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        assert mgr.mark_notification_sent(notif.notification_id) is True

    def test_status_becomes_sent(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        mgr.mark_notification_sent(notif.notification_id)
        assert notif.status == "sent"

    def test_sent_at_set(self, mgr):
        ba = _assess(mgr)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        mgr.mark_notification_sent(notif.notification_id)
        assert notif.sent_at is not None

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.mark_notification_sent("nonexistent") is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_overdue_notifications
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetOverdueNotifications:
    def test_empty_initially(self, mgr):
        assert mgr.get_overdue_notifications() == []

    def test_not_overdue_when_no_notification_required(self, mgr):
        _assess(mgr, data_types=["system_logs"])
        assert mgr.get_overdue_notifications() == []

    def test_overdue_when_past_deadline_with_pending_notif(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        # Set deadline to the past
        ba.notification_deadline = _now() - timedelta(days=1)
        mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        overdue = mgr.get_overdue_notifications()
        assert ba in overdue

    def test_not_overdue_if_closed(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        ba.notification_deadline = _now() - timedelta(days=1)
        ba.status = "closed"
        mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        assert mgr.get_overdue_notifications() == []

    def test_not_overdue_if_notification_sent(self, mgr):
        ba = _assess(mgr, data_types=["ssn"])
        ba.notification_deadline = _now() - timedelta(days=1)
        notif = mgr.create_notification(ba.assessment_id, "regulator", "HHS", "email")
        mgr.mark_notification_sent(notif.notification_id)
        assert mgr.get_overdue_notifications() == []


# ═══════════════════════════════════════════════════════════════════════════════
# get_assessment / list_assessments / close_assessment
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetAssessment:
    def test_returns_none_for_unknown(self, mgr):
        assert mgr.get_assessment("nonexistent") is None

    def test_returns_assessment(self, mgr):
        ba = _assess(mgr)
        assert mgr.get_assessment(ba.assessment_id) is ba


class TestListAssessments:
    def test_empty_initially(self, mgr):
        assert mgr.list_assessments() == []

    def test_returns_all(self, mgr):
        _assess(mgr)
        _assess(mgr)
        assert len(mgr.list_assessments()) == 2

    def test_filter_by_status(self, mgr):
        ba = _assess(mgr)
        mgr.close_assessment(ba.assessment_id, "admin-1")
        assert len(mgr.list_assessments(status="assessing")) == 0
        assert len(mgr.list_assessments(status="closed")) == 1


class TestCloseAssessment:
    def test_returns_true(self, mgr):
        ba = _assess(mgr)
        assert mgr.close_assessment(ba.assessment_id, "admin-1") is True

    def test_status_closed(self, mgr):
        ba = _assess(mgr)
        mgr.close_assessment(ba.assessment_id, "admin-1")
        assert ba.status == "closed"

    def test_returns_false_for_unknown(self, mgr):
        assert mgr.close_assessment("nonexistent", "admin-1") is False

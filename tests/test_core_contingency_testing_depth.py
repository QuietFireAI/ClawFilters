# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_contingency_testing_depth.py
# REM: Depth tests for core/contingency_testing.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone

from core.contingency_testing import (
    ContingencyTest, ContingencyTestManager, ScheduledTest, TestType
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(ContingencyTestManager)
    m._tests = {}
    m._schedules = {}
    return m


def _now():
    return datetime.now(timezone.utc)


def _record(mgr, test_type=TestType.BACKUP_RESTORE, conducted_by="admin-1",
            duration=60, passed=True, findings=None, corrective_actions=None):
    if findings is None:
        findings = []
    if corrective_actions is None:
        corrective_actions = []
    return mgr.record_test_result(
        test_type=test_type,
        conducted_by=conducted_by,
        duration=duration,
        passed=passed,
        findings=findings,
        corrective_actions=corrective_actions
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TestType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestTestType:
    def test_backup_restore(self):
        assert TestType.BACKUP_RESTORE.value == "backup_restore"

    def test_failover(self):
        assert TestType.FAILOVER.value == "failover"

    def test_disaster_recovery(self):
        assert TestType.DISASTER_RECOVERY.value == "disaster_recovery"

    def test_data_integrity(self):
        assert TestType.DATA_INTEGRITY.value == "data_integrity"

    def test_emergency_mode(self):
        assert TestType.EMERGENCY_MODE.value == "emergency_mode"

    def test_five_types(self):
        assert len(TestType) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# ContingencyTest dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestContingencyTestDataclass:
    def test_to_dict_keys(self, mgr):
        ct = _record(mgr)
        d = ct.to_dict()
        assert set(d.keys()) == {
            "test_id", "test_type", "conducted_by", "conducted_at",
            "duration_minutes", "passed", "findings", "corrective_actions",
            "next_scheduled"
        }

    def test_to_dict_test_type_is_string(self, mgr):
        ct = _record(mgr, test_type=TestType.FAILOVER)
        assert ct.to_dict()["test_type"] == "failover"

    def test_to_dict_conducted_at_iso(self, mgr):
        ct = _record(mgr)
        assert isinstance(ct.to_dict()["conducted_at"], str)

    def test_to_dict_passed_true(self, mgr):
        ct = _record(mgr, passed=True)
        assert ct.to_dict()["passed"] is True

    def test_to_dict_passed_false(self, mgr):
        ct = _record(mgr, passed=False)
        assert ct.to_dict()["passed"] is False

    def test_to_dict_next_scheduled_none(self, mgr):
        ct = _record(mgr)
        assert ct.to_dict()["next_scheduled"] is None

    def test_to_dict_findings(self, mgr):
        ct = _record(mgr, findings=["Backup took too long"])
        assert ct.to_dict()["findings"] == ["Backup took too long"]

    def test_to_dict_corrective_actions(self, mgr):
        ct = _record(mgr, corrective_actions=["Upgrade storage"])
        assert ct.to_dict()["corrective_actions"] == ["Upgrade storage"]


# ═══════════════════════════════════════════════════════════════════════════════
# ScheduledTest dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestScheduledTestDataclass:
    def test_to_dict_keys(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        d = sched.to_dict()
        assert set(d.keys()) == {
            "schedule_id", "test_type", "scheduled_for", "conducted_by", "completed"
        }

    def test_to_dict_completed_false(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        assert sched.to_dict()["completed"] is False

    def test_to_dict_test_type_string(self, mgr):
        sched = mgr.schedule_test(TestType.DISASTER_RECOVERY, _now() + timedelta(days=30), "admin-1")
        assert sched.to_dict()["test_type"] == "disaster_recovery"

    def test_to_dict_scheduled_for_iso(self, mgr):
        future = _now() + timedelta(days=30)
        sched = mgr.schedule_test(TestType.FAILOVER, future, "admin-1")
        assert isinstance(sched.to_dict()["scheduled_for"], str)


# ═══════════════════════════════════════════════════════════════════════════════
# schedule_test
# ═══════════════════════════════════════════════════════════════════════════════

class TestScheduleTest:
    def test_returns_scheduled_test(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        assert isinstance(sched, ScheduledTest)

    def test_schedule_id_prefix(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        assert sched.schedule_id.startswith("sched_")

    def test_stored_in_schedules(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        assert sched.schedule_id in mgr._schedules

    def test_not_completed_initially(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "admin-1")
        assert sched.completed is False

    def test_test_type_stored(self, mgr):
        sched = mgr.schedule_test(TestType.DATA_INTEGRITY, _now() + timedelta(days=7), "admin-1")
        assert sched.test_type == TestType.DATA_INTEGRITY

    def test_conducted_by_stored(self, mgr):
        sched = mgr.schedule_test(TestType.FAILOVER, _now() + timedelta(days=30), "dr-team")
        assert sched.conducted_by == "dr-team"


# ═══════════════════════════════════════════════════════════════════════════════
# record_test_result
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecordTestResult:
    def test_returns_contingency_test(self, mgr):
        ct = _record(mgr)
        assert isinstance(ct, ContingencyTest)

    def test_test_id_prefix(self, mgr):
        ct = _record(mgr)
        assert ct.test_id.startswith("ctest_")

    def test_stored_in_tests(self, mgr):
        ct = _record(mgr)
        assert ct.test_id in mgr._tests

    def test_conducted_at_set(self, mgr):
        ct = _record(mgr)
        assert ct.conducted_at is not None

    def test_conducted_by_stored(self, mgr):
        ct = _record(mgr, conducted_by="dr-team")
        assert ct.conducted_by == "dr-team"

    def test_duration_stored(self, mgr):
        ct = _record(mgr, duration=45)
        assert ct.duration_minutes == 45

    def test_passed_stored(self, mgr):
        ct = _record(mgr, passed=False)
        assert ct.passed is False

    def test_findings_stored(self, mgr):
        ct = _record(mgr, findings=["Issue A", "Issue B"])
        assert ct.findings == ["Issue A", "Issue B"]

    def test_corrective_actions_stored(self, mgr):
        ct = _record(mgr, corrective_actions=["Fix A"])
        assert ct.corrective_actions == ["Fix A"]


# ═══════════════════════════════════════════════════════════════════════════════
# get_test_history
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTestHistory:
    def test_empty_initially(self, mgr):
        assert mgr.get_test_history() == []

    def test_returns_all(self, mgr):
        _record(mgr, test_type=TestType.BACKUP_RESTORE)
        _record(mgr, test_type=TestType.FAILOVER)
        assert len(mgr.get_test_history()) == 2

    def test_filter_by_type(self, mgr):
        _record(mgr, test_type=TestType.BACKUP_RESTORE)
        _record(mgr, test_type=TestType.FAILOVER)
        result = mgr.get_test_history(test_type=TestType.BACKUP_RESTORE)
        assert len(result) == 1
        assert result[0].test_type == TestType.BACKUP_RESTORE

    def test_sorted_newest_first(self, mgr):
        ct1 = _record(mgr, test_type=TestType.BACKUP_RESTORE)
        ct2 = _record(mgr, test_type=TestType.BACKUP_RESTORE)
        # Manually set conducted_at to ensure ordering
        ct1.conducted_at = _now() - timedelta(hours=2)
        ct2.conducted_at = _now() - timedelta(hours=1)
        history = mgr.get_test_history()
        assert history[0].test_id == ct2.test_id

    def test_no_filter_returns_all_types(self, mgr):
        for ttype in TestType:
            _record(mgr, test_type=ttype)
        assert len(mgr.get_test_history()) == len(TestType)


# ═══════════════════════════════════════════════════════════════════════════════
# get_overdue_tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetOverdueTests:
    def test_all_overdue_with_no_tests(self, mgr):
        overdue = mgr.get_overdue_tests(interval_days=90)
        assert set(overdue) == set(TestType)

    def test_recent_test_not_overdue(self, mgr):
        ct = _record(mgr, test_type=TestType.BACKUP_RESTORE)
        ct.conducted_at = _now() - timedelta(days=30)
        overdue = mgr.get_overdue_tests(interval_days=90)
        assert TestType.BACKUP_RESTORE not in overdue

    def test_old_test_overdue(self, mgr):
        ct = _record(mgr, test_type=TestType.FAILOVER)
        ct.conducted_at = _now() - timedelta(days=120)
        overdue = mgr.get_overdue_tests(interval_days=90)
        assert TestType.FAILOVER in overdue

    def test_mixed_overdue(self, mgr):
        # BACKUP_RESTORE is recent → not overdue
        ct1 = _record(mgr, test_type=TestType.BACKUP_RESTORE)
        ct1.conducted_at = _now() - timedelta(days=10)
        overdue = mgr.get_overdue_tests(interval_days=90)
        assert TestType.BACKUP_RESTORE not in overdue
        assert TestType.FAILOVER in overdue  # never tested

    def test_custom_interval(self, mgr):
        ct = _record(mgr, test_type=TestType.DATA_INTEGRITY)
        ct.conducted_at = _now() - timedelta(days=10)
        # 5-day interval → overdue
        overdue = mgr.get_overdue_tests(interval_days=5)
        assert TestType.DATA_INTEGRITY in overdue


# ═══════════════════════════════════════════════════════════════════════════════
# get_compliance_summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetComplianceSummary:
    def test_has_generated_at(self, mgr):
        summary = mgr.get_compliance_summary()
        assert "generated_at" in summary

    def test_has_test_types(self, mgr):
        summary = mgr.get_compliance_summary()
        assert "test_types" in summary

    def test_all_test_types_present(self, mgr):
        summary = mgr.get_compliance_summary()
        for ttype in TestType:
            assert ttype.value in summary["test_types"]

    def test_no_tests_gives_zero_counts(self, mgr):
        summary = mgr.get_compliance_summary()
        br = summary["test_types"][TestType.BACKUP_RESTORE.value]
        assert br["total_tests"] == 0
        assert br["pass_count"] == 0
        assert br["fail_count"] == 0
        assert br["last_tested"] is None

    def test_one_pass_recorded(self, mgr):
        _record(mgr, test_type=TestType.FAILOVER, passed=True)
        summary = mgr.get_compliance_summary()
        fo = summary["test_types"][TestType.FAILOVER.value]
        assert fo["total_tests"] == 1
        assert fo["pass_count"] == 1
        assert fo["fail_count"] == 0
        assert fo["last_passed"] is True

    def test_one_fail_recorded(self, mgr):
        _record(mgr, test_type=TestType.FAILOVER, passed=False)
        summary = mgr.get_compliance_summary()
        fo = summary["test_types"][TestType.FAILOVER.value]
        assert fo["pass_count"] == 0
        assert fo["fail_count"] == 1
        assert fo["last_passed"] is False

    def test_mixed_pass_fail(self, mgr):
        _record(mgr, test_type=TestType.DISASTER_RECOVERY, passed=True)
        _record(mgr, test_type=TestType.DISASTER_RECOVERY, passed=False)
        summary = mgr.get_compliance_summary()
        dr = summary["test_types"][TestType.DISASTER_RECOVERY.value]
        assert dr["total_tests"] == 2
        assert dr["pass_count"] == 1
        assert dr["fail_count"] == 1

    def test_last_tested_iso_string(self, mgr):
        _record(mgr, test_type=TestType.EMERGENCY_MODE)
        summary = mgr.get_compliance_summary()
        em = summary["test_types"][TestType.EMERGENCY_MODE.value]
        assert isinstance(em["last_tested"], str)

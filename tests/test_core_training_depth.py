# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_training_depth.py
# REM: Depth coverage for core/training.py
# REM: TrainingType, TrainingRecord, TrainingRequirement, TrainingManager — in-memory.

import pytest
from datetime import datetime, timedelta, timezone

from core.training import (
    TrainingType,
    TrainingRecord,
    TrainingRequirement,
    TrainingManager,
    _ALL_ROLES,
)
from core.rbac import Role


# ─── Patch Redis so audit.log() uses in-memory path ────────────────────────────
@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def manager():
    """Bypass __init__ to avoid _load_from_redis() hitting compliance_store."""
    m = object.__new__(TrainingManager)
    m._records = []
    m._requirements = {}
    m._register_defaults()
    return m


def _complete(manager, user_id="user-001",
              ttype=TrainingType.HIPAA_PRIVACY, score=90.0, passed=True):
    return manager.record_completion(user_id, ttype, score, passed)


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrainingType:
    def test_hipaa_privacy_value(self):
        assert TrainingType.HIPAA_PRIVACY == "hipaa_privacy"

    def test_hipaa_security_value(self):
        assert TrainingType.HIPAA_SECURITY == "hipaa_security"

    def test_incident_response_value(self):
        assert TrainingType.INCIDENT_RESPONSE == "incident_response"

    def test_phishing_awareness_value(self):
        assert TrainingType.PHISHING_AWARENESS == "phishing_awareness"

    def test_data_handling_value(self):
        assert TrainingType.DATA_HANDLING == "data_handling"

    def test_annual_refresher_value(self):
        assert TrainingType.ANNUAL_REFRESHER == "annual_refresher"

    def test_six_members(self):
        assert len(TrainingType) == 6

    def test_is_str_subclass(self):
        assert isinstance(TrainingType.HIPAA_PRIVACY, str)


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingRecord.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrainingRecordToDict:
    def _make_record(self, **kwargs):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        defaults = dict(
            record_id="train_abc",
            user_id="user-001",
            training_type=TrainingType.HIPAA_PRIVACY,
            completed_at=ts,
            expires_at=ts + timedelta(days=365),
            score=90.0,
            passed=True,
            certificate_id="cert_xyz",
        )
        defaults.update(kwargs)
        return TrainingRecord(**defaults)

    def test_returns_dict(self):
        r = self._make_record()
        assert isinstance(r.to_dict(), dict)

    def test_record_id_present(self):
        r = self._make_record(record_id="train_xyz")
        assert r.to_dict()["record_id"] == "train_xyz"

    def test_user_id_present(self):
        r = self._make_record(user_id="user-999")
        assert r.to_dict()["user_id"] == "user-999"

    def test_training_type_is_value(self):
        r = self._make_record(training_type=TrainingType.HIPAA_SECURITY)
        assert r.to_dict()["training_type"] == "hipaa_security"

    def test_completed_at_isoformat(self):
        ts = datetime(2026, 3, 1, tzinfo=timezone.utc)
        r = self._make_record(completed_at=ts)
        assert r.to_dict()["completed_at"] == ts.isoformat()

    def test_expires_at_isoformat(self):
        ts = datetime(2027, 3, 1, tzinfo=timezone.utc)
        r = self._make_record(expires_at=ts)
        assert r.to_dict()["expires_at"] == ts.isoformat()

    def test_score_present(self):
        r = self._make_record(score=85.5)
        assert r.to_dict()["score"] == 85.5

    def test_score_none_allowed(self):
        r = self._make_record(score=None)
        assert r.to_dict()["score"] is None

    def test_passed_true(self):
        r = self._make_record(passed=True)
        assert r.to_dict()["passed"] is True

    def test_passed_false(self):
        r = self._make_record(passed=False)
        assert r.to_dict()["passed"] is False

    def test_certificate_id_present(self):
        r = self._make_record(certificate_id="cert_abc")
        assert r.to_dict()["certificate_id"] == "cert_abc"

    def test_certificate_id_none(self):
        r = self._make_record(certificate_id=None)
        assert r.to_dict()["certificate_id"] is None

    def test_all_eight_keys_present(self):
        r = self._make_record()
        expected = {
            "record_id", "user_id", "training_type", "completed_at",
            "expires_at", "score", "passed", "certificate_id"
        }
        assert set(r.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingRequirement.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrainingRequirementToDict:
    def test_returns_dict(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles={Role.VIEWER},
            renewal_period_days=365,
            minimum_score=80.0
        )
        assert isinstance(req.to_dict(), dict)

    def test_training_type_is_value(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_SECURITY,
            required_for_roles={Role.ADMIN},
            renewal_period_days=365,
            minimum_score=80.0
        )
        assert req.to_dict()["training_type"] == "hipaa_security"

    def test_required_for_roles_is_list(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles={Role.VIEWER, Role.ADMIN},
            renewal_period_days=365,
            minimum_score=80.0
        )
        assert isinstance(req.to_dict()["required_for_roles"], list)

    def test_required_for_roles_contains_role_values(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles={Role.VIEWER},
            renewal_period_days=365,
            minimum_score=80.0
        )
        assert "viewer" in req.to_dict()["required_for_roles"]

    def test_renewal_period_days(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles=set(),
            renewal_period_days=180,
            minimum_score=70.0
        )
        assert req.to_dict()["renewal_period_days"] == 180

    def test_minimum_score(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles=set(),
            renewal_period_days=365,
            minimum_score=75.0
        )
        assert req.to_dict()["minimum_score"] == 75.0

    def test_all_four_keys_present(self):
        req = TrainingRequirement(
            training_type=TrainingType.HIPAA_PRIVACY,
            required_for_roles=set(),
            renewal_period_days=365,
            minimum_score=80.0
        )
        expected = {"training_type", "required_for_roles", "renewal_period_days", "minimum_score"}
        assert set(req.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager — default requirements
# ═══════════════════════════════════════════════════════════════════════════════

class TestDefaultRequirements:
    def test_six_requirements_registered(self, manager):
        assert len(manager._requirements) == 6

    def test_hipaa_privacy_registered(self, manager):
        assert TrainingType.HIPAA_PRIVACY in manager._requirements

    def test_hipaa_security_registered(self, manager):
        assert TrainingType.HIPAA_SECURITY in manager._requirements

    def test_incident_response_registered(self, manager):
        assert TrainingType.INCIDENT_RESPONSE in manager._requirements

    def test_phishing_awareness_registered(self, manager):
        assert TrainingType.PHISHING_AWARENESS in manager._requirements

    def test_data_handling_registered(self, manager):
        assert TrainingType.DATA_HANDLING in manager._requirements

    def test_annual_refresher_registered(self, manager):
        assert TrainingType.ANNUAL_REFRESHER in manager._requirements

    def test_hipaa_privacy_min_score_80(self, manager):
        assert manager._requirements[TrainingType.HIPAA_PRIVACY].minimum_score == 80.0

    def test_phishing_awareness_renewal_180_days(self, manager):
        assert manager._requirements[TrainingType.PHISHING_AWARENESS].renewal_period_days == 180

    def test_hipaa_privacy_applies_to_all_roles(self, manager):
        req = manager._requirements[TrainingType.HIPAA_PRIVACY]
        assert req.required_for_roles == _ALL_ROLES


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.add_requirement()
# ═══════════════════════════════════════════════════════════════════════════════

class TestAddRequirement:
    def test_stores_requirement(self, manager):
        manager.add_requirement(TrainingType.HIPAA_PRIVACY, {Role.VIEWER}, 90, 75.0)
        req = manager._requirements[TrainingType.HIPAA_PRIVACY]
        assert req.minimum_score == 75.0

    def test_overrides_existing(self, manager):
        manager.add_requirement(TrainingType.HIPAA_PRIVACY, {Role.VIEWER}, 90, 99.0)
        assert manager._requirements[TrainingType.HIPAA_PRIVACY].minimum_score == 99.0

    def test_new_requirement_counted(self, manager):
        initial = len(manager._requirements)
        # All types are already registered, just overriding
        manager.add_requirement(TrainingType.ANNUAL_REFRESHER, {Role.ADMIN}, 180, 70.0)
        assert len(manager._requirements) == initial


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.record_completion()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecordCompletion:
    def test_returns_training_record(self, manager):
        r = _complete(manager)
        assert isinstance(r, TrainingRecord)

    def test_record_id_has_prefix(self, manager):
        r = _complete(manager)
        assert r.record_id.startswith("train_")

    def test_user_id_stored(self, manager):
        r = _complete(manager, user_id="user-555")
        assert r.user_id == "user-555"

    def test_training_type_stored(self, manager):
        r = _complete(manager, ttype=TrainingType.HIPAA_SECURITY)
        assert r.training_type == TrainingType.HIPAA_SECURITY

    def test_score_stored(self, manager):
        r = _complete(manager, score=92.5)
        assert r.score == 92.5

    def test_passed_stored(self, manager):
        r = _complete(manager, passed=True)
        assert r.passed is True

    def test_failed_has_no_certificate(self, manager):
        r = _complete(manager, passed=False)
        assert r.certificate_id is None

    def test_passed_has_certificate(self, manager):
        r = _complete(manager, passed=True)
        assert r.certificate_id is not None
        assert r.certificate_id.startswith("cert_")

    def test_expires_at_set_from_requirement(self, manager):
        r = _complete(manager, ttype=TrainingType.HIPAA_PRIVACY)
        # HIPAA_PRIVACY has 365-day renewal
        delta = r.expires_at - r.completed_at
        assert abs(delta.days - 365) <= 1

    def test_phishing_expires_in_180_days(self, manager):
        r = _complete(manager, ttype=TrainingType.PHISHING_AWARENESS)
        delta = r.expires_at - r.completed_at
        assert abs(delta.days - 180) <= 1

    def test_record_appended_to_list(self, manager):
        _complete(manager)
        assert len(manager._records) == 1

    def test_multiple_records_stored(self, manager):
        _complete(manager, user_id="u1")
        _complete(manager, user_id="u2")
        assert len(manager._records) == 2

    def test_training_type_as_string_accepted(self, manager):
        r = manager.record_completion("user-001", "hipaa_privacy", 80.0, True)
        assert r.training_type == TrainingType.HIPAA_PRIVACY


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.get_overdue_trainings()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetOverdueTrainings:
    def test_returns_list(self, manager):
        assert isinstance(manager.get_overdue_trainings("user-001", {Role.VIEWER}), list)

    def test_no_completions_all_required_trainings_overdue(self, manager):
        # A viewer needs HIPAA_PRIVACY, HIPAA_SECURITY, PHISHING_AWARENESS, DATA_HANDLING, ANNUAL_REFRESHER
        # (INCIDENT_RESPONSE is not required for VIEWER)
        overdue = manager.get_overdue_trainings("user-001", {Role.VIEWER})
        assert len(overdue) > 0

    def test_completed_training_not_overdue(self, manager):
        _complete(manager, user_id="user-001", ttype=TrainingType.HIPAA_PRIVACY, passed=True)
        overdue = manager.get_overdue_trainings("user-001", {Role.VIEWER})
        assert TrainingType.HIPAA_PRIVACY not in overdue

    def test_failed_training_still_overdue(self, manager):
        _complete(manager, user_id="user-001", ttype=TrainingType.HIPAA_PRIVACY, passed=False)
        overdue = manager.get_overdue_trainings("user-001", {Role.VIEWER})
        assert TrainingType.HIPAA_PRIVACY in overdue

    def test_expired_training_overdue(self, manager):
        # Add a record that completed and expired
        ts = datetime.now(timezone.utc) - timedelta(days=400)
        manager._records.append(TrainingRecord(
            record_id="train_old",
            user_id="user-001",
            training_type=TrainingType.HIPAA_PRIVACY,
            completed_at=ts,
            expires_at=ts + timedelta(days=365),  # Expired
            score=90.0,
            passed=True,
        ))
        overdue = manager.get_overdue_trainings("user-001", {Role.VIEWER})
        assert TrainingType.HIPAA_PRIVACY in overdue

    def test_incident_response_not_required_for_viewer(self, manager):
        # INCIDENT_RESPONSE is not required for VIEWER role
        overdue = manager.get_overdue_trainings("user-001", {Role.VIEWER})
        assert TrainingType.INCIDENT_RESPONSE not in overdue

    def test_incident_response_required_for_admin(self, manager):
        overdue = manager.get_overdue_trainings("user-001", {Role.ADMIN})
        assert TrainingType.INCIDENT_RESPONSE in overdue


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.is_compliant()
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsCompliant:
    def test_not_compliant_with_no_training(self, manager):
        assert manager.is_compliant("user-001", {Role.VIEWER}) is False

    def test_returns_bool(self, manager):
        assert isinstance(manager.is_compliant("user-001", {Role.VIEWER}), bool)

    def test_compliant_when_all_completed(self, manager):
        # Complete all required trainings for VIEWER
        required = [t for t, req in manager._requirements.items()
                    if req.required_for_roles.intersection({Role.VIEWER})]
        for ttype in required:
            _complete(manager, user_id="user-001", ttype=ttype, passed=True)
        assert manager.is_compliant("user-001", {Role.VIEWER}) is True


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.get_compliance_status()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetComplianceStatus:
    def test_returns_dict(self, manager):
        assert isinstance(manager.get_compliance_status("user-001"), dict)

    def test_has_user_id(self, manager):
        status = manager.get_compliance_status("user-001")
        assert status["user_id"] == "user-001"

    def test_has_total_completions(self, manager):
        status = manager.get_compliance_status("user-001")
        assert "total_completions" in status

    def test_has_passed(self, manager):
        status = manager.get_compliance_status("user-001")
        assert "passed" in status

    def test_has_current_valid(self, manager):
        status = manager.get_compliance_status("user-001")
        assert "current_valid" in status

    def test_has_expired(self, manager):
        status = manager.get_compliance_status("user-001")
        assert "expired" in status

    def test_has_records(self, manager):
        status = manager.get_compliance_status("user-001")
        assert "records" in status
        assert isinstance(status["records"], list)

    def test_counts_increase_after_completion(self, manager):
        _complete(manager, user_id="user-001", passed=True)
        status = manager.get_compliance_status("user-001")
        assert status["total_completions"] == 1
        assert status["passed"] == 1
        assert status["current_valid"] == 1

    def test_failed_not_counted_in_passed(self, manager):
        _complete(manager, user_id="user-001", passed=False)
        status = manager.get_compliance_status("user-001")
        assert status["total_completions"] == 1
        assert status["passed"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# TrainingManager.get_compliance_report()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetComplianceReport:
    def test_returns_dict(self, manager):
        assert isinstance(manager.get_compliance_report(), dict)

    def test_has_generated_at(self, manager):
        report = manager.get_compliance_report()
        assert "generated_at" in report
        assert report["generated_at"] != ""

    def test_has_total_completions(self, manager):
        assert "total_completions" in manager.get_compliance_report()

    def test_has_passed(self, manager):
        assert "passed" in manager.get_compliance_report()

    def test_has_failed(self, manager):
        assert "failed" in manager.get_compliance_report()

    def test_has_current_valid(self, manager):
        assert "current_valid" in manager.get_compliance_report()

    def test_has_unique_users_trained(self, manager):
        assert "unique_users_trained" in manager.get_compliance_report()

    def test_has_requirements_count(self, manager):
        report = manager.get_compliance_report()
        assert "requirements_count" in report
        assert report["requirements_count"] == 6

    def test_has_requirements_dict(self, manager):
        assert "requirements" in manager.get_compliance_report()
        assert isinstance(manager.get_compliance_report()["requirements"], dict)

    def test_empty_manager_zeroes(self, manager):
        report = manager.get_compliance_report()
        assert report["total_completions"] == 0
        assert report["unique_users_trained"] == 0

    def test_counts_after_completions(self, manager):
        _complete(manager, user_id="u1", passed=True)
        _complete(manager, user_id="u2", passed=False)
        report = manager.get_compliance_report()
        assert report["total_completions"] == 2
        assert report["passed"] == 1
        assert report["failed"] == 1
        assert report["unique_users_trained"] == 2

    def test_get_overdue_training_alias(self, manager):
        result = manager.get_overdue_training("user-001")
        assert isinstance(result, list)
        assert all(isinstance(t, str) for t in result)

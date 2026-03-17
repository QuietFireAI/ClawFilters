# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_phi_disclosure_depth.py
# REM: Depth tests for core/phi_disclosure.py — pure in-memory, no external deps

import pytest
from datetime import datetime, timedelta, timezone

from core.phi_disclosure import (
    HIPAA_RETENTION_YEARS,
    PHIDisclosureManager,
    PHIDisclosureRecord,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    m = object.__new__(PHIDisclosureManager)
    m._disclosures = {}
    return m


def _now():
    return datetime.now(timezone.utc)


def _record(mgr, patient_id="p1", recipient="Lab Corp",
            purpose="Treatment", phi_description="CBC results",
            recorded_by="nurse-1", date_of_disclosure=None):
    return mgr.record_disclosure(
        patient_id=patient_id,
        recipient=recipient,
        purpose=purpose,
        phi_description=phi_description,
        recorded_by=recorded_by,
        date_of_disclosure=date_of_disclosure
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

class TestConstants:
    def test_hipaa_retention_years(self):
        assert HIPAA_RETENTION_YEARS == 6


# ═══════════════════════════════════════════════════════════════════════════════
# PHIDisclosureRecord dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestPHIDisclosureRecord:
    def test_to_dict_key_count(self, mgr):
        rec = _record(mgr)
        d = rec.to_dict()
        assert len(d) == 7

    def test_to_dict_all_keys(self, mgr):
        rec = _record(mgr)
        assert set(rec.to_dict().keys()) == {
            "disclosure_id", "patient_id", "recipient", "purpose",
            "phi_description", "date_of_disclosure", "recorded_by"
        }

    def test_to_dict_disclosure_id(self, mgr):
        rec = _record(mgr)
        assert rec.to_dict()["disclosure_id"] == rec.disclosure_id

    def test_to_dict_patient_id(self, mgr):
        rec = _record(mgr, patient_id="patient-99")
        assert rec.to_dict()["patient_id"] == "patient-99"

    def test_to_dict_recipient(self, mgr):
        rec = _record(mgr, recipient="Specialty Clinic")
        assert rec.to_dict()["recipient"] == "Specialty Clinic"

    def test_to_dict_purpose(self, mgr):
        rec = _record(mgr, purpose="Legal Proceeding")
        assert rec.to_dict()["purpose"] == "Legal Proceeding"

    def test_to_dict_phi_description(self, mgr):
        rec = _record(mgr, phi_description="Full medical history")
        assert rec.to_dict()["phi_description"] == "Full medical history"

    def test_to_dict_date_iso_string(self, mgr):
        rec = _record(mgr)
        assert isinstance(rec.to_dict()["date_of_disclosure"], str)

    def test_to_dict_recorded_by(self, mgr):
        rec = _record(mgr, recorded_by="doctor-1")
        assert rec.to_dict()["recorded_by"] == "doctor-1"


# ═══════════════════════════════════════════════════════════════════════════════
# record_disclosure
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecordDisclosure:
    def test_returns_phi_disclosure_record(self, mgr):
        rec = _record(mgr)
        assert isinstance(rec, PHIDisclosureRecord)

    def test_disclosure_id_prefix(self, mgr):
        rec = _record(mgr)
        assert rec.disclosure_id.startswith("phi_disc_")

    def test_stored_under_patient(self, mgr):
        rec = _record(mgr, patient_id="p1")
        assert "p1" in mgr._disclosures
        assert rec in mgr._disclosures["p1"]

    def test_multiple_patients_separate(self, mgr):
        _record(mgr, patient_id="p1")
        _record(mgr, patient_id="p2")
        assert len(mgr._disclosures) == 2

    def test_multiple_disclosures_same_patient(self, mgr):
        _record(mgr, patient_id="p1")
        _record(mgr, patient_id="p1")
        assert len(mgr._disclosures["p1"]) == 2

    def test_custom_date_used(self, mgr):
        custom_date = _now() - timedelta(days=10)
        rec = _record(mgr, date_of_disclosure=custom_date)
        assert rec.date_of_disclosure == custom_date

    def test_defaults_to_now(self, mgr):
        before = _now()
        rec = _record(mgr)
        after = _now()
        assert before <= rec.date_of_disclosure <= after

    def test_patient_id_stored(self, mgr):
        rec = _record(mgr, patient_id="pat-abc")
        assert rec.patient_id == "pat-abc"

    def test_recipient_stored(self, mgr):
        rec = _record(mgr, recipient="External Lab")
        assert rec.recipient == "External Lab"


# ═══════════════════════════════════════════════════════════════════════════════
# get_disclosures_for_patient
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetDisclosuresForPatient:
    def test_empty_for_unknown_patient(self, mgr):
        assert mgr.get_disclosures_for_patient("unknown") == []

    def test_returns_patient_disclosures(self, mgr):
        _record(mgr, patient_id="p1")
        result = mgr.get_disclosures_for_patient("p1")
        assert len(result) == 1

    def test_no_cross_patient_leak(self, mgr):
        _record(mgr, patient_id="p1")
        _record(mgr, patient_id="p2")
        result = mgr.get_disclosures_for_patient("p1")
        assert all(r.patient_id == "p1" for r in result)

    def test_to_date_filter(self, mgr):
        old = _now() - timedelta(days=30)
        recent = _now() - timedelta(days=5)
        _record(mgr, patient_id="p1", date_of_disclosure=old)
        _record(mgr, patient_id="p1", date_of_disclosure=recent)
        cutoff = _now() - timedelta(days=10)
        result = mgr.get_disclosures_for_patient("p1", to_date=cutoff)
        assert len(result) == 1

    def test_from_date_filter(self, mgr):
        old = _now() - timedelta(days=100)
        recent = _now() - timedelta(days=5)
        _record(mgr, patient_id="p1", date_of_disclosure=old)
        _record(mgr, patient_id="p1", date_of_disclosure=recent)
        cutoff = _now() - timedelta(days=50)
        result = mgr.get_disclosures_for_patient("p1", from_date=cutoff)
        assert len(result) == 1

    def test_older_than_six_years_excluded(self, mgr):
        very_old = _now() - timedelta(days=365 * 7)
        _record(mgr, patient_id="p1", date_of_disclosure=very_old)
        result = mgr.get_disclosures_for_patient("p1")
        assert len(result) == 0

    def test_within_six_years_included(self, mgr):
        five_years_ago = _now() - timedelta(days=365 * 5)
        _record(mgr, patient_id="p1", date_of_disclosure=five_years_ago)
        result = mgr.get_disclosures_for_patient("p1")
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# generate_accounting_report / get_accounting_report
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateAccountingReport:
    def test_returns_dict(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert isinstance(report, dict)

    def test_report_id_prefix(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert report["report_id"].startswith("phi_rpt_")

    def test_patient_id_in_report(self, mgr):
        report = mgr.generate_accounting_report("patient-77")
        assert report["patient_id"] == "patient-77"

    def test_zero_disclosures_for_new_patient(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert report["total_disclosures"] == 0
        assert report["disclosures"] == []

    def test_disclosures_count_matches(self, mgr):
        _record(mgr, patient_id="p1")
        _record(mgr, patient_id="p1")
        report = mgr.generate_accounting_report("p1")
        assert report["total_disclosures"] == 2
        assert len(report["disclosures"]) == 2

    def test_has_hipaa_reference(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert "hipaa_reference" in report
        assert "164.528" in report["hipaa_reference"]

    def test_retention_years_field(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert report["retention_years"] == HIPAA_RETENTION_YEARS

    def test_has_generated_at(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert "generated_at" in report

    def test_has_retention_window_start(self, mgr):
        report = mgr.generate_accounting_report("p1")
        assert "retention_window_start" in report

    def test_get_accounting_report_alias(self, mgr):
        r1 = mgr.generate_accounting_report("p1")
        r2 = mgr.get_accounting_report("p1")
        # Both should have same structure (different report_id since called twice)
        assert r1["patient_id"] == r2["patient_id"]
        assert "report_id" in r2


# ═══════════════════════════════════════════════════════════════════════════════
# get_disclosure_count
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetDisclosureCount:
    def test_returns_dict(self, mgr):
        result = mgr.get_disclosure_count()
        assert isinstance(result, dict)

    def test_all_keys_present(self, mgr):
        result = mgr.get_disclosure_count()
        assert set(result.keys()) == {
            "total_patients_with_disclosures",
            "total_disclosure_records",
            "within_retention_window",
            "retention_window_years",
            "as_of"
        }

    def test_zero_counts_initially(self, mgr):
        result = mgr.get_disclosure_count()
        assert result["total_patients_with_disclosures"] == 0
        assert result["total_disclosure_records"] == 0
        assert result["within_retention_window"] == 0

    def test_retention_window_years(self, mgr):
        result = mgr.get_disclosure_count()
        assert result["retention_window_years"] == HIPAA_RETENTION_YEARS

    def test_counts_after_records(self, mgr):
        _record(mgr, patient_id="p1")
        _record(mgr, patient_id="p2")
        result = mgr.get_disclosure_count()
        assert result["total_patients_with_disclosures"] == 2
        assert result["total_disclosure_records"] == 2
        assert result["within_retention_window"] == 2

    def test_old_disclosure_not_in_retention(self, mgr):
        seven_years_ago = _now() - timedelta(days=365 * 7)
        _record(mgr, patient_id="p1", date_of_disclosure=seven_years_ago)
        result = mgr.get_disclosure_count()
        assert result["total_disclosure_records"] == 1
        assert result["within_retention_window"] == 0

    def test_as_of_is_string(self, mgr):
        result = mgr.get_disclosure_count()
        assert isinstance(result["as_of"], str)


# ═══════════════════════════════════════════════════════════════════════════════
# get_disclosure
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetDisclosure:
    def test_returns_none_for_unknown(self, mgr):
        assert mgr.get_disclosure("nonexistent") is None

    def test_returns_record_by_id(self, mgr):
        rec = _record(mgr, patient_id="p1")
        found = mgr.get_disclosure(rec.disclosure_id)
        assert found is rec

    def test_finds_across_patients(self, mgr):
        _record(mgr, patient_id="p1")
        rec2 = _record(mgr, patient_id="p2")
        found = mgr.get_disclosure(rec2.disclosure_id)
        assert found is rec2

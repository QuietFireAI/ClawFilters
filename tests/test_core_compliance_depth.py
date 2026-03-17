# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_compliance_depth.py
# REM: Depth tests for core/compliance.py — pure in-memory, no external deps

import json
import pytest
from datetime import datetime, timedelta, timezone

from core.compliance import (
    ComplianceControl,
    ComplianceEngine,
    ComplianceFramework,
    ComplianceReport,
    ControlStatus,
    SOC2_CONTROLS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _now():
    return datetime.now(timezone.utc)


def _period():
    end = _now()
    start = end - timedelta(days=30)
    return start, end


@pytest.fixture
def engine():
    return ComplianceEngine()


def _make_control(evidence_required=None):
    return ComplianceControl(
        control_id="CC1.1",
        framework=ComplianceFramework.SOC2,
        title="Test Control",
        description="A test control",
        category="Test Category",
        evidence_required=evidence_required or ["auth_logs"],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceFramework enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestComplianceFramework:
    def test_soc2_value(self):
        assert ComplianceFramework.SOC2.value == "soc2"

    def test_iso27001_value(self):
        assert ComplianceFramework.ISO27001.value == "iso27001"

    def test_nist_value(self):
        assert ComplianceFramework.NIST.value == "nist"

    def test_custom_value(self):
        assert ComplianceFramework.CUSTOM.value == "custom"

    def test_four_frameworks(self):
        assert len(ComplianceFramework) == 4


# ═══════════════════════════════════════════════════════════════════════════════
# ControlStatus enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestControlStatus:
    def test_compliant_value(self):
        assert ControlStatus.COMPLIANT.value == "compliant"

    def test_partial_value(self):
        assert ControlStatus.PARTIAL.value == "partial"

    def test_non_compliant_value(self):
        assert ControlStatus.NON_COMPLIANT.value == "non_compliant"

    def test_not_applicable_value(self):
        assert ControlStatus.NOT_APPLICABLE.value == "not_applicable"

    def test_needs_evidence_value(self):
        assert ControlStatus.NEEDS_EVIDENCE.value == "needs_evidence"

    def test_five_statuses(self):
        assert len(ControlStatus) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# SOC2_CONTROLS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSOC2Controls:
    def test_has_ten_controls(self):
        assert len(SOC2_CONTROLS) == 10

    def test_each_has_control_id(self):
        for ctrl in SOC2_CONTROLS:
            assert "control_id" in ctrl

    def test_each_has_category(self):
        for ctrl in SOC2_CONTROLS:
            assert "category" in ctrl

    def test_each_has_evidence_required(self):
        for ctrl in SOC2_CONTROLS:
            assert "evidence_required" in ctrl
            assert isinstance(ctrl["evidence_required"], list)

    def test_cc6_1_present(self):
        ids = [c["control_id"] for c in SOC2_CONTROLS]
        assert "CC6.1" in ids

    def test_cc8_1_present(self):
        ids = [c["control_id"] for c in SOC2_CONTROLS]
        assert "CC8.1" in ids


# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceEngine init
# ═══════════════════════════════════════════════════════════════════════════════

class TestComplianceEngineInit:
    def test_reports_empty_initially(self, engine):
        assert len(engine._reports) == 0

    def test_evidence_sources_dict_exists(self, engine):
        assert isinstance(engine._evidence_sources, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# register_evidence_source / collect_evidence
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegisterEvidenceSource:
    def test_registered_source_callable(self, engine):
        engine.register_evidence_source("test_type", lambda s, e: [])
        assert "test_type" in engine._evidence_sources

    def test_collect_returns_empty_for_unregistered(self, engine):
        start, end = _period()
        result = engine.collect_evidence("unknown_type", start, end)
        assert result == []

    def test_collect_calls_registered_function(self, engine):
        sentinel = [{"type": "auth", "source": "test"}]
        engine.register_evidence_source("auth_type", lambda s, e: sentinel)
        start, end = _period()
        result = engine.collect_evidence("auth_type", start, end)
        assert result == sentinel

    def test_collect_passes_period_to_function(self, engine):
        received = {}

        def _capture(s, e):
            received["start"] = s
            received["end"] = e
            return []

        engine.register_evidence_source("capture_type", _capture)
        start, end = _period()
        engine.collect_evidence("capture_type", start, end)
        assert received["start"] == start
        assert received["end"] == end

    def test_collect_handles_exception_gracefully(self, engine):
        def _bad(s, e):
            raise RuntimeError("simulated failure")

        engine.register_evidence_source("bad_type", _bad)
        start, end = _period()
        result = engine.collect_evidence("bad_type", start, end)
        assert result == []

    def test_overwrite_existing_source(self, engine):
        engine.register_evidence_source("t", lambda s, e: [{"v": 1}])
        engine.register_evidence_source("t", lambda s, e: [{"v": 2}])
        start, end = _period()
        result = engine.collect_evidence("t", start, end)
        assert result[0]["v"] == 2


# ═══════════════════════════════════════════════════════════════════════════════
# assess_control
# ═══════════════════════════════════════════════════════════════════════════════

class TestAssessControl:
    def test_needs_evidence_when_no_sources(self, engine):
        ctrl = _make_control(["auth_logs"])
        assessed = engine.assess_control(ctrl, *_period())
        assert assessed.status == ControlStatus.NEEDS_EVIDENCE

    def test_compliant_when_all_evidence_collected(self, engine):
        engine.register_evidence_source("auth_logs", lambda s, e: [{"x": 1}])
        ctrl = _make_control(["auth_logs"])
        assessed = engine.assess_control(ctrl, *_period())
        assert assessed.status == ControlStatus.COMPLIANT

    def test_partial_when_some_evidence_collected(self, engine):
        engine.register_evidence_source("source_a", lambda s, e: [{"x": 1}])
        # source_b not registered → no evidence
        ctrl = _make_control(["source_a", "source_b"])
        assessed = engine.assess_control(ctrl, *_period())
        assert assessed.status == ControlStatus.PARTIAL

    def test_last_assessed_set(self, engine):
        ctrl = _make_control()
        before = _now()
        engine.assess_control(ctrl, *_period())
        assert ctrl.last_assessed is not None
        assert ctrl.last_assessed >= before

    def test_evidence_collected_populated(self, engine):
        engine.register_evidence_source("auth_logs", lambda s, e: [{"t": 1}, {"t": 2}])
        ctrl = _make_control(["auth_logs"])
        engine.assess_control(ctrl, *_period())
        assert len(ctrl.evidence_collected) == 2

    def test_evidence_aggregated_across_types(self, engine):
        engine.register_evidence_source("type_a", lambda s, e: [{"v": "a"}])
        engine.register_evidence_source("type_b", lambda s, e: [{"v": "b"}])
        ctrl = _make_control(["type_a", "type_b"])
        engine.assess_control(ctrl, *_period())
        assert len(ctrl.evidence_collected) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# generate_report
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateReport:
    def test_returns_compliance_report(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert isinstance(report, ComplianceReport)

    def test_report_id_prefix(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.report_id.startswith("rpt_soc2_")

    def test_soc2_report_has_ten_controls(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert len(report.controls) == 10

    def test_non_soc2_report_has_no_controls(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.CUSTOM, start, end)
        assert len(report.controls) == 0

    def test_report_stored_in_reports(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.report_id in engine._reports

    def test_report_framework_matches(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.framework == ComplianceFramework.SOC2

    def test_report_period_start(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.period_start == start

    def test_report_period_end(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.period_end == end

    def test_report_generated_by(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end, generated_by="auditor-1")
        assert report.generated_by == "auditor-1"

    def test_summary_has_total_controls(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.summary["total_controls"] == 10

    def test_compliance_percentage_in_summary(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert "compliance_percentage" in report.summary

    def test_compliance_percentage_is_numeric(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert isinstance(report.summary["compliance_percentage"], (int, float))

    def test_compliance_percentage_with_evidence(self, engine):
        # Register evidence for all SOC2 evidence types that appear in controls
        evidence_types = set()
        for ctrl in SOC2_CONTROLS:
            evidence_types.update(ctrl["evidence_required"])
        for et in evidence_types:
            engine.register_evidence_source(et, lambda s, e: [{"x": 1}])
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.summary["compliance_percentage"] > 0

    def test_needs_evidence_count_without_sources(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        # With no registered sources, all controls → NEEDS_EVIDENCE
        assert report.summary["needs_evidence"] == 10


# ═══════════════════════════════════════════════════════════════════════════════
# get_report / list_reports
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetReport:
    def test_returns_none_for_unknown(self, engine):
        assert engine.get_report("nonexistent") is None

    def test_returns_report(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert engine.get_report(report.report_id) is report


class TestListReports:
    def test_empty_initially(self, engine):
        assert engine.list_reports() == []

    def test_returns_all_reports(self, engine):
        start, end = _period()
        engine.generate_report(ComplianceFramework.SOC2, start, end)
        engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert len(engine.list_reports()) == 2

    def test_filter_by_framework(self, engine):
        start, end = _period()
        engine.generate_report(ComplianceFramework.SOC2, start, end)
        engine.generate_report(ComplianceFramework.CUSTOM, start, end)
        soc2 = engine.list_reports(framework=ComplianceFramework.SOC2)
        assert len(soc2) == 1

    def test_each_entry_has_report_id(self, engine):
        start, end = _period()
        engine.generate_report(ComplianceFramework.SOC2, start, end)
        for entry in engine.list_reports():
            assert "report_id" in entry

    def test_each_entry_has_compliance_percentage(self, engine):
        start, end = _period()
        engine.generate_report(ComplianceFramework.SOC2, start, end)
        for entry in engine.list_reports():
            assert "compliance_percentage" in entry


# ═══════════════════════════════════════════════════════════════════════════════
# export_report_json
# ═══════════════════════════════════════════════════════════════════════════════

class TestExportReportJson:
    def test_returns_none_for_unknown(self, engine):
        assert engine.export_report_json("nonexistent") is None

    def test_returns_valid_json_string(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        result = engine.export_report_json(report.report_id)
        assert result is not None
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_json_has_report_id(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        result = json.loads(engine.export_report_json(report.report_id))
        assert result["report_id"] == report.report_id

    def test_json_has_controls_list(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        result = json.loads(engine.export_report_json(report.report_id))
        assert isinstance(result["controls"], list)


# ═══════════════════════════════════════════════════════════════════════════════
# get_evidence_requirements
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetEvidenceRequirements:
    def test_soc2_returns_list(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        assert isinstance(result, list)

    def test_soc2_returns_nonempty(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        assert len(result) > 0

    def test_custom_returns_empty(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.CUSTOM)
        assert result == []

    def test_each_entry_has_type_and_registered(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        for entry in result:
            assert "type" in entry
            assert "registered" in entry

    def test_registered_false_when_not_registered(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        # Fresh engine has no sources registered for SOC2 controls
        for entry in result:
            assert entry["registered"] is False

    def test_registered_true_after_registration(self, engine):
        # Get a real evidence type from SOC2 controls
        first_type = SOC2_CONTROLS[0]["evidence_required"][0]
        engine.register_evidence_source(first_type, lambda s, e: [])
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        by_type = {e["type"]: e["registered"] for e in result}
        assert by_type[first_type] is True

    def test_results_are_sorted(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        types = [e["type"] for e in result]
        assert types == sorted(types)

    def test_no_duplicate_types(self, engine):
        result = engine.get_evidence_requirements(ComplianceFramework.SOC2)
        types = [e["type"] for e in result]
        assert len(types) == len(set(types))


# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceReport.to_dict
# ═══════════════════════════════════════════════════════════════════════════════

class TestComplianceReportToDict:
    def test_to_dict_has_required_keys(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        d = report.to_dict()
        assert "report_id" in d
        assert "framework" in d
        assert "generated_at" in d
        assert "generated_by" in d
        assert "period" in d
        assert "summary" in d
        assert "controls" in d

    def test_to_dict_period_has_start_end(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        period = report.to_dict()["period"]
        assert "start" in period
        assert "end" in period

    def test_to_dict_framework_is_string(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        assert report.to_dict()["framework"] == "soc2"

    def test_to_dict_generated_at_is_iso(self, engine):
        start, end = _period()
        report = engine.generate_report(ComplianceFramework.SOC2, start, end)
        ts = report.to_dict()["generated_at"]
        assert isinstance(ts, str)
        # Verify it's a valid ISO datetime (won't raise)
        datetime.fromisoformat(ts)

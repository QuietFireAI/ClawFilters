# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_system_analysis_depth.py
# REM: Depth coverage for core/system_analysis.py
# REM: Pure Python classes (enums, dataclasses) + SystemAnalyzer (in-memory ops).

import pytest
from datetime import datetime, timezone

from core.system_analysis import (
    AnalysisFinding,
    AnalysisSeverity,
    SystemAnalysisReport,
    SystemAnalyzer,
)


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisSeverity enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalysisSeverityEnum:
    def test_critical(self):
        assert AnalysisSeverity.CRITICAL == "critical"

    def test_high(self):
        assert AnalysisSeverity.HIGH == "high"

    def test_medium(self):
        assert AnalysisSeverity.MEDIUM == "medium"

    def test_low(self):
        assert AnalysisSeverity.LOW == "low"

    def test_info(self):
        assert AnalysisSeverity.INFO == "info"

    def test_all_unique(self):
        values = [s.value for s in AnalysisSeverity]
        assert len(values) == len(set(values))


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisFinding dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalysisFinding:
    def test_create_minimal(self):
        f = AnalysisFinding(
            category="test",
            severity=AnalysisSeverity.HIGH,
            title="Test finding",
            description="A test finding"
        )
        assert f.category == "test"
        assert f.severity == AnalysisSeverity.HIGH
        assert f.title == "Test finding"
        assert f.auto_remediated is False

    def test_create_with_all_fields(self):
        f = AnalysisFinding(
            category="agent_health",
            severity=AnalysisSeverity.CRITICAL,
            title="Critical issue",
            description="Detailed description",
            affected_resource="agent_001",
            recommendation="Fix it now",
            auto_remediated=True
        )
        assert f.affected_resource == "agent_001"
        assert f.recommendation == "Fix it now"
        assert f.auto_remediated is True

    def test_default_affected_resource_none(self):
        f = AnalysisFinding("test", AnalysisSeverity.LOW, "title", "desc")
        assert f.affected_resource is None

    def test_default_recommendation_none(self):
        f = AnalysisFinding("test", AnalysisSeverity.LOW, "title", "desc")
        assert f.recommendation is None


# ═══════════════════════════════════════════════════════════════════════════════
# SystemAnalysisReport.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

def _make_report(findings=None):
    now = datetime.now(timezone.utc)
    return SystemAnalysisReport(
        report_id="analysis_abc123",
        timestamp=now,
        triggered_by="test",
        duration_seconds=1.5,
        findings=findings or [],
        summary={"total_findings": 0},
        agent_health={"total_agents": 2},
        federation_health={"total_relationships": 0},
        security_posture={"score": 90, "rating": "EXCELLENT"},
        recommendations=["Keep it up"],
    )


class TestSystemAnalysisReportToDict:
    def test_has_report_id(self):
        r = _make_report()
        assert r.to_dict()["report_id"] == "analysis_abc123"

    def test_has_timestamp_iso(self):
        r = _make_report()
        d = r.to_dict()
        assert "T" in d["timestamp"]

    def test_has_triggered_by(self):
        r = _make_report()
        assert r.to_dict()["triggered_by"] == "test"

    def test_finding_count_zero(self):
        r = _make_report()
        assert r.to_dict()["finding_count"] == 0

    def test_finding_count_with_findings(self):
        findings = [
            AnalysisFinding("test", AnalysisSeverity.HIGH, "H1", "d"),
            AnalysisFinding("test", AnalysisSeverity.CRITICAL, "C1", "d"),
        ]
        r = _make_report(findings)
        assert r.to_dict()["finding_count"] == 2

    def test_findings_by_severity_keys(self):
        r = _make_report()
        by_sev = r.to_dict()["findings_by_severity"]
        for sev in AnalysisSeverity:
            assert sev.value in by_sev

    def test_findings_by_severity_counts(self):
        findings = [
            AnalysisFinding("t", AnalysisSeverity.CRITICAL, "C1", "d"),
            AnalysisFinding("t", AnalysisSeverity.HIGH, "H1", "d"),
            AnalysisFinding("t", AnalysisSeverity.HIGH, "H2", "d"),
        ]
        r = _make_report(findings)
        by_sev = r.to_dict()["findings_by_severity"]
        assert by_sev["critical"] == 1
        assert by_sev["high"] == 2
        assert by_sev["medium"] == 0

    def test_findings_list_in_dict(self):
        findings = [AnalysisFinding("cat", AnalysisSeverity.LOW, "title", "desc")]
        r = _make_report(findings)
        d = r.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["category"] == "cat"
        assert d["findings"][0]["severity"] == "low"

    def test_finding_with_affected_resource(self):
        findings = [AnalysisFinding("cat", AnalysisSeverity.HIGH, "T", "D",
                                    affected_resource="agent_A")]
        r = _make_report(findings)
        d = r.to_dict()
        assert d["findings"][0]["affected_resource"] == "agent_A"

    def test_finding_auto_remediated_in_dict(self):
        findings = [AnalysisFinding("cat", AnalysisSeverity.INFO, "T", "D",
                                    auto_remediated=True)]
        r = _make_report(findings)
        d = r.to_dict()
        assert d["findings"][0]["auto_remediated"] is True

    def test_has_recommendations(self):
        r = _make_report()
        assert "recommendations" in r.to_dict()
        assert "Keep it up" in r.to_dict()["recommendations"]

    def test_has_agent_health(self):
        r = _make_report()
        assert r.to_dict()["agent_health"]["total_agents"] == 2

    def test_has_security_posture(self):
        r = _make_report()
        assert r.to_dict()["security_posture"]["score"] == 90


# ═══════════════════════════════════════════════════════════════════════════════
# SystemAnalyzer — pure calculation methods
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def analyzer():
    return SystemAnalyzer()


class TestCalculateSecurityPosture:
    def test_no_findings_score_100(self, analyzer):
        result = analyzer._calculate_security_posture([])
        assert result["score"] == 100

    def test_no_findings_rating_excellent(self, analyzer):
        result = analyzer._calculate_security_posture([])
        assert result["rating"] == "EXCELLENT"

    def test_critical_finding_deducts_20(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D")]
        result = analyzer._calculate_security_posture(findings)
        assert result["score"] == 80

    def test_high_finding_deducts_10(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")]
        result = analyzer._calculate_security_posture(findings)
        assert result["score"] == 90

    def test_medium_finding_deducts_5(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.MEDIUM, "T", "D")]
        result = analyzer._calculate_security_posture(findings)
        assert result["score"] == 95

    def test_low_finding_deducts_2(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.LOW, "T", "D")]
        result = analyzer._calculate_security_posture(findings)
        assert result["score"] == 98

    def test_score_never_below_zero(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D")] * 10
        result = analyzer._calculate_security_posture(findings)
        assert result["score"] == 0

    def test_rating_good_range(self, analyzer):
        # 75-89 = GOOD
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")] * 2  # 80 points
        result = analyzer._calculate_security_posture(findings)
        assert result["rating"] == "GOOD"

    def test_rating_fair_range(self, analyzer):
        # 50-74 = FAIR
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")] * 3  # 70 points
        result = analyzer._calculate_security_posture(findings)
        assert result["rating"] == "FAIR"

    def test_rating_poor_range(self, analyzer):
        # 25-49 = POOR
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")] * 6  # 40 points
        result = analyzer._calculate_security_posture(findings)
        assert result["rating"] == "POOR"

    def test_rating_critical_range(self, analyzer):
        # 0-24 = CRITICAL
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D")] * 5  # 0 points
        result = analyzer._calculate_security_posture(findings)
        assert result["rating"] == "CRITICAL"

    def test_has_critical_issues_count(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D")] * 2
        result = analyzer._calculate_security_posture(findings)
        assert result["critical_issues"] == 2

    def test_has_high_issues_count(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")] * 3
        result = analyzer._calculate_security_posture(findings)
        assert result["high_issues"] == 3


class TestGenerateRecommendations:
    def test_no_findings_empty_recommendations(self, analyzer):
        result = analyzer._generate_recommendations([], {"score": 100, "critical_issues": 0, "high_issues": 0})
        assert isinstance(result, list)

    def test_critical_findings_trigger_immediate(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D",
                                    recommendation="Fix it")]
        result = analyzer._generate_recommendations(findings, {"score": 80, "critical_issues": 1})
        assert any("IMMEDIATE" in r for r in result)

    def test_high_findings_trigger_high_priority(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.HIGH, "T", "D")]
        result = analyzer._generate_recommendations(findings, {"score": 90, "critical_issues": 0})
        assert any("HIGH PRIORITY" in r for r in result)

    def test_low_score_triggers_full_review(self, analyzer):
        result = analyzer._generate_recommendations([], {"score": 40, "critical_issues": 0})
        assert any("security review" in r.lower() for r in result)

    def test_medium_score_triggers_assessment(self, analyzer):
        result = analyzer._generate_recommendations([], {"score": 60, "critical_issues": 0})
        assert any("assessment" in r.lower() for r in result)

    def test_critical_recommendations_included(self, analyzer):
        findings = [AnalysisFinding("t", AnalysisSeverity.CRITICAL, "T", "D",
                                    recommendation="Quarantine agent")]
        result = analyzer._generate_recommendations(findings, {"score": 80, "critical_issues": 1})
        assert any("Quarantine" in r for r in result)


class TestSystemAnalyzerInit:
    def test_last_report_initially_none(self, analyzer):
        assert analyzer._last_report is None

    def test_report_history_initially_empty(self, analyzer):
        assert analyzer._report_history == []

    def test_get_last_report_none(self, analyzer):
        assert analyzer.get_last_report() is None

    def test_get_report_history_empty(self, analyzer):
        result = analyzer.get_report_history()
        assert result == []


class TestRunFullAnalysis:
    def test_run_full_analysis_returns_report(self, analyzer):
        report = analyzer.run_full_analysis(triggered_by="test")
        assert report is not None

    def test_run_full_analysis_stores_last_report(self, analyzer):
        analyzer.run_full_analysis(triggered_by="test")
        assert analyzer._last_report is not None

    def test_run_full_analysis_appends_to_history(self, analyzer):
        initial = len(analyzer._report_history)
        analyzer.run_full_analysis(triggered_by="test")
        assert len(analyzer._report_history) == initial + 1

    def test_get_last_report_after_run(self, analyzer):
        analyzer.run_full_analysis(triggered_by="test_run")
        result = analyzer.get_last_report()
        assert result is not None
        assert result["triggered_by"] == "test_run"

    def test_report_has_summary(self, analyzer):
        report = analyzer.run_full_analysis()
        d = report.to_dict()
        assert "summary" in d

    def test_report_summary_has_total_findings(self, analyzer):
        report = analyzer.run_full_analysis()
        assert "total_findings" in report.summary

    def test_report_has_findings_list(self, analyzer):
        report = analyzer.run_full_analysis()
        assert isinstance(report.findings, list)

    def test_report_has_security_posture(self, analyzer):
        report = analyzer.run_full_analysis()
        d = report.to_dict()
        assert "security_posture" in d
        assert "score" in d["security_posture"]

    def test_report_has_recommendations(self, analyzer):
        report = analyzer.run_full_analysis()
        assert isinstance(report.recommendations, list)

    def test_report_duration_positive(self, analyzer):
        report = analyzer.run_full_analysis()
        assert report.duration_seconds >= 0

    def test_auto_remediate_runs(self, analyzer):
        # Should not raise even with auto_remediate=True
        report = analyzer.run_full_analysis(auto_remediate=True)
        assert report is not None

    def test_get_report_history_limit(self, analyzer):
        for i in range(3):
            analyzer.run_full_analysis()
        result = analyzer.get_report_history(limit=2)
        assert len(result) <= 2

    def test_report_history_capped_at_50(self, analyzer):
        fresh = SystemAnalyzer()
        for i in range(55):
            fresh.run_full_analysis()
        assert len(fresh._report_history) <= 50

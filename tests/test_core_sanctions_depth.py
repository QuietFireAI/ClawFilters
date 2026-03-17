# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_sanctions_depth.py
# REM: Depth coverage for core/sanctions.py
# REM: SanctionSeverity, SanctionRecord, SanctionsManager — in-memory.

import pytest
from datetime import datetime, timezone

from core.sanctions import (
    SanctionSeverity,
    SanctionRecord,
    SanctionsManager,
)


# ─── Patch Redis so audit.log() uses in-memory path ────────────────────────────
@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def manager():
    """Bypass __init__ to avoid _load_from_redis() hitting compliance_store (Redis).

    The compliance_store has its own Redis pool not covered by the get_redis patch.
    object.__new__ gives us a clean instance with no Redis involvement.
    """
    from core.sanctions import SanctionsManager as _SM
    m = object.__new__(_SM)
    m._sanctions = {}
    return m


def _impose(manager, user_id="user-001", violation="PHI breach",
            severity=SanctionSeverity.WARNING, imposed_by="admin"):
    return manager.impose_sanction(user_id, violation, severity, imposed_by)


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionSeverity enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestSanctionSeverity:
    def test_warning_value(self):
        assert SanctionSeverity.WARNING == "warning"

    def test_reprimand_value(self):
        assert SanctionSeverity.REPRIMAND == "reprimand"

    def test_suspension_value(self):
        assert SanctionSeverity.SUSPENSION == "suspension"

    def test_termination_value(self):
        assert SanctionSeverity.TERMINATION == "termination"

    def test_referral_value(self):
        assert SanctionSeverity.REFERRAL == "referral"

    def test_five_members(self):
        assert len(SanctionSeverity) == 5

    def test_is_str_subclass(self):
        assert isinstance(SanctionSeverity.WARNING, str)


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionRecord.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestSanctionRecordToDict:
    def _make_record(self, **kwargs):
        defaults = dict(
            sanction_id="sanc_abc123",
            user_id="user-001",
            violation_description="PHI breach",
            severity=SanctionSeverity.WARNING,
            imposed_by="admin",
            imposed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            is_active=True,
        )
        defaults.update(kwargs)
        return SanctionRecord(**defaults)

    def test_returns_dict(self):
        r = self._make_record()
        assert isinstance(r.to_dict(), dict)

    def test_sanction_id_present(self):
        r = self._make_record(sanction_id="sanc_xyz")
        assert r.to_dict()["sanction_id"] == "sanc_xyz"

    def test_user_id_present(self):
        r = self._make_record(user_id="user-999")
        assert r.to_dict()["user_id"] == "user-999"

    def test_violation_description_present(self):
        r = self._make_record(violation_description="test violation")
        assert r.to_dict()["violation_description"] == "test violation"

    def test_severity_is_value_string(self):
        r = self._make_record(severity=SanctionSeverity.TERMINATION)
        assert r.to_dict()["severity"] == "termination"

    def test_imposed_by_present(self):
        r = self._make_record(imposed_by="security_officer")
        assert r.to_dict()["imposed_by"] == "security_officer"

    def test_imposed_at_is_isoformat(self):
        ts = datetime(2026, 3, 15, tzinfo=timezone.utc)
        r = self._make_record(imposed_at=ts)
        assert r.to_dict()["imposed_at"] == ts.isoformat()

    def test_resolved_at_none_when_not_resolved(self):
        r = self._make_record()
        assert r.to_dict()["resolved_at"] is None

    def test_resolved_at_isoformat_when_resolved(self):
        ts_resolved = datetime(2026, 4, 1, tzinfo=timezone.utc)
        r = self._make_record(resolved_at=ts_resolved, is_active=False)
        assert r.to_dict()["resolved_at"] == ts_resolved.isoformat()

    def test_resolution_notes_present(self):
        r = self._make_record(resolution_notes="training completed")
        assert r.to_dict()["resolution_notes"] == "training completed"

    def test_is_active_true(self):
        r = self._make_record(is_active=True)
        assert r.to_dict()["is_active"] is True

    def test_is_active_false(self):
        r = self._make_record(is_active=False)
        assert r.to_dict()["is_active"] is False

    def test_all_nine_keys_present(self):
        r = self._make_record()
        expected = {
            "sanction_id", "user_id", "violation_description", "severity",
            "imposed_by", "imposed_at", "resolved_at", "resolution_notes", "is_active"
        }
        assert set(r.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.impose_sanction()
# ═══════════════════════════════════════════════════════════════════════════════

class TestImposeSanction:
    def test_returns_sanction_record(self, manager):
        result = _impose(manager)
        assert isinstance(result, SanctionRecord)

    def test_sanction_id_has_prefix(self, manager):
        result = _impose(manager)
        assert result.sanction_id.startswith("sanc_")

    def test_user_id_stored(self, manager):
        result = _impose(manager, user_id="user-777")
        assert result.user_id == "user-777"

    def test_violation_stored(self, manager):
        result = _impose(manager, violation="unauthorized access")
        assert result.violation_description == "unauthorized access"

    def test_severity_stored(self, manager):
        result = _impose(manager, severity=SanctionSeverity.TERMINATION)
        assert result.severity == SanctionSeverity.TERMINATION

    def test_imposed_by_stored(self, manager):
        result = _impose(manager, imposed_by="security_officer")
        assert result.imposed_by == "security_officer"

    def test_is_active_true(self, manager):
        result = _impose(manager)
        assert result.is_active is True

    def test_sanction_stored_in_manager(self, manager):
        result = _impose(manager)
        assert result.sanction_id in manager._sanctions

    def test_imposed_at_is_datetime(self, manager):
        result = _impose(manager)
        assert isinstance(result.imposed_at, datetime)

    def test_severity_as_string_accepted(self, manager):
        result = manager.impose_sanction("user-001", "violation", "warning", "admin")
        assert result.severity == SanctionSeverity.WARNING

    def test_multiple_sanctions_all_stored(self, manager):
        _impose(manager, user_id="user-001")
        _impose(manager, user_id="user-001")
        _impose(manager, user_id="user-002")
        assert len(manager._sanctions) == 3

    def test_unique_sanction_ids(self, manager):
        r1 = _impose(manager)
        r2 = _impose(manager)
        assert r1.sanction_id != r2.sanction_id


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.resolve_sanction()
# ═══════════════════════════════════════════════════════════════════════════════

class TestResolveSanction:
    def test_returns_true_for_active_sanction(self, manager):
        record = _impose(manager)
        assert manager.resolve_sanction(record.sanction_id, "admin", "resolved after training") is True

    def test_returns_false_for_unknown_id(self, manager):
        assert manager.resolve_sanction("nonexistent_id", "admin", "notes") is False

    def test_returns_false_if_already_resolved(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "first resolution")
        assert manager.resolve_sanction(record.sanction_id, "admin", "second resolution") is False

    def test_is_active_becomes_false(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "resolved")
        assert manager._sanctions[record.sanction_id].is_active is False

    def test_resolved_at_set(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "resolved")
        assert manager._sanctions[record.sanction_id].resolved_at is not None

    def test_resolution_notes_set(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "training completed")
        assert manager._sanctions[record.sanction_id].resolution_notes == "training completed"


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.get_user_sanctions()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetUserSanctions:
    def test_returns_list(self, manager):
        assert isinstance(manager.get_user_sanctions("nobody"), list)

    def test_empty_for_unknown_user(self, manager):
        assert manager.get_user_sanctions("nobody") == []

    def test_returns_user_sanctions(self, manager):
        _impose(manager, user_id="user-001")
        _impose(manager, user_id="user-001")
        _impose(manager, user_id="user-002")
        result = manager.get_user_sanctions("user-001")
        assert len(result) == 2

    def test_does_not_include_other_users(self, manager):
        _impose(manager, user_id="user-A")
        _impose(manager, user_id="user-B")
        result = manager.get_user_sanctions("user-A")
        assert all(r.user_id == "user-A" for r in result)

    def test_includes_resolved_sanctions(self, manager):
        record = _impose(manager, user_id="user-001")
        manager.resolve_sanction(record.sanction_id, "admin", "done")
        result = manager.get_user_sanctions("user-001")
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.get_active_sanctions()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetActiveSanctions:
    def test_returns_dict(self, manager):
        assert isinstance(manager.get_active_sanctions(), dict)

    def test_has_has_active_key(self, manager):
        assert "has_active" in manager.get_active_sanctions()

    def test_has_sanctions_key(self, manager):
        assert "sanctions" in manager.get_active_sanctions()

    def test_no_sanctions_has_active_false(self, manager):
        assert manager.get_active_sanctions()["has_active"] is False

    def test_active_sanction_has_active_true(self, manager):
        _impose(manager)
        assert manager.get_active_sanctions()["has_active"] is True

    def test_sanctions_list_contains_dicts(self, manager):
        _impose(manager)
        result = manager.get_active_sanctions()
        assert all(isinstance(s, dict) for s in result["sanctions"])

    def test_resolved_sanction_excluded(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "done")
        result = manager.get_active_sanctions()
        assert result["has_active"] is False

    def test_filter_by_user_id(self, manager):
        _impose(manager, user_id="user-A")
        _impose(manager, user_id="user-B")
        result = manager.get_active_sanctions(user_id="user-A")
        assert len(result["sanctions"]) == 1
        assert result["sanctions"][0]["user_id"] == "user-A"

    def test_filter_by_user_id_no_match(self, manager):
        _impose(manager, user_id="user-A")
        result = manager.get_active_sanctions(user_id="user-Z")
        assert result["has_active"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.list_sanctions()
# ═══════════════════════════════════════════════════════════════════════════════

class TestListSanctions:
    def test_returns_list(self, manager):
        assert isinstance(manager.list_sanctions(), list)

    def test_empty_list_initially(self, manager):
        assert manager.list_sanctions() == []

    def test_includes_all_sanctions(self, manager):
        _impose(manager, user_id="user-001")
        _impose(manager, user_id="user-002")
        assert len(manager.list_sanctions()) == 2

    def test_includes_resolved_sanctions(self, manager):
        record = _impose(manager)
        manager.resolve_sanction(record.sanction_id, "admin", "done")
        assert len(manager.list_sanctions()) == 1

    def test_items_are_dicts(self, manager):
        _impose(manager)
        for item in manager.list_sanctions():
            assert isinstance(item, dict)

    def test_filter_by_user_id(self, manager):
        _impose(manager, user_id="user-A")
        _impose(manager, user_id="user-B")
        result = manager.list_sanctions(user_id="user-A")
        assert len(result) == 1
        assert result[0]["user_id"] == "user-A"


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsManager.has_active_sanctions()
# ═══════════════════════════════════════════════════════════════════════════════

class TestHasActiveSanctions:
    def test_returns_false_for_no_sanctions(self, manager):
        assert manager.has_active_sanctions("nobody") is False

    def test_returns_true_with_active_sanction(self, manager):
        _impose(manager, user_id="user-001")
        assert manager.has_active_sanctions("user-001") is True

    def test_returns_false_after_resolution(self, manager):
        record = _impose(manager, user_id="user-001")
        manager.resolve_sanction(record.sanction_id, "admin", "resolved")
        assert manager.has_active_sanctions("user-001") is False

    def test_returns_bool(self, manager):
        result = manager.has_active_sanctions("user-001")
        assert isinstance(result, bool)

    def test_other_user_sanctions_not_counted(self, manager):
        _impose(manager, user_id="user-B")
        assert manager.has_active_sanctions("user-A") is False

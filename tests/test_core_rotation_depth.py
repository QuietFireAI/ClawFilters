# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_rotation_depth.py
# REM: Depth coverage for core/rotation.py
# REM: SecretType, ActiveSecret, KeyRotationManager — in-memory.

import pytest
from datetime import datetime, timedelta, timezone

from core.rotation import (
    SecretType,
    RotationRecord,
    ActiveSecret,
    KeyRotationManager,
)


# ─── Patch Redis so audit.log() uses in-memory path ────────────────────────────
@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    """Fresh KeyRotationManager — pure in-memory, no Redis dependencies."""
    return KeyRotationManager()


# ═══════════════════════════════════════════════════════════════════════════════
# SecretType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretType:
    def test_jwt_secret_value(self):
        assert SecretType.JWT_SECRET == "jwt_secret"

    def test_agent_signing_key_value(self):
        assert SecretType.AGENT_SIGNING_KEY == "agent_signing_key"

    def test_federation_session_value(self):
        assert SecretType.FEDERATION_SESSION == "federation_session"

    def test_api_key_value(self):
        assert SecretType.API_KEY == "api_key"

    def test_four_members(self):
        assert len(SecretType) == 4

    def test_is_str_subclass(self):
        assert isinstance(SecretType.JWT_SECRET, str)


# ═══════════════════════════════════════════════════════════════════════════════
# ActiveSecret.is_in_grace_period()
# ═══════════════════════════════════════════════════════════════════════════════

class TestActiveSecretIsInGracePeriod:
    def test_no_previous_key_returns_false(self):
        s = ActiveSecret(
            current_key=b"newkey",
            current_key_created_at=datetime.now(timezone.utc),
        )
        assert s.is_in_grace_period() is False

    def test_expired_previous_key_returns_false(self):
        s = ActiveSecret(
            current_key=b"newkey",
            current_key_created_at=datetime.now(timezone.utc),
            previous_key=b"oldkey",
            previous_key_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert s.is_in_grace_period() is False

    def test_active_previous_key_returns_true(self):
        s = ActiveSecret(
            current_key=b"newkey",
            current_key_created_at=datetime.now(timezone.utc),
            previous_key=b"oldkey",
            previous_key_expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        assert s.is_in_grace_period() is True

    def test_returns_bool(self):
        s = ActiveSecret(current_key=b"k", current_key_created_at=datetime.now(timezone.utc))
        assert isinstance(s.is_in_grace_period(), bool)


# ═══════════════════════════════════════════════════════════════════════════════
# ActiveSecret.validate_with_either_key()
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateWithEitherKey:
    def test_validates_with_current_key(self):
        current = b"correct_current_key"
        s = ActiveSecret(current_key=current, current_key_created_at=datetime.now(timezone.utc))
        assert s.validate_with_either_key(lambda k, x: k == x, current) is True

    def test_fails_with_wrong_key_no_grace(self):
        s = ActiveSecret(current_key=b"current", current_key_created_at=datetime.now(timezone.utc))
        assert s.validate_with_either_key(lambda k, x: k == x, b"wrong") is False

    def test_validates_with_previous_key_in_grace_period(self):
        old = b"old_key"
        new = b"new_key"
        s = ActiveSecret(
            current_key=new,
            current_key_created_at=datetime.now(timezone.utc),
            previous_key=old,
            previous_key_expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        # Validator matches old key, not new
        assert s.validate_with_either_key(lambda k, x: k == x, old) is True

    def test_previous_key_not_used_after_expiry(self):
        old = b"old_key"
        new = b"new_key"
        s = ActiveSecret(
            current_key=new,
            current_key_created_at=datetime.now(timezone.utc),
            previous_key=old,
            previous_key_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # expired
        )
        assert s.validate_with_either_key(lambda k, x: k == x, old) is False

    def test_returns_bool(self):
        s = ActiveSecret(current_key=b"k", current_key_created_at=datetime.now(timezone.utc))
        assert isinstance(s.validate_with_either_key(lambda k, v: True, b"any"), bool)


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRotationManager.rotate_jwt_secret()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRotateJwtSecret:
    def test_returns_tuple(self, mgr):
        result = mgr.rotate_jwt_secret()
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_success_true(self, mgr):
        success, _, _ = mgr.rotate_jwt_secret()
        assert success is True

    def test_message_is_string(self, mgr):
        _, msg, _ = mgr.rotate_jwt_secret()
        assert isinstance(msg, str)

    def test_new_secret_is_bytes(self, mgr):
        _, _, secret = mgr.rotate_jwt_secret()
        assert isinstance(secret, bytes)

    def test_new_secret_is_32_bytes(self, mgr):
        _, _, secret = mgr.rotate_jwt_secret()
        assert len(secret) == 32

    def test_jwt_secret_stored(self, mgr):
        mgr.rotate_jwt_secret()
        assert mgr._jwt_secret is not None

    def test_current_key_matches_returned(self, mgr):
        _, _, secret = mgr.rotate_jwt_secret()
        assert mgr._jwt_secret.current_key == secret

    def test_rotation_recorded_in_history(self, mgr):
        mgr.rotate_jwt_secret()
        assert len(mgr._rotation_history) == 1

    def test_rotation_type_is_jwt(self, mgr):
        mgr.rotate_jwt_secret()
        assert mgr._rotation_history[0].secret_type == SecretType.JWT_SECRET

    def test_rotated_by_stored(self, mgr):
        mgr.rotate_jwt_secret(rotated_by="security_officer")
        assert mgr._rotation_history[0].rotated_by == "security_officer"

    def test_reason_stored(self, mgr):
        mgr.rotate_jwt_secret(reason="breach_response")
        assert mgr._rotation_history[0].reason == "breach_response"

    def test_second_rotation_stores_old_key_as_previous(self, mgr):
        _, _, first_key = mgr.rotate_jwt_secret()
        mgr.rotate_jwt_secret()
        assert mgr._jwt_secret.previous_key == first_key

    def test_second_rotation_sets_grace_period(self, mgr):
        mgr.rotate_jwt_secret()
        mgr.rotate_jwt_secret(grace_period_hours=12)
        assert mgr._jwt_secret.is_in_grace_period() is True

    def test_keys_change_between_rotations(self, mgr):
        _, _, key1 = mgr.rotate_jwt_secret()
        _, _, key2 = mgr.rotate_jwt_secret()
        assert key1 != key2

    def test_rotation_identifier_is_global(self, mgr):
        mgr.rotate_jwt_secret()
        assert mgr._rotation_history[0].identifier == "global"


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRotationManager.get_rotation_history()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetRotationHistory:
    def test_empty_initially(self, mgr):
        assert mgr.get_rotation_history() == []

    def test_returns_list(self, mgr):
        assert isinstance(mgr.get_rotation_history(), list)

    def test_returns_all_records_after_rotation(self, mgr):
        mgr.rotate_jwt_secret()
        mgr.rotate_jwt_secret()
        assert len(mgr.get_rotation_history()) == 2

    def test_sorted_newest_first(self, mgr):
        mgr.rotate_jwt_secret()
        mgr.rotate_jwt_secret()
        history = mgr.get_rotation_history()
        assert history[0].rotated_at >= history[1].rotated_at

    def test_filter_by_secret_type(self, mgr):
        mgr.rotate_jwt_secret()
        # Manually add an agent rotation record
        mgr._rotation_history.append(RotationRecord(
            secret_type=SecretType.AGENT_SIGNING_KEY,
            identifier="agent-001",
            rotated_at=datetime.now(timezone.utc),
            rotated_by="system",
            old_key_expires_at=datetime.now(timezone.utc),
            reason="test"
        ))
        jwt_records = mgr.get_rotation_history(secret_type=SecretType.JWT_SECRET)
        assert all(r.secret_type == SecretType.JWT_SECRET for r in jwt_records)
        assert len(jwt_records) == 1

    def test_filter_by_identifier(self, mgr):
        mgr.rotate_jwt_secret()
        history = mgr.get_rotation_history(identifier="global")
        assert len(history) == 1
        assert history[0].identifier == "global"

    def test_filter_by_since(self, mgr):
        mgr.rotate_jwt_secret()
        since = datetime.now(timezone.utc) + timedelta(hours=1)
        history = mgr.get_rotation_history(since=since)
        assert len(history) == 0

    def test_filter_since_includes_recent(self, mgr):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        mgr.rotate_jwt_secret()
        history = mgr.get_rotation_history(since=since)
        assert len(history) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRotationManager.get_next_scheduled_rotation()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetNextScheduledRotation:
    def test_no_history_returns_none(self, mgr):
        result = mgr.get_next_scheduled_rotation(SecretType.JWT_SECRET, "global")
        assert result is None

    def test_returns_datetime_after_rotation(self, mgr):
        mgr.rotate_jwt_secret()
        result = mgr.get_next_scheduled_rotation(SecretType.JWT_SECRET, "global")
        assert isinstance(result, datetime)

    def test_next_rotation_is_90_days_from_last_for_jwt(self, mgr):
        mgr.rotate_jwt_secret()
        last = mgr._rotation_history[0].rotated_at
        next_due = mgr.get_next_scheduled_rotation(SecretType.JWT_SECRET, "global")
        expected = last + timedelta(days=90)
        # Allow a small delta for execution time
        assert abs((next_due - expected).total_seconds()) < 1

    def test_agent_key_rotation_180_days(self, mgr):
        now = datetime.now(timezone.utc)
        mgr._rotation_history.append(RotationRecord(
            secret_type=SecretType.AGENT_SIGNING_KEY,
            identifier="agent-001",
            rotated_at=now,
            rotated_by="system",
            old_key_expires_at=now,
            reason="test"
        ))
        result = mgr.get_next_scheduled_rotation(SecretType.AGENT_SIGNING_KEY, "agent-001")
        expected = now + timedelta(days=180)
        assert abs((result - expected).total_seconds()) < 1


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRotationManager.cleanup_expired_grace_periods()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCleanupExpiredGracePeriods:
    def test_no_grace_period_no_error(self, mgr):
        mgr.rotate_jwt_secret(grace_period_hours=0)
        mgr.cleanup_expired_grace_periods()  # Should not raise

    def test_clears_expired_jwt_grace_period(self, mgr):
        mgr.rotate_jwt_secret()  # First rotation to create old key
        mgr.rotate_jwt_secret(grace_period_hours=0)  # Second rotation with zero grace
        # Manually set expiry to past
        mgr._jwt_secret.previous_key_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        mgr.cleanup_expired_grace_periods()
        assert mgr._jwt_secret.previous_key is None

    def test_active_grace_period_not_cleared(self, mgr):
        mgr.rotate_jwt_secret()  # First key
        _, _, second_key = mgr.rotate_jwt_secret(grace_period_hours=24)  # Active grace
        mgr.cleanup_expired_grace_periods()
        assert mgr._jwt_secret.previous_key is not None  # Not cleared yet

    def test_cleanup_agent_secrets(self, mgr):
        # Manually set an expired agent secret grace period
        from datetime import timedelta
        secret = ActiveSecret(
            current_key=b"new",
            current_key_created_at=datetime.now(timezone.utc),
            previous_key=b"old",
            previous_key_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        mgr._active_secrets["agent:test-001"] = secret
        mgr.cleanup_expired_grace_periods()
        assert mgr._active_secrets["agent:test-001"].previous_key is None


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRotationManager._rotation_schedule
# ═══════════════════════════════════════════════════════════════════════════════

class TestRotationSchedule:
    def test_jwt_schedule_90_days(self, mgr):
        assert mgr._rotation_schedule[SecretType.JWT_SECRET] == timedelta(days=90)

    def test_agent_key_schedule_180_days(self, mgr):
        assert mgr._rotation_schedule[SecretType.AGENT_SIGNING_KEY] == timedelta(days=180)

    def test_federation_schedule_30_days(self, mgr):
        assert mgr._rotation_schedule[SecretType.FEDERATION_SESSION] == timedelta(days=30)

    def test_api_key_schedule_365_days(self, mgr):
        assert mgr._rotation_schedule[SecretType.API_KEY] == timedelta(days=365)

    def test_all_four_types_in_schedule(self, mgr):
        assert len(mgr._rotation_schedule) == 4

# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_signing_depth.py
# REM: Depth coverage for core/signing.py
# REM: SignedAgentMessage, AgentKeyRegistry, MessageSigner — all pure in-memory.

import pytest
import secrets
from datetime import datetime, timedelta, timezone

from core.signing import (
    REPLAY_WINDOW_SECONDS,
    AgentKeyRegistry,
    MessageSigner,
    SignedAgentMessage,
)


def _make_message(
    agent_id="agent-001",
    action="test_action",
    secret_key=None,
    payload=None,
    timestamp=None,
    message_id=None,
):
    """Helper: create a properly signed message."""
    import hashlib, hmac, json, uuid as uuid_mod
    sk = secret_key or secrets.token_bytes(32)
    ts = timestamp or datetime.now(timezone.utc)
    mid = message_id or str(uuid_mod.uuid4())

    # Build unsigned message to get canonical payload
    msg = SignedAgentMessage(
        message_id=mid,
        agent_id=agent_id,
        timestamp=ts,
        action=action,
        payload=payload or {},
        signature="placeholder",
    )
    canonical = msg.get_signing_payload()
    sig = hmac.new(sk, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return SignedAgentMessage(
        message_id=mid,
        agent_id=agent_id,
        timestamp=ts,
        action=action,
        payload=payload or {},
        signature=sig,
    ), sk


# ═══════════════════════════════════════════════════════════════════════════════
# SignedAgentMessage.get_signing_payload()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetSigningPayload:
    def test_returns_string(self):
        msg, _ = _make_message()
        assert isinstance(msg.get_signing_payload(), str)

    def test_deterministic_same_call(self):
        msg, _ = _make_message()
        assert msg.get_signing_payload() == msg.get_signing_payload()

    def test_contains_message_id(self):
        msg, _ = _make_message(message_id="test-id-12345")
        assert "test-id-12345" in msg.get_signing_payload()

    def test_contains_agent_id(self):
        msg, _ = _make_message(agent_id="agent-xyz")
        assert "agent-xyz" in msg.get_signing_payload()

    def test_contains_action(self):
        msg, _ = _make_message(action="delete_file")
        assert "delete_file" in msg.get_signing_payload()

    def test_different_payloads_different_canonical(self):
        msg1, _ = _make_message(payload={"key": "val1"})
        msg2, _ = _make_message(payload={"key": "val2"})
        assert msg1.get_signing_payload() != msg2.get_signing_payload()


# ═══════════════════════════════════════════════════════════════════════════════
# SignedAgentMessage.verify()
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerify:
    def test_verify_correct_key_returns_true(self):
        msg, sk = _make_message()
        assert msg.verify(sk) is True

    def test_verify_wrong_key_returns_false(self):
        msg, _ = _make_message()
        wrong_key = secrets.token_bytes(32)
        assert msg.verify(wrong_key) is False

    def test_verify_returns_bool(self):
        msg, sk = _make_message()
        assert isinstance(msg.verify(sk), bool)

    def test_tampered_action_fails_verification(self):
        import hashlib, hmac
        msg, sk = _make_message(action="list_files")
        # Tampered version — same key but different action
        tampered = SignedAgentMessage(
            message_id=msg.message_id,
            agent_id=msg.agent_id,
            timestamp=msg.timestamp,
            action="delete_all",  # different action
            payload=msg.payload,
            signature=msg.signature,  # original signature — won't match
        )
        assert tampered.verify(sk) is False


# ═══════════════════════════════════════════════════════════════════════════════
# SignedAgentMessage.is_expired()
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsExpired:
    def test_fresh_message_not_expired(self):
        msg, _ = _make_message()
        assert msg.is_expired() is False

    def test_old_message_expired(self):
        old_ts = datetime.now(timezone.utc) - timedelta(seconds=REPLAY_WINDOW_SECONDS + 60)
        msg, _ = _make_message(timestamp=old_ts)
        assert msg.is_expired() is True

    def test_custom_window(self):
        ts = datetime.now(timezone.utc) - timedelta(seconds=60)
        msg, _ = _make_message(timestamp=ts)
        assert msg.is_expired(window_seconds=30) is True
        assert msg.is_expired(window_seconds=120) is False

    def test_returns_bool(self):
        msg, _ = _make_message()
        assert isinstance(msg.is_expired(), bool)


# ═══════════════════════════════════════════════════════════════════════════════
# AgentKeyRegistry
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def registry():
    return AgentKeyRegistry()


class TestAgentKeyRegistryRegister:
    def test_returns_bytes_key(self, registry):
        key = registry.register_agent("agent-001")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generated_key_stored(self, registry):
        key = registry.register_agent("agent-001")
        assert registry.get_key("agent-001") == key

    def test_explicit_key_stored(self, registry):
        sk = secrets.token_bytes(32)
        result = registry.register_agent("agent-001", secret_key=sk)
        assert result == sk
        assert registry.get_key("agent-001") == sk

    def test_revoked_agent_cannot_reregister(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "test", "admin")
        with pytest.raises(PermissionError):
            registry.register_agent("agent-001")

    def test_cleared_revocation_allows_reregister(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "test", "admin")
        registry.clear_revocation("agent-001", "admin")
        key = registry.register_agent("agent-001")
        assert isinstance(key, bytes)


class TestAgentKeyRegistryGetKey:
    def test_unknown_agent_returns_none(self, registry):
        assert registry.get_key("nobody") is None

    def test_registered_agent_returns_key(self, registry):
        sk = secrets.token_bytes(32)
        registry.register_agent("agent-001", secret_key=sk)
        assert registry.get_key("agent-001") == sk


class TestAgentKeyRegistryRevoke:
    def test_revoke_known_agent_returns_true(self, registry):
        registry.register_agent("agent-001")
        assert registry.revoke_agent("agent-001", "reason", "admin") is True

    def test_revoke_unknown_agent_returns_false(self, registry):
        assert registry.revoke_agent("nobody", "reason", "admin") is False

    def test_revoke_removes_key(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "reason", "admin")
        assert registry.get_key("agent-001") is None

    def test_is_revoked_true_after_revoke(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "reason", "admin")
        assert registry.is_revoked("agent-001") is True

    def test_is_revoked_false_for_active_agent(self, registry):
        registry.register_agent("agent-001")
        assert registry.is_revoked("agent-001") is False

    def test_is_revoked_false_for_unknown(self, registry):
        assert registry.is_revoked("nobody") is False


class TestClearRevocation:
    def test_clear_revoked_agent_returns_true(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "reason", "admin")
        assert registry.clear_revocation("agent-001", "admin") is True

    def test_clear_non_revoked_returns_false(self, registry):
        assert registry.clear_revocation("nobody", "admin") is False

    def test_cleared_agent_no_longer_revoked(self, registry):
        registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "reason", "admin")
        registry.clear_revocation("agent-001", "admin")
        assert registry.is_revoked("agent-001") is False


class TestVerifyMessage:
    def test_valid_message_returns_true(self, registry):
        sk = registry.register_agent("agent-001")
        msg, _ = _make_message("agent-001", secret_key=sk)
        valid, reason = registry.verify_message(msg)
        assert valid is True
        assert reason == "Valid"

    def test_unknown_agent_rejected(self, registry):
        msg, _ = _make_message("unknown-agent")
        valid, reason = registry.verify_message(msg)
        assert valid is False
        assert "unknown" in reason.lower()

    def test_invalid_signature_rejected(self, registry):
        registry.register_agent("agent-001")
        msg, _ = _make_message("agent-001", secret_key=secrets.token_bytes(32))
        # msg signed with different key than registered key
        valid, reason = registry.verify_message(msg)
        assert valid is False
        assert "signature" in reason.lower()

    def test_expired_message_rejected(self, registry):
        sk = registry.register_agent("agent-001")
        old_ts = datetime.now(timezone.utc) - timedelta(seconds=REPLAY_WINDOW_SECONDS + 60)
        msg, _ = _make_message("agent-001", secret_key=sk, timestamp=old_ts)
        valid, reason = registry.verify_message(msg)
        assert valid is False
        assert "expire" in reason.lower()

    def test_duplicate_message_rejected(self, registry):
        import uuid
        sk = registry.register_agent("agent-001")
        mid = str(uuid.uuid4())
        msg, _ = _make_message("agent-001", secret_key=sk, message_id=mid)
        # First time should succeed
        valid1, _ = registry.verify_message(msg)
        assert valid1 is True
        # Second time same message_id → replay
        msg2, _ = _make_message("agent-001", secret_key=sk, message_id=mid)
        valid2, reason = registry.verify_message(msg2)
        assert valid2 is False
        assert "replay" in reason.lower() or "duplicate" in reason.lower()

    def test_revoked_agent_message_rejected(self, registry):
        sk = registry.register_agent("agent-001")
        registry.revoke_agent("agent-001", "compromised", "admin")
        msg, _ = _make_message("agent-001", secret_key=sk)
        valid, reason = registry.verify_message(msg)
        assert valid is False
        assert "revoked" in reason.lower()

    def test_returns_tuple(self, registry):
        sk = registry.register_agent("agent-001")
        msg, _ = _make_message("agent-001", secret_key=sk)
        result = registry.verify_message(msg)
        assert isinstance(result, tuple)
        assert len(result) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# MessageSigner
# ═══════════════════════════════════════════════════════════════════════════════

class TestMessageSigner:
    @pytest.fixture
    def signer(self):
        sk = secrets.token_bytes(32)
        return MessageSigner("agent-signer-001", sk), sk

    def test_sign_returns_signed_message(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {"key": "val"})
        assert isinstance(msg, SignedAgentMessage)

    def test_signed_message_verifiable(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {"key": "val"})
        assert msg.verify(sk) is True

    def test_signed_message_agent_id_correct(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {})
        assert msg.agent_id == "agent-signer-001"

    def test_signed_message_action_correct(self, signer):
        ms, sk = signer
        msg = ms.sign("delete_backup", {})
        assert msg.action == "delete_backup"

    def test_signed_message_payload_included(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {"foo": "bar"})
        assert msg.payload == {"foo": "bar"}

    def test_signed_message_has_message_id(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {})
        assert msg.message_id is not None
        assert len(msg.message_id) > 0

    def test_signed_message_not_expired(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {})
        assert msg.is_expired() is False

    def test_target_agent_set(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {}, target_agent="target-agent-002")
        assert msg.target_agent == "target-agent-002"

    def test_reply_to_set(self, signer):
        ms, sk = signer
        msg = ms.sign("test_action", {}, reply_to="original-msg-id")
        assert msg.reply_to == "original-msg-id"

    def test_full_roundtrip_with_registry(self):
        registry = AgentKeyRegistry()
        sk = registry.register_agent("signing-agent-001")
        signer = MessageSigner("signing-agent-001", sk)
        msg = signer.sign("list_files", {"path": "/data"})
        valid, reason = registry.verify_message(msg)
        assert valid is True

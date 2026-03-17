# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_audit_depth.py
# REM: Depth coverage for core/audit.py
# REM: AuditChainEntry, ChainState, AuditLogger — in-memory fallback path (no Redis).

import hashlib
import json
import unittest.mock
import pytest
from datetime import datetime, timezone

from core.audit import (
    GENESIS_HASH,
    ActorType,
    AuditChainEntry,
    AuditEventType,
    AuditLogger,
    ChainState,
)


# ─── Force in-memory path for all tests ────────────────────────────────────────
# AuditLogger._create_chain_entry() imports get_redis() at call time.
# Patching it here ensures every log() call uses the fast in-memory fallback,
# preventing hundreds of TCP connection attempts to localhost:6379 per test run.

@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _make_entry(
    sequence=1,
    timestamp=None,
    event_type="auth.success",
    message="test message",
    actor="system",
    actor_type="system",
    resource=None,
    details=None,
    previous_hash=None,
) -> AuditChainEntry:
    """Build a chain entry and compute its hash."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    if previous_hash is None:
        previous_hash = GENESIS_HASH
    entry = AuditChainEntry(
        sequence=sequence,
        timestamp=timestamp,
        event_type=event_type,
        message=message,
        actor=actor,
        actor_type=actor_type,
        resource=resource,
        details=details or {},
        previous_hash=previous_hash,
    )
    entry.entry_hash = entry.compute_hash()
    return entry


def _fresh_logger() -> AuditLogger:
    """Reuse the module-level audit singleton but reset its in-memory chain state.

    Creating a new AuditLogger() each time would hit Redis (even to fail) twice per
    instance, making hundreds of network attempts across the test suite.  Resetting
    the singleton is safe — each test gets a clean chain with no shared state.
    """
    from core.audit import audit as _audit_singleton
    _audit_singleton._chain_entries = []
    _audit_singleton._chain_state = ChainState(
        chain_id="test-chain-id",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return _audit_singleton


# ═══════════════════════════════════════════════════════════════════════════════
# GENESIS_HASH
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenesisHash:
    def test_genesis_hash_is_64_chars(self):
        assert len(GENESIS_HASH) == 64

    def test_genesis_hash_all_zeros(self):
        assert GENESIS_HASH == "0" * 64

    def test_genesis_hash_is_string(self):
        assert isinstance(GENESIS_HASH, str)


# ═══════════════════════════════════════════════════════════════════════════════
# AuditEventType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditEventType:
    def test_auth_success(self):
        assert AuditEventType.AUTH_SUCCESS == "auth.success"

    def test_auth_failure(self):
        assert AuditEventType.AUTH_FAILURE == "auth.failure"

    def test_auth_token_issued(self):
        assert AuditEventType.AUTH_TOKEN_ISSUED == "auth.token_issued"

    def test_task_dispatched(self):
        assert AuditEventType.TASK_DISPATCHED == "task.dispatched"

    def test_task_completed(self):
        assert AuditEventType.TASK_COMPLETED == "task.completed"

    def test_task_failed(self):
        assert AuditEventType.TASK_FAILED == "task.failed"

    def test_external_request(self):
        assert AuditEventType.EXTERNAL_REQUEST == "external.request"

    def test_external_blocked(self):
        assert AuditEventType.EXTERNAL_BLOCKED == "external.blocked"

    def test_external_response(self):
        assert AuditEventType.EXTERNAL_RESPONSE == "external.response"

    def test_system_startup(self):
        assert AuditEventType.SYSTEM_STARTUP == "system.startup"

    def test_system_shutdown(self):
        assert AuditEventType.SYSTEM_SHUTDOWN == "system.shutdown"

    def test_system_error(self):
        assert AuditEventType.SYSTEM_ERROR == "system.error"

    def test_agent_registered(self):
        assert AuditEventType.AGENT_REGISTERED == "agent.registered"

    def test_agent_heartbeat(self):
        assert AuditEventType.AGENT_HEARTBEAT == "agent.heartbeat"

    def test_agent_action(self):
        assert AuditEventType.AGENT_ACTION == "agent.action"

    def test_security_alert(self):
        assert AuditEventType.SECURITY_ALERT == "security.alert"

    def test_security_qms_bypass(self):
        assert AuditEventType.SECURITY_QMS_BYPASS == "security.qms_bypass"

    def test_capability_check(self):
        assert AuditEventType.CAPABILITY_CHECK == "capability.check"

    def test_approval_granted(self):
        assert AuditEventType.APPROVAL_GRANTED == "approval.granted"

    def test_anomaly_detected(self):
        assert AuditEventType.ANOMALY_DETECTED == "anomaly.detected"

    def test_tool_registered(self):
        assert AuditEventType.TOOL_REGISTERED == "tool.registered"

    def test_tool_checkout(self):
        assert AuditEventType.TOOL_CHECKOUT == "tool.checkout"

    def test_tool_return(self):
        assert AuditEventType.TOOL_RETURN == "tool.return"

    def test_tool_hitl_gate(self):
        assert AuditEventType.TOOL_HITL_GATE == "tool.hitl_gate"

    def test_identity_registered(self):
        assert AuditEventType.IDENTITY_REGISTERED == "identity.registered"

    def test_identity_verified(self):
        assert AuditEventType.IDENTITY_VERIFIED == "identity.verified"

    def test_identity_revoked(self):
        assert AuditEventType.IDENTITY_REVOKED == "identity.revoked"

    def test_openclaw_registered(self):
        assert AuditEventType.OPENCLAW_REGISTERED == "openclaw.registered"

    def test_openclaw_action_allowed(self):
        assert AuditEventType.OPENCLAW_ACTION_ALLOWED == "openclaw.action_allowed"

    def test_openclaw_action_blocked(self):
        assert AuditEventType.OPENCLAW_ACTION_BLOCKED == "openclaw.action_blocked"

    def test_openclaw_trust_promoted(self):
        assert AuditEventType.OPENCLAW_TRUST_PROMOTED == "openclaw.trust_promoted"

    def test_openclaw_suspended(self):
        assert AuditEventType.OPENCLAW_SUSPENDED == "openclaw.suspended"

    def test_is_str_subclass(self):
        assert isinstance(AuditEventType.AUTH_SUCCESS, str)


# ═══════════════════════════════════════════════════════════════════════════════
# ActorType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestActorType:
    def test_human(self):
        assert ActorType.HUMAN == "human"

    def test_ai_agent(self):
        assert ActorType.AI_AGENT == "ai_agent"

    def test_system(self):
        assert ActorType.SYSTEM == "system"

    def test_service_account(self):
        assert ActorType.SERVICE_ACCOUNT == "service_account"

    def test_emergency(self):
        assert ActorType.EMERGENCY == "emergency"

    def test_five_values(self):
        assert len(ActorType) == 5

    def test_is_str_subclass(self):
        assert isinstance(ActorType.HUMAN, str)


# ═══════════════════════════════════════════════════════════════════════════════
# AuditChainEntry.compute_hash()
# ═══════════════════════════════════════════════════════════════════════════════

class TestComputeHash:
    def test_returns_string(self):
        entry = _make_entry()
        assert isinstance(entry.compute_hash(), str)

    def test_returns_64_hex_chars(self):
        entry = _make_entry()
        h = entry.compute_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        entry = _make_entry(timestamp="2026-01-01T00:00:00+00:00")
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2

    def test_different_sequence_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(sequence=1, timestamp=ts)
        e2 = _make_entry(sequence=2, timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_message_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(message="hello", timestamp=ts)
        e2 = _make_entry(message="world", timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_actor_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(actor="alice", timestamp=ts)
        e2 = _make_entry(actor="bob", timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_event_type_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(event_type="auth.success", timestamp=ts)
        e2 = _make_entry(event_type="auth.failure", timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_resource_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(resource=None, timestamp=ts)
        e2 = _make_entry(resource="/api/tasks", timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_details_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(details={"key": "a"}, timestamp=ts)
        e2 = _make_entry(details={"key": "b"}, timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_previous_hash_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(previous_hash=GENESIS_HASH, timestamp=ts)
        e2 = _make_entry(previous_hash="a" * 64, timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_different_actor_type_different_hash(self):
        ts = "2026-01-01T00:00:00+00:00"
        e1 = _make_entry(actor_type="human", timestamp=ts)
        e2 = _make_entry(actor_type="ai_agent", timestamp=ts)
        assert e1.compute_hash() != e2.compute_hash()

    def test_hash_matches_manual_sha256(self):
        """Verify exact SHA-256 computation matches the spec."""
        ts = "2026-01-01T00:00:00+00:00"
        entry = AuditChainEntry(
            sequence=1,
            timestamp=ts,
            event_type="auth.success",
            message="test",
            actor="system",
            actor_type="system",
            resource=None,
            details={},
            previous_hash=GENESIS_HASH,
        )
        content = json.dumps({
            "sequence": 1,
            "timestamp": ts,
            "event_type": "auth.success",
            "message": "test",
            "actor": "system",
            "actor_type": "system",
            "resource": None,
            "details": {},
            "previous_hash": GENESIS_HASH,
        }, sort_keys=True, separators=(',', ':'))
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert entry.compute_hash() == expected


# ═══════════════════════════════════════════════════════════════════════════════
# AuditChainEntry.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditChainEntryToDict:
    def test_returns_dict(self):
        entry = _make_entry()
        assert isinstance(entry.to_dict(), dict)

    def test_has_sequence(self):
        entry = _make_entry(sequence=42)
        assert entry.to_dict()["sequence"] == 42

    def test_has_timestamp(self):
        ts = "2026-01-01T00:00:00+00:00"
        entry = _make_entry(timestamp=ts)
        assert entry.to_dict()["timestamp"] == ts

    def test_has_event_type(self):
        entry = _make_entry(event_type="task.dispatched")
        assert entry.to_dict()["event_type"] == "task.dispatched"

    def test_has_message(self):
        entry = _make_entry(message="hello world")
        assert entry.to_dict()["message"] == "hello world"

    def test_has_actor(self):
        entry = _make_entry(actor="alice")
        assert entry.to_dict()["actor"] == "alice"

    def test_has_actor_type(self):
        entry = _make_entry(actor_type="human")
        assert entry.to_dict()["actor_type"] == "human"

    def test_has_resource(self):
        entry = _make_entry(resource="/data/file.txt")
        assert entry.to_dict()["resource"] == "/data/file.txt"

    def test_has_details(self):
        entry = _make_entry(details={"method": "GET"})
        assert entry.to_dict()["details"] == {"method": "GET"}

    def test_has_previous_hash(self):
        entry = _make_entry(previous_hash=GENESIS_HASH)
        assert entry.to_dict()["previous_hash"] == GENESIS_HASH

    def test_has_entry_hash(self):
        entry = _make_entry()
        d = entry.to_dict()
        assert "entry_hash" in d
        assert len(d["entry_hash"]) == 64

    def test_entry_hash_matches_computed(self):
        entry = _make_entry()
        assert entry.to_dict()["entry_hash"] == entry.compute_hash()

    def test_all_ten_keys_present(self):
        entry = _make_entry()
        d = entry.to_dict()
        expected_keys = {
            "sequence", "timestamp", "event_type", "message",
            "actor", "actor_type", "resource", "details",
            "previous_hash", "entry_hash"
        }
        assert set(d.keys()) == expected_keys


# ═══════════════════════════════════════════════════════════════════════════════
# ChainState defaults
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainState:
    def test_default_last_sequence_zero(self):
        cs = ChainState()
        assert cs.last_sequence == 0

    def test_default_last_hash_is_genesis(self):
        cs = ChainState()
        assert cs.last_hash == GENESIS_HASH

    def test_default_entries_count_zero(self):
        cs = ChainState()
        assert cs.entries_count == 0

    def test_chain_id_defaults_empty(self):
        cs = ChainState()
        assert cs.chain_id == ""


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.get_chain_state()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetChainState:
    def test_returns_dict(self):
        lg = _fresh_logger()
        assert isinstance(lg.get_chain_state(), dict)

    def test_has_chain_id(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "chain_id" in state
        assert state["chain_id"] == "test-chain-id"

    def test_has_last_sequence(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "last_sequence" in state
        assert state["last_sequence"] == 0

    def test_has_last_hash(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "last_hash" in state
        assert state["last_hash"] == GENESIS_HASH

    def test_has_created_at(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "created_at" in state
        assert state["created_at"] != ""

    def test_has_entries_count(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "entries_count" in state
        assert state["entries_count"] == 0

    def test_has_in_memory_entries(self):
        lg = _fresh_logger()
        state = lg.get_chain_state()
        assert "in_memory_entries" in state
        assert state["in_memory_entries"] == 0

    def test_sequence_increments_after_log(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test", actor="system")
        state = lg.get_chain_state()
        assert state["last_sequence"] == 1

    def test_in_memory_entries_increments(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test", actor="system")
        state = lg.get_chain_state()
        assert state["in_memory_entries"] == 1

    def test_entries_count_increments(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test", actor="system")
        state = lg.get_chain_state()
        assert state["entries_count"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.get_recent_entries()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetRecentEntries:
    def test_empty_logger_returns_empty_list(self):
        lg = _fresh_logger()
        assert lg.get_recent_entries() == []

    def test_returns_list(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        assert isinstance(lg.get_recent_entries(), list)

    def test_entries_are_dicts(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        entries = lg.get_recent_entries()
        assert all(isinstance(e, dict) for e in entries)

    def test_limit_respected(self):
        lg = _fresh_logger()
        for i in range(10):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        assert len(lg.get_recent_entries(limit=5)) == 5

    def test_default_limit_100(self):
        lg = _fresh_logger()
        for i in range(5):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        # Default limit is 100 — all 5 returned
        assert len(lg.get_recent_entries()) == 5

    def test_returns_most_recent(self):
        lg = _fresh_logger()
        for i in range(5):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        entries = lg.get_recent_entries(limit=2)
        # Last 2 events should have sequences 4 and 5
        seqs = [e["sequence"] for e in entries]
        assert seqs == [4, 5]

    def test_each_entry_has_entry_hash(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        entries = lg.get_recent_entries()
        assert all("entry_hash" in e for e in entries)


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.verify_chain()
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyChain:
    def test_empty_chain_is_valid(self):
        lg = _fresh_logger()
        result = lg.verify_chain()
        assert result["valid"] is True

    def test_empty_chain_message(self):
        lg = _fresh_logger()
        result = lg.verify_chain()
        assert "No entries" in result["message"]

    def test_empty_chain_entries_checked_zero(self):
        lg = _fresh_logger()
        result = lg.verify_chain()
        assert result["entries_checked"] == 0

    def test_single_valid_entry(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        result = lg.verify_chain()
        assert result["valid"] is True

    def test_multiple_valid_entries(self):
        lg = _fresh_logger()
        for i in range(5):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        result = lg.verify_chain()
        assert result["valid"] is True
        assert result["entries_checked"] == 5

    def test_valid_chain_no_breaks(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test1")
        lg.log(AuditEventType.AUTH_FAILURE, "test2")
        result = lg.verify_chain()
        assert result["breaks"] == []

    def test_valid_chain_success_message(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        result = lg.verify_chain()
        assert "verified" in result["message"].lower() or "success" in result["message"].lower()

    def test_tampered_hash_detected(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        # Manually tamper the stored entry_hash
        lg._chain_entries[0].entry_hash = "a" * 64
        entries = [e.to_dict() for e in lg._chain_entries]
        result = lg.verify_chain(entries)
        assert result["valid"] is False
        assert len(result["breaks"]) == 1
        assert result["breaks"][0]["issue"] == "hash_mismatch"

    def test_tampered_message_detected(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "original message")
        entry = lg._chain_entries[0]
        # Tamper the message but keep the original hash
        tampered = entry.to_dict()
        tampered["message"] = "tampered message"
        # entry_hash was computed with original message, so it won't match
        result = lg.verify_chain([tampered])
        assert result["valid"] is False

    def test_chain_break_detected(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "event1")
        lg.log(AuditEventType.AUTH_FAILURE, "event2")
        # Break the chain: change entry 2's previous_hash
        entries = [e.to_dict() for e in lg._chain_entries]
        # Recompute entry 2 with wrong previous_hash to create chain break
        entry2_dict = entries[1].copy()
        entry2_dict["previous_hash"] = "b" * 64
        # Re-compute its hash so hash_mismatch doesn't mask chain_break
        e2 = AuditChainEntry(
            sequence=entry2_dict["sequence"],
            timestamp=entry2_dict["timestamp"],
            event_type=entry2_dict["event_type"],
            message=entry2_dict["message"],
            actor=entry2_dict["actor"],
            actor_type=entry2_dict.get("actor_type", "system"),
            resource=entry2_dict.get("resource"),
            details=entry2_dict.get("details", {}),
            previous_hash="b" * 64,
        )
        entry2_dict["entry_hash"] = e2.compute_hash()
        result = lg.verify_chain([entries[0], entry2_dict])
        assert result["valid"] is False
        issues = [b["issue"] for b in result["breaks"]]
        assert "chain_break" in issues

    def test_verify_chain_explicit_entries(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        entries = lg.get_recent_entries()
        result = lg.verify_chain(entries)
        assert result["valid"] is True

    def test_verify_chain_has_chain_id(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        result = lg.verify_chain()
        assert "chain_id" in result

    def test_verify_chain_has_first_last_sequence(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "event1")
        lg.log(AuditEventType.AUTH_SUCCESS, "event2")
        result = lg.verify_chain()
        assert result["first_sequence"] == 1
        assert result["last_sequence"] == 2

    def test_tampered_sequence_detected(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        entry_dict = lg._chain_entries[0].to_dict()
        # Modify sequence without updating hash
        entry_dict["sequence"] = 999
        result = lg.verify_chain([entry_dict])
        assert result["valid"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.export_chain_for_compliance()
# ═══════════════════════════════════════════════════════════════════════════════

class TestExportChainForCompliance:
    def test_returns_dict(self):
        lg = _fresh_logger()
        assert isinstance(lg.export_chain_for_compliance(), dict)

    def test_has_export_timestamp(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "export_timestamp" in result
        assert result["export_timestamp"] != ""

    def test_has_chain_id(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "chain_id" in result

    def test_has_chain_created_at(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "chain_created_at" in result

    def test_has_total_entries(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "total_entries" in result

    def test_has_exported_entries(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "exported_entries" in result

    def test_has_verification(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "verification" in result
        assert isinstance(result["verification"], dict)

    def test_has_entries_list(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert "entries" in result
        assert isinstance(result["entries"], list)

    def test_empty_logger_exported_entries_zero(self):
        lg = _fresh_logger()
        result = lg.export_chain_for_compliance()
        assert result["exported_entries"] == 0

    def test_entries_count_matches(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "e1")
        lg.log(AuditEventType.AUTH_SUCCESS, "e2")
        result = lg.export_chain_for_compliance()
        assert result["exported_entries"] == 2

    def test_start_sequence_filter(self):
        lg = _fresh_logger()
        for i in range(5):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        result = lg.export_chain_for_compliance(start_sequence=3)
        # Entries with sequence >= 3 (sequences 3, 4, 5)
        assert result["exported_entries"] == 3

    def test_end_sequence_filter(self):
        lg = _fresh_logger()
        for i in range(5):
            lg.log(AuditEventType.AUTH_SUCCESS, f"event {i}")
        result = lg.export_chain_for_compliance(end_sequence=3)
        # Entries with sequence <= 3 (sequences 1, 2, 3)
        assert result["exported_entries"] == 3

    def test_verification_valid_for_valid_chain(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        result = lg.export_chain_for_compliance()
        assert result["verification"]["valid"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# AuditLogger.log() — chain linking
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogChaining:
    def test_first_entry_previous_hash_is_genesis(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "first event")
        entry = lg._chain_entries[0]
        assert entry.previous_hash == GENESIS_HASH

    def test_second_entry_links_to_first(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "first")
        lg.log(AuditEventType.AUTH_FAILURE, "second")
        first = lg._chain_entries[0]
        second = lg._chain_entries[1]
        assert second.previous_hash == first.entry_hash

    def test_entry_hash_not_empty(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        assert lg._chain_entries[0].entry_hash != ""

    def test_entry_hash_length_64(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "test")
        assert len(lg._chain_entries[0].entry_hash) == 64

    def test_sequence_increments(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "e1")
        lg.log(AuditEventType.AUTH_SUCCESS, "e2")
        lg.log(AuditEventType.AUTH_SUCCESS, "e3")
        seqs = [e.sequence for e in lg._chain_entries]
        assert seqs == [1, 2, 3]

    def test_event_type_stored_correctly(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.TASK_COMPLETED, "task done")
        assert lg._chain_entries[0].event_type == "task.completed"

    def test_actor_stored_correctly(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "msg", actor="alice")
        assert lg._chain_entries[0].actor == "alice"

    def test_actor_defaults_to_system(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "msg")
        assert lg._chain_entries[0].actor == "system"

    def test_resource_stored_correctly(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "msg", resource="/api/tasks")
        assert lg._chain_entries[0].resource == "/api/tasks"

    def test_details_stored_correctly(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "msg", details={"key": "val"})
        assert lg._chain_entries[0].details == {"key": "val"}

    def test_qms_status_appended_to_message(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "Authentication done", qms_status="Thank_You")
        assert lg._chain_entries[0].message == "Authentication done_Thank_You"

    def test_no_qms_status_message_unchanged(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "plain message")
        assert lg._chain_entries[0].message == "plain message"

    def test_actor_type_stored_correctly(self):
        lg = _fresh_logger()
        lg.log(AuditEventType.AUTH_SUCCESS, "msg", actor_type="human")
        assert lg._chain_entries[0].actor_type == "human"


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience methods
# ═══════════════════════════════════════════════════════════════════════════════

class TestConvenienceMethods:
    def test_auth_success_creates_entry(self):
        lg = _fresh_logger()
        lg.auth_success("alice")
        assert len(lg._chain_entries) == 1

    def test_auth_success_event_type(self):
        lg = _fresh_logger()
        lg.auth_success("alice")
        assert lg._chain_entries[0].event_type == "auth.success"

    def test_auth_success_message_contains_actor(self):
        lg = _fresh_logger()
        lg.auth_success("alice")
        assert "alice" in lg._chain_entries[0].message

    def test_auth_success_qms_suffix(self):
        lg = _fresh_logger()
        lg.auth_success("alice")
        assert lg._chain_entries[0].message.endswith("_Thank_You")

    def test_auth_failure_creates_entry(self):
        lg = _fresh_logger()
        lg.auth_failure("bob", "bad password")
        assert len(lg._chain_entries) == 1

    def test_auth_failure_event_type(self):
        lg = _fresh_logger()
        lg.auth_failure("bob", "bad password")
        assert lg._chain_entries[0].event_type == "auth.failure"

    def test_auth_failure_message_contains_reason(self):
        lg = _fresh_logger()
        lg.auth_failure("bob", "bad password")
        assert "bad password" in lg._chain_entries[0].message

    def test_auth_failure_qms_suffix(self):
        lg = _fresh_logger()
        lg.auth_failure("bob", "bad password")
        assert lg._chain_entries[0].message.endswith("_Thank_You_But_No")

    def test_auth_failure_details_has_reason(self):
        lg = _fresh_logger()
        lg.auth_failure("bob", "expired token")
        assert lg._chain_entries[0].details["reason"] == "expired token"

    def test_task_dispatched_creates_entry(self):
        lg = _fresh_logger()
        lg.task_dispatched("backup_task", "task-123", "alice")
        assert len(lg._chain_entries) == 1

    def test_task_dispatched_event_type(self):
        lg = _fresh_logger()
        lg.task_dispatched("backup_task", "task-123", "alice")
        assert lg._chain_entries[0].event_type == "task.dispatched"

    def test_task_dispatched_qms_please(self):
        lg = _fresh_logger()
        lg.task_dispatched("backup_task", "task-123", "alice")
        assert lg._chain_entries[0].message.endswith("_Please")

    def test_task_dispatched_resource_is_task_id(self):
        lg = _fresh_logger()
        lg.task_dispatched("backup_task", "task-456", "alice")
        assert lg._chain_entries[0].resource == "task-456"

    def test_task_completed_creates_entry(self):
        lg = _fresh_logger()
        lg.task_completed("backup_task", "task-123")
        assert len(lg._chain_entries) == 1

    def test_task_completed_event_type(self):
        lg = _fresh_logger()
        lg.task_completed("backup_task", "task-123")
        assert lg._chain_entries[0].event_type == "task.completed"

    def test_task_completed_qms_thank_you(self):
        lg = _fresh_logger()
        lg.task_completed("backup_task", "task-123")
        assert lg._chain_entries[0].message.endswith("_Thank_You")

    def test_task_failed_creates_entry(self):
        lg = _fresh_logger()
        lg.task_failed("backup_task", "task-123", "timeout")
        assert len(lg._chain_entries) == 1

    def test_task_failed_event_type(self):
        lg = _fresh_logger()
        lg.task_failed("backup_task", "task-123", "timeout")
        assert lg._chain_entries[0].event_type == "task.failed"

    def test_task_failed_message_contains_error(self):
        lg = _fresh_logger()
        lg.task_failed("backup_task", "task-123", "timeout")
        assert "timeout" in lg._chain_entries[0].message

    def test_task_failed_qms_suffix(self):
        lg = _fresh_logger()
        lg.task_failed("backup_task", "task-123", "timeout")
        assert lg._chain_entries[0].message.endswith("_Thank_You_But_No")

    def test_external_request_creates_entry(self):
        lg = _fresh_logger()
        lg.external_request("https://api.example.com", "alice")
        assert len(lg._chain_entries) == 1

    def test_external_request_event_type(self):
        lg = _fresh_logger()
        lg.external_request("https://api.example.com", "alice")
        assert lg._chain_entries[0].event_type == "external.request"

    def test_external_request_resource_is_url(self):
        lg = _fresh_logger()
        lg.external_request("https://api.example.com", "alice")
        assert lg._chain_entries[0].resource == "https://api.example.com"

    def test_external_request_default_method_get(self):
        lg = _fresh_logger()
        lg.external_request("https://api.example.com", "alice")
        assert lg._chain_entries[0].details["method"] == "GET"

    def test_external_request_custom_method(self):
        lg = _fresh_logger()
        lg.external_request("https://api.example.com", "alice", method="POST")
        assert lg._chain_entries[0].details["method"] == "POST"

    def test_external_blocked_creates_entry(self):
        lg = _fresh_logger()
        lg.external_blocked("https://bad.com", "alice", "not whitelisted")
        assert len(lg._chain_entries) == 1

    def test_external_blocked_event_type(self):
        lg = _fresh_logger()
        lg.external_blocked("https://bad.com", "alice", "not whitelisted")
        assert lg._chain_entries[0].event_type == "external.blocked"

    def test_external_blocked_message_contains_blocked(self):
        lg = _fresh_logger()
        lg.external_blocked("https://bad.com", "alice", "not whitelisted")
        assert "BLOCKED" in lg._chain_entries[0].message

    def test_external_blocked_details_has_reason(self):
        lg = _fresh_logger()
        lg.external_blocked("https://bad.com", "alice", "not whitelisted")
        assert lg._chain_entries[0].details["reason"] == "not whitelisted"

    def test_multiple_convenience_methods_chain_correctly(self):
        lg = _fresh_logger()
        lg.auth_success("alice")
        lg.task_dispatched("work", "t-1", "alice")
        lg.task_completed("work", "t-1")
        result = lg.verify_chain()
        assert result["valid"] is True
        assert result["entries_checked"] == 3

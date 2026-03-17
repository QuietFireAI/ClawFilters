# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_qms_depth.py
# REM: Coverage depth tests for core/qms.py
# REM: Pure unit tests — no DB, no Redis, no HTTP

import pytest
from core.qms import (
    QMSStatus, QMSBlockType, QMSFieldType,
    QMSBlock, QMSChain, QMSMessage,
    SYSTEM_HALT, PRIORITY_LEVELS, DEFAULT_PRIORITY, DEFAULT_TTL_BY_PRIORITY,
    _detect_block_type, _make_block, _wrap_qualifier,
    build_chain, build_halt_chain,
    parse_chain, find_chains,
    validate_chain, validate_chain_string, validate_chain_semantics,
    is_chain_formatted, is_qms_formatted, validate_qms, parse_qms,
    get_default_ttl, get_message_schema,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════

class TestQMSStatusEnum:
    def test_please(self):
        assert QMSStatus.PLEASE == "Please"

    def test_thank_you(self):
        assert QMSStatus.THANK_YOU == "Thank_You"

    def test_thank_you_but_no(self):
        assert QMSStatus.THANK_YOU_BUT_NO == "Thank_You_But_No"

    def test_excuse_me(self):
        assert QMSStatus.EXCUSE_ME == "Excuse_Me"

    def test_pretty_please(self):
        assert QMSStatus.PRETTY_PLEASE == "Pretty_Please"

    def test_all_five_values(self):
        assert len(QMSStatus) == 5


class TestQMSBlockTypeEnum:
    def test_priority(self):
        assert QMSBlockType.PRIORITY == "!!"

    def test_origin(self):
        assert QMSBlockType.ORIGIN == "<>"

    def test_correlation(self):
        assert QMSBlockType.CORRELATION == "@@"

    def test_generic(self):
        assert QMSBlockType.GENERIC == ""

    def test_numeric(self):
        assert QMSBlockType.NUMERIC == "$$"

    def test_identifier(self):
        assert QMSBlockType.IDENTIFIER == "##"

    def test_string(self):
        assert QMSBlockType.STRING == "%%"

    def test_query(self):
        assert QMSBlockType.QUERY == "??"

    def test_version(self):
        assert QMSBlockType.VERSION == "&&"

    def test_encrypted(self):
        assert QMSBlockType.ENCRYPTED == "||"

    def test_command(self):
        assert QMSBlockType.COMMAND == "_"

    def test_system_halt(self):
        assert QMSBlockType.SYSTEM_HALT == "%%%%"


class TestQMSFieldTypeEnum:
    def test_critical(self):
        assert QMSFieldType.CRITICAL == "::"

    def test_priority(self):
        assert QMSFieldType.PRIORITY == "$$"

    def test_policy(self):
        assert QMSFieldType.POLICY == "##"

    def test_target(self):
        assert QMSFieldType.TARGET == "@@"

    def test_question(self):
        assert QMSFieldType.QUESTION == "??"


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

class TestConstants:
    def test_system_halt_value(self):
        assert SYSTEM_HALT == "%%%%"

    def test_priority_levels(self):
        assert "URGENT" in PRIORITY_LEVELS
        assert "P1" in PRIORITY_LEVELS
        assert "P2" in PRIORITY_LEVELS
        assert "P3" in PRIORITY_LEVELS

    def test_default_priority(self):
        assert DEFAULT_PRIORITY == "P2"

    def test_default_ttl_urgent(self):
        assert DEFAULT_TTL_BY_PRIORITY["URGENT"] == 10

    def test_default_ttl_p1(self):
        assert DEFAULT_TTL_BY_PRIORITY["P1"] == 30

    def test_default_ttl_p2(self):
        assert DEFAULT_TTL_BY_PRIORITY["P2"] == 120

    def test_default_ttl_p3(self):
        assert DEFAULT_TTL_BY_PRIORITY["P3"] == 600


# ═══════════════════════════════════════════════════════════════════════════════
# _detect_block_type
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectBlockType:
    def test_system_halt(self):
        assert _detect_block_type("%%%%") == QMSBlockType.SYSTEM_HALT

    def test_priority_urgent(self):
        assert _detect_block_type("!URGENT!") == QMSBlockType.PRIORITY

    def test_priority_p1(self):
        assert _detect_block_type("!P1!") == QMSBlockType.PRIORITY

    def test_origin(self):
        assert _detect_block_type("<backup_agent>") == QMSBlockType.ORIGIN

    def test_correlation(self):
        assert _detect_block_type("@@REQ_abc123@@") == QMSBlockType.CORRELATION

    def test_command_please(self):
        assert _detect_block_type("_Please") == QMSBlockType.COMMAND

    def test_command_thank_you(self):
        assert _detect_block_type("_Thank_You") == QMSBlockType.COMMAND

    def test_numeric(self):
        assert _detect_block_type("$$49.99$$") == QMSBlockType.NUMERIC

    def test_identifier(self):
        assert _detect_block_type("##USER_123##") == QMSBlockType.IDENTIFIER

    def test_string(self):
        assert _detect_block_type("%%error message%%") == QMSBlockType.STRING

    def test_query(self):
        assert _detect_block_type("??Specify_Path??") == QMSBlockType.QUERY

    def test_version(self):
        assert _detect_block_type("&&QMS_v2.2.0&&") == QMSBlockType.VERSION

    def test_encrypted(self):
        assert _detect_block_type("||a746fg2e||") == QMSBlockType.ENCRYPTED

    def test_generic_action(self):
        assert _detect_block_type("Create_Backup") == QMSBlockType.GENERIC

    def test_generic_plain(self):
        assert _detect_block_type("Ping") == QMSBlockType.GENERIC

    def test_single_exclamation_not_priority(self):
        # "!x!" has len==3, which is > 2 — but what about "!!"?
        # Single char: "!!" len==2, not >2 → generic
        assert _detect_block_type("!!") == QMSBlockType.GENERIC

    def test_short_correlation_not_matched(self):
        # "@@" has len==2, not >4
        assert _detect_block_type("@@") == QMSBlockType.GENERIC


# ═══════════════════════════════════════════════════════════════════════════════
# _make_block and _wrap_qualifier
# ═══════════════════════════════════════════════════════════════════════════════

class TestMakeBlock:
    def test_make_origin_block(self):
        b = _make_block("<agent_x>")
        assert b.block_type == QMSBlockType.ORIGIN
        assert b.content == "<agent_x>"

    def test_make_generic_block(self):
        b = _make_block("Create_Backup")
        assert b.block_type == QMSBlockType.GENERIC

    def test_make_system_halt_block(self):
        b = _make_block("%%%%")
        assert b.block_type == QMSBlockType.SYSTEM_HALT


class TestWrapQualifier:
    def test_wrap_priority(self):
        assert _wrap_qualifier("P1", QMSBlockType.PRIORITY) == "!P1!"

    def test_wrap_origin(self):
        assert _wrap_qualifier("agent_x", QMSBlockType.ORIGIN) == "<agent_x>"

    def test_wrap_correlation(self):
        assert _wrap_qualifier("REQ_001", QMSBlockType.CORRELATION) == "@@REQ_001@@"

    def test_wrap_numeric(self):
        assert _wrap_qualifier("49.99", QMSBlockType.NUMERIC) == "$$49.99$$"

    def test_wrap_identifier(self):
        assert _wrap_qualifier("USER_123", QMSBlockType.IDENTIFIER) == "##USER_123##"

    def test_wrap_string(self):
        assert _wrap_qualifier("some error", QMSBlockType.STRING) == "%%some error%%"

    def test_wrap_query(self):
        assert _wrap_qualifier("Which_Path", QMSBlockType.QUERY) == "??Which_Path??"

    def test_wrap_version(self):
        assert _wrap_qualifier("QMS_v2.2.0", QMSBlockType.VERSION) == "&&QMS_v2.2.0&&"

    def test_wrap_encrypted(self):
        assert _wrap_qualifier("abc123", QMSBlockType.ENCRYPTED) == "||abc123||"

    def test_wrap_command(self):
        assert _wrap_qualifier("Please", QMSBlockType.COMMAND) == "_Please"

    def test_wrap_system_halt(self):
        assert _wrap_qualifier("ignored", QMSBlockType.SYSTEM_HALT) == "%%%%"

    def test_wrap_generic(self):
        assert _wrap_qualifier("Create_Backup", QMSBlockType.GENERIC) == "Create_Backup"


# ═══════════════════════════════════════════════════════════════════════════════
# QMSBlock
# ═══════════════════════════════════════════════════════════════════════════════

class TestQMSBlock:
    def test_to_string(self):
        b = QMSBlock(content="Ping", block_type=QMSBlockType.GENERIC)
        assert b.to_string() == "::Ping::"

    def test_inner_value_priority(self):
        b = QMSBlock(content="!P1!", block_type=QMSBlockType.PRIORITY)
        assert b.inner_value == "P1"

    def test_inner_value_origin(self):
        b = QMSBlock(content="<agent_x>", block_type=QMSBlockType.ORIGIN)
        assert b.inner_value == "agent_x"

    def test_inner_value_system_halt(self):
        b = QMSBlock(content="%%%%", block_type=QMSBlockType.SYSTEM_HALT)
        assert b.inner_value == ""

    def test_inner_value_command(self):
        b = QMSBlock(content="_Please", block_type=QMSBlockType.COMMAND)
        assert b.inner_value == "Please"

    def test_inner_value_generic(self):
        b = QMSBlock(content="Create_Backup", block_type=QMSBlockType.GENERIC)
        assert b.inner_value == "Create_Backup"

    def test_inner_value_numeric(self):
        b = QMSBlock(content="$$49.99$$", block_type=QMSBlockType.NUMERIC)
        assert b.inner_value == "49.99"

    def test_inner_value_identifier(self):
        b = QMSBlock(content="##USER_123##", block_type=QMSBlockType.IDENTIFIER)
        assert b.inner_value == "USER_123"

    def test_inner_value_string(self):
        b = QMSBlock(content="%%error%%", block_type=QMSBlockType.STRING)
        assert b.inner_value == "error"

    def test_inner_value_query(self):
        b = QMSBlock(content="??Which_Path??", block_type=QMSBlockType.QUERY)
        assert b.inner_value == "Which_Path"

    def test_inner_value_encrypted(self):
        b = QMSBlock(content="||abc123||", block_type=QMSBlockType.ENCRYPTED)
        assert b.inner_value == "abc123"

    def test_inner_value_version(self):
        b = QMSBlock(content="&&v2&&", block_type=QMSBlockType.VERSION)
        assert b.inner_value == "v2"


# ═══════════════════════════════════════════════════════════════════════════════
# build_chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildChain:
    def test_basic_chain_structure(self):
        chain = build_chain("backup_agent", "Create_Backup", QMSStatus.PLEASE)
        assert chain.origin == "backup_agent"
        assert chain.action == "Create_Backup"
        assert chain.command == QMSStatus.PLEASE

    def test_chain_has_correlation_id(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.THANK_YOU)
        assert chain.correlation_id is not None
        assert chain.correlation_id.startswith("REQ_")

    def test_custom_correlation_id(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE,
                            correlation_id="REQ_custom01")
        assert chain.correlation_id == "REQ_custom01"

    def test_chain_with_priority(self):
        chain = build_chain("agent_x", "Alert", QMSStatus.PLEASE, priority="P1")
        assert chain.priority == "P1"
        assert chain._offset == 1

    def test_chain_invalid_priority_defaults(self):
        chain = build_chain("agent_x", "Alert", QMSStatus.PLEASE, priority="INVALID")
        # Falls back to DEFAULT_PRIORITY
        assert chain.priority == DEFAULT_PRIORITY

    def test_chain_with_ttl(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE, ttl_seconds=30)
        assert chain.ttl_seconds == 30

    def test_chain_no_priority_no_offset(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        assert chain.priority is None
        assert chain._offset == 0

    def test_chain_with_data_blocks(self):
        chain = build_chain(
            "agent_x", "Process",  QMSStatus.PLEASE,
            data_blocks=[("user_123", QMSBlockType.IDENTIFIER),
                         ("49.99", QMSBlockType.NUMERIC)]
        )
        assert len(chain.data_blocks) == 2

    def test_chain_to_string_non_empty(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        s = chain.to_string()
        assert "<agent_x>" in s
        assert "_Please" in s

    def test_chain_not_halt(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        assert chain.is_halt is False

    def test_chain_thank_you_command(self):
        chain = build_chain("agent_x", "Done", QMSStatus.THANK_YOU)
        assert chain.command == QMSStatus.THANK_YOU

    def test_chain_all_statuses(self):
        for status in QMSStatus:
            chain = build_chain("agent_x", "Op", status)
            assert chain.command == status


# ═══════════════════════════════════════════════════════════════════════════════
# build_halt_chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildHaltChain:
    def test_halt_chain_is_halt(self):
        chain = build_halt_chain("agent_x", "Critical_Op")
        assert chain.is_halt is True

    def test_halt_chain_with_reason(self):
        chain = build_halt_chain("agent_x", "Critical_Op",
                                 reason="Database connection lost")
        assert chain.halt_reason == "Database connection lost"

    def test_halt_chain_without_reason(self):
        chain = build_halt_chain("agent_x", "Critical_Op")
        assert chain.halt_reason is None

    def test_halt_chain_default_priority_urgent(self):
        chain = build_halt_chain("agent_x", "Critical_Op")
        assert chain.priority == "URGENT"

    def test_halt_chain_custom_priority(self):
        chain = build_halt_chain("agent_x", "Critical_Op", priority="P1")
        assert chain.priority == "P1"

    def test_halt_chain_origin(self):
        chain = build_halt_chain("payment_agent", "Process_Payment",
                                 reason="DB lost")
        assert chain.origin == "payment_agent"

    def test_halt_chain_has_data_blocks(self):
        chain = build_halt_chain(
            "agent_x", "Op",
            data_blocks=[("TXN_001", QMSBlockType.IDENTIFIER)]
        )
        assert chain.is_halt is True

    def test_halt_chain_correlation_auto_generated(self):
        chain = build_halt_chain("agent_x", "Op")
        assert chain.correlation_id is not None

    def test_halt_chain_custom_correlation(self):
        chain = build_halt_chain("agent_x", "Op",
                                 correlation_id="REQ_halt01")
        assert chain.correlation_id == "REQ_halt01"

    def test_halt_chain_invalid_priority_defaults_urgent(self):
        chain = build_halt_chain("agent_x", "Op", priority="BOGUS")
        assert chain.priority == "URGENT"


# ═══════════════════════════════════════════════════════════════════════════════
# QMSChain properties (edge cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQMSChainProperties:
    def test_empty_chain_origin_none(self):
        chain = QMSChain(blocks=[])
        assert chain.origin is None

    def test_empty_chain_correlation_none(self):
        chain = QMSChain(blocks=[])
        assert chain.correlation_id is None

    def test_empty_chain_action_none(self):
        chain = QMSChain(blocks=[])
        assert chain.action is None

    def test_empty_chain_command_none(self):
        chain = QMSChain(blocks=[])
        assert chain.command is None

    def test_empty_chain_is_halt_false(self):
        chain = QMSChain(blocks=[])
        assert chain.is_halt is False

    def test_halt_reason_none_when_no_halt(self):
        chain = build_chain("a", "Op", QMSStatus.PLEASE)
        assert chain.halt_reason is None

    def test_ttl_none_without_ttl(self):
        chain = build_chain("a", "Op", QMSStatus.PLEASE)
        assert chain.ttl_seconds is None

    def test_ttl_extracted(self):
        chain = build_chain("a", "Op", QMSStatus.PLEASE, ttl_seconds=60)
        assert chain.ttl_seconds == 60

    def test_data_blocks_empty_short_chain(self):
        chain = build_chain("a", "Op", QMSStatus.PLEASE)
        # No explicit data blocks → empty
        assert chain.data_blocks == []

    def test_data_blocks_halt_chain(self):
        chain = build_halt_chain("a", "Op", reason="Failure")
        # data_blocks stops before halt block
        assert isinstance(chain.data_blocks, list)

    def test_chain_to_string_contains_separator(self):
        chain = build_chain("a", "Op", QMSStatus.PLEASE)
        s = chain.to_string()
        assert "-" in s


# ═══════════════════════════════════════════════════════════════════════════════
# parse_chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseChain:
    def test_parse_valid_chain(self):
        chain = build_chain("backup_agent", "Ping", QMSStatus.PLEASE)
        s = chain.to_string()
        parsed = parse_chain(s)
        assert parsed is not None
        assert parsed.origin == "backup_agent"

    def test_parse_none_returns_none(self):
        assert parse_chain(None) is None

    def test_parse_empty_string_returns_none(self):
        assert parse_chain("") is None

    def test_parse_non_string_returns_none(self):
        assert parse_chain(12345) is None

    def test_parse_plain_text_returns_none(self):
        assert parse_chain("This is just plain text") is None

    def test_parse_preserves_raw(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        s = chain.to_string()
        parsed = parse_chain(s)
        assert parsed.raw != ""

    def test_parse_halt_chain(self):
        chain = build_halt_chain("agent_x", "Op", reason="DB lost")
        s = chain.to_string()
        parsed = parse_chain(s)
        assert parsed is not None
        assert parsed.is_halt is True

    def test_parse_chain_with_priority(self):
        chain = build_chain("agent_x", "Alert", QMSStatus.PLEASE, priority="P1")
        s = chain.to_string()
        parsed = parse_chain(s)
        assert parsed is not None
        assert parsed.priority == "P1"


# ═══════════════════════════════════════════════════════════════════════════════
# find_chains
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindChains:
    def test_find_no_chains(self):
        assert find_chains("plain text, no chains here") == []

    def test_find_empty_string(self):
        assert find_chains("") == []

    def test_find_none(self):
        assert find_chains(None) == []

    def test_find_single_chain(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        s = chain.to_string()
        result = find_chains(s)
        assert len(result) == 1

    def test_find_multiple_chains(self):
        c1 = build_chain("agent_a", "Ping", QMSStatus.PLEASE).to_string()
        c2 = build_chain("agent_b", "Pong", QMSStatus.THANK_YOU).to_string()
        text = f"LOG: {c1} and also {c2}"
        result = find_chains(text)
        assert len(result) == 2

    def test_find_chains_in_surrounding_text(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE).to_string()
        text = f"[2026-01-01] INFO: {chain} end of log line"
        result = find_chains(text)
        assert len(result) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# validate_chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateChain:
    def test_valid_chain_passes(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        result = validate_chain(chain)
        assert result.valid is True
        assert result.errors == []

    def test_empty_chain_fails(self):
        chain = QMSChain(blocks=[])
        result = validate_chain(chain)
        assert result.valid is False

    def test_none_chain_fails(self):
        result = validate_chain(None)
        assert result.valid is False

    def test_valid_halt_chain_passes(self):
        chain = build_halt_chain("agent_x", "Op", reason="DB lost")
        result = validate_chain(chain)
        assert result.valid is True

    def test_halt_chain_no_reason_has_warning(self):
        chain = build_halt_chain("agent_x", "Op")
        result = validate_chain(chain)
        # Valid but warns about no postscript
        assert result.valid is True
        assert any("halt_no_reason" in w for w in result.warnings)

    def test_missing_origin_gives_error(self):
        # Build chain and remove origin block
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        # Remove the origin block (index 0 since no priority)
        chain.blocks.pop(0)
        result = validate_chain(chain)
        assert result.valid is False
        assert any("origin" in e for e in result.errors)

    def test_chain_with_priority_validates(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE, priority="URGENT")
        result = validate_chain(chain)
        assert result.valid is True

    def test_chain_too_short_fails(self):
        # Only one block
        chain = QMSChain(blocks=[QMSBlock("<agent_x>", QMSBlockType.ORIGIN)])
        result = validate_chain(chain)
        assert result.valid is False

    def test_valid_chain_with_data_blocks(self):
        chain = build_chain("agent_x", "Process", QMSStatus.PLEASE,
                            data_blocks=[("USER_001", QMSBlockType.IDENTIFIER)])
        result = validate_chain(chain)
        assert result.valid is True

    def test_chain_with_ttl_validates(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE, ttl_seconds=30)
        result = validate_chain(chain)
        assert result.valid is True


# ═══════════════════════════════════════════════════════════════════════════════
# is_chain_formatted / is_qms_formatted
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainFormattedChecks:
    def test_is_chain_formatted_true(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        assert is_chain_formatted(chain.to_string()) is True

    def test_is_chain_formatted_false(self):
        assert is_chain_formatted("plain text") is False

    def test_is_chain_formatted_none(self):
        assert is_chain_formatted(None) is False

    def test_is_chain_formatted_empty(self):
        assert is_chain_formatted("") is False

    def test_is_qms_formatted_formal_chain(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        assert is_qms_formatted(chain.to_string()) is True

    def test_is_qms_formatted_legacy_suffix(self):
        assert is_qms_formatted("Create_Backup_Please") is True

    def test_is_qms_formatted_thank_you(self):
        assert is_qms_formatted("Operation_Thank_You completed") is True

    def test_is_qms_formatted_plain_text(self):
        assert is_qms_formatted("just some text") is False

    def test_is_qms_formatted_none(self):
        assert is_qms_formatted(None) is False


# ═══════════════════════════════════════════════════════════════════════════════
# validate_qms (legacy)
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateQMS:
    def test_valid_qms_message(self):
        ok, warning = validate_qms("Create_Backup_Please", log_warning=False)
        assert ok is True
        assert warning is None

    def test_invalid_message_returns_warning(self):
        ok, warning = validate_qms("just some text", log_warning=False)
        assert ok is False
        assert warning is not None

    def test_none_message_is_invalid(self):
        ok, warning = validate_qms(None, log_warning=False)
        assert ok is False

    def test_formal_chain_is_valid(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        ok, _ = validate_qms(chain.to_string(), log_warning=False)
        assert ok is True

    def test_thank_you_but_no_is_valid(self):
        ok, _ = validate_qms("Upload_Thank_You_But_No", log_warning=False)
        assert ok is True


# ═══════════════════════════════════════════════════════════════════════════════
# parse_qms (legacy)
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseQMS:
    def test_parse_please(self):
        msg = parse_qms("Create_Backup_Please")
        assert msg is not None
        assert msg.action == "Create_Backup"
        assert msg.status == QMSStatus.PLEASE

    def test_parse_thank_you(self):
        msg = parse_qms("Upload_Thank_You")
        assert msg is not None
        assert msg.status == QMSStatus.THANK_YOU

    def test_parse_thank_you_but_no(self):
        msg = parse_qms("Login_Thank_You_But_No")
        assert msg is not None
        assert msg.status == QMSStatus.THANK_YOU_BUT_NO

    def test_parse_none_returns_none(self):
        assert parse_qms(None) is None

    def test_parse_empty_returns_none(self):
        assert parse_qms("") is None

    def test_parse_plain_text_returns_none(self):
        assert parse_qms("just text here") is None

    def test_parse_message_has_timestamp(self):
        msg = parse_qms("Op_Please")
        assert msg.timestamp is not None

    def test_parse_message_to_string(self):
        msg = parse_qms("Op_Please")
        s = msg.to_string()
        assert "Op" in s
        assert "Please" in s


# ═══════════════════════════════════════════════════════════════════════════════
# validate_chain_string
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateChainString:
    def test_valid_chain_string(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        valid, result = validate_chain_string(chain.to_string(), log_warning=False)
        assert valid is True
        assert result is not None

    def test_plain_text_not_valid(self):
        valid, result = validate_chain_string("plain text", log_warning=False)
        assert valid is False
        assert result is None

    def test_empty_string_not_valid(self):
        valid, result = validate_chain_string("", log_warning=False)
        assert valid is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_default_ttl / get_message_schema
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaFunctions:
    def test_get_default_ttl_urgent(self):
        ttl = get_default_ttl("URGENT")
        assert isinstance(ttl, int)
        assert ttl > 0

    def test_get_default_ttl_p1(self):
        ttl = get_default_ttl("P1")
        assert isinstance(ttl, int)

    def test_get_default_ttl_none_uses_p2(self):
        ttl = get_default_ttl(None)
        assert isinstance(ttl, int)

    def test_get_default_ttl_unknown_priority(self):
        ttl = get_default_ttl("BOGUS")
        assert isinstance(ttl, int)
        assert ttl > 0

    def test_get_message_schema_returns_none_or_dict(self):
        result = get_message_schema("Tool_Checkout")
        assert result is None or isinstance(result, dict)

    def test_get_message_schema_unknown_action(self):
        result = get_message_schema("Completely_Unknown_Action_XYZ")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# validate_chain_semantics
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateChainSemantics:
    def test_valid_chain_passes_semantics(self):
        chain = build_chain("agent_x", "Unknown_Custom_Action", QMSStatus.PLEASE)
        result = validate_chain_semantics(chain)
        # Unknown types pass with warnings
        assert result.valid is True

    def test_invalid_chain_fails_semantics(self):
        chain = QMSChain(blocks=[])
        result = validate_chain_semantics(chain)
        assert result.valid is False

    def test_semantics_returns_validation_result(self):
        chain = build_chain("agent_x", "Ping", QMSStatus.PLEASE)
        result = validate_chain_semantics(chain)
        assert hasattr(result, "valid")
        assert hasattr(result, "errors")
        assert hasattr(result, "warnings")

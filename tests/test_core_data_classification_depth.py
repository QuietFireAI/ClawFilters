# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_data_classification_depth.py
# REM: Depth coverage for core/data_classification.py
# REM: DataClassification, classification_rank, at_least, classify_data,
# REM: ClassificationPolicy, get_policy, list_policies — all pure in-memory.

import pytest

from core.data_classification import (
    DEFAULT_POLICIES,
    DataClassification,
    ClassificationPolicy,
    _CLASSIFICATION_ORDER,
    _FINANCIAL_DATA_TYPES,
    _PII_DATA_TYPES,
    at_least,
    classify_data,
    classification_rank,
    get_policy,
    list_policies,
)


# ═══════════════════════════════════════════════════════════════════════════════
# DataClassification enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataClassificationEnum:
    def test_public_value(self):
        assert DataClassification.PUBLIC == "public"

    def test_internal_value(self):
        assert DataClassification.INTERNAL == "internal"

    def test_confidential_value(self):
        assert DataClassification.CONFIDENTIAL == "confidential"

    def test_restricted_value(self):
        assert DataClassification.RESTRICTED == "restricted"

    def test_four_members(self):
        assert len(DataClassification) == 4

    def test_is_str_subclass(self):
        assert isinstance(DataClassification.PUBLIC, str)

    def test_enum_identity(self):
        assert DataClassification("public") is DataClassification.PUBLIC
        assert DataClassification("restricted") is DataClassification.RESTRICTED


# ═══════════════════════════════════════════════════════════════════════════════
# _CLASSIFICATION_ORDER
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassificationOrder:
    def test_order_length(self):
        assert len(_CLASSIFICATION_ORDER) == 4

    def test_public_is_first(self):
        assert _CLASSIFICATION_ORDER[0] is DataClassification.PUBLIC

    def test_internal_is_second(self):
        assert _CLASSIFICATION_ORDER[1] is DataClassification.INTERNAL

    def test_confidential_is_third(self):
        assert _CLASSIFICATION_ORDER[2] is DataClassification.CONFIDENTIAL

    def test_restricted_is_last(self):
        assert _CLASSIFICATION_ORDER[3] is DataClassification.RESTRICTED


# ═══════════════════════════════════════════════════════════════════════════════
# classification_rank()
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassificationRank:
    def test_public_rank_zero(self):
        assert classification_rank(DataClassification.PUBLIC) == 0

    def test_internal_rank_one(self):
        assert classification_rank(DataClassification.INTERNAL) == 1

    def test_confidential_rank_two(self):
        assert classification_rank(DataClassification.CONFIDENTIAL) == 2

    def test_restricted_rank_three(self):
        assert classification_rank(DataClassification.RESTRICTED) == 3

    def test_returns_int(self):
        assert isinstance(classification_rank(DataClassification.PUBLIC), int)

    def test_ascending_order(self):
        ranks = [classification_rank(c) for c in DataClassification]
        # Note: enum iteration order may not be by rank; just check all ranks are 0-3
        assert set(ranks) == {0, 1, 2, 3}

    def test_restricted_highest(self):
        r = classification_rank(DataClassification.RESTRICTED)
        for dc in DataClassification:
            assert r >= classification_rank(dc)

    def test_public_lowest(self):
        r = classification_rank(DataClassification.PUBLIC)
        for dc in DataClassification:
            assert r <= classification_rank(dc)


# ═══════════════════════════════════════════════════════════════════════════════
# at_least()
# ═══════════════════════════════════════════════════════════════════════════════

class TestAtLeast:
    # PUBLIC against all minimums
    def test_public_at_least_public(self):
        assert at_least(DataClassification.PUBLIC, DataClassification.PUBLIC) is True

    def test_public_not_at_least_internal(self):
        assert at_least(DataClassification.PUBLIC, DataClassification.INTERNAL) is False

    def test_public_not_at_least_confidential(self):
        assert at_least(DataClassification.PUBLIC, DataClassification.CONFIDENTIAL) is False

    def test_public_not_at_least_restricted(self):
        assert at_least(DataClassification.PUBLIC, DataClassification.RESTRICTED) is False

    # INTERNAL against all minimums
    def test_internal_at_least_public(self):
        assert at_least(DataClassification.INTERNAL, DataClassification.PUBLIC) is True

    def test_internal_at_least_internal(self):
        assert at_least(DataClassification.INTERNAL, DataClassification.INTERNAL) is True

    def test_internal_not_at_least_confidential(self):
        assert at_least(DataClassification.INTERNAL, DataClassification.CONFIDENTIAL) is False

    def test_internal_not_at_least_restricted(self):
        assert at_least(DataClassification.INTERNAL, DataClassification.RESTRICTED) is False

    # CONFIDENTIAL against all minimums
    def test_confidential_at_least_public(self):
        assert at_least(DataClassification.CONFIDENTIAL, DataClassification.PUBLIC) is True

    def test_confidential_at_least_internal(self):
        assert at_least(DataClassification.CONFIDENTIAL, DataClassification.INTERNAL) is True

    def test_confidential_at_least_confidential(self):
        assert at_least(DataClassification.CONFIDENTIAL, DataClassification.CONFIDENTIAL) is True

    def test_confidential_not_at_least_restricted(self):
        assert at_least(DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED) is False

    # RESTRICTED against all minimums
    def test_restricted_at_least_public(self):
        assert at_least(DataClassification.RESTRICTED, DataClassification.PUBLIC) is True

    def test_restricted_at_least_internal(self):
        assert at_least(DataClassification.RESTRICTED, DataClassification.INTERNAL) is True

    def test_restricted_at_least_confidential(self):
        assert at_least(DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL) is True

    def test_restricted_at_least_restricted(self):
        assert at_least(DataClassification.RESTRICTED, DataClassification.RESTRICTED) is True

    def test_returns_bool(self):
        result = at_least(DataClassification.INTERNAL, DataClassification.PUBLIC)
        assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# _FINANCIAL_DATA_TYPES and _PII_DATA_TYPES keyword sets
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataTypeSets:
    def test_financial_contains_financial(self):
        assert "financial" in _FINANCIAL_DATA_TYPES

    def test_financial_contains_tax_return(self):
        assert "tax_return" in _FINANCIAL_DATA_TYPES

    def test_financial_contains_wire_transfer(self):
        assert "wire_transfer" in _FINANCIAL_DATA_TYPES

    def test_financial_contains_balance_sheet(self):
        assert "balance_sheet" in _FINANCIAL_DATA_TYPES

    def test_pii_contains_ssn(self):
        assert "ssn" in _PII_DATA_TYPES

    def test_pii_contains_pii(self):
        assert "pii" in _PII_DATA_TYPES

    def test_pii_contains_medical(self):
        assert "medical" in _PII_DATA_TYPES

    def test_pii_contains_passport(self):
        assert "passport" in _PII_DATA_TYPES

    def test_financial_and_pii_disjoint(self):
        assert _FINANCIAL_DATA_TYPES.isdisjoint(_PII_DATA_TYPES)


# ═══════════════════════════════════════════════════════════════════════════════
# classify_data()
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyData:
    # Rule 1: Financial → RESTRICTED
    def test_financial_is_restricted(self):
        assert classify_data("financial", "generic") == DataClassification.RESTRICTED

    def test_bank_statement_is_restricted(self):
        assert classify_data("bank_statement", "generic") == DataClassification.RESTRICTED

    def test_wire_transfer_is_restricted(self):
        assert classify_data("wire_transfer", "any_tenant") == DataClassification.RESTRICTED

    def test_tax_return_is_restricted(self):
        assert classify_data("tax_return", "generic") == DataClassification.RESTRICTED

    def test_balance_sheet_is_restricted(self):
        assert classify_data("balance_sheet", "generic") == DataClassification.RESTRICTED

    def test_escrow_is_restricted(self):
        assert classify_data("escrow", "generic") == DataClassification.RESTRICTED

    def test_closing_statement_is_restricted(self):
        assert classify_data("closing_statement", "generic") == DataClassification.RESTRICTED

    def test_w2_is_restricted(self):
        assert classify_data("w2", "generic") == DataClassification.RESTRICTED

    def test_hud1_is_restricted(self):
        assert classify_data("hud1", "generic") == DataClassification.RESTRICTED

    def test_financial_law_firm_still_restricted(self):
        # Rule 1 takes priority over Rule 3
        assert classify_data("financial", "law_firm") == DataClassification.RESTRICTED

    def test_financial_case_insensitive(self):
        assert classify_data("FINANCIAL", "generic") == DataClassification.RESTRICTED

    def test_financial_strip_whitespace(self):
        assert classify_data("  financial  ", "generic") == DataClassification.RESTRICTED

    # Rule 2: PII → CONFIDENTIAL
    def test_ssn_is_confidential(self):
        assert classify_data("ssn", "generic") == DataClassification.CONFIDENTIAL

    def test_pii_is_confidential(self):
        assert classify_data("pii", "generic") == DataClassification.CONFIDENTIAL

    def test_medical_is_confidential(self):
        assert classify_data("medical", "generic") == DataClassification.CONFIDENTIAL

    def test_passport_is_confidential(self):
        assert classify_data("passport", "generic") == DataClassification.CONFIDENTIAL

    def test_driver_license_is_confidential(self):
        assert classify_data("driver_license", "generic") == DataClassification.CONFIDENTIAL

    def test_background_check_is_confidential(self):
        assert classify_data("background_check", "generic") == DataClassification.CONFIDENTIAL

    def test_health_record_is_confidential(self):
        assert classify_data("health_record", "generic") == DataClassification.CONFIDENTIAL

    def test_pii_case_insensitive(self):
        assert classify_data("SSN", "generic") == DataClassification.CONFIDENTIAL

    def test_pii_strip_whitespace(self):
        assert classify_data("  ssn  ", "generic") == DataClassification.CONFIDENTIAL

    def test_pii_law_firm_still_confidential(self):
        # Rule 2 fires before Rule 3; result is same (CONFIDENTIAL)
        assert classify_data("ssn", "law_firm") == DataClassification.CONFIDENTIAL

    # Rule 3: law_firm → CONFIDENTIAL floor
    def test_law_firm_contract_is_confidential(self):
        assert classify_data("contract", "law_firm") == DataClassification.CONFIDENTIAL

    def test_law_firm_email_is_confidential(self):
        assert classify_data("email", "law_firm") == DataClassification.CONFIDENTIAL

    def test_law_firm_notes_is_confidential(self):
        assert classify_data("notes", "law_firm") == DataClassification.CONFIDENTIAL

    def test_law_firm_case_insensitive_tenant(self):
        assert classify_data("contract", "LAW_FIRM") == DataClassification.CONFIDENTIAL

    def test_law_firm_strip_whitespace_tenant(self):
        assert classify_data("contract", "  law_firm  ") == DataClassification.CONFIDENTIAL

    # Rule 4: Default → INTERNAL
    def test_generic_document_is_internal(self):
        assert classify_data("document", "generic") == DataClassification.INTERNAL

    def test_generic_notes_is_internal(self):
        assert classify_data("notes", "generic") == DataClassification.INTERNAL

    def test_generic_report_is_internal(self):
        assert classify_data("report", "generic") == DataClassification.INTERNAL

    def test_unknown_type_is_internal(self):
        assert classify_data("completely_unknown_type", "generic") == DataClassification.INTERNAL

    def test_empty_data_type_is_internal(self):
        assert classify_data("", "generic") == DataClassification.INTERNAL

    def test_different_non_law_tenants_all_internal(self):
        for tenant in ["hospital", "school", "startup", "enterprise"]:
            result = classify_data("document", tenant)
            assert result == DataClassification.INTERNAL, f"Expected INTERNAL for tenant {tenant}"

    def test_returns_dataclassification_instance(self):
        result = classify_data("document", "generic")
        assert isinstance(result, DataClassification)

    # Priority order: Rule 1 beats Rule 3, Rule 2 beats Rule 3
    def test_rule1_beats_rule3(self):
        # financial in a law_firm → RESTRICTED not CONFIDENTIAL
        assert classify_data("financial", "law_firm") == DataClassification.RESTRICTED

    def test_rule2_in_law_firm_confidential(self):
        # PII in law_firm → both rules say CONFIDENTIAL
        assert classify_data("ssn", "law_firm") == DataClassification.CONFIDENTIAL


# ═══════════════════════════════════════════════════════════════════════════════
# ClassificationPolicy
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassificationPolicy:
    def test_to_dict_returns_dict(self):
        policy = ClassificationPolicy(classification=DataClassification.INTERNAL)
        assert isinstance(policy.to_dict(), dict)

    def test_to_dict_has_classification(self):
        policy = ClassificationPolicy(classification=DataClassification.INTERNAL)
        assert policy.to_dict()["classification"] == "internal"

    def test_to_dict_has_required_permissions(self):
        policy = ClassificationPolicy(
            classification=DataClassification.INTERNAL,
            required_permissions={"view:dashboard", "view:agents"},
        )
        d = policy.to_dict()
        assert "required_permissions" in d
        assert set(d["required_permissions"]) == {"view:dashboard", "view:agents"}

    def test_to_dict_required_permissions_is_list(self):
        policy = ClassificationPolicy(classification=DataClassification.INTERNAL)
        assert isinstance(policy.to_dict()["required_permissions"], list)

    def test_to_dict_has_allowed_export(self):
        policy = ClassificationPolicy(
            classification=DataClassification.CONFIDENTIAL, allowed_export=False
        )
        assert policy.to_dict()["allowed_export"] is False

    def test_to_dict_has_requires_audit_on_access(self):
        policy = ClassificationPolicy(
            classification=DataClassification.RESTRICTED,
            requires_audit_on_access=True,
        )
        assert policy.to_dict()["requires_audit_on_access"] is True

    def test_to_dict_has_description(self):
        policy = ClassificationPolicy(
            classification=DataClassification.PUBLIC,
            description="test description",
        )
        assert policy.to_dict()["description"] == "test description"

    def test_to_dict_all_keys_present(self):
        policy = ClassificationPolicy(classification=DataClassification.PUBLIC)
        expected = {
            "classification", "required_permissions",
            "allowed_export", "requires_audit_on_access", "description"
        }
        assert set(policy.to_dict().keys()) == expected

    def test_default_allowed_export_true(self):
        policy = ClassificationPolicy(classification=DataClassification.PUBLIC)
        assert policy.allowed_export is True

    def test_default_requires_audit_false(self):
        policy = ClassificationPolicy(classification=DataClassification.PUBLIC)
        assert policy.requires_audit_on_access is False


# ═══════════════════════════════════════════════════════════════════════════════
# DEFAULT_POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

class TestDefaultPolicies:
    def test_has_four_entries(self):
        assert len(DEFAULT_POLICIES) == 4

    def test_has_public_key(self):
        assert DataClassification.PUBLIC in DEFAULT_POLICIES

    def test_has_internal_key(self):
        assert DataClassification.INTERNAL in DEFAULT_POLICIES

    def test_has_confidential_key(self):
        assert DataClassification.CONFIDENTIAL in DEFAULT_POLICIES

    def test_has_restricted_key(self):
        assert DataClassification.RESTRICTED in DEFAULT_POLICIES

    def test_public_allows_export(self):
        assert DEFAULT_POLICIES[DataClassification.PUBLIC].allowed_export is True

    def test_internal_allows_export(self):
        assert DEFAULT_POLICIES[DataClassification.INTERNAL].allowed_export is True

    def test_confidential_no_export(self):
        assert DEFAULT_POLICIES[DataClassification.CONFIDENTIAL].allowed_export is False

    def test_restricted_no_export(self):
        assert DEFAULT_POLICIES[DataClassification.RESTRICTED].allowed_export is False

    def test_confidential_requires_audit(self):
        assert DEFAULT_POLICIES[DataClassification.CONFIDENTIAL].requires_audit_on_access is True

    def test_restricted_requires_audit(self):
        assert DEFAULT_POLICIES[DataClassification.RESTRICTED].requires_audit_on_access is True

    def test_public_no_audit(self):
        assert DEFAULT_POLICIES[DataClassification.PUBLIC].requires_audit_on_access is False

    def test_restricted_has_security_permission(self):
        perms = DEFAULT_POLICIES[DataClassification.RESTRICTED].required_permissions
        assert "security:audit" in perms

    def test_all_have_view_dashboard(self):
        for dc, policy in DEFAULT_POLICIES.items():
            assert "view:dashboard" in policy.required_permissions, f"Missing view:dashboard for {dc}"


# ═══════════════════════════════════════════════════════════════════════════════
# get_policy()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetPolicy:
    def test_returns_classification_policy(self):
        policy = get_policy(DataClassification.PUBLIC)
        assert isinstance(policy, ClassificationPolicy)

    def test_public_policy(self):
        policy = get_policy(DataClassification.PUBLIC)
        assert policy.classification == DataClassification.PUBLIC

    def test_internal_policy(self):
        policy = get_policy(DataClassification.INTERNAL)
        assert policy.classification == DataClassification.INTERNAL

    def test_confidential_policy(self):
        policy = get_policy(DataClassification.CONFIDENTIAL)
        assert policy.classification == DataClassification.CONFIDENTIAL

    def test_restricted_policy(self):
        policy = get_policy(DataClassification.RESTRICTED)
        assert policy.classification == DataClassification.RESTRICTED

    def test_policy_matches_default_policies(self):
        for dc in DataClassification:
            assert get_policy(dc) is DEFAULT_POLICIES[dc]


# ═══════════════════════════════════════════════════════════════════════════════
# list_policies()
# ═══════════════════════════════════════════════════════════════════════════════

class TestListPolicies:
    def test_returns_list(self):
        assert isinstance(list_policies(), list)

    def test_returns_four_policies(self):
        assert len(list_policies()) == 4

    def test_all_items_are_dicts(self):
        for p in list_policies():
            assert isinstance(p, dict)

    def test_all_have_classification_key(self):
        for p in list_policies():
            assert "classification" in p

    def test_all_have_required_permissions_key(self):
        for p in list_policies():
            assert "required_permissions" in p

    def test_all_have_allowed_export_key(self):
        for p in list_policies():
            assert "allowed_export" in p

    def test_all_have_requires_audit_key(self):
        for p in list_policies():
            assert "requires_audit_on_access" in p

    def test_all_have_description_key(self):
        for p in list_policies():
            assert "description" in p

    def test_classifications_cover_all_levels(self):
        values = {p["classification"] for p in list_policies()}
        assert values == {"public", "internal", "confidential", "restricted"}

    def test_no_missing_descriptions(self):
        for p in list_policies():
            assert p["description"] != ""

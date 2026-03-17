# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_tenancy_depth.py
# REM: Depth coverage for core/tenancy.py
# REM: TenantType, Tenant, ClientMatter, TenantContext, TenantManager — in-memory.

import pytest
from datetime import datetime, timezone

from core.tenancy import (
    ClientMatter,
    Tenant,
    TenantContext,
    TenantManager,
    TenantType,
    tenant_scoped_key,
)


# ─── Patch Redis so audit.log() uses in-memory path ────────────────────────────
@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    monkeypatch.setattr("core.persistence.get_redis", lambda: None)


@pytest.fixture
def mgr():
    """Bypass __init__ to avoid _load_from_redis() hitting tenancy_store (Redis)."""
    m = object.__new__(TenantManager)
    m._tenants = {}
    m._matters = {}
    return m


def _create_tenant(mgr, name="Acme Corp", tenant_type="general", created_by="admin"):
    return mgr.create_tenant(name=name, tenant_type=tenant_type, created_by=created_by)


def _create_matter(mgr, tenant, name="Matter 001", matter_type="transaction"):
    return mgr.create_matter(tenant.tenant_id, name, matter_type, created_by="attorney")


# ═══════════════════════════════════════════════════════════════════════════════
# TenantType enum
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantType:
    def test_law_firm_value(self):
        assert TenantType.LAW_FIRM == "law_firm"

    def test_insurance_value(self):
        assert TenantType.INSURANCE == "insurance"

    def test_real_estate_value(self):
        assert TenantType.REAL_ESTATE == "real_estate"

    def test_healthcare_value(self):
        assert TenantType.HEALTHCARE == "healthcare"

    def test_small_business_value(self):
        assert TenantType.SMALL_BUSINESS == "small_business"

    def test_personal_value(self):
        assert TenantType.PERSONAL == "personal"

    def test_general_value(self):
        assert TenantType.GENERAL == "general"

    def test_seven_members(self):
        assert len(TenantType) == 7

    def test_is_str_subclass(self):
        assert isinstance(TenantType.LAW_FIRM, str)


# ═══════════════════════════════════════════════════════════════════════════════
# Tenant.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantToDict:
    def _make_tenant(self, **kwargs):
        defaults = dict(
            tenant_id="tenant_abc123",
            name="Acme Law LLP",
            tenant_type=TenantType.LAW_FIRM,
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        defaults.update(kwargs)
        return Tenant(**defaults)

    def test_returns_dict(self):
        assert isinstance(self._make_tenant().to_dict(), dict)

    def test_tenant_id_present(self):
        t = self._make_tenant(tenant_id="tenant_xyz")
        assert t.to_dict()["tenant_id"] == "tenant_xyz"

    def test_name_present(self):
        t = self._make_tenant(name="Smith & Jones")
        assert t.to_dict()["name"] == "Smith & Jones"

    def test_tenant_type_is_value_string(self):
        t = self._make_tenant(tenant_type=TenantType.HEALTHCARE)
        assert t.to_dict()["tenant_type"] == "healthcare"

    def test_created_at_is_isoformat(self):
        ts = datetime(2026, 3, 1, tzinfo=timezone.utc)
        t = self._make_tenant(created_at=ts)
        assert t.to_dict()["created_at"] == ts.isoformat()

    def test_is_active_true(self):
        t = self._make_tenant(is_active=True)
        assert t.to_dict()["is_active"] is True

    def test_settings_present(self):
        t = self._make_tenant(settings={"max_agents": 5})
        assert t.to_dict()["settings"] == {"max_agents": 5}

    def test_data_classification_default_present(self):
        t = self._make_tenant(data_classification_default="confidential")
        assert t.to_dict()["data_classification_default"] == "confidential"

    def test_created_by_present(self):
        t = self._make_tenant(created_by="admin")
        assert t.to_dict()["created_by"] == "admin"

    def test_allowed_actors_present(self):
        t = self._make_tenant(allowed_actors=["admin", "user-001"])
        assert "admin" in t.to_dict()["allowed_actors"]

    def test_nine_keys_present(self):
        t = self._make_tenant()
        expected = {
            "tenant_id", "name", "tenant_type", "created_at",
            "is_active", "settings", "data_classification_default",
            "created_by", "allowed_actors"
        }
        assert set(t.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# ClientMatter.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestClientMatterToDict:
    def _make_matter(self, **kwargs):
        defaults = dict(
            matter_id="matter_abc123",
            tenant_id="tenant_xyz",
            name="Smith v Jones",
            matter_type="litigation",
        )
        defaults.update(kwargs)
        return ClientMatter(**defaults)

    def test_returns_dict(self):
        assert isinstance(self._make_matter().to_dict(), dict)

    def test_matter_id_present(self):
        m = self._make_matter(matter_id="matter_001")
        assert m.to_dict()["matter_id"] == "matter_001"

    def test_tenant_id_present(self):
        m = self._make_matter(tenant_id="tenant_abc")
        assert m.to_dict()["tenant_id"] == "tenant_abc"

    def test_name_present(self):
        m = self._make_matter(name="Deal 2026")
        assert m.to_dict()["name"] == "Deal 2026"

    def test_matter_type_present(self):
        m = self._make_matter(matter_type="transaction")
        assert m.to_dict()["matter_type"] == "transaction"

    def test_status_present(self):
        m = self._make_matter(status="hold")
        assert m.to_dict()["status"] == "hold"

    def test_created_at_is_isoformat(self):
        ts = datetime(2026, 1, 15, tzinfo=timezone.utc)
        m = self._make_matter(created_at=ts)
        assert m.to_dict()["created_at"] == ts.isoformat()

    def test_closed_at_none_when_unset(self):
        m = self._make_matter()
        assert m.to_dict()["closed_at"] is None

    def test_closed_at_isoformat_when_set(self):
        ts = datetime(2026, 6, 1, tzinfo=timezone.utc)
        m = self._make_matter(closed_at=ts)
        assert m.to_dict()["closed_at"] == ts.isoformat()

    def test_metadata_present(self):
        m = self._make_matter(metadata={"client": "Smith"})
        assert m.to_dict()["metadata"] == {"client": "Smith"}

    def test_eight_keys_present(self):
        m = self._make_matter()
        expected = {
            "matter_id", "tenant_id", "name", "matter_type",
            "status", "created_at", "closed_at", "metadata"
        }
        assert set(m.to_dict().keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# TenantContext.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantContextToDict:
    def test_returns_dict(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1")
        assert isinstance(ctx.to_dict(), dict)

    def test_tenant_id_present(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1")
        assert ctx.to_dict()["tenant_id"] == "t1"

    def test_user_id_present(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1")
        assert ctx.to_dict()["user_id"] == "u1"

    def test_matter_id_none_when_unset(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1")
        assert ctx.to_dict()["matter_id"] is None

    def test_matter_id_when_set(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1", matter_id="m1")
        assert ctx.to_dict()["matter_id"] == "m1"

    def test_three_keys_present(self):
        ctx = TenantContext(tenant_id="t1", user_id="u1")
        assert set(ctx.to_dict().keys()) == {"tenant_id", "user_id", "matter_id"}


# ═══════════════════════════════════════════════════════════════════════════════
# tenant_scoped_key()
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantScopedKey:
    def test_format_correct(self):
        assert tenant_scoped_key("t1", "sessions") == "tenant:t1:sessions"

    def test_contains_tenant_id(self):
        assert "tenant_abc" in tenant_scoped_key("tenant_abc", "data")

    def test_contains_key(self):
        assert "my_key" in tenant_scoped_key("t1", "my_key")

    def test_different_tenants_different_keys(self):
        k1 = tenant_scoped_key("t1", "sessions")
        k2 = tenant_scoped_key("t2", "sessions")
        assert k1 != k2


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.create_tenant()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateTenant:
    def test_returns_tenant(self, mgr):
        assert isinstance(_create_tenant(mgr), Tenant)

    def test_tenant_id_has_prefix(self, mgr):
        t = _create_tenant(mgr)
        assert t.tenant_id.startswith("tenant_")

    def test_name_stored(self, mgr):
        t = _create_tenant(mgr, name="BigCo")
        assert t.name == "BigCo"

    def test_type_stored(self, mgr):
        t = _create_tenant(mgr, tenant_type="healthcare")
        assert t.tenant_type == TenantType.HEALTHCARE

    def test_is_active_true(self, mgr):
        assert _create_tenant(mgr).is_active is True

    def test_created_by_stored(self, mgr):
        t = _create_tenant(mgr, created_by="security_officer")
        assert t.created_by == "security_officer"

    def test_creator_in_allowed_actors(self, mgr):
        t = _create_tenant(mgr, created_by="admin_user")
        assert "admin_user" in t.allowed_actors

    def test_tenant_stored_in_manager(self, mgr):
        t = _create_tenant(mgr)
        assert t.tenant_id in mgr._tenants

    def test_law_firm_gets_confidential_classification(self, mgr):
        t = _create_tenant(mgr, tenant_type="law_firm")
        assert t.data_classification_default == "confidential"

    def test_non_law_firm_gets_internal_classification(self, mgr):
        t = _create_tenant(mgr, tenant_type="healthcare")
        assert t.data_classification_default == "internal"

    def test_unknown_type_defaults_to_general(self, mgr):
        t = _create_tenant(mgr, tenant_type="invalid_type")
        assert t.tenant_type == TenantType.GENERAL

    def test_unique_tenant_ids(self, mgr):
        t1 = _create_tenant(mgr)
        t2 = _create_tenant(mgr)
        assert t1.tenant_id != t2.tenant_id


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.get_tenant()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTenant:
    def test_returns_tenant_by_id(self, mgr):
        t = _create_tenant(mgr)
        result = mgr.get_tenant(t.tenant_id)
        assert result is t

    def test_returns_none_for_unknown(self, mgr):
        assert mgr.get_tenant("nonexistent_id") is None


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.list_tenants()
# ═══════════════════════════════════════════════════════════════════════════════

class TestListTenants:
    def test_returns_list(self, mgr):
        assert isinstance(mgr.list_tenants(), list)

    def test_empty_initially(self, mgr):
        assert mgr.list_tenants() == []

    def test_returns_all_when_no_filter(self, mgr):
        _create_tenant(mgr)
        _create_tenant(mgr)
        assert len(mgr.list_tenants()) == 2

    def test_actor_filter_returns_accessible_tenants(self, mgr):
        t = _create_tenant(mgr, created_by="alice")
        _create_tenant(mgr, created_by="bob")
        result = mgr.list_tenants(actor_filter="alice")
        assert len(result) == 1
        assert result[0].tenant_id == t.tenant_id

    def test_actor_filter_no_match_returns_empty(self, mgr):
        _create_tenant(mgr, created_by="alice")
        assert mgr.list_tenants(actor_filter="charlie") == []


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.grant_tenant_access()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGrantTenantAccess:
    def test_returns_true_for_known_tenant(self, mgr):
        t = _create_tenant(mgr)
        assert mgr.grant_tenant_access(t.tenant_id, "new_user") is True

    def test_returns_false_for_unknown_tenant(self, mgr):
        assert mgr.grant_tenant_access("nonexistent", "user") is False

    def test_actor_added_to_allowed_actors(self, mgr):
        t = _create_tenant(mgr)
        mgr.grant_tenant_access(t.tenant_id, "new_user")
        assert "new_user" in t.allowed_actors

    def test_idempotent_no_duplicate(self, mgr):
        t = _create_tenant(mgr, created_by="admin")
        mgr.grant_tenant_access(t.tenant_id, "admin")
        assert t.allowed_actors.count("admin") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.deactivate_tenant()
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeactivateTenant:
    def test_returns_true_for_active_tenant(self, mgr):
        t = _create_tenant(mgr)
        assert mgr.deactivate_tenant(t.tenant_id) is True

    def test_returns_false_for_unknown_tenant(self, mgr):
        assert mgr.deactivate_tenant("nonexistent") is False

    def test_tenant_is_inactive_after_deactivate(self, mgr):
        t = _create_tenant(mgr)
        mgr.deactivate_tenant(t.tenant_id)
        assert mgr._tenants[t.tenant_id].is_active is False


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.create_matter()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateMatter:
    def test_returns_client_matter(self, mgr):
        t = _create_tenant(mgr)
        assert isinstance(_create_matter(mgr, t), ClientMatter)

    def test_returns_none_for_unknown_tenant(self, mgr):
        assert mgr.create_matter("nonexistent", "Test", "transaction") is None

    def test_returns_none_for_inactive_tenant(self, mgr):
        t = _create_tenant(mgr)
        mgr.deactivate_tenant(t.tenant_id)
        assert mgr.create_matter(t.tenant_id, "Test", "transaction") is None

    def test_matter_id_has_prefix(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert m.matter_id.startswith("matter_")

    def test_matter_name_stored(self, mgr):
        t = _create_tenant(mgr)
        m = mgr.create_matter(t.tenant_id, "Smith Case", "litigation")
        assert m.name == "Smith Case"

    def test_matter_type_stored(self, mgr):
        t = _create_tenant(mgr)
        m = mgr.create_matter(t.tenant_id, "Deal", "transaction")
        assert m.matter_type == "transaction"

    def test_status_is_active(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert m.status == "active"

    def test_tenant_id_stored(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert m.tenant_id == t.tenant_id

    def test_matter_stored_in_manager(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert m.matter_id in mgr._matters


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.get_matter() and list_matters()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetAndListMatters:
    def test_get_matter_by_id(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert mgr.get_matter(m.matter_id) is m

    def test_get_matter_none_for_unknown(self, mgr):
        assert mgr.get_matter("nonexistent") is None

    def test_list_matters_returns_list(self, mgr):
        t = _create_tenant(mgr)
        assert isinstance(mgr.list_matters(t.tenant_id), list)

    def test_list_matters_empty_for_no_matters(self, mgr):
        t = _create_tenant(mgr)
        assert mgr.list_matters(t.tenant_id) == []

    def test_list_matters_returns_tenant_matters(self, mgr):
        t = _create_tenant(mgr)
        _create_matter(mgr, t)
        _create_matter(mgr, t)
        assert len(mgr.list_matters(t.tenant_id)) == 2

    def test_list_matters_excludes_other_tenants(self, mgr):
        t1 = _create_tenant(mgr)
        t2 = _create_tenant(mgr)
        _create_matter(mgr, t1)
        assert len(mgr.list_matters(t2.tenant_id)) == 0

    def test_list_matters_status_filter(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.close_matter(m.matter_id)
        active = mgr.list_matters(t.tenant_id, status_filter="active")
        assert len(active) == 0
        closed = mgr.list_matters(t.tenant_id, status_filter="closed")
        assert len(closed) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.close_matter()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCloseMatter:
    def test_returns_true_for_active_matter(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert mgr.close_matter(m.matter_id) is True

    def test_returns_false_for_unknown_matter(self, mgr):
        assert mgr.close_matter("nonexistent") is False

    def test_returns_false_for_held_matter(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.set_matter_hold(m.matter_id)
        assert mgr.close_matter(m.matter_id) is False

    def test_status_becomes_closed(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.close_matter(m.matter_id)
        assert mgr._matters[m.matter_id].status == "closed"

    def test_closed_at_set(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.close_matter(m.matter_id)
        assert mgr._matters[m.matter_id].closed_at is not None


# ═══════════════════════════════════════════════════════════════════════════════
# TenantManager.set_matter_hold() and release_matter_hold()
# ═══════════════════════════════════════════════════════════════════════════════

class TestMatterHold:
    def test_set_hold_returns_true(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        assert mgr.set_matter_hold(m.matter_id) is True

    def test_set_hold_returns_false_for_unknown(self, mgr):
        assert mgr.set_matter_hold("nonexistent") is False

    def test_set_hold_returns_false_for_closed(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.close_matter(m.matter_id)
        assert mgr.set_matter_hold(m.matter_id) is False

    def test_status_becomes_hold(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.set_matter_hold(m.matter_id)
        assert mgr._matters[m.matter_id].status == "hold"

    def test_release_hold_returns_true(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.set_matter_hold(m.matter_id)
        assert mgr.release_matter_hold(m.matter_id) is True

    def test_release_hold_returns_false_for_unknown(self, mgr):
        assert mgr.release_matter_hold("nonexistent") is False

    def test_release_hold_returns_false_if_not_on_hold(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)  # status="active"
        assert mgr.release_matter_hold(m.matter_id) is False

    def test_status_returns_active_after_release(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.set_matter_hold(m.matter_id)
        mgr.release_matter_hold(m.matter_id)
        assert mgr._matters[m.matter_id].status == "active"

    def test_held_matter_cannot_be_closed(self, mgr):
        t = _create_tenant(mgr)
        m = _create_matter(mgr, t)
        mgr.set_matter_hold(m.matter_id)
        assert mgr.close_matter(m.matter_id) is False
        assert mgr._matters[m.matter_id].status == "hold"

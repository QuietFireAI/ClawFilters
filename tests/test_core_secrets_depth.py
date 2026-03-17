# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# tests/test_core_secrets_depth.py
# REM: Depth tests for core/secrets.py — pure in-memory + tmpdir, no Redis

import os
import pytest
from pathlib import Path

from core.secrets import (
    INSECURE_DEFAULTS,
    SECRET_REGISTRY,
    SecretDefinition,
    SecretValue,
    SecretsProvider,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def provider(tmp_path):
    """REM: Fresh SecretsProvider with isolated tmpdir (no Docker secrets)."""
    p = SecretsProvider(secrets_dir=tmp_path)
    p._is_production = False
    return p


@pytest.fixture
def secret_file(tmp_path):
    """REM: Helper that writes a secret file and returns path."""
    def _write(filename, value):
        f = tmp_path / filename
        f.write_text(value)
        return f
    return _write


# ═══════════════════════════════════════════════════════════════════════════════
# INSECURE_DEFAULTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestInsecureDefaults:
    def test_changeme_in_defaults(self):
        assert "changeme" in INSECURE_DEFAULTS

    def test_password_in_defaults(self):
        assert "password" in INSECURE_DEFAULTS

    def test_admin_in_defaults(self):
        assert "admin" in INSECURE_DEFAULTS

    def test_test_in_defaults(self):
        assert "test" in INSECURE_DEFAULTS

    def test_change_me_in_production_in_defaults(self):
        assert "CHANGE_ME_IN_PRODUCTION" in INSECURE_DEFAULTS

    def test_is_frozenset(self):
        assert isinstance(INSECURE_DEFAULTS, frozenset)


# ═══════════════════════════════════════════════════════════════════════════════
# SecretValue
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretValue:
    def test_get_returns_actual_value(self):
        sv = SecretValue("my_super_secret", name="test_key")
        assert sv.get() == "my_super_secret"

    def test_str_redacted(self):
        sv = SecretValue("my_super_secret", name="test_key")
        assert str(sv) == "***REDACTED***"

    def test_repr_redacted(self):
        sv = SecretValue("my_super_secret", name="test_key")
        assert "REDACTED" in repr(sv)
        assert "my_super_secret" not in repr(sv)

    def test_repr_has_name(self):
        sv = SecretValue("value", name="api_key")
        assert "api_key" in repr(sv)

    def test_eq_with_same_secret_value(self):
        sv1 = SecretValue("abc", name="k1")
        sv2 = SecretValue("abc", name="k2")
        assert sv1 == sv2

    def test_eq_with_string(self):
        sv = SecretValue("hello", name="k1")
        assert sv == "hello"

    def test_neq_with_different_string(self):
        sv = SecretValue("hello", name="k1")
        assert sv != "world"

    def test_hash_equals_hash_of_value(self):
        sv = SecretValue("abc", name="k")
        assert hash(sv) == hash("abc")

    def test_len_equals_value_length(self):
        sv = SecretValue("12345", name="k")
        assert len(sv) == 5

    def test_bool_true_for_nonempty(self):
        sv = SecretValue("x", name="k")
        assert bool(sv) is True

    def test_bool_false_for_empty(self):
        sv = SecretValue("", name="k")
        assert bool(sv) is False

    def test_eq_with_non_string_returns_not_implemented(self):
        sv = SecretValue("abc", name="k")
        assert sv.__eq__(42) is NotImplemented


# ═══════════════════════════════════════════════════════════════════════════════
# SecretDefinition
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretDefinition:
    def test_fields_present(self):
        sd = SecretDefinition(
            name="my_secret",
            env_var="MY_SECRET",
            docker_secret_name="my_secret_file",
        )
        assert sd.name == "my_secret"
        assert sd.env_var == "MY_SECRET"
        assert sd.docker_secret_name == "my_secret_file"

    def test_required_default_true(self):
        sd = SecretDefinition(name="x", env_var="X", docker_secret_name="x")
        assert sd.required is True

    def test_min_length_default_32(self):
        sd = SecretDefinition(name="x", env_var="X", docker_secret_name="x")
        assert sd.min_length == 32

    def test_optional_secret(self):
        sd = SecretDefinition(name="x", env_var="X", docker_secret_name="x", required=False)
        assert sd.required is False


# ═══════════════════════════════════════════════════════════════════════════════
# SECRET_REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretRegistry:
    def test_has_mcp_api_key(self):
        assert "mcp_api_key" in SECRET_REGISTRY

    def test_has_jwt_secret_key(self):
        assert "jwt_secret_key" in SECRET_REGISTRY

    def test_has_encryption_key(self):
        assert "encryption_key" in SECRET_REGISTRY

    def test_has_encryption_salt(self):
        assert "encryption_salt" in SECRET_REGISTRY

    def test_mcp_api_key_is_required(self):
        assert SECRET_REGISTRY["mcp_api_key"].required is True

    def test_webui_secret_key_optional(self):
        assert SECRET_REGISTRY["webui_secret_key"].required is False

    def test_mcp_api_key_docker_name(self):
        assert SECRET_REGISTRY["mcp_api_key"].docker_secret_name == "telsonbase_mcp_api_key"


# ═══════════════════════════════════════════════════════════════════════════════
# SecretsProvider init
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretsProviderInit:
    def test_cache_empty_initially(self, provider):
        assert len(provider._cache) == 0

    def test_not_loaded_initially(self, provider):
        assert provider._loaded is False

    def test_not_production_in_test_mode(self, provider):
        assert provider._is_production is False


# ═══════════════════════════════════════════════════════════════════════════════
# _read_docker_secret
# ═══════════════════════════════════════════════════════════════════════════════

class TestReadDockerSecret:
    def test_returns_none_when_file_missing(self, provider):
        result = provider._read_docker_secret("nonexistent_file")
        assert result is None

    def test_returns_value_from_file(self, provider, secret_file, tmp_path):
        secret_file("my_api_key", "supersecretvalue1234567890abcdef")
        result = provider._read_docker_secret("my_api_key")
        assert result == "supersecretvalue1234567890abcdef"

    def test_strips_whitespace(self, provider, secret_file, tmp_path):
        secret_file("my_api_key", "  trimmedvalue  \n")
        result = provider._read_docker_secret("my_api_key")
        assert result == "trimmedvalue"

    def test_returns_none_for_empty_file(self, provider, secret_file, tmp_path):
        secret_file("empty_secret", "")
        result = provider._read_docker_secret("empty_secret")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# _read_env_var
# ═══════════════════════════════════════════════════════════════════════════════

class TestReadEnvVar:
    def test_returns_none_when_not_set(self, provider):
        os.environ.pop("TEST_SECRET_XYZ_ABC", None)
        assert provider._read_env_var("TEST_SECRET_XYZ_ABC") is None

    def test_returns_value_when_set(self, provider, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_XYZ", "my_value")
        assert provider._read_env_var("TEST_SECRET_XYZ") == "my_value"

    def test_strips_whitespace(self, provider, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_WS", "  spaced  ")
        assert provider._read_env_var("TEST_SECRET_WS") == "spaced"

    def test_returns_none_for_empty_string(self, provider, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_EMPTY", "")
        assert provider._read_env_var("TEST_SECRET_EMPTY") is None


# ═══════════════════════════════════════════════════════════════════════════════
# _validate_value
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateValue:
    def _defn(self, min_length=32, name="test_key"):
        return SecretDefinition(
            name=name, env_var="TEST", docker_secret_name="test",
            min_length=min_length
        )

    def test_valid_value_returns_true(self, provider):
        defn = self._defn(min_length=4)
        assert provider._validate_value(defn, "a" * 32) is True

    def test_insecure_default_returns_true_in_dev_mode(self, provider):
        # In dev mode, warns but still returns True
        defn = self._defn(min_length=4)
        result = provider._validate_value(defn, "changeme")
        assert result is True  # dev mode — warns but doesn't block

    def test_insecure_default_returns_false_in_production(self, provider):
        provider._is_production = True
        defn = self._defn(min_length=4)
        result = provider._validate_value(defn, "changeme")
        assert result is False

    def test_too_short_returns_true_in_dev_mode(self, provider):
        defn = self._defn(min_length=32)
        result = provider._validate_value(defn, "short")
        assert result is True  # dev mode — warns but doesn't block

    def test_too_short_returns_false_in_production(self, provider):
        provider._is_production = True
        defn = self._defn(min_length=32)
        result = provider._validate_value(defn, "short")
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# load_secret
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoadSecret:
    def test_raises_for_unknown_name(self, provider):
        with pytest.raises(ValueError, match="Unknown secret"):
            provider.load_secret("nonexistent_secret_name")

    def test_loads_from_docker_secret(self, provider, secret_file):
        # Use mcp_api_key — docker_secret_name is "telsonbase_mcp_api_key"
        secret_file("telsonbase_mcp_api_key", "a" * 32)
        sv = provider.load_secret("mcp_api_key")
        assert sv is not None
        assert sv.get() == "a" * 32

    def test_loads_from_env_var(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "b" * 32)
        sv = provider.load_secret("mcp_api_key")
        assert sv is not None
        assert sv.get() == "b" * 32

    def test_docker_secret_takes_priority_over_env(self, provider, secret_file, monkeypatch):
        secret_file("telsonbase_mcp_api_key", "docker_value_" + "x" * 20)
        monkeypatch.setenv("MCP_API_KEY", "env_value_" + "y" * 22)
        sv = provider.load_secret("mcp_api_key")
        assert sv.get().startswith("docker_value_")

    def test_returns_none_for_optional_missing(self, provider):
        # webui_secret_key is optional — should return None when not set
        os.environ.pop("WEBUI_SECRET_KEY", None)
        sv = provider.load_secret("webui_secret_key")
        assert sv is None

    def test_returns_none_for_required_missing_in_dev(self, provider):
        os.environ.pop("MCP_API_KEY", None)
        sv = provider.load_secret("mcp_api_key")
        assert sv is None  # dev mode — warns but returns None

    def test_caches_loaded_secret(self, provider, secret_file):
        secret_file("telsonbase_mcp_api_key", "c" * 32)
        sv = provider.load_secret("mcp_api_key")
        assert "mcp_api_key" in provider._cache

    def test_source_tracked(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "d" * 32)
        provider.load_secret("mcp_api_key")
        assert provider._sources.get("mcp_api_key") == "env_var"


# ═══════════════════════════════════════════════════════════════════════════════
# get / get_raw
# ═══════════════════════════════════════════════════════════════════════════════

class TestGet:
    def test_get_returns_cached_value(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "e" * 32)
        provider.load_secret("mcp_api_key")
        sv = provider.get("mcp_api_key")
        assert sv is not None

    def test_get_raw_returns_string(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "f" * 32)
        result = provider.get_raw("mcp_api_key")
        assert result == "f" * 32

    def test_get_raw_returns_none_when_missing(self, provider):
        os.environ.pop("MCP_API_KEY", None)
        result = provider.get_raw("mcp_api_key")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# report_status
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportStatus:
    def test_returns_dict(self, provider):
        report = provider.report_status()
        assert isinstance(report, dict)

    def test_all_secrets_in_report(self, provider):
        report = provider.report_status()
        for name in SECRET_REGISTRY:
            assert name in report

    def test_not_loaded_by_default(self, provider):
        report = provider.report_status()
        assert report["mcp_api_key"]["loaded"] is False

    def test_loaded_after_load(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "g" * 32)
        provider.load_secret("mcp_api_key")
        report = provider.report_status()
        assert report["mcp_api_key"]["loaded"] is True

    def test_length_zero_when_not_loaded(self, provider):
        report = provider.report_status()
        assert report["mcp_api_key"]["length"] == 0

    def test_length_nonzero_when_loaded(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "h" * 40)
        provider.load_secret("mcp_api_key")
        report = provider.report_status()
        assert report["mcp_api_key"]["length"] == 40

    def test_required_field_matches_registry(self, provider):
        report = provider.report_status()
        assert report["mcp_api_key"]["required"] is True
        assert report["webui_secret_key"]["required"] is False

    def test_meets_min_length_true_when_long_enough(self, provider, monkeypatch):
        monkeypatch.setenv("MCP_API_KEY", "i" * 32)
        provider.load_secret("mcp_api_key")
        report = provider.report_status()
        assert report["mcp_api_key"]["meets_min_length"] is True

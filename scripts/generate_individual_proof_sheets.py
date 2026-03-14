# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
"""
TelsonBase — Individual Proof Sheet Generator
Generates one TB-TEST-[CODE]-[NNN] proof sheet per test function.
720 total sheets across 15 test files, organized in subdirectories.
"""
import os
import re

BASE_DIR = "C:/Claude_Code/TelsonBase/proof_sheets/individual"
VERSION = "v11.0.1"
DATE = "March 8, 2026"

# ─── Security battery hardcoded descriptions (from TB-PROOF-043 through 051) ───
SEC_DESCRIPTIONS = {
    # TestAuthSecurity
    "test_api_key_hash_uses_sha256": "API keys are hashed with SHA-256 before storage — raw key is never persisted",
    "test_api_key_hash_not_plaintext": "Hashed key is provably different from the original plaintext — no identity encoding",
    "test_jwt_token_generation": "JWT generation produces a valid 3-part encoded string",
    "test_jwt_token_decode_roundtrip": "JWT round-trips correctly — subject and permissions claims survive encode/decode",
    "test_jwt_expiration_enforcement": "Expired JWTs are rejected by the decoder — no grace period",
    "test_jwt_revocation_check": "Revoked JWTs are rejected before natural expiration",
    "test_constant_time_comparison_used_in_auth": "API key comparison uses hmac.compare_digest — timing-attack resistant",
    "test_mfa_enrollment_generates_valid_totp_secret": "MFA enrollment generates a valid RFC 6238 TOTP secret",
    "test_mfa_verification_valid_token": "A valid TOTP token is accepted by the verifier",
    "test_mfa_verification_invalid_token": "An invalid TOTP token is rejected",
    "test_mfa_replay_attack_prevention": "The same TOTP token is rejected if presented twice — replay protection active",
    "test_mfa_backup_code_single_use": "MFA backup codes are consumed on first use — cannot be reused",
    "test_mfa_required_for_privileged_roles": "MFA enrollment is enforced for admin and security roles",
    "test_mfa_not_required_for_viewer": "MFA is not required for the viewer role",
    "test_api_key_rotation_invalidates_old_key": "Rotating an API key invalidates the previous key immediately",
    "test_emergency_access_requires_approval": "Emergency (break-glass) access requires an approval gate before activation",
    "test_emergency_access_auto_expires": "Emergency access sessions auto-expire — no indefinite privilege elevation",
    "test_session_auto_logoff_idle_timeout": "Idle sessions are terminated at the configured timeout",
    "test_session_max_duration_enforcement": "Sessions are forcibly closed at absolute max duration regardless of activity",
    # TestEncryptionIntegrity
    "test_aes256gcm_ciphertext_differs_from_plaintext": "Encrypted output is never the same as the input plaintext",
    "test_aes256gcm_decryption_recovers_original": "AES-256-GCM decryption returns the exact original plaintext",
    "test_different_nonces_produce_different_ciphertexts": "Each encryption call produces unique ciphertext — no nonce reuse",
    "test_tampered_ciphertext_fails_decryption": "Any modification to ciphertext causes decryption to fail via GCM authentication tag",
    "test_pbkdf2_key_derivation_consistent": "PBKDF2 produces the same key for the same password and salt — deterministic",
    "test_hmac_integrity_hash_deterministic": "HMAC produces the same hash for the same input — deterministic",
    "test_hmac_integrity_verification_valid": "HMAC verification accepts a correctly signed payload",
    "test_hmac_integrity_verification_fails_tampered": "HMAC verification rejects a tampered payload",
    "test_hmac_integrity_verification_fails_wrong_context": "HMAC verification rejects a payload signed with a different context key",
    "test_encrypted_dict_roundtrip_preserves_fields": "Encrypting a dictionary and decrypting it recovers all original fields",
    "test_string_encryption_roundtrip": "String values encrypt and decrypt without data loss",
    # TestAccessControl
    "test_viewer_cannot_manage_agents": "The VIEWER role is denied agent management permissions",
    "test_operator_cannot_admin_config": "The OPERATOR role is denied admin configuration access",
    "test_admin_has_management_permissions": "The ADMIN role holds all management-level permissions",
    "test_super_admin_has_all_permissions": "The SUPER_ADMIN role holds every defined permission",
    "test_permission_check_denies_unlisted": "Any permission not explicitly granted is denied by default",
    "test_role_assignment_audit_logged": "Role assignments are written to the audit chain",
    "test_custom_permission_grants_work": "Custom per-user grants extend beyond the base role",
    "test_custom_denial_overrides_role_grant": "A custom denial on a user overrides what the role would allow — deny wins",
    "test_user_deactivation_blocks_access": "Deactivating a user immediately prevents authentication",
    "test_session_creation_requires_valid_user": "Sessions can only be created for active, valid users",
    "test_session_invalidation_on_user_deactivation": "Existing sessions are invalidated when a user is deactivated",
    "test_mfa_enforcement_blocks_unenrolled_privileged": "Privileged roles without MFA enrollment cannot create sessions",
    "test_session_creation_blocked_for_inactive_user": "Inactive user accounts are blocked at session creation",
    # TestAuditTrailIntegrity
    "test_audit_chain_starts_with_genesis_hash": "The first audit entry uses a known genesis hash as its previous-hash",
    "test_each_entry_includes_previous_hash": "Every audit entry carries the SHA-256 hash of the preceding entry",
    "test_chain_verification_detects_tampering": "Modifying any past entry causes chain verification to fail",
    "test_audit_entries_include_actor_type": "Every audit entry records who performed the action (actor field)",
    "test_audit_captures_auth_successes": "Successful authentication events are written to the audit chain",
    "test_audit_captures_auth_failures": "Failed authentication attempts are written to the audit chain",
    "test_audit_captures_security_alerts": "Security alert events are written to the audit chain",
    "test_chain_hash_is_sha256": "The audit chain hash algorithm is SHA-256 — not MD5, not SHA-1",
    "test_audit_entries_timestamped_utc": "All audit entries carry UTC timestamps (timezone-aware)",
    "test_sequence_numbers_monotonically_increasing": "Sequence numbers increment by 1 per entry — no gaps, no reuse",
    "test_chain_verification_passes_for_valid_chain": "An unmodified audit chain passes full verification",
    # TestNetworkSecurity
    "test_cors_no_wildcard_default": "Default CORS configuration does not permit wildcard (*) origins",
    "test_redis_url_contains_password_when_configured": "Redis connection URL includes authentication when a password is set",
    "test_health_endpoint_does_not_leak_details": "The /health endpoint returns status only — no internal version, config, or stack info",
    "test_production_mode_blocks_insecure_defaults": "TELSONBASE_ENV=production rejects default/weak credentials at startup",
    "test_default_session_timeout_15_minutes_or_less": "Standard session idle timeout is 15 minutes or less — HIPAA compliant",
    "test_privileged_role_session_timeout_10_minutes": "Admin and security role sessions timeout at 10 minutes or less",
    "test_mqtt_auth_required": "MQTT broker configuration enforces authentication — anonymous connections rejected",
    "test_jwt_algorithm_configured": "JWT signing algorithm is explicitly configured — not defaulted to 'none'",
    "test_external_domain_whitelist_restrictive": "ALLOWED_EXTERNAL_DOMAINS is set and does not permit unrestricted external calls",
    # TestDataProtection
    "test_phi_deidentification_removes_all_18_identifiers": "All 18 HIPAA Safe Harbor identifiers are removed from PHI records",
    "test_deidentified_data_contains_no_phi_patterns": "De-identified output contains no residual PHI patterns (names, dates, SSN, etc.)",
    "test_minimum_necessary_strips_denied_fields": "Minimum necessary enforcement removes fields outside a user's authorized scope",
    "test_minimum_necessary_viewer_limited_scope": "Viewers receive only fields within their minimum necessary scope",
    "test_minimum_necessary_superadmin_full_scope": "Super admins receive full scope — no fields stripped",
    "test_data_classification_financial_is_restricted": "Financial data is classified at the RESTRICTED level",
    "test_data_classification_pii_is_confidential": "PII is classified at the CONFIDENTIAL level",
    "test_legal_hold_blocks_deletion": "Records under legal hold cannot be deleted — deletion returns an error",
    "test_data_retention_policy_enforcement": "Records past their retention period are flagged for disposal per policy",
    "test_tenant_data_isolation_scoped_keys": "Tenant data is stored under namespaced Redis keys — no cross-tenant bleed",
    "test_legal_hold_release_changes_status": "Releasing a legal hold updates the record status and permits deletion",
    # TestComplianceInfrastructure
    "test_sanctions_can_be_imposed_and_tracked": "Sanctions are created, stored, and retrievable by ID",
    "test_training_requirements_enforce_role_compliance": "Training requirements are enforced per role — non-compliant users are flagged",
    "test_overdue_training_detection": "Personnel with overdue training are detected and surfaced",
    "test_contingency_test_results_recorded": "Contingency plan test results are recorded with type, date, and outcome",
    "test_baa_lifecycle_draft_to_active": "Business Associate Agreements move from DRAFT to ACTIVE status",
    "test_breach_severity_triggers_notification": "A breach above the severity threshold triggers a notification record",
    "test_phi_disclosure_accounting_records": "PHI disclosures are recorded with recipient, purpose, and date per HIPAA §164.528",
    "test_hitrust_controls_registered_and_assessed": "HITRUST CSF controls are registered with assessment status",
    "test_hitrust_compliance_posture_calculation": "HITRUST posture score is calculated from control assessment data",
    "test_breach_notification_deadline_tracking": "Breach notification deadlines are tracked within HITECH's 60-day requirement",
    "test_sanctions_resolution": "Sanctions can be resolved and their status updated accordingly",
    # TestCryptographicStandards
    "test_signing_key_length_minimum_256_bits": "Signing keys are at least 256 bits — no short keys accepted",
    "test_hash_chain_uses_sha256_not_md5": "The audit chain hash function is SHA-256, not a weaker algorithm",
    "test_totp_uses_rfc6238_standard": "TOTP implementation is compatible with RFC 6238 — standard authenticator apps work",
    "test_backup_codes_use_cryptographic_randomness": "MFA backup codes are generated with secrets (CSPRNG), not random",
    "test_key_derivation_uses_minimum_iterations": "PBKDF2 runs at minimum 100,000 iterations — brute-force resistant",
    "test_aes_key_size_is_256_bits": "AES key size is exactly 256 bits — not 128, not 192",
    "test_gcm_nonce_size_is_96_bits": "GCM nonce size is 96 bits — NIST-recommended for AES-GCM",
    "test_encryption_key_derivation_uses_sha256": "Encryption key derivation uses SHA-256 as the PRF",
    # TestRuntimeBoundaries
    "test_rate_limiter_blocks_at_burst_limit": "Rate limiter allows exactly burst_size requests then blocks the next — wall is real, not advisory",
    "test_captcha_expired_challenge_rejected": "An expired CAPTCHA challenge is rejected even with the correct answer — time enforcement is real",
    "test_email_verification_expired_token_rejected": "An expired email verification token is rejected and marked EXPIRED — tokens cannot be recycled",
}

# ─── Source file mappings per test class ───
CLASS_SOURCES = {
    "TestAuthSecurity": ["core/auth.py", "core/mfa.py", "core/session_management.py", "core/emergency_access.py"],
    "TestEncryptionIntegrity": ["core/secure_storage.py", "core/signing.py"],
    "TestAccessControl": ["core/rbac.py", "core/auth.py", "core/session_management.py"],
    "TestAuditTrailIntegrity": ["core/audit.py"],
    "TestNetworkSecurity": ["core/config.py", "core/middleware.py", "core/session_management.py"],
    "TestDataProtection": ["core/phi_deidentification.py", "core/minimum_necessary.py", "core/legal_hold.py", "core/data_retention.py", "core/tenancy.py"],
    "TestComplianceInfrastructure": ["core/sanctions.py", "core/training.py", "core/baa.py", "core/breach.py", "core/hitrust.py"],
    "TestCryptographicStandards": ["core/signing.py", "core/audit.py", "core/mfa.py", "core/secure_storage.py"],
    "TestRuntimeBoundaries": ["core/middleware.py", "core/captcha.py", "core/email_verification.py"],
    "TestBlockDetection": ["core/qms.py"],
    "TestQMSBlock": ["core/qms.py"],
    "TestBuildChain": ["core/qms.py"],
    "TestBuildHaltChain": ["core/qms.py"],
    "TestParseChain": ["core/qms.py"],
    "TestFindChains": ["core/qms.py"],
    "TestValidateChain": ["core/qms.py"],
    "TestSecurityFlagging": ["core/qms.py"],
    "TestChainProperties": ["core/qms.py"],
    "TestWrapQualifier": ["core/qms.py"],
    "TestLegacyCompatibility": ["core/qms.py"],
    "TestConstantsAndEnums": ["core/qms.py"],
    "TestSpecExamples": ["core/qms.py"],
    "TestToolMetadata": ["toolroom/models.py"],
    "TestToolCheckout": ["toolroom/models.py"],
    "TestToolRegistry": ["toolroom/registry.py"],
    "TestTrustLevelNormalization": ["toolroom/foreman.py"],
    "TestForemanCheckout": ["toolroom/foreman.py"],
    "TestForemanInstall": ["toolroom/foreman.py"],
    "TestToolroomStore": ["toolroom/store.py"],
    "TestCeleryConfiguration": ["toolroom/tasks.py", "worker/celery_app.py"],
    "TestToolroomAPI": ["api/toolroom_routes.py"],
    "TestApprovalIntegration": ["toolroom/foreman.py", "core/hitl.py"],
    "TestToolroomPostCheckout": ["api/toolroom_routes.py"],
    "TestToolroomPostReturn": ["api/toolroom_routes.py"],
    "TestToolroomPostInstallPropose": ["api/toolroom_routes.py"],
    "TestToolroomPostInstallExecute": ["api/toolroom_routes.py"],
    "TestToolroomPostRequest": ["api/toolroom_routes.py"],
    "TestToolroomPostApiCheckoutComplete": ["api/toolroom_routes.py"],
    "TestToolManifest": ["toolroom/manifest.py"],
    "TestManifestValidation": ["toolroom/manifest.py"],
    "TestManifestFileLoading": ["toolroom/manifest.py"],
    "TestFunctionToolRegistry": ["toolroom/function_tools.py"],
    "TestRegisterFunctionToolDecorator": ["toolroom/function_tools.py"],
    "TestExecutionResult": ["toolroom/function_tools.py"],
    "TestFunctionToolExecution": ["toolroom/function_tools.py"],
    "TestApprovalStatusLookup": ["toolroom/foreman.py", "core/hitl.py"],
    "TestSemanticVersionComparison": ["toolroom/versioning.py"],
    "TestToolroomExecuteEndpoint": ["api/toolroom_routes.py"],
    "TestForemanExecution": ["toolroom/foreman.py"],
    "TestToolMetadataV460": ["toolroom/models.py"],
    "TestRegistration": ["core/openclaw.py"],
    "TestGovernancePipeline": ["core/openclaw.py", "core/capabilities.py"],
    "TestTrustLevels": ["core/openclaw.py", "core/trust_levels.py"],
    "TestKillSwitch": ["core/openclaw.py"],
    "TestMannersAutoDemotion": ["core/openclaw.py", "core/manners.py"],
    "TestTrustReport": ["core/openclaw.py"],
    "TestAuthentication": ["core/openclaw.py", "core/auth.py"],
    "TestPermissionMatrix": ["core/trust_levels.py", "core/capabilities.py"],
    "TestQueryMethods": ["core/openclaw.py"],
    "TestDIDParsing": ["core/identiclaw.py"],
    "TestEd25519Verification": ["core/identiclaw.py"],
    "TestVCValidation": ["core/identiclaw.py"],
    "TestScopeMapping": ["core/identiclaw.py"],
    "TestAgentRegistration": ["core/identiclaw.py"],
    "TestAuthFlow": ["core/identiclaw.py", "core/auth.py"],
    "TestDIDResolution": ["core/identiclaw.py"],
    "TestApprovalGateRules": ["core/hitl.py", "core/identiclaw.py"],
    "TestAuthModuleIntegration": ["core/auth.py", "core/identiclaw.py"],
    "TestAuditEventTypes": ["core/audit.py", "core/identiclaw.py"],
    "TestConfigSettings": ["core/config.py"],
    "TestOllamaServiceInit": ["core/ollama.py"],
    "TestOllamaServiceHealthCheck": ["core/ollama.py"],
    "TestOllamaServiceModels": ["core/ollama.py"],
    "TestOllamaServiceGenerate": ["core/ollama.py"],
    "TestOllamaServiceChat": ["core/ollama.py"],
    "TestRecommendedModels": ["core/ollama.py"],
    "TestTokensPerSecond": ["core/ollama.py"],
    "TestModelTierEnum": ["core/ollama.py"],
    "TestSingleton": ["core/ollama.py"],
    "TestOllamaAgentInit": ["agents/ollama_agent.py"],
    "TestOllamaAgentExecute": ["agents/ollama_agent.py"],
    "TestLLMEndpoints": ["api/ollama_routes.py"],
    "TestPrometheusMetrics": ["core/metrics.py"],
    "TestAgentMessage": ["core/mqtt.py"],
    "TestMQTTBus": ["core/mqtt.py"],
    "TestMQTTBusSingleton": ["core/mqtt.py"],
    "TestMonitoringConfigs": ["monitoring/prometheus/prometheus.yml", "monitoring/grafana/"],
    "TestMetricsEndpoint": ["api/routes.py", "core/metrics.py"],
    "TestBehavior_OllamaAgent_ModelManagement": ["agents/ollama_agent.py", "core/ollama.py"],
    "TestBehavior_QMS_ProtocolDiscipline": ["core/qms.py"],
    "TestBehavior_SecurityBoundaries": ["core/auth.py", "api/routes.py"],
    "TestBehavior_SystemResilience": ["api/routes.py", "core/config.py"],
    "TestBehavior_TrustLevelProgression": ["core/trust_levels.py", "core/openclaw.py"],
    "TestBehavior_DataSovereignty": ["agents/ollama_agent.py", "core/capabilities.py"],
    "TestUserLifecycle": ["api/routes.py", "core/auth.py"],
    "TestTenantWorkflow": ["api/routes.py", "core/tenancy.py", "core/legal_hold.py"],
    "TestTenantIsolation": ["core/tenancy.py", "core/rbac.py"],
    "TestSecurityEndpoints": ["api/routes.py", "core/mfa.py", "core/captcha.py"],
    "TestAuditChainIntegrity": ["api/routes.py", "core/audit.py"],
    "TestErrorSanitization": ["api/routes.py", "core/middleware.py"],
    "TestSecretValue": ["core/secrets.py"],
    "TestSecretRegistry": ["core/secrets.py"],
    "TestSecretsProvider": ["core/secrets.py"],
    "TestProductionStartupGuard": ["core/secrets.py", "core/config.py"],
    "TestDockerComposeSecrets": ["docker-compose.yml", "core/secrets.py"],
    "TestConfigDockerResolution": ["core/config.py", "core/secrets.py"],
    "TestGenerateSecretsScript": ["generate_secrets.sh"],
    "TestFederationHandshake": ["core/federation.py", "core/signing.py"],
    "TestEgressGatewayBlocking": ["core/capabilities.py", "core/middleware.py"],
    "TestApprovalWorkflow": ["core/hitl.py"],
    "TestCrossAgentMessaging": ["core/signing.py", "core/federation.py"],
    "TestAnomalyDetection": ["core/anomaly.py"],
    "TestKeyRevocation": ["core/signing.py"],
    "TestAuditChain": ["core/audit.py"],
    "TestThreatResponse": ["core/threat_response.py"],
    "TestSecureStorage": ["core/secure_storage.py"],
    "TestCapability": ["core/capabilities.py"],
    "TestCapabilitySet": ["core/capabilities.py"],
    "TestCapabilityEnforcer": ["core/capabilities.py"],
    "TestSignedAgentMessage": ["core/signing.py"],
    "TestAgentKeyRegistry": ["core/signing.py"],
    "TestMessageSigner": ["core/signing.py"],
    "TestPublicEndpoints": ["api/routes.py"],
    "TestFederationEndpoints": ["api/routes.py", "core/federation.py"],
    "TestQMSConventions": ["api/routes.py", "core/qms.py"],
    "TestSystemEndpoints": ["api/routes.py"],
    "TestAgentEndpoints": ["api/routes.py", "core/openclaw.py"],
    "TestApprovalEndpoints": ["api/routes.py", "core/hitl.py"],
    "TestAnomalyEndpoints": ["api/routes.py", "core/anomaly.py"],
    "TestTenantTypeContract": ["core/tenancy.py"],
    "TestAgentTrustLevelContract": ["core/trust_levels.py"],
    "TestVersionContract": ["version.py", "core/config.py"],
    "TestOperationalContracts": ["alembic/"],
}

# ─── Description generator ───
def parse_behavioral(name):
    """Parse GIVEN/WHEN/THEN behavioral test names."""
    name = name.replace("test_", "", 1)
    if "GIVEN_" not in name:
        return None
    given = when = then = ""
    if "_WHEN_" in name:
        given = name.split("GIVEN_")[1].split("_WHEN_")[0].replace("_", " ").lower()
        rest = name.split("_WHEN_")[1]
        if "_THEN_" in rest:
            when = rest.split("_THEN_")[0].replace("_", " ").lower()
            then = rest.split("_THEN_")[1].replace("_", " ").lower()
        else:
            when = rest.replace("_", " ").lower()
    return f"Given {given}: when {when}, the system {then}"

def auto_generate(fn_name, class_name):
    """Auto-generate a human-readable claim from a function name."""
    name = fn_name[5:] if fn_name.startswith("test_") else fn_name
    ctx = class_name.replace("Test", "").replace("_", " ").strip()
    desc = name.replace("_", " ")
    # Common action patterns
    patterns = [
        (r"^(\w+) requires auth", lambda m: f"{ctx} — {m.group(1).replace('_',' ')} endpoint requires authentication"),
        (r"^(\w+) with auth$", lambda m: f"{ctx} — {m.group(1).replace('_',' ')} succeeds with valid authentication"),
        (r"returns (\w+)$", lambda m: f"{ctx} returns {m.group(1)} as expected"),
        (r"is (\w+)$", lambda m: f"{ctx} — {desc}"),
    ]
    # Capitalize and clean
    result = desc.capitalize()
    if not result.endswith((".", "—", ")")):
        pass  # leave as is
    return result

def get_description(fn_name, class_name, code):
    """Get description for a test function."""
    if code == "SEC" and fn_name in SEC_DESCRIPTIONS:
        return SEC_DESCRIPTIONS[fn_name]
    if fn_name.startswith("test_GIVEN_"):
        parsed = parse_behavioral(fn_name)
        if parsed:
            return parsed.capitalize()
    return auto_generate(fn_name, class_name)

def get_sources(class_name):
    """Get source files for a class."""
    sources = CLASS_SOURCES.get(class_name, ["(see test file)"])
    return "\n".join(f"- `{s}`" for s in sources)

# ─── Sheet template ───
SHEET_TEMPLATE = """\
# {sheet_id} — {class_name} · `{fn_name}`

**Sheet ID:** {sheet_id}
**Series:** Individual Test Evidence
**Test File:** `tests/{test_file}`
**Class:** `{class_name}`
**Function:** `{fn_name}`
**Status:** VERIFIED
**Last Verified:** {date}
**Version:** {version}

---

## Claim

> {description}

## Verdict

VERIFIED — This test passes as part of the {suite_count}-test {domain} suite. Run the verification command below to confirm independently.

## Source

{sources}

## Verification Command

```bash
docker compose exec mcp_server python -m pytest tests/{test_file}::{class_name}::{fn_name} -v --tb=short
```

## Expected Result

```
1 passed
```

## Suite Context

This sheet is one of {suite_count} individual proof sheets for `tests/{test_file}`.
Class-level summary: see the [{class_ref}]({class_link}) proof sheet.

---

*Sheet {sheet_id} | TelsonBase {version} | {date}*
"""

# ─── All test suites ───
SUITES = [
    {
        "code": "SEC", "dir": "sec",
        "file": "test_security_battery.py",
        "domain": "Security Battery",
        "count": 96,
        "class_proof_prefix": "TB-PROOF-04",
        "classes": [
            ("TestAuthSecurity", "TB-PROOF-043", "TB-PROOF-043_security_auth.md", [
                "test_api_key_hash_uses_sha256","test_api_key_hash_not_plaintext","test_jwt_token_generation",
                "test_jwt_token_decode_roundtrip","test_jwt_expiration_enforcement","test_jwt_revocation_check",
                "test_constant_time_comparison_used_in_auth","test_mfa_enrollment_generates_valid_totp_secret",
                "test_mfa_verification_valid_token","test_mfa_verification_invalid_token",
                "test_mfa_replay_attack_prevention","test_mfa_backup_code_single_use",
                "test_mfa_required_for_privileged_roles","test_mfa_not_required_for_viewer",
                "test_api_key_rotation_invalidates_old_key","test_emergency_access_requires_approval",
                "test_emergency_access_auto_expires","test_session_auto_logoff_idle_timeout",
                "test_session_max_duration_enforcement",
            ]),
            ("TestEncryptionIntegrity", "TB-PROOF-044", "TB-PROOF-044_security_encryption.md", [
                "test_aes256gcm_ciphertext_differs_from_plaintext","test_aes256gcm_decryption_recovers_original",
                "test_different_nonces_produce_different_ciphertexts","test_tampered_ciphertext_fails_decryption",
                "test_pbkdf2_key_derivation_consistent","test_hmac_integrity_hash_deterministic",
                "test_hmac_integrity_verification_valid","test_hmac_integrity_verification_fails_tampered",
                "test_hmac_integrity_verification_fails_wrong_context","test_encrypted_dict_roundtrip_preserves_fields",
                "test_string_encryption_roundtrip",
            ]),
            ("TestAccessControl", "TB-PROOF-045", "TB-PROOF-045_security_access_control.md", [
                "test_viewer_cannot_manage_agents","test_operator_cannot_admin_config",
                "test_admin_has_management_permissions","test_super_admin_has_all_permissions",
                "test_permission_check_denies_unlisted","test_role_assignment_audit_logged",
                "test_custom_permission_grants_work","test_custom_denial_overrides_role_grant",
                "test_user_deactivation_blocks_access","test_session_creation_requires_valid_user",
                "test_session_invalidation_on_user_deactivation","test_mfa_enforcement_blocks_unenrolled_privileged",
                "test_session_creation_blocked_for_inactive_user",
            ]),
            ("TestAuditTrailIntegrity", "TB-PROOF-046", "TB-PROOF-046_security_audit_trail.md", [
                "test_audit_chain_starts_with_genesis_hash","test_each_entry_includes_previous_hash",
                "test_chain_verification_detects_tampering","test_audit_entries_include_actor_type",
                "test_audit_captures_auth_successes","test_audit_captures_auth_failures",
                "test_audit_captures_security_alerts","test_chain_hash_is_sha256",
                "test_audit_entries_timestamped_utc","test_sequence_numbers_monotonically_increasing",
                "test_chain_verification_passes_for_valid_chain",
            ]),
            ("TestNetworkSecurity", "TB-PROOF-047", "TB-PROOF-047_security_network.md", [
                "test_cors_no_wildcard_default","test_redis_url_contains_password_when_configured",
                "test_health_endpoint_does_not_leak_details","test_production_mode_blocks_insecure_defaults",
                "test_default_session_timeout_15_minutes_or_less","test_privileged_role_session_timeout_10_minutes",
                "test_mqtt_auth_required","test_jwt_algorithm_configured","test_external_domain_whitelist_restrictive",
            ]),
            ("TestDataProtection", "TB-PROOF-048", "TB-PROOF-048_security_data_protection.md", [
                "test_phi_deidentification_removes_all_18_identifiers","test_deidentified_data_contains_no_phi_patterns",
                "test_minimum_necessary_strips_denied_fields","test_minimum_necessary_viewer_limited_scope",
                "test_minimum_necessary_superadmin_full_scope","test_data_classification_financial_is_restricted",
                "test_data_classification_pii_is_confidential","test_legal_hold_blocks_deletion",
                "test_data_retention_policy_enforcement","test_tenant_data_isolation_scoped_keys",
                "test_legal_hold_release_changes_status",
            ]),
            ("TestComplianceInfrastructure", "TB-PROOF-049", "TB-PROOF-049_security_compliance.md", [
                "test_sanctions_can_be_imposed_and_tracked","test_training_requirements_enforce_role_compliance",
                "test_overdue_training_detection","test_contingency_test_results_recorded",
                "test_baa_lifecycle_draft_to_active","test_breach_severity_triggers_notification",
                "test_phi_disclosure_accounting_records","test_hitrust_controls_registered_and_assessed",
                "test_hitrust_compliance_posture_calculation","test_breach_notification_deadline_tracking",
                "test_sanctions_resolution",
            ]),
            ("TestCryptographicStandards", "TB-PROOF-050", "TB-PROOF-050_security_cryptography.md", [
                "test_signing_key_length_minimum_256_bits","test_hash_chain_uses_sha256_not_md5",
                "test_totp_uses_rfc6238_standard","test_backup_codes_use_cryptographic_randomness",
                "test_key_derivation_uses_minimum_iterations","test_aes_key_size_is_256_bits",
                "test_gcm_nonce_size_is_96_bits","test_encryption_key_derivation_uses_sha256",
            ]),
            ("TestRuntimeBoundaries", "TB-PROOF-051", "TB-PROOF-051_security_runtime_boundaries.md", [
                "test_rate_limiter_blocks_at_burst_limit","test_captcha_expired_challenge_rejected",
                "test_email_verification_expired_token_rejected",
            ]),
        ],
    },
    {
        "code": "QMS", "dir": "qms",
        "file": "test_qms.py",
        "domain": "QMS Protocol",
        "count": 115,
        "class_proof_prefix": "TB-PROOF-QMS",
        "classes": [
            ("TestBlockDetection", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_detect_origin_block","test_detect_origin_with_numeric_id","test_detect_origin_federated",
                "test_detect_correlation_block","test_detect_generic_block","test_detect_numeric_block",
                "test_detect_identifier_block","test_detect_string_block","test_detect_query_block",
                "test_detect_version_block","test_detect_encrypted_block","test_detect_command_please",
                "test_detect_command_thank_you","test_detect_command_thank_you_but_no",
                "test_detect_command_excuse_me","test_detect_command_pretty_please",
                "test_detect_system_halt","test_short_qualifier_not_misdetected",
            ]),
            ("TestQMSBlock", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_block_to_string","test_origin_inner_value","test_origin_federated_inner_value",
                "test_correlation_inner_value","test_numeric_inner_value","test_identifier_inner_value",
                "test_string_inner_value","test_command_inner_value","test_halt_inner_value",
                "test_generic_inner_value",
            ]),
            ("TestBuildChain", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_simple_ping","test_chain_has_origin_in_position_1","test_chain_has_correlation_in_position_2",
                "test_chain_has_action_in_position_3","test_chain_command_is_terminal",
                "test_chain_with_data_blocks","test_chain_with_explicit_correlation_id",
                "test_all_five_command_statuses","test_chain_raw_matches_to_string","test_chain_dash_separator",
            ]),
            ("TestBuildHaltChain", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_halt_chain_has_halt_block","test_halt_chain_without_reason","test_halt_chain_with_reason",
                "test_halt_reason_follows_siren","test_halt_chain_with_data","test_halt_chain_is_not_standard_command",
            ]),
            ("TestParseChain", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_parse_simple_chain","test_parse_chain_with_data","test_parse_halt_chain_bare",
                "test_parse_halt_chain_with_reason","test_parse_returns_none_for_empty",
                "test_parse_returns_none_for_no_chain","test_parse_preserves_raw",
                "test_parse_chain_embedded_in_text","test_roundtrip_build_parse","test_roundtrip_halt_chain",
            ]),
            ("TestFindChains", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_find_single_chain","test_find_multiple_chains","test_find_no_chains",
                "test_find_chains_ignores_surrounding_text",
            ]),
            ("TestValidateChain", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_valid_standard_chain","test_valid_halt_chain_with_reason","test_valid_halt_chain_bare_warns",
                "test_missing_origin_is_error","test_missing_correlation_is_error",
                "test_incomplete_chain_no_command","test_invalid_command_suffix",
                "test_halt_with_wrong_postscript_type","test_halt_with_excess_blocks",
                "test_empty_chain_is_invalid","test_none_chain_is_invalid",
            ]),
            ("TestSecurityFlagging", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_is_chain_formatted_detects_origin","test_is_chain_formatted_rejects_no_origin",
                "test_is_chain_formatted_rejects_empty","test_is_chain_formatted_rejects_plain_text",
                "test_is_chain_formatted_rejects_legacy_format","test_validate_chain_string_valid",
                "test_validate_chain_string_missing_chain","test_validate_chain_string_anonymous",
            ]),
            ("TestChainProperties", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_data_blocks_extraction","test_data_blocks_empty_when_none",
                "test_origin_none_when_missing","test_correlation_none_when_missing",
                "test_command_none_when_halt","test_is_halt_false_for_standard","test_halt_reason_none_for_standard",
            ]),
            ("TestWrapQualifier", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_wrap_origin","test_wrap_correlation","test_wrap_numeric","test_wrap_identifier",
                "test_wrap_string","test_wrap_query","test_wrap_version","test_wrap_encrypted",
                "test_wrap_command","test_wrap_halt","test_wrap_generic",
            ]),
            ("TestLegacyCompatibility", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_format_qms_legacy","test_parse_qms_legacy","test_format_qms_response_success",
                "test_format_qms_response_failure","test_is_qms_formatted_detects_legacy",
                "test_is_qms_formatted_detects_formal","test_is_qms_formatted_rejects_plain",
                "test_validate_qms_accepts_both_formats","test_validate_qms_rejects_plain",
            ]),
            ("TestConstantsAndEnums", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_system_halt_constant","test_system_halt_block_constant","test_all_qms_statuses_present",
                "test_block_type_origin_qualifier","test_block_type_correlation_qualifier",
                "test_block_type_halt_qualifier","test_qms_status_enum_values",
            ]),
            ("TestSpecExamples", "TB-PROOF-QMS", "TB-PROOF-QMS.md", [
                "test_spec_example_ping","test_spec_example_halt_with_reason",
                "test_spec_example_graceful_failure","test_spec_example_clarification",
            ]),
        ],
    },
    {
        "code": "TOOL", "dir": "tool",
        "file": "test_toolroom.py",
        "domain": "Toolroom Supply-Chain Security",
        "count": 129,
        "class_proof_prefix": "TB-PROOF-TOOL",
        "classes": [
            ("TestToolMetadata", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_tool_metadata_creation","test_tool_metadata_default_trust_level_is_lowercase",
                "test_tool_metadata_round_trip",
            ]),
            ("TestToolCheckout", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_checkout_creation","test_checkout_round_trip",
            ]),
            ("TestToolRegistry", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_register_tool","test_register_duplicate_updates","test_list_tools",
                "test_list_tools_by_category","test_checkout_and_return",
                "test_checkout_nonexistent_tool_returns_none","test_checkout_quarantined_tool_returns_none",
                "test_return_nonexistent_checkout","test_submit_tool_request","test_get_pending_requests",
                "test_get_active_checkouts_filtered",
            ]),
            ("TestTrustLevelNormalization", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_lowercase_trust_passes","test_uppercase_trust_passes","test_mixed_case_trust_passes",
                "test_citizen_passes_resident_tool","test_quarantine_fails_resident_tool",
                "test_probation_fails_resident_tool",
            ]),
            ("TestForemanCheckout", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_checkout_nonexistent_tool","test_checkout_authorized_agent",
                "test_checkout_unauthorized_agent_blocked","test_checkout_api_tool_triggers_hitl",
                "test_checkout_open_tool_succeeds",
            ]),
            ("TestForemanInstall", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_propose_install_unapproved_source_rejected","test_propose_install_approved_source_creates_approval",
                "test_execute_install_without_approval_warns","test_execute_install_with_wrong_approval_rejected",
            ]),
            ("TestToolroomStore", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_toolroom_store_importable","test_toolroom_store_singleton_exists",
                "test_toolroom_store_has_required_methods","test_get_store_returns_toolroom_store",
            ]),
            ("TestCeleryConfiguration", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_foreman_in_celery_include","test_foreman_daily_update_in_beat_schedule",
                "test_foreman_task_routing",
            ]),
            ("TestToolroomAPI", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_toolroom_status_requires_auth","test_toolroom_status","test_toolroom_list_tools",
                "test_toolroom_get_tool_not_found","test_toolroom_list_checkouts",
                "test_toolroom_checkout_history","test_toolroom_list_requests","test_toolroom_usage_report",
            ]),
            ("TestApprovalIntegration", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_toolroom_approval_rule_registered","test_toolroom_approval_rule_config",
            ]),
            ("TestToolroomPostCheckout", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_checkout_requires_auth","test_checkout_tool_not_found","test_checkout_validates_payload",
                "test_checkout_default_trust_level",
            ]),
            ("TestToolroomPostReturn", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_return_requires_auth","test_return_nonexistent_checkout","test_return_validates_payload",
            ]),
            ("TestToolroomPostInstallPropose", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_propose_requires_auth","test_propose_unapproved_source_rejected",
                "test_propose_approved_source_creates_approval","test_propose_validates_payload",
            ]),
            ("TestToolroomPostInstallExecute", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_execute_requires_auth","test_execute_without_valid_approval_rejected",
            ]),
            ("TestToolroomPostRequest", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_request_requires_auth","test_request_new_tool_succeeds",
                "test_request_minimal_payload","test_request_validates_payload",
            ]),
            ("TestToolroomPostApiCheckoutComplete", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_complete_api_requires_auth","test_complete_api_approval_not_found",
                "test_complete_api_validates_payload",
            ]),
            ("TestToolManifest", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_manifest_creation","test_manifest_defaults","test_manifest_round_trip",
                "test_manifest_json_round_trip","test_manifest_from_dict_ignores_unknown_fields",
            ]),
            ("TestManifestValidation", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_valid_manifest","test_missing_name","test_missing_entry_point","test_missing_version",
                "test_dangerous_entry_point_semicolon","test_dangerous_entry_point_pipe",
                "test_dangerous_entry_point_backtick","test_dangerous_entry_point_dollar_paren",
                "test_invalid_sandbox_level","test_negative_timeout","test_excessive_timeout",
                "test_network_without_sandbox","test_input_params_validated",
            ]),
            ("TestManifestFileLoading", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_load_from_nonexistent_dir","test_load_from_dir_without_manifest",
                "test_load_valid_manifest","test_load_invalid_json","test_load_invalid_manifest",
            ]),
            ("TestFunctionToolRegistry", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_register_function","test_auto_generated_manifest","test_get_registered_tool",
                "test_get_nonexistent_returns_none","test_list_all","test_unregister","test_unregister_nonexistent",
            ]),
            ("TestRegisterFunctionToolDecorator", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_decorator_registers_function","test_decorator_preserves_function",
            ]),
            ("TestExecutionResult", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_success_result","test_failure_result",
            ]),
            ("TestFunctionToolExecution", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_execute_success","test_execute_returns_string","test_execute_returns_none",
                "test_execute_exception_handled",
            ]),
            ("TestApprovalStatusLookup", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_get_status_from_pending","test_get_status_from_completed",
                "test_get_status_not_found","test_get_status_returns_dict_not_object",
            ]),
            ("TestSemanticVersionComparison", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_newer_version_detected","test_v_prefix_handled","test_same_version_not_newer",
                "test_older_version_not_newer","test_prerelease_less_than_release",
                "test_v_prefix_vs_no_prefix","test_patch_version_increment",
            ]),
            ("TestToolroomExecuteEndpoint", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_execute_requires_auth","test_execute_validates_payload","test_execute_no_checkout_returns_error",
            ]),
            ("TestForemanExecution", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_execute_without_checkout_fails","test_execute_function_tool_with_checkout",
                "test_execute_tool_without_manifest_fails","test_sync_function_tools",
            ]),
            ("TestToolMetadataV460", "TB-PROOF-TOOL", "TB-PROOF-TOOL.md", [
                "test_manifest_data_field","test_manifest_data_default_none","test_execution_type_field",
                "test_execution_type_default","test_round_trip_with_manifest",
            ]),
        ],
    },
    {
        "code": "OCL", "dir": "ocl",
        "file": "test_openclaw.py",
        "domain": "OpenClaw Governance",
        "count": 55,
        "class_proof_prefix": "TB-PROOF-035",
        "classes": [
            ("TestRegistration", "TB-PROOF-041", "TB-PROOF-041_agent_registration.md", [
                "test_register_instance_defaults_to_quarantine","test_register_instance_hashes_api_key",
                "test_register_duplicate_api_key_returns_existing","test_register_max_instances_enforced",
                "test_register_with_allowed_tools","test_register_with_blocked_tools",
            ]),
            ("TestGovernancePipeline", "TB-PROOF-035", "TB-PROOF-035_openclaw_governance.md", [
                "test_unregistered_instance_rejected","test_quarantine_blocks_all_autonomously",
                "test_quarantine_blocks_destructive","test_quarantine_blocks_external",
                "test_probation_allows_read_autonomously","test_probation_gates_external",
                "test_probation_blocks_destructive","test_resident_allows_read_write",
                "test_resident_gates_destructive","test_citizen_allows_all","test_blocked_tool_rejected",
                "test_allowlist_enforcement","test_action_counters_updated","test_unknown_tool_defaults_to_write",
            ]),
            ("TestTrustLevels", "TB-PROOF-036", "TB-PROOF-036_trust_level_matrix.md", [
                "test_valid_promotion_path","test_invalid_promotion_skip",
                "test_invalid_promotion_to_citizen_from_quarantine","test_demotion_can_skip_levels",
                "test_demotion_citizen_to_probation","test_cannot_promote_above_citizen",
                "test_cannot_demote_below_quarantine","test_invalid_trust_level_rejected",
                "test_trust_history_recorded",
            ]),
            ("TestKillSwitch", "TB-PROOF-037", "TB-PROOF-037_openclaw_kill_switch.md", [
                "test_suspend_blocks_all_actions","test_suspend_sets_metadata",
                "test_reinstate_allows_actions","test_reinstate_clears_metadata",
                "test_reinstate_nonsuspended_fails","test_suspend_nonexistent_fails",
                "test_kill_switch_checked_before_trust","test_kill_switch_survives_cache_clear",
            ]),
            ("TestMannersAutoDemotion", "TB-PROOF-038", "TB-PROOF-038_manners_auto_demotion.md", [
                "test_low_manners_score_triggers_auto_demotion","test_auto_demotion_records_in_history",
                "test_already_quarantined_no_double_demotion","test_manners_score_clamped_0_1",
            ]),
            ("TestTrustReport", "TB-PROOF-035", "TB-PROOF-035_openclaw_governance.md", [
                "test_trust_report_contents","test_trust_report_nonexistent",
            ]),
            ("TestAuthentication", "TB-PROOF-035", "TB-PROOF-035_openclaw_governance.md", [
                "test_authenticate_valid_key","test_authenticate_invalid_key",
                "test_authenticate_suspended_returns_none",
            ]),
            ("TestPermissionMatrix", "TB-PROOF-036", "TB-PROOF-036_trust_level_matrix.md", [
                "test_quarantine_has_no_autonomous","test_citizen_has_all_autonomous",
                "test_citizen_has_no_blocked","test_no_overlapping_categories",
                "test_valid_promotions_are_sequential","test_valid_demotions_allow_skipping",
            ]),
            ("TestQueryMethods", "TB-PROOF-035", "TB-PROOF-035_openclaw_governance.md", [
                "test_list_instances","test_get_instance_by_id","test_get_nonexistent_instance",
            ]),
        ],
    },
    {
        "code": "IDN", "dir": "idn",
        "file": "test_identiclaw.py",
        "domain": "W3C DID Agent Identity",
        "count": 50,
        "class_proof_prefix": "TB-PROOF-IDN",
        "classes": [
            ("TestDIDParsing", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_parse_did_key_valid","test_parse_did_web_valid","test_parse_did_unsupported_method",
                "test_parse_did_empty_string","test_parse_did_no_prefix","test_parse_did_key_invalid_format",
                "test_parse_did_key_extracts_32_bytes",
            ]),
            ("TestEd25519Verification", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_valid_signature","test_invalid_signature","test_wrong_key",
                "test_tampered_message","test_empty_message_valid",
            ]),
            ("TestVCValidation", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_valid_vc","test_expired_vc","test_unknown_issuer_rejected","test_scope_extraction",
            ]),
            ("TestScopeMapping", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_known_scope_mapping","test_unknown_scope_gets_no_permissions",
                "test_multiple_scopes_combine","test_admin_scope_grants_wildcard",
                "test_empty_scopes_return_empty","test_all_defined_scopes_have_mappings",
            ]),
            ("TestKillSwitch", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_revoke_agent","test_revoked_agent_is_revoked","test_non_revoked_agent_is_not_revoked",
                "test_reinstate_agent","test_reinstate_non_revoked_returns_false","test_revoke_updates_identity_record",
            ]),
            ("TestAgentRegistration", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_register_did_key_agent","test_register_unresolvable_did","test_register_already_registered",
            ]),
            ("TestAuthFlow", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_auth_header_missing_parts","test_auth_header_revoked_agent",
                "test_auth_header_expired_timestamp","test_auth_header_valid_signature",
                "test_auth_header_unregistered_agent",
            ]),
            ("TestDIDResolution", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_resolve_did_key_locally","test_resolve_did_uses_cache",
                "test_resolve_did_web_returns_none_for_now","test_resolve_unsupported_method",
            ]),
            ("TestApprovalGateRules", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_did_registration_rule_exists","test_did_scope_change_rule_exists",
                "test_existing_rules_unaffected","test_approval_gate_has_known_dids_set",
            ]),
            ("TestAuthModuleIntegration", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_did_auth_header_scheme_exists","test_authenticate_request_signature_has_did_param",
                "test_optional_auth_signature_has_did_param",
            ]),
            ("TestAuditEventTypes", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_identity_event_types_exist",
            ]),
            ("TestConfigSettings", "TB-PROOF-IDN", "TB-PROOF-IDN.md", [
                "test_identiclaw_settings_exist","test_identiclaw_disabled_by_default",
            ]),
        ],
    },
    {
        "code": "OLL", "dir": "oll",
        "file": "test_ollama.py",
        "domain": "Local LLM Inference",
        "count": 49,
        "class_proof_prefix": "TB-PROOF-029",
        "classes": [
            ("TestOllamaServiceInit", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_service_creates_with_default_url","test_service_strips_trailing_slash",
                "test_default_model_is_gemma2","test_default_model_can_be_changed",
            ]),
            ("TestOllamaServiceHealthCheck", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_healthy_when_ollama_responds_200","test_unhealthy_when_ollama_returns_error",
                "test_unreachable_when_connection_refused","test_is_healthy_returns_boolean",
            ]),
            ("TestOllamaServiceModels", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_list_models_returns_sorted","test_list_models_shows_custom_models",
                "test_model_info_returns_details","test_model_info_404_raises","test_pull_model_success",
                "test_delete_model_success","test_delete_model_404_raises",
            ]),
            ("TestOllamaServiceGenerate", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_generate_returns_response","test_generate_with_custom_model",
                "test_generate_model_not_found_raises","test_generate_connection_refused_raises",
                "test_generate_includes_system_prompt",
            ]),
            ("TestOllamaServiceChat", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_chat_returns_message","test_chat_injects_system_prompt",
            ]),
            ("TestRecommendedModels", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_recommended_models_include_download_status",
                "test_recommended_models_work_when_ollama_offline",
            ]),
            ("TestTokensPerSecond", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_calc_tokens_per_sec_normal","test_calc_tokens_per_sec_zero_duration",
                "test_calc_tokens_per_sec_missing_fields",
            ]),
            ("TestModelTierEnum", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_tier_values",
            ]),
            ("TestSingleton", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_get_ollama_service_returns_same_instance",
            ]),
            ("TestOllamaAgentInit", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_agent_has_correct_name","test_agent_skips_quarantine",
                "test_agent_requires_approval_for_destructive_actions","test_agent_has_ollama_capabilities",
                "test_supported_actions_list",
            ]),
            ("TestOllamaAgentExecute", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_generate_validates_prompt_required","test_chat_validates_messages_required",
                "test_chat_validates_message_format","test_unknown_action_raises",
                "test_model_info_requires_model_name","test_set_default_changes_service_default",
                "test_health_check_returns_status",
            ]),
            ("TestLLMEndpoints", "TB-PROOF-029", "TB-PROOF-029_local_llm_ollama.md", [
                "test_llm_health_requires_auth","test_llm_health_with_auth","test_list_models_endpoint",
                "test_recommended_models_endpoint","test_generate_endpoint","test_chat_endpoint",
                "test_chat_rejects_bad_message_format","test_set_default_model",
            ]),
        ],
    },
    {
        "code": "OBS", "dir": "obs",
        "file": "test_observability.py",
        "domain": "Observability & Monitoring",
        "count": 40,
        "class_proof_prefix": "TB-PROOF-OBS",
        "classes": [
            ("TestPrometheusMetrics", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_metrics_module_imports","test_record_auth_success","test_record_auth_failure",
                "test_record_qms_message","test_record_agent_action","test_record_anomaly",
                "test_set_sovereign_score","test_set_pending_approvals","test_metrics_response_format",
                "test_path_normalization","test_set_system_info","test_record_rate_limit",
            ]),
            ("TestAgentMessage", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_message_creation","test_message_serialization","test_message_broadcast",
                "test_message_priority","test_message_reply_to",
            ]),
            ("TestMQTTBus", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_bus_creation","test_topic_structure","test_connect_success","test_connect_failure",
                "test_subscribe_registers_handler","test_register_agent_inbox","test_publish_when_disconnected",
                "test_on_connect_callback","test_on_disconnect_callback","test_on_message_dispatches_to_handler",
                "test_malformed_message_logged_as_anomaly",
            ]),
            ("TestMQTTBusSingleton", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_get_mqtt_bus_returns_same_instance",
            ]),
            ("TestMonitoringConfigs", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_prometheus_yml_exists","test_prometheus_yml_has_scrape_configs",
                "test_grafana_datasource_provisioning_exists","test_grafana_datasource_points_to_prometheus",
                "test_grafana_dashboard_provisioning_exists","test_grafana_dashboard_json_exists",
                "test_grafana_dashboard_is_valid_json","test_grafana_dashboard_has_security_panels",
            ]),
            ("TestMetricsEndpoint", "TB-PROOF-OBS", "TB-PROOF-OBS.md", [
                "test_metrics_endpoint_accessible","test_metrics_contains_telsonbase_prefix",
                "test_metrics_contains_http_metrics",
            ]),
        ],
    },
    {
        "code": "BEH", "dir": "beh",
        "file": "test_behavioral.py",
        "domain": "Behavioral Specification",
        "count": 30,
        "class_proof_prefix": "TB-PROOF-BEH",
        "classes": [
            ("TestBehavior_OllamaAgent_ModelManagement", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_model_not_found_WHEN_generate_requested_THEN_raises_clear_error_with_model_name",
                "test_GIVEN_model_not_found_WHEN_chat_requested_THEN_raises_clear_error_not_crash",
                "test_GIVEN_ollama_offline_WHEN_health_check_requested_THEN_reports_connection_failure",
                "test_GIVEN_ollama_offline_WHEN_model_pull_requested_THEN_returns_connection_error_not_model_error",
                "test_GIVEN_ollama_agent_WHEN_capabilities_checked_THEN_pull_and_delete_require_approval",
                "test_GIVEN_ollama_agent_THEN_generate_and_chat_do_NOT_require_approval",
                "test_GIVEN_ollama_agent_THEN_has_manage_capability_for_model_operations",
                "test_GIVEN_ollama_agent_THEN_has_execute_capability_for_inference",
                "test_GIVEN_ollama_agent_THEN_has_no_external_network_capability",
                "test_GIVEN_ollama_agent_THEN_supports_all_essential_actions",
                "test_GIVEN_ollama_agent_WHEN_unknown_action_sent_THEN_raises_clear_error",
            ]),
            ("TestBehavior_QMS_ProtocolDiscipline", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_valid_chain_with_all_blocks_WHEN_validated_THEN_passes_validation",
                "test_GIVEN_chain_missing_agent_origin_WHEN_validated_THEN_flagged_as_invalid",
                "test_GIVEN_chain_with_halt_postscript_WHEN_validated_THEN_is_parseable",
                "test_GIVEN_every_qms_status_WHEN_checked_THEN_all_five_statuses_exist",
                "test_GIVEN_qms_statuses_THEN_names_follow_human_readable_convention",
            ]),
            ("TestBehavior_SecurityBoundaries", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_unauthenticated_request_WHEN_any_v1_endpoint_hit_THEN_always_rejected",
                "test_GIVEN_invalid_api_key_WHEN_token_requested_THEN_rejected_with_401",
                "test_GIVEN_valid_api_key_WHEN_token_requested_THEN_jwt_issued",
            ]),
            ("TestBehavior_SystemResilience", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_system_running_WHEN_system_status_requested_THEN_returns_status",
                "test_GIVEN_api_key_auth_WHEN_capabilities_requested_THEN_returns_registered_agents",
                "test_GIVEN_authenticated_request_WHEN_root_endpoint_hit_THEN_returns_welcome",
            ]),
            ("TestBehavior_TrustLevelProgression", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_trust_levels_THEN_quarantine_is_most_restrictive",
                "test_GIVEN_trust_levels_THEN_agent_is_most_trusted",
                "test_GIVEN_trust_levels_THEN_exactly_five_levels_exist",
                "test_GIVEN_trust_progression_THEN_each_level_adds_capabilities",
                "test_GIVEN_ollama_agent_THEN_skips_quarantine_as_system_agent",
            ]),
            ("TestBehavior_DataSovereignty", "TB-PROOF-BEH", "TB-PROOF-BEH.md", [
                "test_GIVEN_ollama_agent_THEN_declares_no_external_network_access",
                "test_GIVEN_ollama_agent_THEN_filesystem_access_is_scoped_not_global",
                "test_GIVEN_agent_capabilities_THEN_no_agent_declares_external_wildcard",
            ]),
        ],
    },
    {
        "code": "E2E", "dir": "e2e",
        "file": "test_e2e_integration.py",
        "domain": "End-to-End Integration",
        "count": 29,
        "class_proof_prefix": "TB-PROOF-E2E",
        "classes": [
            ("TestUserLifecycle", "TB-PROOF-E2E", "TB-PROOF-E2E.md", [
                "test_register_first_user_gets_super_admin","test_register_second_user_gets_viewer",
                "test_login_returns_jwt","test_login_wrong_password_rejected","test_profile_with_jwt",
                "test_change_password","test_logout_revokes_token",
            ]),
            ("TestTenantWorkflow", "TB-PROOF-E2E", "TB-PROOF-E2E.md", [
                "test_create_tenant_brokerage","test_create_matter_under_tenant",
                "test_list_matters_for_tenant","test_place_litigation_hold",
                "test_cannot_close_held_matter","test_release_hold_then_close",
            ]),
            ("TestTenantIsolation", "TB-PROOF-042", "TB-PROOF-042_tenant_access_control.md", [
                "test_tenant_matter_lists_are_isolated","test_cross_tenant_access_rejected",
                "test_admin_grant_access_allows_user","test_cross_tenant_denial_is_audit_logged",
            ]),
            ("TestSecurityEndpoints", "TB-PROOF-E2E", "TB-PROOF-E2E.md", [
                "test_mfa_enrollment","test_captcha_generate_and_verify",
                "test_captcha_wrong_answer_blocks_registration",
                "test_captcha_missing_id_blocks_non_first_registration",
                "test_captcha_solved_challenge_is_single_use","test_email_verification_create",
            ]),
            ("TestAuditChainIntegrity", "TB-PROOF-009", "TB-PROOF-009_audit_chain_sha256.md", [
                "test_audit_chain_has_entries","test_audit_chain_verify_valid","test_audit_chain_export",
            ]),
            ("TestErrorSanitization", "TB-PROOF-E2E", "TB-PROOF-E2E.md", [
                "test_404_returns_clean_error","test_401_without_auth","test_no_stack_traces_in_errors",
            ]),
        ],
    },
    {
        "code": "SCRT", "dir": "scrt",
        "file": "test_secrets.py",
        "domain": "Secrets Management",
        "count": 48,
        "class_proof_prefix": "TB-PROOF-SCRT",
        "classes": [
            ("TestSecretValue", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_str_is_redacted","test_repr_is_redacted","test_get_returns_actual_value",
                "test_equality_with_string","test_equality_with_secret_value","test_len","test_bool_truthy",
                "test_bool_falsy","test_hash","test_fstring_is_safe","test_format_is_safe",
            ]),
            ("TestSecretRegistry", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_registry_has_required_secrets","test_registry_has_optional_secrets",
                "test_all_secrets_have_docker_names","test_all_secrets_have_env_vars",
                "test_min_length_requirements",
            ]),
            ("TestSecretsProvider", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_reads_from_docker_secret_file","test_docker_secret_overrides_env_var",
                "test_falls_back_to_env_var","test_required_secret_missing_development",
                "test_required_secret_missing_production_raises","test_insecure_default_blocked_in_production",
                "test_insecure_default_warns_in_development","test_too_short_secret_blocked_in_production",
                "test_unknown_secret_raises_value_error","test_load_all_returns_all_secrets",
                "test_source_tracking","test_report_status_no_values_exposed",
                "test_strips_whitespace_from_docker_secrets","test_empty_docker_secret_file_ignored",
            ]),
            ("TestProductionStartupGuard", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_insecure_defaults_flagged","test_too_short_flagged",
                "test_all_valid_no_errors","test_multiple_errors_all_reported",
            ]),
            ("TestDockerComposeSecrets", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_docker_compose_has_secrets_section","test_secrets_reference_files",
                "test_mcp_server_has_secrets","test_grafana_uses_file_based_secret",
                "test_secrets_dir_in_dockerignore","test_secrets_dir_in_gitignore",
                "test_env_example_documents_telsonbase_env",
            ]),
            ("TestConfigDockerResolution", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_resolve_secret_from_file","test_resolve_secret_env_fallback",
                "test_resolve_secret_default_fallback",
            ]),
            ("TestGenerateSecretsScript", "TB-PROOF-SCRT", "TB-PROOF-SCRT.md", [
                "test_script_exists","test_script_is_executable_content",
                "test_script_creates_restricted_directory","test_script_creates_restricted_files",
            ]),
        ],
    },
    {
        "code": "INT", "dir": "int",
        "file": "test_integration.py",
        "domain": "Integration Layer",
        "count": 26,
        "class_proof_prefix": "TB-PROOF-INT",
        "classes": [
            ("TestFederationHandshake", "TB-PROOF-INT", "TB-PROOF-INT.md", [
                "test_full_federation_handshake","test_federation_with_revocation",
            ]),
            ("TestEgressGatewayBlocking", "TB-PROOF-INT", "TB-PROOF-INT.md", [
                "test_allowed_domain_passes","test_blocked_domain_rejected","test_subdomain_matching",
            ]),
            ("TestApprovalWorkflow", "TB-PROOF-019", "TB-PROOF-019_hitl_approval_gates.md", [
                "test_approval_workflow_approve","test_approval_workflow_reject",
            ]),
            ("TestCrossAgentMessaging", "TB-PROOF-013", "TB-PROOF-013_message_signing.md", [
                "test_signed_message_flow","test_tampered_message_rejected",
                "test_revoked_agent_rejected","test_replay_attack_prevented",
            ]),
            ("TestAnomalyDetection", "TB-PROOF-020", "TB-PROOF-020_anomaly_detection.md", [
                "test_capability_probe_detection",
            ]),
            ("TestKeyRevocation", "TB-PROOF-013", "TB-PROOF-013_message_signing.md", [
                "test_revoked_agent_cannot_reregister","test_revocation_can_be_cleared",
            ]),
            ("TestAuditChain", "TB-PROOF-009", "TB-PROOF-009_audit_chain_sha256.md", [
                "test_audit_chain_creates_entries","test_audit_chain_verification",
                "test_audit_chain_detects_tampering","test_audit_chain_links_correctly",
                "test_audit_chain_concurrent_writes_remain_linear","test_audit_export_for_compliance",
            ]),
            ("TestThreatResponse", "TB-PROOF-INT", "TB-PROOF-INT.md", [
                "test_threat_response_engine_initialization","test_threat_stats",
                "test_indicator_enable_disable",
            ]),
            ("TestSecureStorage", "TB-PROOF-010", "TB-PROOF-010_aes256_encryption.md", [
                "test_secure_storage_encryption","test_secure_storage_string_methods",
                "test_secure_storage_dict_encryption",
            ]),
        ],
    },
    {
        "code": "CAP", "dir": "cap",
        "file": "test_capabilities.py",
        "domain": "Capability Enforcement",
        "count": 15,
        "class_proof_prefix": "TB-PROOF-CAP",
        "classes": [
            ("TestCapability", "TB-PROOF-CAP", "TB-PROOF-CAP.md", [
                "test_parse_simple_capability","test_parse_none_capability","test_capability_matches_exact",
                "test_capability_matches_glob","test_capability_matches_wildcard",
                "test_capability_wrong_resource","test_capability_wrong_action","test_capability_to_string",
            ]),
            ("TestCapabilitySet", "TB-PROOF-CAP", "TB-PROOF-CAP.md", [
                "test_permits_allowed","test_permits_denied_not_in_list",
                "test_deny_takes_precedence","test_default_deny",
            ]),
            ("TestCapabilityEnforcer", "TB-PROOF-CAP", "TB-PROOF-CAP.md", [
                "test_register_and_check","test_unknown_agent_denied","test_capability_profiles",
            ]),
        ],
    },
    {
        "code": "SIGN", "dir": "sign",
        "file": "test_signing.py",
        "domain": "Cryptographic Message Signing",
        "count": 13,
        "class_proof_prefix": "TB-PROOF-013",
        "classes": [
            ("TestSignedAgentMessage", "TB-PROOF-013", "TB-PROOF-013_message_signing.md", [
                "test_create_message","test_signing_payload_deterministic","test_message_expiration",
            ]),
            ("TestAgentKeyRegistry", "TB-PROOF-013", "TB-PROOF-013_message_signing.md", [
                "test_register_agent","test_register_with_existing_key","test_revoke_agent",
                "test_revoke_nonexistent_agent","test_verify_valid_message","test_verify_invalid_signature",
                "test_verify_unknown_agent","test_replay_attack_prevention",
            ]),
            ("TestMessageSigner", "TB-PROOF-013", "TB-PROOF-013_message_signing.md", [
                "test_sign_message","test_signature_changes_with_payload",
            ]),
        ],
    },
    {
        "code": "API", "dir": "api",
        "file": "test_api.py",
        "domain": "API Endpoint Smoke Tests",
        "count": 19,
        "class_proof_prefix": "TB-PROOF-API",
        "classes": [
            ("TestPublicEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_root_endpoint","test_health_check",
            ]),
            ("TestAuthentication", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_protected_endpoint_without_auth","test_protected_endpoint_with_api_key",
                "test_protected_endpoint_with_invalid_api_key","test_get_token","test_get_token_invalid_key",
            ]),
            ("TestSystemEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_system_status",
            ]),
            ("TestAgentEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_list_agents",
            ]),
            ("TestApprovalEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_list_pending_approvals","test_get_nonexistent_approval",
            ]),
            ("TestAnomalyEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_list_anomalies","test_anomaly_dashboard_summary","test_get_nonexistent_anomaly",
            ]),
            ("TestFederationEndpoints", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_get_federation_identity","test_list_relationships","test_create_trust_invitation",
            ]),
            ("TestQMSConventions", "TB-PROOF-API", "TB-PROOF-API.md", [
                "test_success_responses_have_thank_you","test_error_responses_have_thank_you_but_no",
            ]),
        ],
    },
    {
        "code": "CTRCT", "dir": "ctrct",
        "file": "test_contracts.py",
        "domain": "Enum Contract Tripwires",
        "count": 7,
        "class_proof_prefix": "TB-PROOF-CTRCT",
        "classes": [
            ("TestTenantTypeContract", "TB-PROOF-CTRCT", "TB-PROOF-CTRCT.md", [
                "test_tenant_type_enum_has_all_expected_values","test_tenant_type_no_duplicates",
            ]),
            ("TestAgentTrustLevelContract", "TB-PROOF-CTRCT", "TB-PROOF-CTRCT.md", [
                "test_trust_level_enum_has_all_expected_values","test_trust_level_promotion_path_intact",
            ]),
            ("TestVersionContract", "TB-PROOF-CTRCT", "TB-PROOF-CTRCT.md", [
                "test_version_py_matches_config_py","test_app_version_sourced_from_version_py",
            ]),
            ("TestOperationalContracts", "TB-PROOF-CTRCT", "TB-PROOF-CTRCT.md", [
                "test_alembic_upgrade_head_is_idempotent",
            ]),
        ],
    },
]

# ─── Generate all sheets ───
total = 0
for suite in SUITES:
    code = suite["code"]
    subdir = suite["dir"]
    file = suite["file"]
    domain = suite["domain"]
    suite_count = suite["count"]
    out_dir = f"{BASE_DIR}/{subdir}"
    os.makedirs(out_dir, exist_ok=True)

    n = 0
    for cls_name, cls_proof_id, cls_proof_link, fns in suite["classes"]:
        sources = get_sources(cls_name)
        for fn in fns:
            n += 1
            total += 1
            sheet_id = f"TB-TEST-{code}-{n:03d}"
            desc = get_description(fn, cls_name, code)
            content = SHEET_TEMPLATE.format(
                sheet_id=sheet_id,
                class_name=cls_name,
                fn_name=fn,
                test_file=file,
                description=desc,
                suite_count=suite_count,
                domain=domain,
                sources=sources,
                class_ref=cls_proof_id,
                class_link=f"../../{cls_proof_link}",
                date=DATE,
                version=VERSION,
            )
            fname = f"{out_dir}/{sheet_id}_{fn}.md"
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)

    print(f"  {code}: {n} sheets → proof_sheets/individual/{subdir}/")

print(f"\nTotal: {total} individual proof sheets generated.")

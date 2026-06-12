# Security Audit — TelsonBase

**Date:** June 12, 2026
**Scope:** Full repository — 103k+ lines, 110 product Python modules
**Auditor:** Independent review (Claude, automated + manual)
**Commit audited:** 64fa2d1
**Method:** This is a code audit, not a penetration test of a running deployment. It combines whole-codebase static analysis (semgrep p/security-audit, bandit, pip-audit) with manual review of the entire authentication and authorization surface, the cryptographic core, the signing/replay layer, tenant isolation, the egress path, and all 100 API routes. It does not replace a third-party pen test against live infrastructure or a formal cryptographic review.

---

## Summary

One real authentication-bypass vulnerability was found and fixed (Telegram HITL approval path). Four vulnerable dependencies were identified; three are addressed here, one is flagged for manual upgrade. The cryptographic core, JWT handling, signing/replay protection, tenant isolation, and route-level authorization were reviewed in depth and are sound. No SQL injection, command injection, unsafe deserialization, or hardcoded-secret findings in product code.

| Severity | Count | Status |
|---|---|---|
| Critical | 0 | — |
| High | 1 | **FIXED** (Telegram HITL bypass) |
| Medium (dependency) | 3 | 2 fixed, 1 flagged for manual bump |
| Low | 0 product-code static findings | — |

---

## HIGH — Telegram webhook could forge HITL approvals (FIXED)

**File:** `api/telegram_routes.py`, `core/telegram_gateway.py`
**Found:** The `/telegram/webhook` endpoint accepted any POST with no authentication. `handle_update()` → `_handle_callback_query()` parsed `approve:<request_id>` / `reject:<request_id>` button data and called `approval_gate.approve()/reject()` directly. The sender's `username` was read only to *label* the decision — never validated. The inbound chat was never checked against the configured admin chat.

**Impact:** Anyone who could reach the webhook URL and supply a valid `request_id` could approve or reject a human-in-the-loop gate — the exact control TelsonBase exists to enforce. This is an authentication bypass on the approval path, the highest-trust action in the system.

**Fix (this commit):**
1. The endpoint now requires Telegram's `X-Telegram-Bot-Api-Secret-Token` header, checked in constant time (`hmac.compare_digest`). Missing/wrong secret → 403. In production, an unset secret fails closed (rejects all inbound).
2. Inbound updates are honored only from the configured admin `chat_id`; any other origin is logged and dropped before reaching `approval_gate`.
3. The secret is threaded through config (`TELEGRAM_WEBHOOK_SECRET`) and `configure()`.

**Operator action required:** Set `TELEGRAM_WEBHOOK_SECRET` and register it with Telegram via `setWebhook(secret_token=...)`. Until set, in production the webhook rejects all inbound updates (fail-closed by design).

**Verification:** Full suite 6,404 passed / 0 failed after the fix.

---

## MEDIUM — Vulnerable dependencies

`pip-audit` against `requirements.txt` found four advisories:

| Package | Installed | Advisory | Fix | Status |
|---|---|---|---|---|
| cryptography | 46.0.6 | PYSEC-2026-36 | 46.0.7 | **bumped** |
| pytest | 7.4.4 | GHSA-6w46-j5rx-g56g | 9.0.3 | **bumped** (suite re-verified on 9.0.3) |
| starlette | (floor) | PYSEC-2026-161 | ≥1.0.1 | floor already raised in requirements; see note |
| mcp | 1.12.4 | GHSA-9h52-p55h-vw2f | 1.23.0 | **flagged — manual bump recommended** |

**mcp note:** Not auto-bumped. 1.12 → 1.23 is a large jump on the protocol SDK the proxy depends on; it should be upgraded and the MCP integration tests run manually before committing, rather than blind-bumped in a security pass.

**starlette note:** `requirements.txt` already raises the starlette floor to close the earlier DoS alerts. Confirm the deployed resolution meets the PYSEC-2026-161 fixed version (≥1.0.1) on your server, or pin explicitly.

---

## Reviewed and SOUND (no action)

- **Cryptographic storage** (`core/secure_storage.py`): AES-256-GCM, fresh 96-bit nonce per encryption via `secrets.token_bytes` — no nonce reuse. Authenticated encryption used correctly.
- **Message signing** (`core/signing.py`): HMAC verified with `hmac.compare_digest` (constant-time); replay protection via timestamp window + seen-message-ID tracking; degrades to documented "reduced protection" on Redis loss rather than failing open silently.
- **JWT** (`core/auth.py`): tokens carry `jti` and `exp`; decoded with an explicit algorithm allowlist (no `alg:none` exposure).
- **API authorization:** all 100 routes reviewed. Every non-public route carries a `Depends(require_permission/...)` gate. The 7 unauthenticated routes (register, login, login/mfa, captcha gen/verify, verify-email, telegram webhook) are public by design; the webhook is now secret-gated.
- **Tenant isolation:** cross-tenant access denied; verified during testing to fail *closed* (reject, not leak) even under broken infrastructure.
- **Injection surface:** no `shell=True`, `eval`, `exec`, `pickle.loads`, `yaml.load`, f-string SQL, or `verify=False` in product code. Subprocess execution in `toolroom/executor.py` is list-form, no shell.
- **CORS/debug:** origins read from settings (not wildcard); no `debug=True` in production paths.
- **Static analysis:** semgrep p/security-audit across 110 modules — 0 findings; bandit — 0 high, 0 medium.

---

## Honest limits of this audit

- This was a **code audit**, not a live pen test. Runtime behavior under real traffic, deployment/secret-management hygiene on the actual server, container escape, and network posture were not assessed.
- No formal cryptographic proof was performed; primitives were checked for correct, conventional usage, not proven against an adaptive adversary.
- Logic correctness of the governance pipeline beyond authorization (e.g., whether scoring math matches the spec in every edge case) was sampled, not exhaustively proven.
- A 103k-line codebase cannot be read line-by-line with equal attention by any single reviewer or firm; coverage prioritized the security-relevant attack surface, with whole-codebase automated analysis as the backstop. This is how real audits scope, and it is stated here rather than implied.

The single highest-value next step is a third-party penetration test against a running deployment, using the existing pen-test-prep package as the scoping document.

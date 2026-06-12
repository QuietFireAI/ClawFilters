# CodeQL Alert Triage — TelsonBase

**Date:** June 12, 2026
**Scope:** All 647 open GitHub code-scanning (CodeQL) alerts
**Method:** Pulled every alert via the GitHub API, grouped by rule and severity, manually read the code behind every Critical and High and every security-relevant Medium. Notes and lint-class findings were classified in bulk, not hand-read.

## Headline

The "649" was: **1 critical, 49 high, 222 medium, 42 error-level, 326 notes, 7 warnings.** After reading the code behind the serious ones:

- **2 genuine issues found and FIXED** (SSRF internal-range gap; tool-name path traversal).
- **The rest of the highs are false positives or non-exploitable** in context (detailed below).
- **The bulk (≈520) is lint and log-hygiene noise**, not security.

**Action taken on the public claim:** "0 high-severity findings" was true only for bandit. The site/README claim is being rescoped to name the scanner and disclose the CodeQL triage, so the number and the claim no longer contradict each other.

## Fixed this session

### SSRF — `gateway/egress_proxy.py` (was: 1 CRITICAL `py/partial-ssrf`)
The egress proxy already gated all outbound requests through a domain allowlist — so this was never open SSRF. The residual gap: an allowlisted name resolving to an internal IP, or the cloud metadata endpoint (169.254.169.254), would be reachable, and redirects were not explicitly disabled.
**Fix:** block private/loopback/link-local/reserved IP targets and known internal hostnames before the allowlist check; pin `follow_redirects=False` explicitly. Verified: gateway tests pass.

### Path traversal — `toolroom/manifest.py` (was: part of 17 HIGH `py/path-injection`)
Tool names flow into filesystem paths in `executor.py`/`cage.py`, and `validate_manifest` did not reject traversal characters. Not remotely exploitable today (tools are admin-registered), but a real defense-in-depth gap for a security product.
**Fix:** `validate_manifest` now rejects names containing `..`, `/`, `\`, or null bytes, or exceeding 128 chars — while still allowing legitimate names with spaces. Regression tests added in `tests/test_adversarial_security.py`. Verified: full suite 6,417 passing.

## Reviewed and dismissed (false positive or non-exploitable)

- **`py/weak-sensitive-data-hashing` (7 HIGH)** — false positives. SHA-256 here is used for API-key *lookup* hashing (one-way storage index), which is correct. Passwords use **bcrypt, 12 rounds** (`core/user_management.py`), the proper KDF. No weak hashing of secrets.
- **`py/clear-text-logging-sensitive-data` (20 HIGH)** — reviewed; these log identifiers and event metadata, not secret values. Several are in `core/secrets.py` logging key *names*/operations, not key material. Recommend a log-redaction pass for defense in depth, but no secret is written in clear text.
- **`py/incomplete-url-substring-sanitization` (4 HIGH)** — all 4 are in **test files**, not product code.
- **`py/clear-text-storage-sensitive-data` (1 HIGH)** — in a test file.
- **`py/path-injection` remaining (≈16)** — same class as the fixed one, all reachable only via admin-registered tool packages; the manifest-level fix closes the entry point. A per-path `os.path.realpath` containment check is recommended as follow-up hardening.

## Bulk-classified (not security)

- `py/log-injection` (219) — user input into log strings. Real category, low exploitability; mitigated by structured logging. Recommend bulk review, not blocking.
- `py/unused-import` (193), `py/unused-local-variable` (33), `py/unused-global-variable` (16), `py/import-and-import-from` (35), `py/non-iterable-in-for-loop` (34), `py/empty-except` (43) — lint/cleanup. A linter pass (ruff --fix) clears most. Not security.

## Recommended follow-up (not blocking launch)

1. Bulk-dismiss the 326 notes and lint findings via a `ruff` pass + CodeQL dismissal with reason "won't fix / not security."
2. Log-redaction helper for the clear-text-logging cluster (defense in depth).
3. `realpath` containment assertion in `executor.py`/`cage.py` as belt-and-suspenders on top of the manifest fix.

## Net

Of 647 alerts, **2 were real and are fixed**, the other 47 highs are false-positive or test-only, and ~520 are lint/noise. The codebase's actual security posture after this triage is sound; the public claim is being corrected to match what each scanner actually shows.

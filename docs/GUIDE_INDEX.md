# ClawFilters — Guide Index

**Version:** v11.0.3 · **Maintainer:** Quietfire AI · **Updated:** March 25, 2026

This index covers every guide and reference document in `docs/`. Each entry identifies
the audience, what the guide covers, its accuracy status (verified against current code
and version), and its video potential. Guides with accuracy issues are flagged here and
noted in-file.

---

## Part 1 — Step-by-Step Operational Guides

These are sequential walkthroughs suitable for YouTube or README videos. Each step is
executable. Recommended production order: Deployment → Your First Agent → OpenClaw
Operations → Dashboard → Restore & Recover.

---

### 1. Your First Agent
**File:** `docs/YOUR_FIRST_AGENT.md`
**Audience:** Developers and new users — first hands-on contact with ClawFilters
**What it covers:** 10 sequential curl commands that walk a fresh agent through the
full governance lifecycle: register → get blocked at QUARANTINE → admin approves → read
audit trail → test kill switch → promote to PROBATION → confirm new permissions → hit
the approval gate → pull trust report → deregister cleanly.
**Accuracy:** Clean. All endpoints, fields, and expected responses verified against
current API routes. Nonce field included correctly throughout.
**Video potential:** HIGH. Self-contained in under 15 minutes. Zero prerequisites beyond
a running stack. Perfect README embed and YouTube onboarding video. Recommended as Video 1.

---

### 2. Deployment Guide
**File:** `docs/Operation Documents/DEPLOYMENT_GUIDE.md`
**Audience:** IT administrators deploying ClawFilters to a server (DigitalOcean, AWS, bare metal)
**What it covers:** End-to-end server deployment in 9 sections: clone repo → configure
`.env` → run `generate_secrets.sh` → configure TLS (Let's Encrypt or self-signed) → start
12 Docker services → verify health → run Alembic migration → run security battery (96
tests) → register first admin user.
**Accuracy:** Accurate. 12-service table is correct. `generate_secrets.sh` bootstrap path
is correct. Alembic `upgrade head` step is present and correctly positioned. Security
battery step references `test_security_battery.py` (96 tests — verify count before video).
Service list shows 11 items in the table (rows 1–11) with note that MailHog is dev-only:
correct for production.
**Video potential:** HIGH. Recommended as the "stand up your own instance" video for
YouTube. Segment into Part 1 (clone/secrets/env) and Part 2 (start/verify/migrate).

---

### 3. Windows Installation Guide
**File:** `docs/Operation Documents/INSTALLATION_GUIDE_WINDOWS.md`
**Audience:** Windows developers running ClawFilters locally via Docker Desktop
**What it covers:** Windows-specific path through Docker Desktop installation, Git Bash
setup, WSL2 requirements, secrets generation on Windows, and first `docker compose up`.
**Accuracy:** Accurate against current setup.
**Video potential:** MEDIUM. Useful for the Windows developer segment. Could be a short
companion to the Deployment Guide (5–8 min). README-worthy as a collapsible section.

---

### 4. User Guide
**File:** `docs/Operation Documents/USER_GUIDE.md`
**Audience:** Day-to-day operators and end users (non-admin)
**What it covers:** Running stack overview (11 services in production), first-run
sequence, admin dashboard (7 tabs), user console (5 tabs), three authentication methods
(API key / JWT / DID), user roles (viewer → operator → manager → admin → security),
first API calls, agent types (ground level / mezzanine / upper floor).
**Accuracy:** Accurate. 11-container production count correct (MailHog excluded). Dashboard
tab list matches current frontend. Auth method descriptions match current API.
**Video potential:** MEDIUM. Good orientation video for operators who are not deploying.
Pairs well with the Dashboard Registration guide. Recommend as a "ClawFilters Tour" video.

---

### 5. OpenClaw Integration Guide
**File:** `docs/Operation Documents/OPENCLAW_INTEGRATION_GUIDE.md`
**Audience:** Developers integrating an OpenClaw agent with ClawFilters governance
**What it covers:** What OpenClaw is and why it needs governance, enabling
`OPENCLAW_ENABLED=true`, the 8-step governance pipeline as it applies to OpenClaw,
wrapping pattern (ClawFilters wraps OpenClaw, never modifies it), trust level permissions
table, configuration reference.
**Accuracy:** Accurate. Pipeline description matches `core/openclaw.py`. Trust level
permissions table aligns with codebase behavior. 8-step order (registered → suspended →
trust level → manners → anomaly → egress → approval → audit) is correct.
**Video potential:** HIGH. The conceptual "why" video for OpenClaw users. Explains the
governance wrapper pattern. Recommended as a standalone concept explainer (8–10 min)
targeting developers building on or operating OpenClaw agents.

---

### 6. OpenClaw Operations Guide
**File:** `docs/Operation Documents/OPENCLAW_OPERATIONS.md`
**Audience:** Operators managing OpenClaw instances day-to-day
**What it covers:** Full governance lifecycle via API: enable integration → register a
claw → submit actions for governance evaluation → promote/demote trust levels → kill
switch (suspend/reinstate) → monitoring (list, get, action history, trust report) → live
test workflow (10 steps with expected responses) → configuration reference → audit trail
queries.
**Accuracy:** Clean. All endpoints verified. Expected responses (allowed/gated/blocked
with correct fields) match current API implementation. The 10-step live test workflow is
executable against the current build. Manners auto-demotion threshold and behavior described
correctly.
**Video potential:** HIGH. The most complete hands-on operations demo available. The 10-step
test workflow is the backbone of a "full governance cycle" video. Recommended as Video 2
(after Your First Agent). Runtime estimate: 12–18 minutes.

---

### 7. Dashboard Agent Registration Guide
**File:** `docs/Operation Documents/DASHBOARD_agent_registration.md`
**Audience:** Operators who prefer the dashboard UI over curl commands
**What it covers:** Step-by-step walkthrough of registering an agent through the admin
dashboard UI, testing it, and verifying governance decisions from the interface.
**Accuracy:** Minor omission: Step 5 Test 1 does not include the nonce field in the
request example. Functionally the step works (nonce is optional in the dashboard) but the
output shown may differ if nonce is absent. No code changes needed — note this in the
video narration.
**Video potential:** MEDIUM. Good complement to the curl-based guides for non-technical
operators. Screen recording of the actual dashboard. 5–8 minutes.

---

### 8. Troubleshooting Guide
**File:** `docs/Operation Documents/TROUBLESHOOTING.md`
**Audience:** Anyone operating ClawFilters who hits an error
**What it covers:** 14 common failure scenarios with diagnosis and fix commands: Docker
daemon not starting (Win/Linux/macOS), ValidationError on startup, 401/403 auth failures,
Redis connection errors, port conflicts, test failures, federation SSL issues, anomaly
false positives, egress gateway blocks, dashboard not loading, module import errors, venv
issues, network/firewall issues, SSL/TLS certificate issues.
**Accuracy:** Mostly accurate. Minor note: several commands use `docker-compose` (v1
hyphenated syntax) while the rest of the project uses `docker compose` (v2 space syntax).
Both work if Docker Compose v2 is installed, but consistency would be cleaner. Not a
correctness issue — just a style inconsistency to address if doing a video.
**Video potential:** LOW as a video. High value as a reference doc and README link. Good
pinned resource for GitHub issues triage.

---

### 9. Telegram Integration Guide
**File:** `docs/Operation Documents/TELEGRAM_GUIDE.md`
**Audience:** Operators who want real-time governance alerts via Telegram
**What it covers:** Setting up the Telegram bot, configuring ClawFilters to push governance
events (agent promotions, suspensions, kill switch activations, anomaly alerts) to a
Telegram channel.
**Accuracy:** **VERSION ERROR — needs fix before video.** The guide states "v11.1.0+" as
the minimum version. Current version is v11.0.3. This is incorrect. Fix: replace
"v11.1.0+" with "v11.0.3+".
**Video potential:** LOW. Niche integration. Useful as a written guide and README footnote.
Not a priority video.

---

### 10. Restore and Recover Guide
**File:** `docs/Backup and Recovery Documents/Restore_and_Recover_Guide.md`
**Audience:** Administrators recovering from a data corruption or failed deploy
**What it covers:** Docker named volume architecture (what persists, what doesn't), 6
volumes targeted by the backup agent (n8n_data legacy note included, Ollama, open-webui,
Redis, Traefik, Mosquitto), the 6-step restore procedure (down → identify → target volume
→ obliterate old data → extract backup → restart), and resilience considerations (fire
drills, off-host backups, Drobo NAS reference, backup frequency tuning).
**Accuracy:** Accurate. The n8n legacy note is correctly handled with a prominent callout
("n8n removed at v8.0.2, replaced by MCP gateway — procedure applies to any volume").
Volume naming convention (`ClawFilters_[volume_name]`) is correct. The alpine container
restore pattern is the right approach.
**Video potential:** MEDIUM. A "how to recover from a broken deploy" video has real utility
for self-hosters. 8–12 minutes. Recommend pairing with BACKUP_RECOVERY.md content.

---

### 11. Demo Walkthrough (Step-by-Step)
**File:** `docs/DEMO_WALKTHROUGH_step_by_step.md`
**Audience:** Internal — video production reference for recording the live demo
**What it covers:** 9-scene recording script with exact commands, expected terminal output,
nonce tracker, and narration cues for a complete governance demonstration from cold start
to audit chain export.
**Accuracy:** **VERSION ERROR — needs fix before recording.** Scene 4 health check
response shows version `"10.0.0Bminus"`. Must be updated to `"11.0.3"` before using this
as a recording guide.
**Video potential:** This IS the video production script. Fix the version string before
recording. Not a public-facing doc — keep internal.

---

## Part 2 — FAQ and Reference Documents

These are not step-by-step guides but are high-value reference material for both the
README and video supplemental links.

---

### 12. FAQ
**File:** `docs/FAQ.md`
**Audience:** Evaluators, technical reviewers, skeptics
**What it covers:** 23 questions with cited source files and verification commands.
Covers agent registration, inter-agent communication, tool access, blocked actions,
operator access, inbound comms governance, audit chain failure handling, token tracking,
security attack response, MCP compatibility, mobile app compatibility, external AI provider
data sharing, HIPAA/SOC 2/HITRUST status, pen test status, maintainer credibility, scale,
model support, license, performance, 8-step pipeline, Manners system, and trust promotion.
**Accuracy:** Anchor IDs in the table of contents still use `telsonbase` slug format
(e.g., `#8-can-telsonbase-track-token-usage`). The display text is correct ("ClawFilters").
Markdown anchor resolution depends on heading text — if headings were updated to ClawFilters,
TOC links may be broken. Verify link resolution before publishing.
**Video potential:** Not a video. Excellent README resource and GitHub Discussions pinned
post. Quote selected Q&A answers in video narration for credibility.

---

### 13. API Reference
**File:** `docs/System Documents/API_REFERENCE.md`
**Audience:** Developers integrating directly with the REST API
**What it covers:** Full endpoint documentation.
**Video potential:** Reference only. Link in README as "Full API Reference."

---

### 14. Agent Autonomy SLA
**File:** `docs/System Documents/AGENT_AUTONOMY_SLA.md`
**Audience:** Governance architects, compliance officers, researchers
**What it covers:** Formal 5-tier SLA specification with OversightLevel metric, autonomy
ceiling per tier, escalation paths, SLA commitments, and arXiv:2511.02885 citation.
**Accuracy:** Verified in prior session (March 25, 2026). 5-principle behavioral scoring
confirmed (not 8). Section numbering corrected.
**Video potential:** LOW as a video. HIGH value as a document to circulate to the outreach
list. Link from README.

---

### 15. Manners Engine Reference
**File:** `docs/System Documents/MANNERS.md`
**Audience:** Developers and compliance officers understanding behavioral scoring
**What it covers:** 5-principle Manners compliance system (HUMAN_CONTROL, TRANSPARENCY,
VALUE_ALIGNMENT, PRIVACY, SECURITY), scoring bands, auto-demotion logic.
**Video potential:** LOW standalone. Key content to reference during the OpenClaw
Operations video.

---

### 16. Toolroom Trust Matrix
**File:** `docs/System Documents/TOOLROOM_TRUST_MATRIX.md`
**Audience:** Architects and operators configuring tool permissions
**What it covers:** Which trust levels can access which tools, tool categories, capability
declarations.
**Video potential:** LOW standalone. Reference image/table for YouTube annotation during
the OpenClaw Operations video.

---

### 17. Security Architecture
**File:** `docs/System Documents/SECURITY_ARCHITECTURE.md`
**Audience:** Security reviewers and compliance teams
**What it covers:** Layered security architecture, threat model, defense-in-depth controls.
**Video potential:** LOW. Reference doc for pen test prep and compliance questionnaires.

---

### 18. Environment Configuration Reference
**File:** `docs/System Documents/ENV_CONFIGURATION.md`
**Audience:** Operators configuring deployments
**What it covers:** All `.env` variables with descriptions, types, and defaults.
**Video potential:** LOW. Reference material, not a walkthrough.

---

### 19. Secrets Management
**File:** `docs/System Documents/SECRETS_MANAGEMENT.md`
**Audience:** Security-conscious operators
**What it covers:** Secret file structure, permissions (644), what each secret controls,
rotation procedures.
**Video potential:** LOW. Short segment in the Deployment Guide video.

---

### 20. High Availability Architecture
**File:** `docs/System Documents/HA_ARCHITECTURE.md`
**Audience:** Enterprise operators planning multi-node deployments
**What it covers:** Scaling beyond a single machine, load balancing, database replication.
**Video potential:** LOW (current v11.0.3 is single-host). Future video when HA is
production-tested.

---

## Part 3 — Compliance and Specialized Documents

Not step-by-step guides. Relevant for compliance reviewers and the outreach list.

| Document | Path | Notes |
|---|---|---|
| Healthcare Compliance | `docs/Compliance Documents/HEALTHCARE_COMPLIANCE.md` | HIPAA + HITRUST coverage |
| Legal Compliance | `docs/Compliance Documents/LEGAL_COMPLIANCE.md` | GDPR, data processing |
| Manners Compliance | `docs/Compliance Documents/MANNERS_COMPLIANCE.md` | Behavioral scoring framework |
| Pentest Preparation | `docs/Compliance Documents/PENTEST_PREPARATION.md` | 162 endpoints, Bandit 0 HIGH |
| Compliance Roadmap | `docs/Compliance Documents/COMPLIANCE_ROADMAP.md` | Path to formal certification |
| QMS Specification | `docs/QMS Documents/QMS_SPECIFICATION.md` | Quality management system spec |
| SOC 2 Type I | `docs/System Documents/SOC2_TYPE_I.md` | SOC 2 readiness documentation |
| Audit Trail | `docs/System Documents/AUDIT_TRAIL.md` | Cryptographic audit chain spec |
| Encryption at Rest | `docs/System Documents/ENCRYPTION_AT_REST.md` | AES-256-GCM implementation |
| Data Processing Agreement | `docs/System Documents/DATA_PROCESSING_AGREEMENT.md` | DPA template |

---

## Part 4 — Backup and Recovery Reference

| Document | Path | Notes |
|---|---|---|
| Backup Recovery Overview | `docs/Backup and Recovery Documents/BACKUP_RECOVERY.md` | Automated backup agent |
| Disaster Recovery | `docs/Backup and Recovery Documents/DISASTER_RECOVERY.md` | Full DR plan |
| Incident Response | `docs/Backup and Recovery Documents/INCIDENT_RESPONSE.md` | Security incident playbook |
| Restore and Recover Guide | `docs/Backup and Recovery Documents/Restore_and_Recover_Guide.md` | Step-by-step (see Part 1 #10) |

---

## Part 5 — Accuracy Issues Requiring Fixes

Two guides have version errors that must be corrected before recording videos.

| Guide | Issue | Fix |
|---|---|---|
| `TELEGRAM_GUIDE.md` | States "v11.1.0+" as minimum version | Change to "v11.0.3+" |
| `DEMO_WALKTHROUGH_step_by_step.md` | Scene 4 health response shows version "10.0.0Bminus" | Update to "11.0.3" |

One minor style inconsistency (not a blocker):

| Guide | Issue |
|---|---|
| `TROUBLESHOOTING.md` | Mix of `docker-compose` (v1) and `docker compose` (v2) syntax |

---

## Recommended Video Production Order

| # | Video | Source Guide | Estimated Runtime | Priority |
|---|---|---|---|---|
| 1 | Your First Agent — Zero to Governed in 15 Minutes | YOUR_FIRST_AGENT.md | 12–15 min | README + YouTube |
| 2 | Full Governance Cycle — OpenClaw Operations | OPENCLAW_OPERATIONS.md | 15–18 min | YouTube |
| 3 | Deploying ClawFilters — Server Setup | DEPLOYMENT_GUIDE.md | 20–25 min (2-part) | YouTube |
| 4 | ClawFilters Tour — Dashboard and User Console | USER_GUIDE.md + DASHBOARD_agent_registration.md | 8–12 min | YouTube |
| 5 | Integrating OpenClaw — The Governance Wrapper | OPENCLAW_INTEGRATION_GUIDE.md | 8–10 min | YouTube |
| 6 | Disaster Recovery — Backup and Restore | Restore_and_Recover_Guide.md | 8–12 min | YouTube |
| 7 | Windows Local Setup | INSTALLATION_GUIDE_WINDOWS.md | 5–8 min | YouTube |

---

*ClawFilters v11.0.3 · Quietfire AI · March 2026*

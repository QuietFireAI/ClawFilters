# TB-PROOF-014: 143 RBAC-Protected Endpoints

**Sheet ID:** TB-PROOF-014
**Claim Source:** clawcoat.com - Hero Section, Capabilities Section
**Status:** VERIFIED
**Test Coverage:** VERIFIED -- TestRBACEndpointCount -- require_permission count >= 140 verified by source introspection test
**Last Verified:** March 25, 2026
**Version:** v11.0.3

---

## Exact Claim

> "143 API endpoints enforced with role-based access control. Four-tier permission taxonomy: view, manage, admin, security."

## Verdict

VERIFIED - 143 endpoints use `Depends(require_permission(...))` across 7 files. Four-tier permission taxonomy confirmed.

Note: `api/openclaw_routes.py` and `api/mcp_gateway.py` use `authenticate_request` directly (trust-tier gating), not `require_permission`. They are auth-required but not RBAC-permission-gated. `core/auth.py` contains a docstring usage example that is not an actual route and is excluded from the count.

## Evidence

### Source Files
| File | RBAC Endpoints | What It Proves |
|---|---|---|
| `main.py` | 65 | Core API RBAC |
| `api/compliance_routes.py` | 39 | Compliance endpoints |
| `api/security_routes.py` | 19 | Security endpoints |
| `api/tenancy_routes.py` | 11 | Tenancy endpoints |
| `api/identiclaw_routes.py` | 6 | Identity endpoints |
| `core/tenant_rate_limiting.py` | 2 | Rate limit endpoints |
| `api/auth_routes.py` | 1 | Admin user listing |
| `api/mcp_gateway.py` | 0 | MCP gateway (trust-tier gated, not RBAC) |
| `api/openclaw_routes.py` | 0 | OpenClaw governance (authenticate_request) |
| **Total** | **143** | |

### Permission Taxonomy

| Tier | Permission Prefix | Example | Who Has It |
|---|---|---|---|
| View | `view:` | `view:agents`, `view:audit`, `view:dashboard` | All authenticated users |
| Manage | `manage:` | `manage:agents`, `manage:federation` | Operators and above |
| Admin | `admin:` | `admin:config`, `admin` | Admins only |
| Security | `security:` | `security:audit`, `security:override` | Security officers only |
| Action | `action:` | `action:approve`, `action:resolve_anomaly` | Role-dependent |

### Code Evidence

```python
# Example from main.py:
@app.get("/v1/agents", ...)
async def list_agents(
    auth: AuthResult = Depends(authenticate_request),
    _perm=Depends(require_permission("view:agents"))
):
```

## Verification Command

```bash
docker compose exec mcp_server python -m pytest \
  tests/test_depth_infrastructure.py::TestRBACEndpointCount -v --tb=short
```

## Expected Result

```
2 passed
```
Total: 143

---

*Sheet TB-PROOF-014 | ClawCoat v11.0.3 | March 25, 2026*

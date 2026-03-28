# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# ClawFilters/api/__init__.py
# REM: API module exports
# REM: n8n_integration removed Feb 24 2026 — replaced by native Goose/MCP at /mcp

from api.compliance_routes import router as compliance_router
from api.security_routes import router as security_router
from api.tenancy_routes import router as tenancy_router

__all__ = ["security_router", "compliance_router", "tenancy_router"]

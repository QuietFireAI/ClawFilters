# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# TelsonBase/core/hitrust.py
# REM: Alias module — routes import from core.hitrust, actual impl is core.hitrust_controls
# REM: v7.2.0CC: Created to resolve module naming mismatch
from core.hitrust_controls import HITRUSTManager, hitrust_manager

__all__ = ["hitrust_manager", "HITRUSTManager"]

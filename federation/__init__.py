# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# ClawFilters/federation/__init__.py
# REM: Federation module exports - cross-instance trust and communication

from federation.trust import (
    FederationManager,
    TrustRelationship,
    TrustStatus,
    TrustLevel,
    InstanceIdentity,
    FederatedMessage
)

# SPDX-FileCopyrightText: 2026 Quietfire AI / Jeff Phillips
# SPDX-License-Identifier: Apache-2.0
# TelsonBase/api/telegram_routes.py
# REM: =======================================================================================
# REM: TELEGRAM WEBHOOK ENDPOINT
# REM: =======================================================================================
# REM: Receives incoming updates from Telegram when webhook mode is configured.
# REM: In polling mode this route is registered but never called by Telegram.
# REM: v11.1.0CC: Initial implementation
# REM: =======================================================================================

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, status

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/telegram", tags=["telegram"])


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def telegram_webhook(request: Request):
    """
    REM: Telegram webhook endpoint — receives updates when TELEGRAM_WEBHOOK_URL is set.
    REM: Telegram requires a 200 response quickly; processing is synchronous but fast.
    """
    from core.telegram_gateway import telegram_gateway

    if not telegram_gateway.enabled:
        raise HTTPException(status_code=404, detail="Telegram gateway not enabled")

    # REM: SECURITY — verify Telegram's secret token header before processing.
    # REM: Without this, a forged POST could approve a HITL gate. Fails closed.
    secret_header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not telegram_gateway.verify_webhook_secret(secret_header):
        raise HTTPException(status_code=403, detail="Invalid webhook secret")

    try:
        update: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    try:
        telegram_gateway.handle_update(update)
    except Exception as e:
        logger.error(f"REM: Telegram webhook handler error: {e}")
        # REM: Still return 200 — Telegram will retry on non-200, causing duplicate processing

    return {"ok": True}

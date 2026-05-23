import asyncio
import logging

from config import get_settings
from fastapi import APIRouter, HTTPException, Query, Request
from models.alert import (
    AlertConfig,
    AlertConfigUpdate,
    AlertHistoryResponse,
    AlertRecord,
    TestAlertResponse,
)
from services.alert_engine import get_alert_engine
from services.email_service import get_email
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
log = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
_SENSITIVE = get_settings().ratelimit_sensitive


@router.get("/config", response_model=AlertConfig)
async def get_config() -> AlertConfig:
    return await get_alert_engine().get_config()


@router.put("/config", response_model=AlertConfig)
async def update_config(patch: AlertConfigUpdate) -> AlertConfig:
    engine = get_alert_engine()
    current = await engine.get_config()
    data = current.model_dump()
    update = patch.model_dump(exclude_none=True)
    data.update(update)
    cfg = AlertConfig.model_validate(data)
    return await engine.save_config(cfg)


@router.post("/test", response_model=TestAlertResponse)
@limiter.limit(_SENSITIVE)
async def send_test_alert(request: Request) -> TestAlertResponse:
    cfg = await get_alert_engine().get_config()
    if not cfg.recipients:
        raise HTTPException(status_code=400, detail="no recipients configured")
    try:
        await asyncio.to_thread(get_email().send_test, cfg.recipients)
    except Exception as exc:
        log.exception("test alert failed")
        raise HTTPException(status_code=502, detail=f"smtp error: {exc}")
    return TestAlertResponse(
        sent=True,
        recipients=cfg.recipients,
        message="Test alert dispatched",
    )


@router.get("/history", response_model=AlertHistoryResponse)
async def alert_history(limit: int = Query(100, ge=1, le=1000)) -> AlertHistoryResponse:
    total, items = await get_alert_engine().history(limit=limit)
    return AlertHistoryResponse(total=total, items=items)


@router.post("/evaluate", response_model=AlertRecord | None, include_in_schema=False)
async def evaluate_event(ctx: dict) -> AlertRecord | None:
    """Internal hook: ETL/forensic-engine posts enriched events here."""
    return await get_alert_engine().evaluate_event(ctx)

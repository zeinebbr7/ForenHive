"""
alerts.py — Alertes & notifications
Rôle : config et historique des alertes (email/SMS/WhatsApp via Twilio).
URL    : /api/alerts/*
Deps   : services.alert_engine, Twilio, SMTP.
Auth   : Bearer token (forenhive.token) requis (sauf chat public).
Codes  : 200 OK | 401 non auth | 403 interdit | 404 absent | 422 valid | 500 engine.
"""

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


@router.post("/resend/{alert_id}", response_model=dict)
async def resend_alert(alert_id: str) -> dict:
    """Re-dispatch email for an alert that is still pending (dispatched=false)."""
    es = get_alert_engine()
    from services.elasticsearch import get_es
    doc = await get_es().get_doc("forenhive-alerts", alert_id)
    if not doc:
        raise HTTPException(status_code=404, detail="alert not found")
    try:
        record = AlertRecord.model_validate(doc)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid alert record: {exc}")

    cfg = await es.get_config()
    recipients = record.recipients or cfg.recipients
    if not recipients:
        raise HTTPException(status_code=400, detail="no recipients configured")

    subject = (
        f"[FORENHIVE] INSIDER THREAT — {record.source_ip}"
        if record.is_internal
        else f"[FORENHIVE] {record.severity.upper()} — {record.source_ip} (score {record.risk_score}/100)"
    )
    ctx = {
        "is_test": False,
        "severity": record.severity.upper(),
        "threat_type": record.threat_type,
        "source_ip": record.source_ip,
        "country": record.country,
        "risk_score": record.risk_score,
        "attempts": record.attempts,
        "mitre_tags": record.mitre_tags,
        "honeypot": record.honeypot,
        "yara_match": record.yara_match,
        "abuseipdb_score": record.abuseipdb_score,
        "ioc_hash": record.ioc_hash or "",
        "tsa_timestamp": record.tsa_timestamp or "",
        "mistral_analysis": record.mistral_analysis,
        "timestamp": record.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if record.timestamp else "",
        "is_internal": record.is_internal,
        "network_class": record.network_class or "",
    }
    try:
        await asyncio.to_thread(get_email().send_alert, recipients, subject, ctx)
    except Exception as exc:
        log.exception("resend failed for %s", alert_id)
        raise HTTPException(status_code=502, detail=f"smtp error: {exc}")

    # Mark as dispatched in ES
    await get_es().index_doc(
        "forenhive-alerts",
        alert_id,
        {**doc, "dispatched": True, "dispatch_error": None},
    )
    log.info("alert %s resent to %d recipient(s)", alert_id, len(recipients))
    return {"resent": True, "recipients": recipients}


@router.post("/resend-pending", response_model=dict)
async def resend_pending_alerts() -> dict:
    """Re-dispatch email for ALL alerts that are still pending (dispatched=false)."""
    from services.elasticsearch import get_es
    es_svc = get_es()
    resp = await es_svc.client.search(
        index="forenhive-alerts",
        body={"size": 200, "query": {"term": {"dispatched": False}}, "sort": [{"timestamp": "desc"}]},
        ignore_unavailable=True,
    )
    hits = resp["hits"]["hits"]
    if not hits:
        return {"resent": 0, "message": "no pending alerts"}

    cfg = await get_alert_engine().get_config()
    sent, failed = 0, 0
    for h in hits:
        alert_id = h["_id"]
        doc = h["_source"]
        try:
            record = AlertRecord.model_validate(doc)
            recipients = record.recipients or cfg.recipients
            if not recipients:
                continue
            subject = (
                f"[FORENHIVE] INSIDER THREAT — {record.source_ip}"
                if record.is_internal
                else f"[FORENHIVE] {record.severity.upper()} — {record.source_ip} (score {record.risk_score}/100)"
            )
            ctx = {
                "is_test": False,
                "severity": record.severity.upper(),
                "threat_type": record.threat_type,
                "source_ip": record.source_ip,
                "country": record.country,
                "risk_score": record.risk_score,
                "attempts": record.attempts,
                "mitre_tags": record.mitre_tags,
                "honeypot": record.honeypot,
                "yara_match": record.yara_match,
                "abuseipdb_score": record.abuseipdb_score,
                "ioc_hash": record.ioc_hash or "",
                "tsa_timestamp": record.tsa_timestamp or "",
                "mistral_analysis": record.mistral_analysis,
                "timestamp": record.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if record.timestamp else "",
                "is_internal": record.is_internal,
                "network_class": record.network_class or "",
            }
            await asyncio.to_thread(get_email().send_alert, recipients, subject, ctx)
            await es_svc.index_doc("forenhive-alerts", alert_id, {**doc, "dispatched": True, "dispatch_error": None})
            sent += 1
        except Exception as exc:
            log.warning("resend failed for alert %s: %s", alert_id, exc)
            failed += 1

    return {"resent": sent, "failed": failed}


@router.post("/resend-by-score", response_model=dict)
async def resend_by_score(min_score: int = Query(60, ge=0, le=100)) -> dict:
    """Re-dispatch email + WhatsApp for all IPs with risk_score >= min_score from suspect-profiles."""
    import uuid
    from datetime import UTC, datetime

    from models.alert import AlertRecord
    from services.elasticsearch import get_es

    es_svc = get_es()
    score_query = {"size": 200, "query": {"range": {"risk_score": {"gte": min_score}}}, "sort": [{"risk_score": "desc"}]}

    try:
        prof_resp = await es_svc.client.search(index="forenhive-suspect-profiles", body=score_query, ignore_unavailable=True)
        alert_resp = await es_svc.client.search(index="forenhive-alerts", body=score_query, ignore_unavailable=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"elasticsearch error: {exc}")

    engine = get_alert_engine()
    cfg = await engine.get_config()
    sent, failed = 0, 0

    # Build AlertRecords from suspect-profiles (primary source of the 13 IPs)
    for h in prof_resp["hits"]["hits"]:
        src = h["_source"]
        ip = src.get("source_ip", "unknown")
        score = int(src.get("risk_score", 0))
        mitre = [t if isinstance(t, str) else (t.get("id") or "") for t in (src.get("mitre_techniques") or [])]
        severity = "critical" if score >= 70 else "high" if score >= 60 else "medium"
        record = AlertRecord(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            severity=severity,
            threat_type=src.get("primary_objective") or "suspicious_activity",
            source_ip=ip,
            country=None,
            honeypot=None,
            risk_score=score,
            attempts=0,
            mitre_tags=[t for t in mitre if t],
            yara_match=None,
            abuseipdb_score=None,
            ioc_hash=None,
            tsa_timestamp=None,
            mistral_analysis=src.get("detective_narrative"),
            is_internal=False,
            network_class="",
            recipients=cfg.recipients,
            dispatched=False,
        )
        try:
            dispatched, err = await engine._dispatch(record)
            record.dispatched = dispatched
            record.dispatch_error = err
            # Save to forenhive-alerts so the platform shows it
            await es_svc.index_doc(
                "forenhive-alerts",
                record.id,
                record.model_dump(mode="json"),
            )
            if dispatched:
                sent += 1
                log.info("resend-by-score dispatched for %s score=%d", ip, score)
            else:
                failed += 1
                log.warning("resend-by-score dispatch failed for %s: %s", ip, err)
        except Exception as exc:
            log.warning("resend-by-score error for %s: %s", ip, exc)
            failed += 1

    # Also resend any existing forenhive-alerts entries with score >= min_score
    for h in alert_resp["hits"]["hits"]:
        alert_id = h["_id"]
        doc = h["_source"]
        try:
            record = AlertRecord.model_validate(doc)
            record.recipients = record.recipients or cfg.recipients
            dispatched, err = await engine._dispatch(record)
            await es_svc.index_doc("forenhive-alerts", alert_id, {**doc, "dispatched": dispatched, "dispatch_error": err})
            if dispatched:
                sent += 1
            else:
                failed += 1
        except Exception as exc:
            log.warning("resend-by-score alert failed for %s: %s", alert_id, exc)
            failed += 1

    log.info("resend-by-score min_score=%d: sent=%d failed=%d", min_score, sent, failed)
    return {"resent": sent, "failed": failed, "min_score": min_score}


@router.post("/evaluate", response_model=AlertRecord | None, include_in_schema=False)
async def evaluate_event(ctx: dict) -> AlertRecord | None:
    """Internal hook: ETL/forensic-engine posts enriched events here."""
    return await get_alert_engine().evaluate_event(ctx)

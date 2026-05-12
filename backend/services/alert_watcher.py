from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from config import get_settings
from services.alert_engine import get_alert_engine
from services.elasticsearch import get_es

log = logging.getLogger(__name__)

WATERMARK_INDEX = "forenhive-config"
WATERMARK_DOC_ID = "alert_watcher_watermark"


class AlertWatcher:
    """Polls honeypot indices for newly ingested events and feeds
    them to the AlertEngine. Uses a persisted watermark so restarts
    don't re-scan already-evaluated events.
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if not self.settings.alert_watcher_enabled:
            log.info("alert watcher disabled by config")
            return
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="alert-watcher")
        log.info("alert watcher started (interval=%ss)", self.settings.alert_watcher_interval_seconds)

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    async def _get_watermark(self) -> str:
        es = get_es()
        doc = await es.get_doc(WATERMARK_INDEX, WATERMARK_DOC_ID)
        if doc and doc.get("watermark_ts"):
            return str(doc["watermark_ts"])
        # First run: start from 5 minutes ago to avoid replaying history.
        return (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    async def _set_watermark(self, iso_ts: str) -> None:
        await get_es().index_doc(
            WATERMARK_INDEX,
            WATERMARK_DOC_ID,
            {"key": "alert_watcher_watermark", "watermark_ts": iso_ts},
        )

    @staticmethod
    def _ctx_from_event(src: Dict[str, Any]) -> Dict[str, Any]:
        # Handle both nested {"source": {"ip": ...}} and dot-notation {"source.ip": ...}
        source_raw = src.get("source") or {}
        source = source_raw if isinstance(source_raw, dict) else {}
        geo = source.get("geo") or src.get("source.geo") or {}
        if not isinstance(geo, dict):
            geo = {}
        asn = source.get("as") or src.get("source.as") or {}
        if not isinstance(asn, dict):
            asn = {}
        ua_raw = src.get("user_agent") or {}
        user_agent = (ua_raw.get("original") if isinstance(ua_raw, dict) else None) or src.get("user_agent.original")
        http_raw = src.get("http") or {}
        http = http_raw if isinstance(http_raw, dict) else {}
        url_raw = src.get("url") or {}
        url = url_raw if isinstance(url_raw, dict) else {}

        # honeypot: handle {"honeypot": {"type": "cowrie"}} and {"honeypot.type": "cowrie"}
        hp_raw = src.get("honeypot")
        honeypot = (hp_raw.get("type") if isinstance(hp_raw, dict) else hp_raw) or src.get("honeypot.type")

        # eventid: handle nested event.id and flat eventid
        ev_raw = src.get("event") or {}
        eventid = src.get("eventid") or src.get("event.id") or (ev_raw.get("id") if isinstance(ev_raw, dict) else None) or ""

        return {
            "source_ip": source.get("ip") or src.get("source.ip") or src.get("src_ip"),
            "severity": src.get("severity"),
            "honeypot": honeypot,
            "threat_type": eventid or (ev_raw.get("type") if isinstance(ev_raw, dict) else None),
            "failed_auth_count": 1 if eventid == "cowrie.login.failed" else 0,
            "is_tor": bool(src.get("is_tor")),
            "is_vpn": bool(src.get("is_vpn")),
            "abuseipdb_score": src.get("abuseipdb_score"),
            "yara_match": src.get("yara_match"),
            "mitre_techniques": [
                t.get("id") for t in (src.get("mitre") or {}).get("technique", [])
                if isinstance(t, dict) and t.get("id")
            ] if isinstance(src.get("mitre"), dict) else [],
            "country": geo.get("country_name"),
            "country_iso": geo.get("country_iso_code"),
            "asn": asn.get("number") if isinstance(asn, dict) else None,
            "as_org": asn.get("organization", {}).get("name") if isinstance(asn, dict) and isinstance(asn.get("organization"), dict) else None,
            "commands": [src["input"]] if src.get("input") else [],
            "http_path": url.get("path") or src.get("url.path") or http.get("path"),
            "user_agent": user_agent,
            "download_attempt": eventid.startswith("cowrie.session.file"),
            "hour_of_day": datetime.now(timezone.utc).hour,
            "raw": src,
        }

    async def _poll_once(self) -> None:
        es = get_es()
        watermark = await self._get_watermark()
        body = {
            "size": 200,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gt": watermark}}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        try:
            resp = await es.client.search(
                index=self.settings.honeypot_indices,
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
            )
        except Exception as exc:
            log.warning("watcher search failed: %s", exc)
            return

        hits = resp["hits"]["hits"]
        if not hits:
            return

        engine = get_alert_engine()
        last_ts = watermark
        for h in hits:
            src = h["_source"]
            ctx = self._ctx_from_event(src)
            try:
                await engine.evaluate_event(ctx)
            except Exception as exc:
                log.warning("alert evaluation error for %s: %s", h.get("_id"), exc)
            ts = src.get("@timestamp")
            if ts:
                last_ts = str(ts)

        if last_ts and last_ts != watermark:
            await self._set_watermark(last_ts)

    async def _loop(self) -> None:
        interval = max(5, self.settings.alert_watcher_interval_seconds)
        while not self._stop.is_set():
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.exception("watcher loop error: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue


_watcher: Optional[AlertWatcher] = None


def get_watcher() -> AlertWatcher:
    global _watcher
    if _watcher is None:
        _watcher = AlertWatcher()
    return _watcher

from __future__ import annotations

import asyncio
import logging
import math
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select

from config import get_settings
from db import session_scope
from models.alert import AlertConfig, AlertRecord, AlertTrigger
from models_sql.user import User
from services.chain_custody import get_custody
from services.elasticsearch import get_es
from services.email_service import get_email
from services.ollama_service import get_ollama

log = logging.getLogger(__name__)

CONFIG_INDEX = "forenhive-config"
CONFIG_DOC_ID = "alert_config"

# High-risk geos (example list, tunable)
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "RU", "CN", "BY"}

# Simple C2/exploit indicators (kept small and auditable)
C2_IOC_KEYWORDS = {"/c2", "/cnc", "cobaltstrike", "metasploit", "empire", "/gate.php"}
EXPLOIT_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
LATERAL_RE = re.compile(r"\b(psexec|wmic|at\s+\\\\|smbexec|net\s+use)\b", re.IGNORECASE)
PRIV_ESC_RE = re.compile(r"\b(sudo|su\s+-|setuid|/etc/shadow|runas)\b", re.IGNORECASE)
PORT_SCAN_PATTERN_MIN_DEST_PORTS = 5


class RiskScorer:
    """Implements the 18-signal risk score (0-100)."""

    SIGNALS = [
        "failed_auth_count",
        "known_tor_exit",
        "abuseipdb_score",
        "yara_match",
        "mitre_technique_count",
        "geo_risk",
        "new_ip",
        "payload_entropy",
        "brute_force_pattern",
        "c2_ioc_match",
        "port_scan_pattern",
        "exploit_cve_match",
        "time_of_day_anomaly",
        "session_duration",
        "command_count",
        "download_attempt",
        "privilege_escalation",
        "lateral_movement",
    ]

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @classmethod
    def score(cls, ctx: Dict[str, Any]) -> Tuple[int, Dict[str, int]]:
        breakdown: Dict[str, int] = {k: 0 for k in cls.SIGNALS}

        fa = int(ctx.get("failed_auth_count", 0))
        breakdown["failed_auth_count"] = min(10, fa // 3)

        if ctx.get("is_tor"):
            breakdown["known_tor_exit"] = 10

        abuse = ctx.get("abuseipdb_score")
        if isinstance(abuse, (int, float)):
            breakdown["abuseipdb_score"] = min(10, int(abuse) // 10)

        if ctx.get("yara_match"):
            breakdown["yara_match"] = 10

        mitre_count = len(ctx.get("mitre_techniques") or [])
        breakdown["mitre_technique_count"] = min(8, mitre_count * 2)

        country = (ctx.get("country_iso") or "").upper()
        if country in HIGH_RISK_COUNTRIES:
            breakdown["geo_risk"] = 6

        if ctx.get("new_ip"):
            breakdown["new_ip"] = 3

        payload = ctx.get("payload") or ""
        entropy = cls._shannon_entropy(str(payload))
        if entropy >= 7.0:
            breakdown["payload_entropy"] = 5
        elif entropy >= 5.5:
            breakdown["payload_entropy"] = 2

        if fa >= 20:
            breakdown["brute_force_pattern"] = 8
        elif fa >= 8:
            breakdown["brute_force_pattern"] = 4

        combined_text = " ".join(
            str(x) for x in (ctx.get("commands") or []) + [ctx.get("http_path") or ""]
        ).lower()
        if any(k in combined_text for k in C2_IOC_KEYWORDS):
            breakdown["c2_ioc_match"] = 8

        if int(ctx.get("unique_dest_ports", 0)) >= PORT_SCAN_PATTERN_MIN_DEST_PORTS:
            breakdown["port_scan_pattern"] = 6

        if EXPLOIT_CVE_RE.search(combined_text):
            breakdown["exploit_cve_match"] = 7

        hour = ctx.get("hour_of_day")
        if isinstance(hour, int) and (hour < 5 or hour >= 22):
            breakdown["time_of_day_anomaly"] = 2

        dur = float(ctx.get("session_duration_seconds", 0))
        if dur >= 900:
            breakdown["session_duration"] = 4
        elif dur >= 120:
            breakdown["session_duration"] = 2

        cmd_count = int(ctx.get("command_count", 0))
        breakdown["command_count"] = min(5, cmd_count // 5)

        if ctx.get("download_attempt"):
            breakdown["download_attempt"] = 4

        if PRIV_ESC_RE.search(combined_text):
            breakdown["privilege_escalation"] = 6

        if LATERAL_RE.search(combined_text):
            breakdown["lateral_movement"] = 6

        total = sum(breakdown.values())
        total = max(0, min(100, total))
        return total, breakdown


class AlertEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._recent_alerts: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    # ---------- config persistence ----------
    async def _ensure_default_config(self) -> AlertConfig:
        es = get_es()
        doc = await es.get_doc(CONFIG_INDEX, CONFIG_DOC_ID)
        if doc and doc.get("value"):
            return AlertConfig.model_validate(doc["value"])
        cfg = AlertConfig(
            recipients=self.settings.alert_recipients_list or ["soc@example.com"],
            threshold=self.settings.risk_alert_threshold,
            triggers=[AlertTrigger.HIGH_SEVERITY],
            dedup_window_minutes=self.settings.alert_dedup_window_minutes,
            enabled=True,
        )
        await self.save_config(cfg)
        return cfg

    async def get_config(self) -> AlertConfig:
        return await self._ensure_default_config()

    async def save_config(self, cfg: AlertConfig) -> AlertConfig:
        es = get_es()
        await es.index_doc(
            CONFIG_INDEX,
            CONFIG_DOC_ID,
            {"key": "alert_config", "value": cfg.model_dump(mode="json")},
        )
        return cfg

    # ---------- dedup ----------
    def _should_dedup(self, source_ip: str, window_min: int) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=window_min)
        for ip, ts in list(self._recent_alerts.items()):
            if ts < cutoff:
                self._recent_alerts.pop(ip, None)
        last = self._recent_alerts.get(source_ip)
        if last and last > cutoff:
            return True
        self._recent_alerts[source_ip] = now
        return False

    # ---------- evaluation + dispatch ----------
    async def evaluate_event(self, ctx: Dict[str, Any]) -> Optional[AlertRecord]:
        async with self._lock:
            cfg = await self.get_config()
            if not cfg.enabled:
                return None

            risk_score, _ = RiskScorer.score(ctx)
            severity = ctx.get("severity") or (
                "critical" if risk_score >= 90 else
                "high" if risk_score >= 75 else
                "medium" if risk_score >= 40 else
                "low"
            )

            triggered = False
            if risk_score >= cfg.threshold:
                triggered = True
            if AlertTrigger.HIGH_SEVERITY in cfg.triggers and severity in ("high", "critical"):
                triggered = True
            if AlertTrigger.BRUTE_FORCE in cfg.triggers and int(ctx.get("failed_auth_count", 0)) >= 20:
                triggered = True
            if AlertTrigger.MALWARE_DETECTED in cfg.triggers and ctx.get("yara_match"):
                triggered = True
            if AlertTrigger.TOR_EXIT in cfg.triggers and ctx.get("is_tor"):
                triggered = True
            if AlertTrigger.C2_MATCH in cfg.triggers:
                blob = " ".join(str(x) for x in (ctx.get("commands") or []) + [ctx.get("http_path") or ""]).lower()
                if any(k in blob for k in C2_IOC_KEYWORDS):
                    triggered = True
            if AlertTrigger.NEW_IP in cfg.triggers and ctx.get("new_ip"):
                triggered = True

            if not triggered:
                return None

            src_ip = ctx.get("source_ip") or "unknown"
            if self._should_dedup(src_ip, cfg.dedup_window_minutes):
                log.info("alert dedup — skipping %s", src_ip)
                return None

            custody = await get_custody().seal(ctx.get("raw") or ctx)

            try:
                mistral = await get_ollama().analyze_profile(
                    {
                        "ip": src_ip,
                        "country": ctx.get("country"),
                        "country_iso": ctx.get("country_iso"),
                        "asn": ctx.get("asn"),
                        "as_org": ctx.get("as_org"),
                        "is_tor": ctx.get("is_tor", False),
                        "is_vpn": ctx.get("is_vpn", False),
                        "abuseipdb_score": ctx.get("abuseipdb_score"),
                        "event_count": ctx.get("event_count", 0),
                        "session_count": ctx.get("session_count", 0),
                        "honeypots": [ctx.get("honeypot")] if ctx.get("honeypot") else [],
                        "top_usernames": ctx.get("top_usernames") or [],
                        "top_commands": ctx.get("commands") or [],
                        "mitre_techniques": ctx.get("mitre_techniques") or [],
                        "yara_matches": [ctx["yara_match"]] if ctx.get("yara_match") else [],
                        "risk_score": risk_score,
                    }
                )
            except Exception as exc:
                log.warning("mistral enrichment failed during alert: %s", exc)
                mistral = None

            record = AlertRecord(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                threat_type=ctx.get("threat_type") or ctx.get("event_type") or "suspicious_activity",
                source_ip=src_ip,
                country=ctx.get("country"),
                honeypot=ctx.get("honeypot"),
                risk_score=risk_score,
                attempts=int(ctx.get("failed_auth_count", 0) or ctx.get("attempts", 0)),
                mitre_tags=list(ctx.get("mitre_techniques") or []),
                yara_match=ctx.get("yara_match"),
                abuseipdb_score=ctx.get("abuseipdb_score"),
                ioc_hash=custody.sha256,
                tsa_timestamp=custody.tsa_token_b64,
                mistral_analysis=mistral,
                recipients=cfg.recipients,
                dispatched=False,
            )

            dispatched, err = await self._dispatch(record)
            record.dispatched = dispatched
            record.dispatch_error = err

            es = get_es()
            await es.index_doc(
                self.settings.es_index_alerts,
                record.id,
                record.model_dump(mode="json"),
            )
            return record

    @staticmethod
    async def _all_user_emails() -> List[str]:
        """Return emails of all active admins and analysts from PostgreSQL."""
        try:
            async with session_scope() as db:
                result = await db.execute(
                    select(User.email).where(User.is_active == True)
                )
                return [row[0] for row in result.all()]
        except Exception as exc:
            log.warning("could not fetch user emails from DB: %s", exc)
            return []

    async def _dispatch(self, record: AlertRecord) -> Tuple[bool, Optional[str]]:
        errors: List[str] = []

        # ── WhatsApp / voice call (Twilio) ──────────────────────────────────
        try:
            from alerts.alert_manager import send_alert as wa_send
            await asyncio.to_thread(wa_send, record.source_ip, record.risk_score)
            log.info("WhatsApp alert dispatched  ip=%s score=%d", record.source_ip, record.risk_score)
        except Exception as exc:
            log.error("WhatsApp dispatch failed: %s", exc)
            errors.append(f"whatsapp: {exc}")

        # ── Email alert with real attack data ───────────────────────────────
        recipients = list(record.recipients or []) or self.settings.alert_recipients_list
        if not recipients:
            recipients = await self._all_user_emails()
        if recipients:
            try:
                ctx = {
                    "is_test":          False,
                    "severity":         (record.severity or "unknown").upper(),
                    "threat_type":      record.threat_type or "suspicious_activity",
                    "source_ip":        record.source_ip,
                    "country":          record.country or "Unknown",
                    "risk_score":       record.risk_score,
                    "attempts":         record.attempts,
                    "mitre_tags":       list(record.mitre_tags or []),
                    "honeypot":         record.honeypot or "unknown",
                    "yara_match":       record.yara_match,
                    "abuseipdb_score":  record.abuseipdb_score,
                    "ioc_hash":         record.ioc_hash or "",
                    "tsa_timestamp":    record.tsa_timestamp or "",
                    "mistral_analysis": record.mistral_analysis or "",
                    "timestamp":        record.timestamp.isoformat() if record.timestamp else "",
                }
                subject = (
                    f"[FORENHIVE ALERT] {ctx['severity']} — "
                    f"{ctx['threat_type']} | {record.source_ip}"
                )
                await asyncio.to_thread(get_email().send_alert, recipients, subject, ctx)
                log.info("Email alert dispatched  ip=%s to=%s", record.source_ip, recipients)
            except Exception as exc:
                log.error("Email dispatch failed: %s", exc)
                errors.append(f"email: {exc}")
        else:
            log.warning("No email recipients configured — email alert skipped for %s", record.source_ip)

        return (not errors), ("; ".join(errors) if errors else None)

    async def history(self, limit: int = 100) -> Tuple[int, List[AlertRecord]]:
        es = get_es()
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "track_total_hits": True,
        }
        try:
            resp = await es.search_docs(self.settings.es_index_alerts, body)
        except Exception:
            return 0, []
        hits = resp["hits"]
        total = hits["total"]["value"] if isinstance(hits["total"], dict) else hits["total"]
        items = [AlertRecord.model_validate(h["_source"]) for h in hits["hits"]]
        return total, items


_svc: Optional[AlertEngine] = None


def get_alert_engine() -> AlertEngine:
    global _svc
    if _svc is None:
        _svc = AlertEngine()
    return _svc

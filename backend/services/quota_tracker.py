"""Async quota tracker backed by the api_quota_status table.

Mirrors forensic-engine/quota_tracker.py so the backend respects the same
exhaustion flags the engine writes (and vice-versa). Without this, the
backend would re-hit AbuseIPDB / IPLocate / VirusTotal every report
generation even when the engine has already marked the API as
quota-exhausted (HTTP 429/403), adding ~15 s per dead call.

Reset policy is identical to the engine: UTC midnight for daily-tier APIs,
1 hour for shodan rate-limits.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from sqlalchemy import text

from db import session_scope

log = logging.getLogger(__name__)


def _next_utc_midnight() -> datetime:
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).date()
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)


_RESET_POLICY = {
    "virustotal":  _next_utc_midnight,
    "abuseipdb":   _next_utc_midnight,
    "iplocate":    _next_utc_midnight,
    "shodan":      lambda: datetime.now(timezone.utc) + timedelta(hours=1),
    "shodan_host": lambda: datetime.now(timezone.utc) + timedelta(hours=1),
}


class QuotaTracker:
    def __init__(self) -> None:
        self._cache: Dict[str, bool] = {}

    async def is_exhausted(self, api: str) -> bool:
        if api in self._cache:
            return self._cache[api]
        try:
            async with session_scope() as db:
                row = (await db.execute(
                    text("SELECT exhausted, reset_at FROM api_quota_status WHERE api_name = :api"),
                    {"api": api},
                )).fetchone()
                if not row:
                    self._cache[api] = False
                    return False
                exhausted, reset_at = row
                if not exhausted:
                    self._cache[api] = False
                    return False
                if reset_at and reset_at <= datetime.now(timezone.utc):
                    log.info("%s: quota reset window passed, clearing flag", api)
                    await db.execute(
                        text(
                            "UPDATE api_quota_status SET exhausted = FALSE, updated_at = NOW() "
                            "WHERE api_name = :api"
                        ),
                        {"api": api},
                    )
                    await db.commit()
                    self._cache[api] = False
                    return False
                self._cache[api] = True
                return True
        except Exception as exc:
            log.warning("QuotaTracker read failed for %s: %s", api, exc)
            self._cache[api] = False
            return False

    async def mark_exhausted(self, api: str, reason: str = "") -> None:
        reset_fn = _RESET_POLICY.get(api, _next_utc_midnight)
        reset_at = reset_fn()
        log.warning(
            "%s: marking quota EXHAUSTED until %s (%s)",
            api, reset_at.isoformat(), reason or "no reason",
        )
        self._cache[api] = True
        try:
            async with session_scope() as db:
                await db.execute(
                    text(
                        """
                        INSERT INTO api_quota_status (api_name, exhausted, reset_at, last_error, updated_at)
                        VALUES (:api, TRUE, :reset_at, :reason, NOW())
                        ON CONFLICT (api_name) DO UPDATE
                            SET exhausted  = TRUE,
                                reset_at   = EXCLUDED.reset_at,
                                last_error = EXCLUDED.last_error,
                                updated_at = NOW()
                        """
                    ),
                    {"api": api, "reset_at": reset_at, "reason": (reason or "")[:500]},
                )
                await db.commit()
        except Exception as exc:
            log.warning("QuotaTracker write failed for %s: %s", api, exc)


_tracker: Optional[QuotaTracker] = None


def get_tracker() -> QuotaTracker:
    global _tracker
    if _tracker is None:
        _tracker = QuotaTracker()
    return _tracker

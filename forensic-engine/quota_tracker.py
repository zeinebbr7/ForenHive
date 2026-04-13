"""
ForenHive Forensic Engine — External API Quota Tracker

Persists daily-quota exhaustion state for external APIs (VirusTotal, AbuseIPDB,
IPLocate, Shodan InternetDB) in PostgreSQL so repeated runs of the engine do
not keep burning retries on APIs that are already known to be exhausted.

Usage:
    tracker = QuotaTracker()
    if tracker.is_exhausted("virustotal"):
        return None                      # skip silently
    # ... call API ...
    if resp.status_code == 429:
        tracker.mark_exhausted("virustotal", reason="HTTP 429")

Reset windows (heuristic, conservative):
    virustotal : next UTC midnight       (free tier resets daily)
    abuseipdb  : next UTC midnight       (free tier resets daily)
    iplocate   : next UTC midnight       (free tier resets daily)
    shodan     : 1 hour                  (InternetDB is free but IP-rate-limited)
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

import psycopg2

import config

log = logging.getLogger("quota_tracker")


def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


def _next_utc_midnight() -> datetime:
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).date()
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)


_RESET_POLICY = {
    "virustotal": _next_utc_midnight,
    "abuseipdb":  _next_utc_midnight,
    "iplocate":   _next_utc_midnight,
    "shodan":     lambda: datetime.now(timezone.utc) + timedelta(hours=1),
}


class QuotaTracker:

    def __init__(self):
        self._cache: dict[str, bool] = {}   # in-memory cache within a single run

    def is_exhausted(self, api: str) -> bool:
        """
        Return True if this API is known to be exhausted and we should skip it.
        Auto-clears the flag if reset_at is in the past.
        """
        if api in self._cache:
            return self._cache[api]

        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT exhausted, reset_at FROM api_quota_status WHERE api_name = %s",
                        (api,)
                    )
                    row = cur.fetchone()
                    if not row:
                        self._cache[api] = False
                        return False

                    exhausted, reset_at = row
                    if not exhausted:
                        self._cache[api] = False
                        return False

                    # Auto-reset if the reset window has passed
                    if reset_at and reset_at <= datetime.now(timezone.utc):
                        log.info(f"{api}: quota reset window passed, clearing flag")
                        cur.execute(
                            "UPDATE api_quota_status "
                            "SET exhausted = FALSE, updated_at = NOW() "
                            "WHERE api_name = %s",
                            (api,)
                        )
                        conn.commit()
                        self._cache[api] = False
                        return False

                    self._cache[api] = True
                    return True
        except Exception as e:
            log.warning(f"QuotaTracker read failed for {api}: {e}")
            self._cache[api] = False
            return False

    def mark_exhausted(self, api: str, reason: str = ""):
        """Mark an API as exhausted until its next reset window."""
        reset_fn = _RESET_POLICY.get(api, _next_utc_midnight)
        reset_at = reset_fn()

        log.warning(
            f"{api}: marking quota EXHAUSTED until {reset_at.isoformat()} "
            f"({reason or 'no reason'})"
        )
        self._cache[api] = True

        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO api_quota_status (api_name, exhausted, reset_at, last_error, updated_at)
                        VALUES (%s, TRUE, %s, %s, NOW())
                        ON CONFLICT (api_name) DO UPDATE
                            SET exhausted  = TRUE,
                                reset_at   = EXCLUDED.reset_at,
                                last_error = EXCLUDED.last_error,
                                updated_at = NOW()
                        """,
                        (api, reset_at, reason[:500])
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"QuotaTracker write failed for {api}: {e}")

    def reset(self, api: str):
        """Manually clear the exhausted flag (e.g. after an API-key upgrade)."""
        self._cache[api] = False
        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE api_quota_status "
                        "SET exhausted = FALSE, updated_at = NOW() "
                        "WHERE api_name = %s",
                        (api,)
                    )
                conn.commit()
            log.info(f"{api}: quota flag manually reset")
        except Exception as e:
            log.warning(f"QuotaTracker reset failed for {api}: {e}")

    def status(self) -> list[dict]:
        """Return current status of all tracked APIs (for CLI --quota-status)."""
        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT api_name, exhausted, reset_at, last_error, updated_at "
                        "FROM api_quota_status ORDER BY api_name"
                    )
                    rows = cur.fetchall()
                    return [
                        {
                            "api_name": r[0],
                            "exhausted": r[1],
                            "reset_at": r[2].isoformat() if r[2] else None,
                            "last_error": r[3],
                            "updated_at": r[4].isoformat() if r[4] else None,
                        }
                        for r in rows
                    ]
        except Exception as e:
            log.warning(f"QuotaTracker status read failed: {e}")
            return []


# Module-level singleton — share one tracker across all callers in a run
_tracker: Optional[QuotaTracker] = None


def get_tracker() -> QuotaTracker:
    global _tracker
    if _tracker is None:
        _tracker = QuotaTracker()
    return _tracker

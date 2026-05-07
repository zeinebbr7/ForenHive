"""
Forensic engine trigger + status tracker.

Called by APScheduler (every 6 h) and the /api/forensics/run endpoint.
Uses the forensic-engine sidecar HTTP API instead of subprocess/docker-compose
because the backend container has no Docker socket.
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime
from typing import Any, Dict

import httpx

log = logging.getLogger(__name__)

last_forensic_run: Dict[str, Any] = {"timestamp": None, "status": "idle"}

# Prevents two callers (scheduler + manual trigger) from overlapping
_invoke_lock = threading.Lock()


def run_forensic_engine() -> None:
    """Trigger the sidecar and block until it finishes (runs in a thread)."""
    if not _invoke_lock.acquire(blocking=False):
        log.info("forensic engine already running — skipping this invocation")
        return

    # Mutate in-place so the dict reference imported by forensics.py stays valid
    last_forensic_run.clear()
    last_forensic_run["timestamp"] = datetime.now().isoformat()
    last_forensic_run["status"] = "running"

    try:
        from config import get_settings
        base = get_settings().forensic_engine_url.rstrip("/")

        r = httpx.post(f"{base}/run-now", timeout=15)
        if r.status_code == 409:
            last_forensic_run["status"] = "already_running"
            log.info("sidecar reported engine already in progress")
            return
        r.raise_for_status()

        # Poll /status until the sidecar finishes (lock released = done)
        deadline = time.time() + 3600
        while time.time() < deadline:
            time.sleep(20)
            try:
                s = httpx.get(f"{base}/status", timeout=5).json()
                if not s.get("running", True):
                    last_forensic_run["status"] = "completed"
                    log.info("forensic engine run completed")
                    return
            except Exception:
                pass

        last_forensic_run["status"] = "timeout"
        log.warning("forensic engine run timed out after 1 h")

    except Exception as exc:
        log.exception("forensic engine run error: %s", exc)
        last_forensic_run["status"] = "error"
        last_forensic_run["error"] = str(exc)
    finally:
        _invoke_lock.release()

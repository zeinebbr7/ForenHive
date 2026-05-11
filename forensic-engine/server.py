"""
ForenHive Forensic Engine — HTTP sidecar (port 8001).

Exposes four endpoints the FastAPI backend calls via ForensicEngineClient:
  GET  /yara/scan/{sha256}       — YARA + VirusTotal result for a hash
  GET  /yara/scan-dionaea        — all file_analysis rows (recent first)
  POST /enrich/ip                — on-demand IP enrichment (cached 24 h)
  POST /mitre/map                — MITRE ATT&CK technique IDs from text
  GET  /health                   — deep health check (infra + external APIs)

Also schedules engine.py as a background subprocess every INTERVAL minutes.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras
import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("forensic-server")

INTERVAL_MINUTES = int(os.environ.get("ENGINE_INTERVAL_MINUTES", "1440"))  # default: 24 h

# Prevents overlapping engine runs when a cycle takes longer than the interval
_engine_lock = threading.Lock()


# ── PostgreSQL helper ─────────────────────────────────────────────────────────

import db_pool

def _pg_conn():
    return db_pool.pooled_conn()


# ── Engine scheduler ──────────────────────────────────────────────────────────

def _engine_loop(interval_minutes: int) -> None:
    """Run engine.py on a fixed interval in a background daemon thread."""
    log.info("Engine scheduler: first run in 30 s, then every %d min.", interval_minutes)
    time.sleep(30)
    while True:
        if _engine_lock.locked():
            log.warning("Engine run still in progress — skipping this tick.")
            time.sleep(interval_minutes * 60)
            continue
        with _engine_lock:
            log.info("=== Forensic engine run START ===")
            try:
                subprocess.run(
                    ["python", "engine.py"],
                    check=False,
                    timeout=3600,
                )
                log.info("=== Forensic engine run DONE ===")
            except subprocess.TimeoutExpired:
                log.error("Engine run timed out after 1 h.")
            except Exception as exc:
                log.error("Engine run error: %s", exc)
        log.info("Next run in %d min.", interval_minutes)
        time.sleep(interval_minutes * 60)


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    t = threading.Thread(target=_engine_loop, args=(INTERVAL_MINUTES,), daemon=True)
    t.start()
    yield


app = FastAPI(title="ForenHive Forensic Engine API", lifespan=lifespan)


# ── Request / response models ─────────────────────────────────────────────────

class EnrichRequest(BaseModel):
    ip: str

class MitreRequest(BaseModel):
    text: str


# ── YARA endpoints ────────────────────────────────────────────────────────────

@app.get("/yara/scan/{sha256}")
def yara_scan_sha256(sha256: str) -> Dict[str, Any]:
    try:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM file_analysis WHERE sha256 = %s", (sha256,))
                row = cur.fetchone()
        if row:
            return {
                "sha256": sha256,
                "engine_available": True,
                "found": True,
                "matches": row["yara_matches"] or [],
                "virustotal_result": row["virustotal_result"],
                "analyzed_at": str(row["analyzed_at"]),
            }
        return {"sha256": sha256, "engine_available": True, "found": False, "matches": []}
    except Exception as exc:
        log.warning("yara scan DB error for %s: %s", sha256, exc)
        return {"sha256": sha256, "engine_available": False, "yara_matches": []}


@app.get("/yara/scan-dionaea")
def yara_scan_dionaea(limit: int = 50) -> List[Dict[str, Any]]:
    limit = min(max(1, limit), 500)
    try:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM file_analysis ORDER BY analyzed_at DESC LIMIT %s",
                    (limit,),
                )
                rows = cur.fetchall()
        return [
            {
                "sha256": r["sha256"],
                "engine_available": True,
                "found": True,
                "matches": r["yara_matches"] or [],
                "virustotal_result": r["virustotal_result"],
                "analyzed_at": str(r["analyzed_at"]),
            }
            for r in rows
        ]
    except Exception as exc:
        log.warning("yara scan-dionaea DB error: %s", exc)
        return []


# ── IP enrichment endpoint ────────────────────────────────────────────────────

@app.post("/enrich/ip")
def enrich_ip(req: EnrichRequest) -> Dict[str, Any]:
    if not req.ip:
        raise HTTPException(status_code=400, detail="ip is required")
    try:
        from enricher import IPEnricher
        enricher = IPEnricher()
        data = enricher.enrich(req.ip)
        return {"ip": req.ip, "engine_available": True, **data}
    except Exception as exc:
        log.warning("enrich_ip failed for %s: %s", req.ip, exc)
        return {"ip": req.ip, "engine_available": False}


# ── MITRE ATT&CK mapping endpoint ────────────────────────────────────────────

@app.post("/mitre/map")
def mitre_map(req: MitreRequest) -> Dict[str, Any]:
    text = req.text or ""
    tl = text.lower()

    # Build a minimal session dict by detecting keywords in the text so that
    # get_techniques_deterministic() can apply its deterministic rules.
    session: Dict[str, Any] = {
        "honeypot_type": "cowrie" if any(k in tl for k in ("ssh", "telnet", "login", "password")) else
                         "dionaea" if any(k in tl for k in ("smb", "mssql", "ftp", "http exploit", "445", "1433")) else
                         "galah" if any(k in tl for k in ("http", "get ", "post ", "user-agent")) else
                         "zeek",
        "login_attempts": 100 if "brute" in tl else (10 if "login" in tl or "password" in tl else 0),
        "success_count":  1 if any(k in tl for k in ("success", "logged in", "authenticated", "shell")) else 0,
        "command_count":  1 if any(k in tl for k in ("cmd", "exec", "shell", "bash", "sh ")) else 0,
        "commands":       [text],
        # key must match what get_techniques_deterministic() reads
        "yara_matches":   [f for f in ("mirai", "wannacry", "emotet", "miner", "rat", "backdoor") if f in tl],
        "http_paths":     [],
        "smb_share_enum": "share" in tl or "netshareenum" in tl,
        "smb_pipe_enum":  "pipe" in tl or "epmapper" in tl,
        "exploit_cves":   ["CVE-2017-0144"] if "eternalblue" in tl or "cve-2017-0144" in tl else [],
        "exfil_bytes":    1 if any(k in tl for k in ("wget", "curl", "download", "tftp")) else 0,
        "destination_port": 0,
    }

    try:
        from mitre_mapper import get_techniques_deterministic
        # get_techniques_deterministic returns list[str] (technique IDs directly)
        ids = get_techniques_deterministic(session)
        return {"techniques": ids}
    except Exception as exc:
        log.warning("mitre_map failed: %s", exc)
        return {"techniques": []}


# ── Manual trigger + status ──────────────────────────────────────────────────

@app.get("/status")
def engine_status() -> Dict[str, Any]:
    """Returns whether an engine run is currently in progress."""
    return {"running": _engine_lock.locked()}


@app.post("/run-now")
def run_now(hours: int = 24) -> Dict[str, Any]:
    """Trigger an immediate engine run. Returns 409 if a run is already in progress.
    Pass ?hours=N to override the lookback window (default 24h)."""
    if _engine_lock.locked():
        raise HTTPException(status_code=409, detail="Engine run already in progress")

    def _run():
        with _engine_lock:
            log.info(f"=== Forensic engine run START (manual trigger, last {hours}h) ===")
            try:
                subprocess.run(["python", "engine.py", "--hours", str(hours)], check=False, timeout=3600)
                log.info("=== Forensic engine run DONE (manual trigger) ===")
            except subprocess.TimeoutExpired:
                log.error("Manual engine run timed out after 1 h.")
            except Exception as exc:
                log.error("Manual engine run error: %s", exc)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"triggered": True, "message": f"Forensic engine run started (last {hours}h)"}


# ── Health check ──────────────────────────────────────────────────────────────

# TCP endpoints used for reachability probes (no API quota consumed)
_API_PROBE_HOSTS: Dict[str, tuple] = {
    "abuseipdb":  ("api.abuseipdb.com",   443),
    "virustotal": ("www.virustotal.com",   443),
    "shodan":     ("internetdb.shodan.io", 443),
    "iplocate":   ("www.iplocate.io",      443),
}

# APIs that require a configured key to be functional
_API_NEEDS_KEY: Dict[str, bool] = {
    "abuseipdb":  True,
    "virustotal": True,
    "shodan":     False,  # free InternetDB works without a key
    "iplocate":   False,
}


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


@app.get("/health")
def health() -> JSONResponse:
    """
    Deep health check.

    Probes every dependency used by the forensic engine:
      • PostgreSQL      — SELECT 1
      • Elasticsearch   — GET /_cluster/health
      • GeoIP databases — file existence check
      • External APIs   — key configured + quota not exhausted + TCP reachable

    Returns HTTP 200 when all critical dependencies (PG, ES, GeoIP) are up.
    Returns HTTP 503 when any critical dependency is down.
    External API issues degrade the status to "degraded" but never raise to 503.
    """
    checks: Dict[str, Any] = {}
    critical_ok = True

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        checks["postgresql"] = {"status": "ok"}
    except Exception as exc:
        checks["postgresql"] = {"status": "error", "detail": str(exc)}
        critical_ok = False

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    try:
        resp = requests.get(f"{config.ES_URL}/_cluster/health", timeout=5)
        cluster_status = resp.json().get("status", "unknown")
        checks["elasticsearch"] = {"status": "ok", "cluster": cluster_status}
    except Exception as exc:
        checks["elasticsearch"] = {"status": "error", "detail": str(exc)}
        critical_ok = False

    # ── GeoIP databases ───────────────────────────────────────────────────────
    city_ok = os.path.exists(config.GEOIP_CITY_DB)
    asn_ok  = os.path.exists(config.GEOIP_ASN_DB)
    if city_ok and asn_ok:
        checks["geoip"] = {"status": "ok"}
    else:
        checks["geoip"] = {
            "status":  "error",
            "city_db": city_ok,
            "asn_db":  asn_ok,
        }
        critical_ok = False

    # ── External API keys ─────────────────────────────────────────────────────
    api_keys: Dict[str, bool] = {
        "abuseipdb":  bool(config.ABUSEIPDB_KEY),
        "virustotal": bool(config.VIRUSTOTAL_KEY),
        "shodan":     True,
        "iplocate":   True,
    }

    # Pull quota state from PG (best-effort; empty dict if PG is already down)
    quota_rows: Dict[str, Dict] = {}
    try:
        from quota_tracker import get_tracker
        for row in get_tracker().status():
            quota_rows[row["api_name"]] = row
    except Exception:
        pass

    for api, (host, port) in _API_PROBE_HOSTS.items():
        key_ok    = api_keys[api]
        needs_key = _API_NEEDS_KEY[api]
        quota     = quota_rows.get(api, {})
        exhausted = bool(quota.get("exhausted", False))
        reachable = _tcp_reachable(host, port)

        if exhausted:
            api_status = "quota_exhausted"
        elif not reachable:
            api_status = "unreachable"
        elif needs_key and not key_ok:
            api_status = "no_key"
        else:
            api_status = "ok"

        checks[api] = {
            "status":          api_status,
            "key_configured":  key_ok,
            "reachable":       reachable,
            "quota_exhausted": exhausted,
            "quota_reset_at":  quota.get("reset_at"),
        }

    overall = "ok" if critical_ok else "degraded"
    http_status = 200 if critical_ok else 503
    return JSONResponse(
        status_code=http_status,
        content={"status": overall, "checks": checks},
    )


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")

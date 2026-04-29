"""
ForenHive Forensic Engine — HTTP sidecar (port 8001).

Exposes four endpoints the FastAPI backend calls via ForensicEngineClient:
  GET  /yara/scan/{sha256}       — YARA + VirusTotal result for a hash
  GET  /yara/scan-dionaea        — all file_analysis rows (recent first)
  POST /enrich/ip                — on-demand IP enrichment (cached 24 h)
  POST /mitre/map                — MITRE ATT&CK technique IDs from text

Also schedules engine.py as a background subprocess every INTERVAL minutes.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("forensic-server")

INTERVAL_MINUTES = int(os.environ.get("ENGINE_INTERVAL_MINUTES", "10"))


# ── PostgreSQL helper ─────────────────────────────────────────────────────────

def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", ""),
    )


# ── Engine scheduler ──────────────────────────────────────────────────────────

def _engine_loop(interval_minutes: int) -> None:
    """Run engine.py on a fixed interval in a background daemon thread."""
    log.info("Engine scheduler: first run in 30 s, then every %d min.", interval_minutes)
    time.sleep(30)
    while True:
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
        "success_count": 1 if any(k in tl for k in ("success", "logged in", "authenticated", "shell")) else 0,
        "commands": [text],
        "yara_families": [f for f in ("mirai", "wannacry", "emotet", "miner", "rat", "backdoor") if f in tl],
        "ports_targeted": [],
        "smb_share_enum": "share" in tl or "netshareenum" in tl,
        "smb_pipe_enum": "pipe" in tl or "epmapper" in tl,
        "exploit_cves": ["CVE-2017-0144"] if "eternalblue" in tl or "cve-2017-0144" in tl else [],
        "download_attempts": 1 if any(k in tl for k in ("wget", "curl", "download", "tftp")) else 0,
        "bytes_sent": 0,
    }

    try:
        from mitre_mapper import get_techniques_deterministic
        techniques = get_techniques_deterministic(session)
        ids = [t.get("id") for t in techniques if t.get("id")]
        return {"techniques": ids}
    except Exception as exc:
        log.warning("mitre_map failed: %s", exc)
        return {"techniques": []}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")

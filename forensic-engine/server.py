"""
ForenHive Forensic Engine — HTTP API
Exposes YARA scanning, IP enrichment and MITRE mapping to the backend.
Runs on port 8001 inside backend-net.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config
from enricher import IPEnricher
from mitre_mapper import MitreMapper, get_techniques_deterministic
from yara_scanner import YARAScanner, calculer_sha256

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("forensic_server")

app = FastAPI(title="ForenHive Forensic Engine", version="1.0.0")

# Singletons — initialised once at startup to avoid recompiling YARA rules on every request
_scanner: YARAScanner | None = None
_enricher: IPEnricher | None = None
_mitre: MitreMapper | None = None


def _get_scanner() -> YARAScanner:
    global _scanner
    if _scanner is None:
        _scanner = YARAScanner()
    return _scanner


def _get_enricher() -> IPEnricher:
    global _enricher
    if _enricher is None:
        _enricher = IPEnricher()
    return _enricher


def _get_mitre() -> MitreMapper:
    global _mitre
    if _mitre is None:
        _mitre = MitreMapper(use_llm=True)
    return _mitre


def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", ""),
    )


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "forensic-engine"}


# ── YARA ───────────────────────────────────────────────────────────────────────

def _fetch_cached_analysis(sha256: str) -> dict | None:
    """Return the stored file_analysis row for this SHA-256, or None."""
    try:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT sha256, yara_matches, virustotal_result, analyzed_at "
                    "FROM file_analysis WHERE sha256 = %s",
                    (sha256,),
                )
                row = cur.fetchone()
                if row:
                    return dict(row)
    except Exception as exc:
        log.warning("DB lookup failed for %s: %s", sha256, exc)
    return None


def _find_file_by_sha256(sha256: str) -> str | None:
    """Walk Dionaea binaries directory and return path of file matching SHA-256."""
    binaries_path = Path(config.DIONAEA_BINARIES_PATH)
    if not binaries_path.exists():
        return None
    for f in binaries_path.iterdir():
        if f.is_file():
            try:
                if calculer_sha256(str(f)) == sha256:
                    return str(f)
            except Exception:
                continue
    return None


@app.get("/yara/scan/{sha256}")
def yara_scan_sha256(sha256: str) -> Dict[str, Any]:
    """
    Return YARA analysis for a specific SHA-256.
    Checks PostgreSQL cache first; falls back to on-demand scan if the file exists.
    """
    # 1. Cache hit
    cached = _fetch_cached_analysis(sha256)
    if cached:
        matches = cached.get("yara_matches") or []
        if isinstance(matches, str):
            matches = json.loads(matches)
        return {
            "sha256": sha256,
            "matches": matches,
            "matched": len(matches) > 0,
            "virustotal": cached.get("virustotal_result"),
            "analyzed_at": str(cached.get("analyzed_at", "")),
            "source": "cache",
            "engine_available": True,
        }

    # 2. On-demand scan
    filepath = _find_file_by_sha256(sha256)
    if not filepath:
        return {
            "sha256": sha256,
            "matches": [],
            "matched": False,
            "virustotal": None,
            "analyzed_at": None,
            "source": "not_found",
            "engine_available": True,
        }

    scanner = _get_scanner()
    matches = scanner.scanner_fichier(filepath)
    scanner._sauvegarder(sha256, matches)
    return {
        "sha256": sha256,
        "matches": matches,
        "matched": len(matches) > 0,
        "virustotal": None,
        "analyzed_at": None,
        "source": "live_scan",
        "engine_available": True,
    }


@app.get("/yara/scan-dionaea")
def yara_scan_all_dionaea(limit: int = Query(default=50, le=500)) -> List[Dict[str, Any]]:
    """Scan all (up to limit) Dionaea captured binaries and return per-file results."""
    scanner = _get_scanner()
    results = scanner.scanner_binaires_dionaea()
    return results[:limit]


# ── IP Enrichment ──────────────────────────────────────────────────────────────

class EnrichRequest(BaseModel):
    ip: str


@app.post("/enrich/ip")
def enrich_ip(body: EnrichRequest) -> Dict[str, Any]:
    """Full IP enrichment: GeoIP, AbuseIPDB, IPLocate, Shodan (cached 24 h)."""
    try:
        result = _get_enricher().enrich(body.ip)
        result["engine_available"] = True
        return result
    except Exception as exc:
        log.error("Enrichment failed for %s: %s", body.ip, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ── MITRE ATT&CK Mapping ───────────────────────────────────────────────────────

class MitreRequest(BaseModel):
    text: str
    session: dict = {}


@app.post("/mitre/map")
def mitre_map(body: MitreRequest) -> Dict[str, Any]:
    """
    Map free text (or a session dict) to MITRE ATT&CK technique IDs.
    Uses deterministic rules; LLM narrative from Mistral 7B if Ollama is up.
    """
    try:
        mitre = _get_mitre()
        # Build a minimal session dict from text if no structured session provided
        session = body.session if body.session else {"commands": [body.text], "honeypot_type": "unknown"}
        result = mitre.map_session(session)
        result["engine_available"] = True
        return result
    except Exception as exc:
        log.error("MITRE mapping failed: %s", exc)
        # Graceful fallback
        return {
            "techniques": [],
            "kill_chain_phase": "unknown",
            "narrative": "",
            "engine_available": True,
            "error": str(exc),
        }

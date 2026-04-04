"""
ForenHive Forensic Engine — VirusTotal SHA-256 Lookup
Looks up file hashes against VirusTotal v3 API.
Results are merged into the file_analysis table in PostgreSQL.
"""

import json
import logging
import time
from typing import Optional

import psycopg2
import requests

import config

log = logging.getLogger("virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"


def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=config.PG_PASSWORD
    )


class VirusTotalScanner:

    def __init__(self):
        self._last_request = 0.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < config.VIRUSTOTAL_RATE_LIMIT_SEC:
            time.sleep(config.VIRUSTOTAL_RATE_LIMIT_SEC - elapsed)
        self._last_request = time.time()

    def lookup_hash(self, sha256: str) -> Optional[dict]:
        """
        Look up a SHA-256 hash on VirusTotal.
        Returns a normalized dict, or None if the hash is unknown.
        """
        if not config.VIRUSTOTAL_KEY:
            log.warning("VIRUSTOTAL_KEY not set — skipping lookup")
            return None

        self._rate_limit()

        try:
            resp = requests.get(
                f"{VT_BASE}/files/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_KEY},
                timeout=15
            )
        except Exception as e:
            log.warning(f"VirusTotal request failed for {sha256}: {e}")
            return None

        if resp.status_code == 404:
            log.info(f"VirusTotal: hash not found — {sha256[:16]}... (unknown malware)")
            return None

        if resp.status_code == 429:
            log.warning("VirusTotal rate limit hit — backing off 60s")
            time.sleep(60)
            return self.lookup_hash(sha256)

        if resp.status_code != 200:
            log.warning(f"VirusTotal returned {resp.status_code} for {sha256[:16]}...")
            return None

        data = resp.json().get("data", {}).get("attributes", {})
        last_analysis = data.get("last_analysis_stats", {})
        malicious  = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total      = malicious + suspicious + undetected + last_analysis.get("harmless", 0)

        # Extract family from popular threat classification
        family = ""
        popular = data.get("popular_threat_classification", {})
        if popular:
            label = popular.get("suggested_threat_label", "")
            family = label.split(".")[0] if label else ""

        result = {
            "sha256":           sha256,
            "detection_ratio":  f"{malicious}/{total}" if total else "0/0",
            "malicious":        malicious,
            "suspicious":       suspicious,
            "undetected":       undetected,
            "family":           family,
            "tags":             data.get("tags", []),
            "first_seen":       data.get("first_submission_date", ""),
            "last_seen":        data.get("last_analysis_date", ""),
            "names":            data.get("names", [])[:5],
        }

        log.info(
            f"VirusTotal [{sha256[:16]}...] "
            f"{malicious}/{total} detections, family={family or 'unknown'}"
        )

        self._save_to_db(sha256, result)
        return result

    def _save_to_db(self, sha256: str, vt_result: dict):
        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO file_analysis (sha256, virustotal_result, analyzed_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (sha256) DO UPDATE
                            SET virustotal_result = EXCLUDED.virustotal_result,
                                analyzed_at       = NOW()
                        """,
                        (sha256, json.dumps(vt_result))
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"DB write failed for {sha256}: {e}")

    def lookup_batch(self, sha256_list: list) -> dict:
        """Lookup multiple hashes. Returns {sha256: result_or_None}."""
        results = {}
        unique = list(set(sha256_list))
        log.info(f"VirusTotal batch lookup: {len(unique)} hashes")
        for sha256 in unique:
            results[sha256] = self.lookup_hash(sha256)
        return results

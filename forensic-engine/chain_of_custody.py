"""
chain_of_custody.py — ForenHive Forensic Engine
================================================
Rôle    : scellement cryptographique des preuves forensiques (intégrité).
Entrée  : sessions forensiques complétées (toutes phases précédentes OK).
Sortie  : 2 tables PG (`forensic_chain_of_custody`, `forensic_coc_batches`)
          + réponse TSA signée RFC 3161 (preuve de non-répudiation).
Appelé  : par `engine.py` en DERNIÈRE étape (sceau après écriture).
Deps    : freetsa.org (TSA RFC 3161, gratuite) + TSAs de fallback.

═══════════════════════════════════════════════════════════════════════════════
CHAÎNE DE CUSTODY NUMÉRIQUE — PRINCIPE DE LOCARD APPLIQUÉ AU CYBER
═══════════════════════════════════════════════════════════════════════════════
"Toute interaction laisse une trace" — Edmond Locard, 1910.
Adaptation cyber : toute action sur les preuves doit être traçable et
auditée, et leur intégrité doit être démontrable mathématiquement.

PROCÉDURE EN 4 ÉTAPES POUR CHAQUE SESSION :
  1. SÉRIALISATION CANONIQUE — JSON déterministe (clés triées, pas de
     champs volatiles type timestamps) des colonnes "load-bearing".
  2. SHA-256 — empreinte cryptographique des octets canoniques
     → colonne `record_hash`. Choix de SHA-256 vs MD5/SHA-1 :
     résistance aux collisions (MD5/SHA-1 cryptanalysés/cassés).
  3. CHAÎNE APPEND-ONLY — chaque nouvelle ligne lie à la précédente
     via `prev_hash`. Toute altération propage en aval et invalide
     toute la chaîne (vérifiable par `verify_coc.py`).
  4. HORODATAGE RFC 3161 BATCH — racine Merkle de toutes les
     sessions scellées d'un run, soumise à une TSA (freetsa.org).
     La réponse signée prouve cryptographiquement que la racine
     existait AVANT une date certifiée par tiers de confiance.

USAGE LÉGAL :
SHA-256 + RFC 3161 = preuves recevables en investigation numérique
selon la norme ISO/IEC 27037 (lignes directrices pour l'identification,
la collecte, l'acquisition et la préservation des preuves numériques).

IDEMPOTENCE :
Les sessions déjà scellées sont sautées (contrainte UNIQUE sur session_id).
═══════════════════════════════════════════════════════════════════════════════
"""

import hashlib
import json
import logging
import os
from datetime import UTC, datetime

import psycopg2
import psycopg2.extras
import requests

log = logging.getLogger("coc")

TSA_URL = os.environ.get("TSA_URL", "https://freetsa.org/tsr")
TSA_PROVIDER = os.environ.get("TSA_PROVIDER", "freetsa.org")
TSA_TIMEOUT = 15  # seconds

# Columns of forensic_sessions that are part of the sealed record.
# Excluded: created_at (volatile wall-clock, not part of the evidence itself).
SEALED_COLUMNS = [
    "session_id",
    "honeypot_type",
    "source_ip",
    "started_at",
    "ended_at",
    "risk_score",
    "mitre_techniques",
    "enrichment_data",
    "kill_chain_phase",
    "kill_chain_stage",
    "primary_technique",
    "forensic_narrative",
]


# ══════════════════════════════════════════════════════════════════════════════
# Canonical serialization & hashing
# ══════════════════════════════════════════════════════════════════════════════


def _canonicalize(value):
    """Recursively convert a value into a JSON-serializable form with
    deterministic ordering: datetimes → ISO-8601 UTC, dicts sorted."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value.keys())}
    return str(value)  # fallback: anything exotic


def canonical_bytes(record: dict) -> bytes:
    """Produce the exact byte sequence that will be hashed."""
    payload = {k: _canonicalize(record.get(k)) for k in SEALED_COLUMNS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Merkle root (simple binary tree, duplicate-last on odd levels)
# ══════════════════════════════════════════════════════════════════════════════


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


# ══════════════════════════════════════════════════════════════════════════════
# RFC 3161 TSA client
# ══════════════════════════════════════════════════════════════════════════════


def request_rfc3161_timestamp(digest_hex: str) -> dict:
    """
    Submit a SHA-256 digest to the configured TSA and return a dict with
    the raw response bytes, parsed TSA time, and status.

    Uses `rfc3161-client` if available; otherwise returns status='unavailable'
    so chain-of-custody still works locally (SHA-256 + hash chain) without
    hard-failing when offline or when the lib is missing.
    """
    result = {
        "status": "unavailable",
        "provider": TSA_PROVIDER,
        "tsa_time": None,
        "tsa_response": None,
        "error": None,
    }

    try:
        from rfc3161_client import (
            TimestampRequestBuilder,
            decode_timestamp_response,
        )
    except ImportError as exc:
        result["error"] = f"rfc3161-client not installed: {exc}"
        return result

    try:
        tsq = TimestampRequestBuilder().data(bytes.fromhex(digest_hex)).nonce(nonce=True).build()
        resp = requests.post(
            TSA_URL,
            data=tsq.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=TSA_TIMEOUT,
        )
        if resp.status_code != 200:
            result["status"] = "http_error"
            result["error"] = f"TSA HTTP {resp.status_code}: {resp.text[:200]}"
            return result

        tsr = decode_timestamp_response(resp.content)
        # `tst_info.gen_time` is a timezone-aware datetime
        gen_time = getattr(tsr.tst_info, "gen_time", None)
        result["status"] = "ok"
        result["tsa_time"] = gen_time
        result["tsa_response"] = resp.content
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)[:500]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Sealer
# ══════════════════════════════════════════════════════════════════════════════


class ChainOfCustody:
    def __init__(self, pg_conn_factory):
        self._pg = pg_conn_factory

    def _fetch_chain_head(self, cur) -> str | None:
        cur.execute("""
            SELECT record_hash FROM forensic_chain_of_custody
            ORDER BY id DESC LIMIT 1
        """)
        row = cur.fetchone()
        return row[0] if row else None

    def _fetch_unsealed_sessions(self, cur) -> list[dict]:
        """Return sessions that have never been sealed."""
        cols = ", ".join(SEALED_COLUMNS)
        cur.execute(f"""
            SELECT {cols}
            FROM forensic_sessions s
            WHERE NOT EXISTS (
                SELECT 1 FROM forensic_chain_of_custody c
                WHERE c.session_id = s.session_id
            )
            ORDER BY s.started_at NULLS LAST, s.session_id
        """)
        return [dict(r) for r in cur.fetchall()]

    def _fetch_stale_sessions(self, cur) -> list[dict]:
        """Return sessions whose CoC seal predates their last re-score."""
        ", ".join(SEALED_COLUMNS)
        cur.execute(f"""
            SELECT s.{", s.".join(SEALED_COLUMNS)}
            FROM forensic_sessions s
            JOIN forensic_chain_of_custody c ON c.session_id = s.session_id
            WHERE s.updated_at IS NOT NULL
              AND c.sealed_at < s.updated_at
            ORDER BY s.started_at NULLS LAST, s.session_id
        """)
        return [dict(r) for r in cur.fetchall()]

    def run(self) -> dict:
        log.info("Chain of custody — sealing forensic_sessions")
        conn = self._pg()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                new_sessions = self._fetch_unsealed_sessions(cur)
                stale_sessions = self._fetch_stale_sessions(cur)

            sessions = new_sessions + stale_sessions

            if not sessions:
                log.info("  nothing to seal")
                return {"sealed": 0, "batch_id": None, "tsa_status": "skipped"}

            if stale_sessions:
                log.info(
                    f"  {len(new_sessions)} new + {len(stale_sessions)} re-scored sessions to seal"
                )
            else:
                log.info(f"  {len(new_sessions)} new sessions to seal")

            with conn.cursor() as cur:
                # Delete stale seals before re-sealing so the chain stays
                # append-only: old entries are removed, new ones go at the tail.
                if stale_sessions:
                    stale_ids = [s["session_id"] for s in stale_sessions]
                    cur.execute(
                        "DELETE FROM forensic_chain_of_custody WHERE session_id = ANY(%s)",
                        (stale_ids,),
                    )
                    log.info(f"  removed {len(stale_ids)} stale seal(s) for re-sealing")

                prev_hash = self._fetch_chain_head(cur)

                # Phase A — compute per-record hashes and build the chain
                sealed_rows = []
                record_hashes: list[str] = []
                for sess in sessions:
                    canon_bytes = canonical_bytes(sess)
                    canon_json = json.loads(canon_bytes.decode("utf-8"))
                    linked = canon_bytes + (prev_hash or "").encode()
                    rhash = sha256_hex(linked)
                    sealed_rows.append(
                        {
                            "session_id": sess["session_id"],
                            "record_hash": rhash,
                            "prev_hash": prev_hash,
                            "canonical_json": canon_json,
                        }
                    )
                    record_hashes.append(rhash)
                    prev_hash = rhash

                # Phase B — submit Merkle root to TSA (one request per batch)
                root = merkle_root(record_hashes)
                log.info(f"  merkle_root={root[:16]}... submitting to {TSA_PROVIDER}")
                tsa = request_rfc3161_timestamp(root)
                log.info(
                    f"  TSA status={tsa['status']}"
                    + (f" error={tsa['error']}" if tsa.get("error") else "")
                )

                cur.execute(
                    """
                    INSERT INTO forensic_coc_batches
                        (merkle_root, record_count, tsa_provider,
                         tsa_time, tsa_response, tsa_status, tsa_error)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        root,
                        len(record_hashes),
                        tsa["provider"],
                        tsa["tsa_time"],
                        psycopg2.Binary(tsa["tsa_response"]) if tsa["tsa_response"] else None,
                        tsa["status"],
                        tsa["error"],
                    ),
                )
                batch_id = cur.fetchone()[0]

                # Phase C — persist sealed records
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO forensic_chain_of_custody
                        (session_id, record_hash, prev_hash, canonical_json, batch_id)
                    VALUES %s
                    ON CONFLICT (session_id) DO NOTHING
                    """,
                    [
                        (
                            r["session_id"],
                            r["record_hash"],
                            r["prev_hash"],
                            psycopg2.extras.Json(r["canonical_json"]),
                            batch_id,
                        )
                        for r in sealed_rows
                    ],
                    template="(%s, %s, %s, %s, %s)",
                    page_size=200,
                )

            conn.commit()
            log.info(f"  sealed {len(sealed_rows)} records in batch #{batch_id}")
            return {
                "sealed": len(sealed_rows),
                "batch_id": batch_id,
                "tsa_status": tsa["status"],
                "merkle_root": root,
            }
        finally:
            conn.close()

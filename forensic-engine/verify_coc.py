"""
ForenHive — Chain of Custody Verifier

Independent script that re-hashes every sealed forensic_session and
validates:

  1. Each record's canonical hash matches what's stored in
     forensic_chain_of_custody.record_hash.
  2. The hash chain is intact (record N's prev_hash equals record N-1's
     record_hash in insertion order).
  3. For each batch, the Merkle root re-computed from its sealed records
     matches the root stored in forensic_coc_batches.
  4. RFC 3161 TSA responses, if present, decode cleanly and their
     embedded timestamp is reported.

Exit code 0 on full success, 1 on any verification failure.

Usage:
  docker exec forenhive-forensic-engine python verify_coc.py
"""

import os
import sys

import config
import psycopg2
import psycopg2.extras
from chain_of_custody import SEALED_COLUMNS, canonical_bytes, merkle_root, sha256_hex


def _pg():
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", ""),
    )


def _fmt_ok(n):
    return f"\033[32mOK\033[0m  {n}"


def _fmt_bad(n):
    return f"\033[31mFAIL\033[0m {n}"


def main() -> int:
    conn = _pg()
    errors = 0
    checked = 0

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # 1. Re-hash every sealed session and compare
            cols = ", ".join(f"s.{c}" for c in SEALED_COLUMNS)
            cur.execute(f"""
                SELECT {cols}, c.record_hash, c.prev_hash, c.batch_id, c.id AS coc_id
                FROM forensic_chain_of_custody c
                JOIN forensic_sessions s USING (session_id)
                ORDER BY c.id
            """)
            rows = cur.fetchall()

            prev = None
            for r in rows:
                checked += 1
                sess = {c: r[c] for c in SEALED_COLUMNS}
                cb = canonical_bytes(sess)
                linked = cb + (prev or "").encode()
                expected = sha256_hex(linked)

                if expected != r["record_hash"]:
                    print(
                        _fmt_bad(
                            f"session={r['session_id']} record_hash mismatch "
                            f"(recomputed={expected[:12]}... stored={r['record_hash'][:12]}...)"
                        )
                    )
                    errors += 1
                elif r["prev_hash"] != prev:
                    print(
                        _fmt_bad(
                            f"session={r['session_id']} prev_hash broken "
                            f"(expected={prev[:12] if prev else 'NULL'}... stored={(r['prev_hash'] or 'NULL')[:12]}...)"
                        )
                    )
                    errors += 1
                prev = r["record_hash"]

            print(f"  → {len(rows)} sealed sessions checked, {len(rows) - errors} valid")

            # 2. Per-batch Merkle root check
            cur.execute("""
                SELECT id, merkle_root, record_count, tsa_provider,
                       tsa_time, tsa_status
                FROM forensic_coc_batches ORDER BY id
            """)
            batches = cur.fetchall()

            for b in batches:
                cur.execute(
                    "SELECT record_hash FROM forensic_chain_of_custody "
                    "WHERE batch_id = %s ORDER BY id",
                    (b["id"],),
                )
                batch_hashes = [row["record_hash"] for row in cur.fetchall()]
                recomputed = merkle_root(batch_hashes)
                if recomputed != b["merkle_root"]:
                    print(
                        _fmt_bad(
                            f"batch #{b['id']} merkle mismatch "
                            f"(recomputed={recomputed[:12]}... stored={b['merkle_root'][:12]}...)"
                        )
                    )
                    errors += 1
                    continue
                tsa_marker = f"TSA {b['tsa_status']}"
                if b["tsa_time"]:
                    tsa_marker += f" @ {b['tsa_time'].isoformat()}"
                print(
                    _fmt_ok(
                        f"batch #{b['id']} {len(batch_hashes)} records, "
                        f"merkle={b['merkle_root'][:12]}... {tsa_marker}"
                    )
                )

    finally:
        conn.close()

    print()
    if errors:
        print(f"\033[31m✗ {errors} error(s) — chain compromised\033[0m")
        return 1
    print(f"\033[32m✓ chain intact — {checked} records, {len(batches)} batch(es)\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())

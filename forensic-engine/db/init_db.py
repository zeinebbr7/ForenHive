#!/usr/bin/env python3
"""
Initialize ForenHive PostgreSQL schema.
Run once before starting the forensic engine.
"""

import os
import sys
import time
import psycopg2
from pathlib import Path

SCHEMA_FILE = Path(__file__).parent / "schema.sql"

def get_conn_params():
    return {
        "host":     os.environ.get("PG_HOST", "forenhive-postgresql"),
        "port":     int(os.environ.get("PG_PORT", 5432)),
        "dbname":   os.environ.get("PG_DB", "forenhive"),
        "user":     os.environ.get("PG_USER", "forenhive"),
        "password": os.environ.get("PG_PASSWORD", ""),
    }

def wait_for_postgres(params, retries=10, delay=3):
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(**params)
            conn.close()
            print(f"[init_db] PostgreSQL ready.")
            return True
        except psycopg2.OperationalError as e:
            print(f"[init_db] Waiting for PostgreSQL ({attempt}/{retries}): {e}")
            time.sleep(delay)
    return False

def init_schema(params):
    sql = SCHEMA_FILE.read_text()
    with psycopg2.connect(**params) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    print("[init_db] Schema applied successfully.")

if __name__ == "__main__":
    # Load .env if present (for local runs outside Docker)
    env_file = Path(__file__).parents[2] / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    params = get_conn_params()
    if not wait_for_postgres(params):
        print("[init_db] ERROR: PostgreSQL not reachable. Aborting.")
        sys.exit(1)

    init_schema(params)
    print("[init_db] Done.")

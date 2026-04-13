"""
ForenHive Forensic Engine — YARA Scanner
Scans Dionaea malware captures with YARA rules.
Results are saved to the file_analysis table in PostgreSQL.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras
import yara

import config

log = logging.getLogger("yara_scanner")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


class YARAScanner:

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or config.YARA_RULES_DIR
        self.rules = self._compile_rules()

    def _compile_rules(self) -> Optional[yara.Rules]:
        rule_files = list(Path(self.rules_dir).glob("*.yar"))
        if not rule_files:
            log.warning(f"No YARA rules found in {self.rules_dir}")
            return None
        sources = {f.stem: str(f) for f in rule_files}
        try:
            rules = yara.compile(filepaths=sources)
            log.info(f"Compiled {len(rule_files)} YARA rule files: {[f.name for f in rule_files]}")
            return rules
        except yara.SyntaxError as e:
            log.error(f"YARA compilation error: {e}")
            return None

    def scan_file(self, filepath: str) -> list:
        """
        Scan a single file. Returns list of match dicts:
        [{"rule": "Mirai_Botnet", "namespace": "mirai", "meta": {...}, "strings": [...]}]
        """
        if not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            result = []
            for m in matches:
                result.append({
                    "rule":      m.rule,
                    "namespace": m.namespace,
                    "meta":      dict(m.meta),
                    "strings":   [
                        {"offset": s.instances[0].offset, "identifier": s.identifier}
                        for s in m.strings
                    ] if m.strings else [],
                })
            return result
        except Exception as e:
            log.warning(f"YARA scan failed on {filepath}: {e}")
            return []

    def _save_to_db(self, sha256: str, yara_matches: list):
        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO file_analysis (sha256, yara_matches, analyzed_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (sha256) DO UPDATE
                            SET yara_matches = EXCLUDED.yara_matches,
                                analyzed_at  = NOW()
                        """,
                        (sha256, json.dumps(yara_matches))
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"DB write failed for {sha256}: {e}")

    def scan_dionaea_downloads(self) -> list:
        """
        Scan all files in the Dionaea binaries directory.
        Returns a list of results with sha256, filepath, and YARA matches.
        """
        binaries_path = Path(config.DIONAEA_BINARIES_PATH)
        if not binaries_path.exists():
            log.warning(f"Dionaea binaries path not found: {binaries_path}")
            return []

        results = []
        files = [f for f in binaries_path.iterdir() if f.is_file()]
        log.info(f"Scanning {len(files)} Dionaea binary files ...")

        for filepath in files:
            sha256 = _sha256_file(str(filepath))
            matches = self.scan_file(str(filepath))

            entry = {
                "filepath": str(filepath),
                "sha256":   sha256,
                "matches":  matches,
                "matched":  len(matches) > 0,
            }
            results.append(entry)

            # Always persist (even zero matches = clean record)
            self._save_to_db(sha256, matches)

            if matches:
                rule_names = [m["rule"] for m in matches]
                log.info(f"MATCH [{filepath.name}] SHA256={sha256[:16]}... → {rule_names}")
            else:
                log.debug(f"Clean [{filepath.name}] SHA256={sha256[:16]}...")

        total_matches = sum(1 for r in results if r["matched"])
        log.info(f"YARA scan complete: {total_matches}/{len(files)} files flagged")
        return results

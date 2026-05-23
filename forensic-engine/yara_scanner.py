"""
yara_scanner.py — ForenHive Forensic Engine
============================================
Rôle    : détection de signatures malware (YARA) sur payloads capturés.
Entrée  : fichiers déposés par Dionaea (binaires, scripts, executables).
Sortie  : table PG `file_analysis` (matchs YARA + métadonnées).
Appelé  : par `engine.py` après l'enrichissement IP.
Deps    : python-yara, règles YARA dans `forensic-engine/yara_rules/`.

═══════════════════════════════════════════════════════════════════════════════
SCANNER YARA — DÉTECTION DE SIGNATURES MALWARE
═══════════════════════════════════════════════════════════════════════════════
Applique les règles YARA du projet sur les payloads capturés par Dionaea.

SCORING TIERED selon la criticité de la règle matchée (contribution
au signal `malware` du risk_score) :
  CRITICAL rules  : +30 points  (ransomware, exploits 0-day)
  HIGH rules      : +20 points  (backdoors, shells web connus)
  MEDIUM rules    : +10 points  (suspects, packers)

COUVERTURE DES RÈGLES :
  • Ransomware (WannaCry, NotPetya, Locky, Ryuk…)
  • Backdoors (Metasploit, Cobalt Strike, ShellBot)
  • Shells web (PHP, ASP, JSP webshells)
  • Exploits connus (EternalBlue payloads, BlueKeep)

IDEMPOTENCE :
Hash SHA-256 du fichier comme clé → re-scan ne crée pas de doublons.
═══════════════════════════════════════════════════════════════════════════════
"""

import hashlib
import json
import logging
from pathlib import Path

import config
import yara

log = logging.getLogger("yara_scanner")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


import db_pool  # noqa: E402  (import tardif intentionnel — db_pool initialisé après config)


def _pg_conn():
    return db_pool.pooled_conn()


class YARAScanner:
    def __init__(self, rules_dir: str | None = None):
        self.rules_dir = rules_dir or config.YARA_RULES_DIR
        self.rules = self._compile_rules()

    def _compile_rules(self) -> yara.Rules | None:
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
                result.append(
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "meta": dict(m.meta),
                        "strings": [
                            {"offset": s.instances[0].offset, "identifier": s.identifier}
                            for s in m.strings
                        ]
                        if m.strings
                        else [],
                    }
                )
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
                        (sha256, json.dumps(yara_matches)),
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
                "sha256": sha256,
                "matches": matches,
                "matched": len(matches) > 0,
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

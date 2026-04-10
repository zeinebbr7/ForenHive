"""
ForenHive -- Scanner YARA
Analyse les fichiers malveillants captures par Dionaea
en les comparant aux regles YARA definies dans yara_rules/.

Les regles detectent : ransomware, RAT, botnet, backdoor, cryptomineur...
Les resultats sont sauvegardes dans la table file_analysis (PostgreSQL).
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

import psycopg2
import yara

import config

log = logging.getLogger("yara_scanner")


def calculer_sha256(chemin_fichier: str) -> str:
    """Calcule l'empreinte SHA-256 d'un fichier (par blocs pour les gros fichiers)."""
    hasher = hashlib.sha256()
    with open(chemin_fichier, "rb") as f:
        for bloc in iter(lambda: f.read(65536), b""):
            hasher.update(bloc)
    return hasher.hexdigest()


def connexion_postgres():
    """Ouvre une connexion a PostgreSQL."""
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


class YARAScanner:
    """
    Compile les regles YARA et scanne les binaires captures par Dionaea.

    Regles disponibles dans yara_rules/ :
      - ransomware.yar     : WannaCry, LockBit
      - rat.yar            : AsyncRAT, ...
      - mirai.yar          : Mirai botnet
      - linux_backdoor.yar : portes derobees Linux
      - crypto_miner.yar   : XMRig et autres mineurs
      - ...
    """

    def __init__(self, dossier_regles: Optional[str] = None):
        self.dossier_regles = dossier_regles or config.YARA_RULES_DIR
        self.rules_dir      = self.dossier_regles   # alias pour compatibilite
        self.rules          = self._compiler_regles()

    # ── Compilation des regles ─────────────────────────────────────────────────

    def _compiler_regles(self) -> Optional[yara.Rules]:
        """Charge et compile tous les fichiers .yar du dossier des regles."""
        fichiers = list(Path(self.dossier_regles).glob("*.yar"))
        if not fichiers:
            log.warning(f"Aucune regle YARA dans {self.dossier_regles}")
            return None

        # Dictionnaire : nom_regle -> chemin_fichier
        sources = {f.stem: str(f) for f in fichiers}

        try:
            regles = yara.compile(filepaths=sources)
            log.info(
                f"Compilation YARA : {len(fichiers)} fichiers charges "
                f"({[f.name for f in fichiers]})"
            )
            return regles
        except yara.SyntaxError as e:
            log.error(f"Erreur de syntaxe dans une regle YARA : {e}")
            return None

    # ── Scan d'un fichier ──────────────────────────────────────────────────────

    def scanner_fichier(self, chemin: str) -> list:
        """
        Scanne un fichier avec toutes les regles YARA chargees.

        Retourne une liste de correspondances :
        [{"rule": "WannaCry_Ransomware", "namespace": "ransomware", "meta": {...}}]
        """
        if not self.rules:
            return []

        try:
            correspondances = self.rules.match(chemin)
            resultats = []
            for match in correspondances:
                resultats.append({
                    "rule":      match.rule,
                    "namespace": match.namespace,
                    "meta":      dict(match.meta),
                    "strings": [
                        {
                            "offset":     s.instances[0].offset,
                            "identifier": s.identifier
                        }
                        for s in match.strings
                    ] if match.strings else [],
                })
            return resultats
        except Exception as e:
            log.warning(f"Scan YARA echoue sur {chemin} : {e}")
            return []

    # ── Sauvegarde en base ─────────────────────────────────────────────────────

    def _sauvegarder(self, sha256: str, correspondances: list):
        """Insere ou met a jour les resultats YARA dans la table file_analysis."""
        try:
            with connexion_postgres() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO file_analysis (sha256, yara_matches, analyzed_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (sha256) DO UPDATE
                            SET yara_matches = EXCLUDED.yara_matches,
                                analyzed_at  = NOW()
                        """,
                        (sha256, json.dumps(correspondances))
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"Sauvegarde YARA echouee pour {sha256} : {e}")

    # ── Scan du dossier Dionaea ────────────────────────────────────────────────

    def scanner_binaires_dionaea(self) -> list:
        """
        Scanne tous les fichiers captures par Dionaea.
        Retourne une liste de resultats par fichier.
        """
        dossier = Path(config.DIONAEA_BINARIES_PATH)
        if not dossier.exists():
            log.warning(f"Dossier Dionaea introuvable : {dossier}")
            return []

        fichiers = [f for f in dossier.iterdir() if f.is_file()]
        log.info(f"Scan YARA de {len(fichiers)} fichiers Dionaea ...")

        resultats = []
        for fichier in fichiers:
            sha256        = calculer_sha256(str(fichier))
            correspondances = self.scanner_fichier(str(fichier))

            entree = {
                "filepath": str(fichier),
                "sha256":   sha256,
                "matches":  correspondances,
                "matched":  len(correspondances) > 0,
            }
            resultats.append(entree)

            # Toujours sauvegarder en base (meme si 0 correspondances = fichier propre)
            self._sauvegarder(sha256, correspondances)

            if correspondances:
                noms_regles = [m["rule"] for m in correspondances]
                log.info(f"DETECTION [{fichier.name}] SHA256={sha256[:16]}... -> {noms_regles}")
            else:
                log.debug(f"Propre [{fichier.name}] SHA256={sha256[:16]}...")

        nb_detectes = sum(1 for r in resultats if r["matched"])
        log.info(f"Scan YARA termine : {nb_detectes}/{len(fichiers)} fichiers detectes")
        return resultats

    # ── Alias (compatibilite avec l'ancien code) ───────────────────────────────
    def scan_file(self, chemin: str) -> list:
        return self.scanner_fichier(chemin)

    def scan_dionaea_downloads(self) -> list:
        return self.scanner_binaires_dionaea()

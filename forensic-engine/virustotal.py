"""
ForenHive -- VirusTotal SHA-256 Lookup
Analyse les fichiers malveillants captures par Dionaea ou Cowrie
en soumettant leur empreinte SHA-256 a l'API VirusTotal v3.
Les resultats sont sauvegardes dans la table file_analysis (PostgreSQL).
"""

import json
import logging
import os
import time
from typing import Optional

import psycopg2
import requests

import config

log = logging.getLogger("virustotal")

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"


def connexion_postgres():
    """Ouvre une connexion a PostgreSQL."""
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


class VirusTotalScanner:
    """
    Envoie des hashes SHA-256 a VirusTotal et recupere les resultats d'analyse.

    Gestion automatique :
    - Cache en base (evite de re-soumettre un hash deja analyse)
    - Rate limiting (free tier : 4 req/sec, 500 req/jour)
    - Retry automatique sur erreur 429 (3 tentatives max)
    """

    def __init__(self):
        self._dernier_appel  = 0.0    # timestamp du dernier appel API
        self._reseau_mort    = False  # True si le reseau est inaccessible

    # ── Respect du rate limit ──────────────────────────────────────────────────

    def _attendre_rate_limit(self):
        """Attend si necessaire pour respecter la limite de 4 req/sec."""
        temps_ecoule = time.time() - self._dernier_appel
        if temps_ecoule < config.VIRUSTOTAL_RATE_LIMIT_SEC:
            time.sleep(config.VIRUSTOTAL_RATE_LIMIT_SEC - temps_ecoule)
        self._dernier_appel = time.time()

    # ── Verification du cache ──────────────────────────────────────────────────

    def _deja_analyse(self, sha256: str) -> bool:
        """
        Retourne True si ce hash a deja ete analyse et sauvegarde en base.
        Evite d'appeler l'API pour un fichier qu'on connait deja.
        """
        try:
            with connexion_postgres() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM file_analysis "
                        "WHERE sha256 = %s AND virustotal_result IS NOT NULL",
                        (sha256,)
                    )
                    return cur.fetchone() is not None
        except Exception:
            return False

    # ── Appel API VirusTotal ───────────────────────────────────────────────────

    def analyser_hash(self, sha256: str, tentative: int = 0) -> Optional[dict]:
        """
        Interroge VirusTotal pour un hash SHA-256.

        Retourne un dictionnaire avec les resultats, ou None si :
        - Pas de cle API configuree
        - Hash inconnu de VT (fichier tres recent ou rare)
        - Reseau inaccessible
        """
        # Verifications preliminaires
        if not config.VIRUSTOTAL_KEY:
            log.warning("VIRUSTOTAL_KEY non configuree -- analyse ignoree")
            return None

        if self._reseau_mort:
            log.debug(f"Reseau VT indisponible -- {sha256[:16]}... ignore")
            return None

        if self._deja_analyse(sha256):
            log.info(f"VT cache hit -- {sha256[:16]}... (deja analyse)")
            return None

        # Respecter le rate limit
        self._attendre_rate_limit()

        # Appel API
        try:
            reponse = requests.get(
                f"{VIRUSTOTAL_URL}/files/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_KEY},
                timeout=15
            )
        except Exception as e:
            erreur = str(e)
            # Si le reseau est completement inaccessible, on arrete tous les appels
            if any(mot in erreur for mot in ("NameResolutionError", "Failed to resolve",
                                             "ConnectionError", "Network is unreachable")):
                log.warning(f"Reseau VT inaccessible ({erreur[:80]}) -- desactivation VT")
                self._reseau_mort = True
            else:
                log.warning(f"Appel VT echoue pour {sha256} : {e}")
            return None

        # Hash inconnu de VirusTotal
        if reponse.status_code == 404:
            log.info(f"VT: hash inconnu -- {sha256[:16]}... (malware tres recent ?)")
            return None

        # Rate limit depasse -- on attend et on reessaie (3 tentatives max)
        if reponse.status_code == 429:
            if tentative >= 2:
                log.warning(f"Rate limit VT persiste apres {tentative + 1} tentatives -- abandon")
                return None
            attente = 60 * (2 ** tentative)  # 60s, 120s
            log.warning(f"Rate limit VT -- attente {attente}s (tentative {tentative + 1}/3)")
            time.sleep(attente)
            return self.analyser_hash(sha256, tentative=tentative + 1)

        if reponse.status_code != 200:
            log.warning(f"VT a retourne {reponse.status_code} pour {sha256[:16]}...")
            return None

        # Extraire les statistiques de detection
        data          = reponse.json().get("data", {}).get("attributes", {})
        stats         = data.get("last_analysis_stats", {})
        nb_malveillant = stats.get("malicious",  0)
        nb_suspect     = stats.get("suspicious", 0)
        nb_propre      = stats.get("undetected", 0)
        nb_total       = nb_malveillant + nb_suspect + nb_propre + stats.get("harmless", 0)

        # Famille de malware (si VT la connait)
        famille = ""
        classification = data.get("popular_threat_classification", {})
        if classification:
            label   = classification.get("suggested_threat_label", "")
            famille = label.split(".")[0] if label else ""

        resultat = {
            "sha256":           sha256,
            "detection_ratio":  f"{nb_malveillant}/{nb_total}" if nb_total else "0/0",
            "malicious":        nb_malveillant,
            "suspicious":       nb_suspect,
            "undetected":       nb_propre,
            "family":           famille,
            "tags":             data.get("tags",  []),
            "first_seen":       data.get("first_submission_date", ""),
            "last_seen":        data.get("last_analysis_date",    ""),
            "names":            data.get("names", [])[:5],
        }

        log.info(
            f"VT [{sha256[:16]}...] "
            f"{nb_malveillant}/{nb_total} detections, famille={famille or 'inconnue'}"
        )

        # Sauvegarder en base PostgreSQL
        self._sauvegarder(sha256, resultat)
        return resultat

    # ── Sauvegarde en base ─────────────────────────────────────────────────────

    def _sauvegarder(self, sha256: str, resultat: dict):
        """Insere ou met a jour le resultat VT dans la table file_analysis."""
        try:
            with connexion_postgres() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO file_analysis (sha256, virustotal_result, analyzed_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (sha256) DO UPDATE
                            SET virustotal_result = EXCLUDED.virustotal_result,
                                analyzed_at       = NOW()
                        """,
                        (sha256, json.dumps(resultat))
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"Sauvegarde VT echouee pour {sha256} : {e}")

    # ── Analyse par lot ────────────────────────────────────────────────────────

    def analyser_lot(self, liste_sha256: list) -> dict:
        """
        Analyse une liste de hashes SHA-256.
        Retourne un dictionnaire {sha256: resultat_ou_None}.
        """
        resultats  = {}
        uniques    = list(set(liste_sha256))
        log.info(f"VT analyse par lot : {len(uniques)} hashes")
        for sha256 in uniques:
            resultats[sha256] = self.analyser_hash(sha256)
        return resultats

    # ── Alias (compatibilite avec l'ancien code) ───────────────────────────────
    def lookup_hash(self, sha256: str, _retries: int = 0) -> Optional[dict]:
        return self.analyser_hash(sha256, tentative=_retries)

    def lookup_batch(self, liste: list) -> dict:
        return self.analyser_lot(liste)

    def _is_cached(self, sha256: str) -> bool:
        return self._deja_analyse(sha256)

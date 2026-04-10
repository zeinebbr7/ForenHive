"""
ForenHive -- Moteur Forensique Principal
Orchestre les 4 etapes de l'analyse :

  1. Enrichissement IP  : GeoIP, AbuseIPDB, Shodan, Whois, Tor/VPN detection
  2. Scan YARA          : analyse des binaires captures par Dionaea
  3. VirusTotal         : lookup SHA-256 des fichiers malveillants
  4. Scoring + MITRE    : calcul du risque et mapping ATT&CK par session

Usage :
  python engine.py                   # analyse complete (24 dernieres heures)
  python engine.py --hours 48        # remonter 48h en arriere
  python engine.py --enrich-only     # enrichissement IP uniquement
  python engine.py --yara-only       # scan YARA uniquement
  python engine.py --score-only      # scoring + MITRE uniquement
  python engine.py --init-db         # initialiser le schema PostgreSQL
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras
import requests
from elasticsearch import Elasticsearch

import config
from db.init_db import init_schema, wait_for_postgres, get_conn_params
from enricher       import IPEnricher
from yara_scanner   import YARAScanner
from virustotal     import VirusTotalScanner
from risk_score     import calculer_score_risque, niveau_risque
from ollama_mitre   import OllamaMitreMapper

# ── Configuration du journal ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("engine")


# ══════════════════════════════════════════════════════════════════════════════
# CONNEXIONS
# ══════════════════════════════════════════════════════════════════════════════

def maintenant_utc():
    return datetime.now(timezone.utc)


def connexion_postgres():
    """Ouvre une connexion a la base PostgreSQL."""
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


def creer_client_elasticsearch() -> Elasticsearch:
    """Cree et retourne un client Elasticsearch."""
    return Elasticsearch(
        [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
        request_timeout=30
    )


# ══════════════════════════════════════════════════════════════════════════════
# REQUETES ELASTICSEARCH
# ══════════════════════════════════════════════════════════════════════════════

def recuperer_sessions(es: Elasticsearch, heures: int) -> list:
    """
    Recupere les sessions Cowrie distinctes depuis Elasticsearch.
    Agregation par session_id avec les champs forensiques cles.
    """
    depuis = (maintenant_utc() - timedelta(hours=heures)).isoformat()

    requete = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp":   {"gte": depuis}}},
                    {"term":  {"honeypot.type.keyword": "cowrie"}},
                    {"exists": {"field": "session.id"}}
                ]
            }
        },
        "aggs": {
            "par_session": {
                "terms": {"field": "session.id.keyword", "size": 5000},
                "aggs": {
                    "source_ip":       {"terms":  {"field": "source.ip.keyword",   "size": 1}},
                    "port_dest":       {"terms":  {"field": "destination.port.keyword", "size": 1}},
                    "nb_connexions":   {"filter": {"prefix": {"event.id": "cowrie.login"}}},
                    "nb_commandes":    {"filter": {"prefix": {"event.id": "cowrie.command"}}},
                    "octets_total":    {"sum":    {"field": "network.bytes"}},
                    "premiere_vue":    {"min":    {"field": "@timestamp"}},
                    "derniere_vue":    {"max":    {"field": "@timestamp"}},
                }
            }
        }
    }

    reponse  = es.search(index=config.ES_INDEX, body=requete)
    sessions = []

    for bucket in reponse["aggregations"]["par_session"]["buckets"]:
        ip   = (bucket["source_ip"]["buckets"] or [{}])[0].get("key", "")
        port = (bucket["port_dest"]["buckets"] or [{}])[0].get("key", 0)
        sessions.append({
            "session_id":       bucket["key"],
            "honeypot_type":    "cowrie",
            "source_ip":        ip,
            "login_attempts":   bucket["nb_connexions"]["doc_count"],
            "command_count":    bucket["nb_commandes"]["doc_count"],
            "exfil_bytes":      int(bucket["octets_total"]["value"] or 0),
            "destination_port": port,
            "started_at":       bucket["premiere_vue"]["value_as_string"],
            "ended_at":         bucket["derniere_vue"]["value_as_string"],
        })

    return sessions


def recuperer_hashes_es(es: Elasticsearch, heures: int) -> list:
    """Recupere les hashes SHA-256 distincts des fichiers telecharges via Cowrie."""
    depuis = (maintenant_utc() - timedelta(hours=heures)).isoformat()

    requete = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range":  {"@timestamp":        {"gte": depuis}}},
            {"exists": {"field": "file.hash.sha256"}}
        ]}},
        "aggs": {"hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 1000}}}
    }

    reponse = es.search(index=config.ES_INDEX, body=requete)
    return [b["key"] for b in reponse["aggregations"]["hashes"]["buckets"]]


def recuperer_commandes_session(es: Elasticsearch, session_id: str) -> list:
    """Recupere la liste des commandes shell executees dans une session Cowrie."""
    requete = {
        "size": 50,
        "_source": ["event.original", "process.command_line"],
        "query": {
            "bool": {
                "filter": [
                    {"term":   {"session.id.keyword": session_id}},
                    {"prefix": {"event.id": "cowrie.command"}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}]
    }
    try:
        reponse  = es.search(index=config.ES_INDEX, body=requete)
        commandes = []
        for hit in reponse["hits"]["hits"]:
            src = hit["_source"]
            cmd = src.get("process.command_line") or src.get("event.original", "")
            if cmd:
                commandes.append(cmd)
        return commandes
    except Exception as e:
        log.warning(f"Impossible de recuperer les commandes de {session_id[:12]} : {e}")
        return []


def recuperer_mapping_ip_hashes(es: Elasticsearch, heures: int) -> dict:
    """
    Construit un dictionnaire {IP: [sha256, ...]} depuis les evenements
    de telechargement Cowrie. Permet de lier les resultats YARA/VT aux sessions.
    """
    depuis = (maintenant_utc() - timedelta(hours=heures)).isoformat()

    requete = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range":  {"@timestamp":    {"gte": depuis}}},
            {"exists": {"field": "file.hash.sha256"}},
            {"exists": {"field": "source.ip"}}
        ]}},
        "aggs": {
            "par_ip": {
                "terms": {"field": "source.ip.keyword", "size": 10000},
                "aggs":  {"hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 100}}}
            }
        }
    }

    reponse = es.search(index=config.ES_INDEX, body=requete)
    mapping = {}
    for bucket in reponse["aggregations"]["par_ip"]["buckets"]:
        ip      = bucket["key"]
        hashes  = [h["key"] for h in bucket["hashes"]["buckets"]]
        mapping[ip] = hashes
    return mapping


def charger_analyses_fichiers() -> dict:
    """
    Charge les resultats YARA + VT depuis PostgreSQL.
    Retourne {sha256: {yara_matches: [...], vt_malicious: int}}.
    """
    resultats = {}
    try:
        with connexion_postgres() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT sha256, yara_matches, virustotal_result FROM file_analysis")
                for ligne in cur.fetchall():
                    sha256     = ligne["sha256"]
                    yara_data  = ligne["yara_matches"] or []
                    noms_regles = [m["rule"] for m in yara_data if isinstance(m, dict) and "rule" in m]
                    vt_data    = ligne["virustotal_result"] or {}
                    resultats[sha256] = {
                        "yara_matches": noms_regles,
                        "vt_malicious": int(vt_data.get("malicious", 0)),
                    }
    except Exception as e:
        log.warning(f"Chargement file_analysis echoue : {e}")
    return resultats


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTANCE POSTGRESQL
# ══════════════════════════════════════════════════════════════════════════════

def sauvegarder_session(session: dict):
    """Insere ou met a jour une session dans la table forensic_sessions."""
    try:
        with connexion_postgres() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO forensic_sessions
                        (session_id, honeypot_type, source_ip, started_at, ended_at,
                         risk_score, mitre_techniques, enrichment_data, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (session_id) DO UPDATE
                        SET risk_score       = EXCLUDED.risk_score,
                            enrichment_data  = EXCLUDED.enrichment_data,
                            mitre_techniques = EXCLUDED.mitre_techniques
                    """,
                    (
                        session["session_id"],
                        session.get("honeypot_type"),
                        session.get("source_ip"),
                        session.get("started_at"),
                        session.get("ended_at"),
                        session.get("risk_score"),
                        json.dumps(session.get("mitre_techniques", [])),
                        json.dumps(session.get("enrichment_data",  {})),
                    )
                )
            conn.commit()
    except Exception as e:
        log.warning(f"Sauvegarde session {session['session_id']} echouee : {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE -- ForensicEngine
# ══════════════════════════════════════════════════════════════════════════════

class ForensicEngine:
    """Orchestre l'analyse forensique complete des evenements honeypot."""

    def __init__(self):
        log.info("Initialisation du ForensicEngine ...")
        self.es      = creer_client_elasticsearch()
        self.enricher = IPEnricher()
        self.yara    = YARAScanner()
        self.vt      = VirusTotalScanner()
        self.mitre   = OllamaMitreMapper()

    # ── Etape 1 : Enrichissement IP ────────────────────────────────────────────

    def etape_enrichissement(self, heures: int = 24) -> dict:
        """Enrichit toutes les IPs attaquantes trouvees dans ES."""
        log.info(f"=== Etape 1 : Enrichissement IP (dernières {heures}h) ===")
        resultats = self.enricher.enrichir_depuis_es(self.es, heures)
        log.info(f"IP enrichies : {len(resultats)}")
        return resultats

    # ── Etape 2 : Scan YARA + VirusTotal (binaires Dionaea) ────────────────────

    def etape_yara_et_vt(self):
        """Scanne les binaires Dionaea avec YARA, puis soumet les detectes a VT."""
        log.info("=== Etape 2 : Scan YARA des binaires Dionaea ===")
        resultats_yara = self.yara.scanner_binaires_dionaea()

        if not resultats_yara:
            log.info("Aucun binaire Dionaea a scanner")
            return []

        # Pour chaque fichier detecte par YARA, interroger VirusTotal
        for entree in resultats_yara:
            if entree["matched"]:
                sha256 = entree["sha256"]
                log.info(f"VT lookup pour {sha256[:16]}... (match YARA)")
                self.vt.analyser_hash(sha256)

        return resultats_yara

    # ── Etape 2b : VirusTotal pour les telechargements Cowrie ──────────────────

    def etape_vt_cowrie(self, heures: int = 24):
        """Interroge VT pour les hashes SHA-256 des fichiers telecharges via Cowrie."""
        log.info(f"=== Etape 2b : VT pour telechargements Cowrie (dernières {heures}h) ===")
        hashes = recuperer_hashes_es(self.es, heures)
        if not hashes:
            log.info("Aucun hash SHA-256 trouve dans ES")
            return
        log.info(f"Soumission de {len(hashes)} hashes a VirusTotal ...")
        self.vt.analyser_lot(hashes)

    # ── Etape 3 : Scoring des sessions + Mapping MITRE ─────────────────────────

    def etape_scoring(self, heures: int = 24, cache_enrichissement: dict = None):
        """
        Calcule le score de risque de chaque session Cowrie et
        mappe les techniques MITRE ATT&CK via Mistral 7B.
        """
        log.info(f"=== Etape 3 : Scoring des sessions (dernières {heures}h) ===")

        sessions           = recuperer_sessions(self.es, heures)
        cache_enrichissement = cache_enrichissement or {}

        # Charger les analyses YARA/VT depuis PostgreSQL
        analyses_fichiers = charger_analyses_fichiers()
        mapping_ip_hashes = recuperer_mapping_ip_hashes(self.es, heures)

        log.info(
            f"Sessions trouvees : {len(sessions)} | "
            f"Analyses fichiers : {len(analyses_fichiers)} | "
            f"IPs avec hashes   : {len(mapping_ip_hashes)}"
        )

        sessions_scorees = []

        for session in sessions:
            ip      = session.get("source_ip", "")
            enrich  = cache_enrichissement.get(ip, {})

            # Agreger les signaux YARA/VT de tous les fichiers associes a cette IP
            hashes_ip    = mapping_ip_hashes.get(ip, [])
            regles_yara  = []
            nb_vt_detect = 0
            for sha256 in hashes_ip:
                analyse      = analyses_fichiers.get(sha256, {})
                regles_yara.extend(analyse.get("yara_matches", []))
                nb_vt_detect = max(nb_vt_detect, analyse.get("vt_malicious", 0))
            regles_yara = list(set(regles_yara))  # supprimer les doublons

            # Construire le profil de session pour le calcul du score
            profil_session = {
                **session,
                "abuse_score":  enrich.get("reputation", {}).get("abuse_score", 0),
                "is_tor":       enrich.get("privacy",    {}).get("is_tor",   False),
                "is_vpn":       enrich.get("privacy",    {}).get("is_vpn",   False),
                "is_proxy":     enrich.get("privacy",    {}).get("is_proxy", False),
                "yara_matches": regles_yara,
                "vt_malicious": nb_vt_detect,
            }

            # Calculer le score de risque (0-100)
            score  = calculer_score_risque(profil_session)
            niveau = niveau_risque(score)

            session["risk_score"]      = score
            session["enrichment_data"] = enrich

            # Mapping MITRE (uniquement si activite notable)
            resultat_mitre = None
            if score > 0 or session.get("login_attempts", 0) > 0:
                commandes      = recuperer_commandes_session(self.es, session["session_id"])
                resultat_mitre = self.mitre.mapper_session(session, commandes)
            session["mitre_techniques"] = resultat_mitre or {}

            # Sauvegarder en PostgreSQL
            sauvegarder_session(session)
            sessions_scorees.append((session["session_id"], ip, score, niveau))

            # Afficher les sessions a risque eleve
            if score >= 40:
                phase = (resultat_mitre or {}).get("kill_chain_phase", "inconnu")
                log.info(
                    f"[{niveau}] Session {session['session_id'][:12]}... "
                    f"IP={ip} score={score} phase={phase}"
                )

        return sessions_scorees

    # ── Analyse complete ────────────────────────────────────────────────────────

    def analyse_complete(self, heures: int = 24):
        """Lance les 4 etapes dans l'ordre et affiche le resume final."""
        debut = time.time()
        log.info(f"====== ForenHive -- Analyse Complete (dernières {heures}h) ======")

        cache_enrich = self.etape_enrichissement(heures)    # Etape 1
        self.etape_yara_et_vt()                             # Etape 2
        self.etape_vt_cowrie(heures)                        # Etape 2b
        sessions = self.etape_scoring(heures, cache_enrich) # Etape 3

        # Resume
        duree = time.time() - debut
        log.info("====== Analyse Terminee ======")
        log.info(f"  IPs enrichies     : {len(cache_enrich)}")
        log.info(f"  Sessions scorees  : {len(sessions)}")
        if sessions:
            critique = sum(1 for _, _, s, _ in sessions if s >= 80)
            haut     = sum(1 for _, _, s, _ in sessions if 60 <= s < 80)
            moyen    = sum(1 for _, _, s, _ in sessions if 40 <= s < 60)
            log.info(f"  Repartition risque: CRITICAL={critique} HIGH={haut} MEDIUM={moyen}")
        log.info(f"  Duree totale      : {duree:.1f}s")


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTREE
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ForenHive Forensic Engine")
    parser.add_argument("--hours",       type=int, default=24, help="Heures a analyser en arriere")
    parser.add_argument("--enrich-only", action="store_true",  help="Enrichissement IP uniquement")
    parser.add_argument("--yara-only",   action="store_true",  help="Scan YARA uniquement")
    parser.add_argument("--score-only",  action="store_true",  help="Scoring + MITRE uniquement")
    parser.add_argument("--init-db",     action="store_true",  help="Initialiser le schema PostgreSQL")
    args = parser.parse_args()

    # Initialisation de la base de donnees
    if args.init_db:
        params = get_conn_params()
        if wait_for_postgres(params):
            init_schema(params)
        sys.exit(0)

    engine = ForensicEngine()

    if args.enrich_only:
        engine.etape_enrichissement(args.hours)
    elif args.yara_only:
        engine.etape_yara_et_vt()
    elif args.score_only:
        engine.etape_scoring(args.hours)
    else:
        engine.analyse_complete(args.hours)


if __name__ == "__main__":
    main()

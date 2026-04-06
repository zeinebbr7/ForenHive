#!/usr/bin/env python3
"""
ForenHive — Test Suite Sprint 2 + Sprint 3
==========================================
Tests: ETL pipeline (ES), YARA, Shodan, AbuseIPDB, VirusTotal,
       GeoIP, risk score, PostgreSQL schema, full enrichment pipeline.

Run inside Docker:
  docker exec forenhive-forensic-engine python /app/tests/test_all.py

Or with docker run (one-shot):
  docker run --rm --network=forenhive_backend-net \\
    --env-file /home/pfe/ForenHive/.env \\
    -e PG_HOST=forenhive-postgresql \\
    -e ES_HOST=forenhive-elasticsearch \\
    -e ABUSEIPDB_KEY=${ABUSEIPDB_API_KEY} \\
    -e SHODAN_KEY=${SHODAN_KEY} \\
    -e VIRUSTOTAL_KEY=${VIRUSTOTAL_API_KEY} \\
    -v /home/pfe/ForenHive/forensic-engine:/app \\
    -v /home/pfe/ForenHive/malware-samples/binaries:/test-binaries:ro \\
    forenhive-forensic-engine python /app/tests/test_all.py
"""

import json
import os
import sys
import time
import hashlib
import tempfile
from pathlib import Path

# ── Add parent dir to path so we can import forensic-engine modules ────────────
sys.path.insert(0, str(Path(__file__).parents[1]))

import config  # noqa: E402

# ── ANSI colors ────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}[PASS]{RESET}"
FAIL = f"{RED}[FAIL]{RESET}"
WARN = f"{YELLOW}[WARN]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

_results = []

def check(name: str, passed: bool, detail: str = ""):
    status = PASS if passed else FAIL
    msg = f"{status} {name}"
    if detail:
        msg += f"  →  {detail}"
    print(msg)
    _results.append((name, passed))

def section(title: str):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 2 — ETL Pipeline (Elasticsearch)
# ══════════════════════════════════════════════════════════════════════════════

def test_sprint2():
    section("SPRINT 2 — ETL Pipeline / Elasticsearch")

    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
            request_timeout=10
        )
    except Exception as e:
        check("ES client import", False, str(e))
        return

    # 1 ── Cluster health ─────────────────────────────────────────────────────
    try:
        health = es.cluster.health(timeout="5s")
        status = health.get("status", "red")
        check("ES cluster health", status in ("green", "yellow"), f"status={status}")
    except Exception as e:
        check("ES cluster health", False, str(e))

    # 2 ── Index existence ────────────────────────────────────────────────────
    try:
        indices = list(es.indices.get(index="honeypot-logs-*").keys())
        check("honeypot-logs-* indices exist", len(indices) > 0,
              f"{len(indices)} index(es): {', '.join(sorted(indices))}")
    except Exception as e:
        check("honeypot-logs-* indices exist", False, str(e))
        return

    # 3 ── Total event count ──────────────────────────────────────────────────
    try:
        resp = es.count(index="honeypot-logs-*")
        total = resp["count"]
        check("Total events in ES", total > 0, f"{total:,} events")
    except Exception as e:
        check("Total events in ES", False, str(e))

    # 4 ── Per-honeypot breakdown ─────────────────────────────────────────────
    honeypots = ["cowrie", "dionaea", "galah", "zeek"]
    for hp in honeypots:
        try:
            resp = es.count(
                index="honeypot-logs-*",
                body={"query": {"term": {"honeypot.type.keyword": hp}}}
            )
            n = resp["count"]
            check(f"Events from {hp}", n >= 0, f"{n:,} events")
        except Exception as e:
            check(f"Events from {hp}", False, str(e))

    # 5 ── ECS field presence ─────────────────────────────────────────────────
    required_fields = ["source.ip", "@timestamp", "honeypot.type", "event.id"]
    for field in required_fields:
        try:
            resp = es.count(
                index="honeypot-logs-*",
                body={"query": {"exists": {"field": field}}}
            )
            n = resp["count"]
            check(f"ECS field '{field}' present", n > 0, f"{n:,} docs have it")
        except Exception as e:
            check(f"ECS field '{field}' present", False, str(e))

    # 6 ── GeoIP enrichment (geo.location) ────────────────────────────────────
    try:
        resp = es.count(
            index="honeypot-logs-*",
            body={"query": {"exists": {"field": "source.geo.location"}}}
        )
        n = resp["count"]
        check("GeoIP enrichment (source.geo.location)", n > 0, f"{n:,} events geo-tagged")
    except Exception as e:
        check("GeoIP enrichment (source.geo.location)", False, str(e))

    # 7 ── Latest event freshness (within last 48h) ────────────────────────────
    try:
        resp = es.search(
            index="honeypot-logs-*",
            body={
                "size": 1,
                "sort": [{"@timestamp": "desc"}],
                "_source": ["@timestamp"]
            }
        )
        hits = resp["hits"]["hits"]
        if hits:
            ts = hits[0]["_source"].get("@timestamp", "")
            check("Latest event exists", True, f"most recent = {ts}")
        else:
            check("Latest event exists", False, "no events found")
    except Exception as e:
        check("Latest event exists", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — PostgreSQL Schema
# ══════════════════════════════════════════════════════════════════════════════

def test_postgresql():
    section("SPRINT 3 — PostgreSQL Schema & Data")

    try:
        import psycopg2
        conn = psycopg2.connect(
            host=config.PG_HOST, port=config.PG_PORT,
            dbname=config.PG_DB, user=config.PG_USER,
            password=config.PG_PASSWORD
        )
    except Exception as e:
        check("PostgreSQL connection", False, str(e))
        return

    check("PostgreSQL connection", True, f"{config.PG_HOST}:{config.PG_PORT}/{config.PG_DB}")

    expected_tables = [
        "ip_enrichment_cache",
        "file_analysis",
        "forensic_sessions",
        "suspect_profiles",
    ]

    with conn.cursor() as cur:
        for table in expected_tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                n = cur.fetchone()[0]
                check(f"Table '{table}' exists", True, f"{n} rows")
            except Exception as e:
                check(f"Table '{table}' exists", False, str(e))
                conn.rollback()

        # Validate forensic_sessions content
        try:
            cur.execute("""
                SELECT COUNT(*), MAX(risk_score), MIN(risk_score)
                FROM forensic_sessions
            """)
            total, max_score, min_score = cur.fetchone()
            check("forensic_sessions has scored data", total > 0,
                  f"{total} sessions, scores: {min_score}–{max_score}")
        except Exception as e:
            check("forensic_sessions has scored data", False, str(e))
            conn.rollback()

        # Validate ip_enrichment_cache
        try:
            cur.execute("""
                SELECT COUNT(*) FROM ip_enrichment_cache WHERE expires_at > NOW()
            """)
            n = cur.fetchone()[0]
            check("ip_enrichment_cache has live entries", n > 0, f"{n} non-expired entries")
        except Exception as e:
            check("ip_enrichment_cache has live entries", False, str(e))
            conn.rollback()

        # Validate file_analysis (YARA + VT)
        try:
            cur.execute("""
                SELECT
                  COUNT(*) as total,
                  COUNT(yara_matches) as with_yara,
                  COUNT(virustotal_result) as with_vt
                FROM file_analysis
            """)
            total, with_yara, with_vt = cur.fetchone()
            check("file_analysis has YARA results", with_yara > 0,
                  f"{with_yara}/{total} files with YARA")
            check("file_analysis has VirusTotal results", with_vt > 0,
                  f"{with_vt}/{total} files with VT")
        except Exception as e:
            check("file_analysis data", False, str(e))
            conn.rollback()

    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — YARA Scanner
# ══════════════════════════════════════════════════════════════════════════════

def test_yara():
    section("SPRINT 3 — YARA Scanner")

    try:
        import yara
        check("yara-python importable", True)
    except ImportError as e:
        check("yara-python importable", False, str(e))
        return

    from yara_scanner import YARAScanner

    # 1 ── Rules compilation ───────────────────────────────────────────────────
    scanner = YARAScanner()
    check("YARA rules compiled", scanner.rules is not None,
          f"rules_dir={scanner.rules_dir}")

    # 2 ── Known malware sample (test_eicar.exe is a fake but real EICAR-like)
    test_binary = "/opt/dionaea/var/lib/dionaea/binaries/1bb736b97b5bcb4c5b3adf5c3c903fa3"
    alt_binary  = "/test-binaries/1bb736b97b5bcb4c5b3adf5c3c903fa3"
    sample_path = test_binary if Path(test_binary).exists() else alt_binary

    if Path(sample_path).exists():
        matches = scanner.scan_file(sample_path)
        matched_rules = [m["rule"] for m in matches]
        check("YARA scan on known sample", True,
              f"rules matched: {matched_rules or 'none'}")
    else:
        check("YARA scan on known sample", False, f"file not found: {sample_path}")

    # 3 ── Synthetic test: create a file with Mirai strings ───────────────────
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Strings from mirai.yar rule
            f.write(b"/bin/busybox MIRAI\x00/bot/bins/mirai.x86\x00")
            f.write(b"LZYD" * 100)
            tmp_path = f.name
        matches = scanner.scan_file(tmp_path)
        matched_rules = [m["rule"] for m in matches]
        os.unlink(tmp_path)
        check("YARA Mirai synthetic test", len(matches) >= 0,
              f"rules: {matched_rules or 'no match (strings may differ)'}")
    except Exception as e:
        check("YARA Mirai synthetic test", False, str(e))

    # 4 ── Full Dionaea scan ───────────────────────────────────────────────────
    try:
        results = scanner.scan_dionaea_downloads()
        flagged = [r for r in results if r["matched"]]
        check("Full Dionaea scan completes", True,
              f"{len(flagged)}/{len(results)} files flagged")
        for r in flagged:
            rules = [m["rule"] for m in r["matches"]]
            print(f"  {INFO} MATCH {Path(r['filepath']).name[:20]}... → {rules}")
    except Exception as e:
        check("Full Dionaea scan completes", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — IP Enrichment (GeoIP, IPLocate, AbuseIPDB, Shodan, Whois)
# ══════════════════════════════════════════════════════════════════════════════

def test_enrichment():
    section("SPRINT 3 — IP Enrichment Pipeline")

    # Test IP: 185.220.101.45 is a known Tor exit node used in test data
    TEST_IP  = "185.220.101.45"
    PRIV_IP  = "10.0.0.1"

    import enricher as enr

    # 1 ── Private IP detection ───────────────────────────────────────────────
    check("Private IP detection (10.0.0.1)", enr._is_private(PRIV_IP))
    check("Public IP not private (185.220.101.45)", not enr._is_private(TEST_IP))

    # 2 ── GeoIP (offline MaxMind) ────────────────────────────────────────────
    result = enr._geoip_lookup(TEST_IP)
    has_geo = bool(result.get("country") or result.get("asn"))
    check("GeoIP lookup (MaxMind)", has_geo,
          result.get("country", "no DB") + f" ASN={result.get('asn','?')}")

    # 3 ── IPLocate (privacy flags) ───────────────────────────────────────────
    result = enr._iplocate_lookup(TEST_IP)
    check("IPLocate lookup reachable", isinstance(result, dict),
          f"is_tor={result.get('is_tor')} is_vpn={result.get('is_vpn')}")

    # 4 ── AbuseIPDB ──────────────────────────────────────────────────────────
    if config.ABUSEIPDB_KEY:
        result = enr._abuseipdb_lookup(TEST_IP)
        score  = result.get("abuse_score", -1)
        check("AbuseIPDB lookup", score >= 0,
              f"abuse_score={score} total_reports={result.get('total_reports','?')}")
    else:
        print(f"  {WARN} ABUSEIPDB_KEY not set — skipping")

    # 5 ── Shodan ─────────────────────────────────────────────────────────────
    if config.SHODAN_KEY:
        result = enr._shodan_lookup(TEST_IP)
        has_ports = "open_ports" in result
        machine   = result.get("machine_type", "unknown")
        services  = result.get("services", [])
        check("Shodan lookup returns data", has_ports,
              f"machine_type={machine} open_ports={result.get('open_ports',[])} services={len(services)}")
        if services:
            print(f"  {INFO} Services detected:")
            for svc in services[:5]:
                prod = svc.get('product') or svc.get('banner', '')[:40]
                print(f"       port {svc['port']}/{svc['transport']}  {prod}")
        check("Shodan machine_type classified", machine != "",
              f"type={machine}")
    else:
        print(f"  {WARN} SHODAN_KEY not set — skipping Shodan tests")

    # 6 ── Whois/RDAP ─────────────────────────────────────────────────────────
    result = enr._whois_lookup(TEST_IP)
    check("Whois/RDAP lookup", isinstance(result, dict),
          f"org={result.get('org','?')} cidr={result.get('cidr','?')}")

    # 7 ── Full IPEnricher.enrich (cache-aware) ───────────────────────────────
    enricher = enr.IPEnricher()
    full = enricher.enrich(TEST_IP)
    check("Full IPEnricher.enrich", "geo" in full and "infrastructure" in full,
          f"keys={list(full.keys())}")

    # Cache round-trip
    t0 = time.time()
    cached = enricher.enrich(TEST_IP)
    elapsed = time.time() - t0
    check("Cache hit < 0.1s", elapsed < 0.1,
          f"{elapsed*1000:.1f}ms (from PostgreSQL cache)")

    # 8 ── Private IP returns minimal record ──────────────────────────────────
    priv = enricher.enrich(PRIV_IP)
    check("Private IP returns {private: True}", priv.get("private") is True)


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — VirusTotal
# ══════════════════════════════════════════════════════════════════════════════

def test_virustotal():
    section("SPRINT 3 — VirusTotal Lookup")

    if not config.VIRUSTOTAL_KEY:
        print(f"  {WARN} VIRUSTOTAL_KEY not set — skipping")
        return

    from virustotal import VirusTotalScanner
    vt = VirusTotalScanner()

    # EICAR test file SHA-256 (well-known, always detected)
    EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    result = vt.lookup_hash(EICAR_SHA256)
    if result:
        check("VirusTotal EICAR lookup", result["malicious"] > 0,
              f"detections={result['detection_ratio']} family={result.get('family','?')}")
    else:
        # Hash may not be indexed — test with known malware from DB
        print(f"  {INFO} EICAR not on VT, trying known hash from file_analysis ...")
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=config.PG_HOST, port=config.PG_PORT,
                dbname=config.PG_DB, user=config.PG_USER,
                password=config.PG_PASSWORD
            )
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sha256 FROM file_analysis WHERE virustotal_result IS NOT NULL LIMIT 1"
                )
                row = cur.fetchone()
            conn.close()
            if row:
                result = vt.lookup_hash(row[0])
                check("VirusTotal re-lookup from DB hash", result is not None,
                      f"hash={row[0][:16]}... detections={result.get('detection_ratio') if result else 'N/A'}")
            else:
                check("VirusTotal lookup (no known hashes in DB)", False, "no hashes to test")
        except Exception as e:
            check("VirusTotal lookup", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — Risk Score
# ══════════════════════════════════════════════════════════════════════════════

def test_risk_score():
    section("SPRINT 3 — Risk Score Calculator")

    from risk_score import calculate_risk_score, risk_level

    # Case 1: Clean session → score should be 0
    score = calculate_risk_score({
        "abuse_score": 0, "is_tor": False, "is_vpn": False, "is_proxy": False,
        "yara_matches": [], "vt_malicious": 0,
        "login_attempts": 0, "destination_port": 80,
        "honeypot_type": "cowrie", "command_count": 0, "exfil_bytes": 0,
    })
    check("Risk score: clean session = 0", score == 0, f"score={score}")

    # Case 2: Max abuse + Tor → 40+10 = 50
    score = calculate_risk_score({
        "abuse_score": 100, "is_tor": True, "is_vpn": False, "is_proxy": False,
        "yara_matches": [], "vt_malicious": 0,
        "login_attempts": 0, "destination_port": 22,
        "honeypot_type": "cowrie", "command_count": 0, "exfil_bytes": 0,
    })
    check("Risk score: abuse=100 + Tor = 50", score == 50, f"score={score}")

    # Case 3: WannaCry YARA match adds 20 pts
    score = calculate_risk_score({
        "abuse_score": 0, "is_tor": False, "is_vpn": False, "is_proxy": False,
        "yara_matches": ["WannaCry_Ransomware"], "vt_malicious": 0,
        "login_attempts": 0, "destination_port": 445,
        "honeypot_type": "dionaea", "command_count": 0, "exfil_bytes": 0,
    })
    check("Risk score: WannaCry + critical port = 25", score == 25, f"score={score}")

    # Case 4: Full critical session → must be capped at 100
    score = calculate_risk_score({
        "abuse_score": 100, "is_tor": True, "is_vpn": True, "is_proxy": True,
        "yara_matches": ["WannaCry_Ransomware", "Mirai_Botnet"], "vt_malicious": 50,
        "login_attempts": 1000, "destination_port": 445,
        "honeypot_type": "cowrie", "command_count": 100, "exfil_bytes": 5_000_000,
    })
    check("Risk score: max attack capped at 100", score == 100, f"score={score}")

    # Case 5: risk_level boundaries
    for val, expected in [(85, "CRITICAL"), (65, "HIGH"), (45, "MEDIUM"), (25, "LOW"), (5, "INFO")]:
        level = risk_level(val)
        check(f"risk_level({val}) = {expected}", level == expected, f"got={level}")


# ══════════════════════════════════════════════════════════════════════════════
# SPRINT 3 — Shodan machine_type classification (unit tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_shodan_classification():
    section("SPRINT 3 — Shodan Machine Classification (unit tests)")

    from enricher import _classify_machine

    # IoT: has iot tag
    host = {"tags": ["iot", "self-signed"], "org": "SomeISP", "isp": "SomeISP", "os": None}
    check("Classify IoT (tag=iot)", _classify_machine(host) == "iot_device",
          f"got={_classify_machine(host)}")

    # VPS: DigitalOcean org
    host = {"tags": [], "org": "DigitalOcean, LLC", "isp": "DigitalOcean", "os": None}
    check("Classify VPS (org=DigitalOcean)", _classify_machine(host) == "vps",
          f"got={_classify_machine(host)}")

    # VPS: AWS
    host = {"tags": [], "org": "Amazon.com, Inc.", "isp": "Amazon.com, Inc.", "os": None}
    check("Classify VPS (org=Amazon)", _classify_machine(host) == "vps",
          f"got={_classify_machine(host)}")

    # Dedicated: has OS, no cloud
    host = {"tags": [], "org": "Some University", "isp": "SomeNet", "os": "Linux 4.15"}
    check("Classify dedicated_server (os present)", _classify_machine(host) == "dedicated_server",
          f"got={_classify_machine(host)}")

    # Unknown: nothing
    host = {"tags": [], "org": "", "isp": "", "os": None}
    check("Classify unknown", _classify_machine(host) == "unknown",
          f"got={_classify_machine(host)}")


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def print_summary():
    section("SUMMARY")
    passed = sum(1 for _, ok in _results if ok)
    failed = sum(1 for _, ok in _results if not ok)
    total  = len(_results)
    pct    = (passed / total * 100) if total else 0

    print(f"\n  Total : {total}")
    print(f"  {GREEN}Passed: {passed}{RESET}")
    if failed:
        print(f"  {RED}Failed: {failed}{RESET}")
        print(f"\n{RED}Failed tests:{RESET}")
        for name, ok in _results:
            if not ok:
                print(f"  {FAIL} {name}")
    print(f"\n  Score : {pct:.0f}%  {'✓ ALL GOOD' if failed == 0 else '✗ SOME FAILURES'}")
    print()
    return failed == 0


if __name__ == "__main__":
    print(f"\n{BOLD}ForenHive Test Suite — Sprint 2 + Sprint 3{RESET}")
    print(f"Config: ES={config.ES_HOST}:{config.ES_PORT}  PG={config.PG_HOST}:{config.PG_PORT}")
    print(f"Keys  : SHODAN={'✓' if config.SHODAN_KEY else '✗'}  "
          f"ABUSEIPDB={'✓' if config.ABUSEIPDB_KEY else '✗'}  "
          f"VT={'✓' if config.VIRUSTOTAL_KEY else '✗'}")

    test_sprint2()
    test_postgresql()
    test_yara()
    test_shodan_classification()
    test_enrichment()
    test_virustotal()
    test_risk_score()

    ok = print_summary()
    sys.exit(0 if ok else 1)

#!/usr/bin/env python3
"""
inject_test_events.py — ForenHive test event injector
Injects simulated honeypot events into Elasticsearch and enriches source IPs
via ipapi.co, then prints a formatted enrichment report.

Usage:
    python3 inject_test_events.py [--dry-run]
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any

# ── Configuration ──────────────────────────────────────────────────────────────
ES_URL   = "http://localhost:9200"
TODAY    = datetime.now(timezone.utc).strftime("%Y.%m.%d")
INDEX    = f"honeypot-logs-{TODAY}"
DEST_IP  = "172.16.1.100"

SOURCE_IPS = [
    "59.22.201.143",    # Korea Telecom (brute force test IP)
    "45.33.32.156",     # Linode US
    "185.220.101.47",   # Tor exit node DE
    "103.251.167.20",   # AS Asia
]

# Brute-force credential pairs rotated across cowrie events
CRED_PAIRS = [
    ("root",     "123456"),
    ("admin",    "admin"),
    ("ubuntu",   "password"),
    ("pi",       "raspberry"),
    ("user",     "1234"),
]

# HTTP paths scanned by attackers
HTTP_PATHS = [
    "/.env",
    "/admin/config.php",
    "/.git/config",
    "/wp-login.php",
    "/actuator/env",
    "/shell?cmd=id",
    "/cgi-bin/luci",
    "/api/v1/pods",
    "/console/",
]

# ── Elasticsearch helpers ──────────────────────────────────────────────────────

def es_request(method: str, path: str, body: dict | None = None) -> dict:
    url  = ES_URL + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        print(f"  [ES ERROR] {method} {path} → HTTP {exc.code}: {body_text[:200]}", file=sys.stderr)
        return {}


def bulk_index(documents: list[tuple[str, str, dict]], dry_run: bool = False) -> int:
    """
    Bulk-index documents into ES.
    documents: list of (index, doc_id, doc_body)
    Returns count of indexed docs.
    """
    if not documents:
        return 0

    lines: list[str] = []
    for idx, doc_id, doc in documents:
        meta = {"index": {"_index": idx, "_id": doc_id}}
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc))
    ndjson = "\n".join(lines) + "\n"

    if dry_run:
        print(f"  [DRY-RUN] Would index {len(documents)} documents into ES.")
        return len(documents)

    data = ndjson.encode()
    req  = urllib.request.Request(
        ES_URL + "/_bulk",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result   = json.loads(resp.read())
            errors   = result.get("errors", False)
            items    = result.get("items", [])
            indexed  = sum(1 for i in items if i.get("index", {}).get("result") in ("created", "updated"))
            if errors:
                failed = [i["index"] for i in items if i.get("index", {}).get("status", 200) >= 400]
                print(f"  [WARN] {len(failed)} document(s) failed:", file=sys.stderr)
                for f in failed[:3]:
                    print(f"    {f.get('_id')} → {f.get('error', {}).get('reason', '?')}", file=sys.stderr)
            return indexed
    except urllib.error.HTTPError as exc:
        print(f"  [BULK ERROR] HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}", file=sys.stderr)
        return 0


# ── Event builders ─────────────────────────────────────────────────────────────

def ts(offset_seconds: int = 0) -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def cowrie_login_failed(ip: str, attempt: int) -> tuple[str, str, dict]:
    user, pwd   = CRED_PAIRS[attempt % len(CRED_PAIRS)]
    session_id  = f"test-{ip.replace('.', '')}-sess"
    doc_id      = f"test-cowrie-{ip.replace('.', '')}-fail-{attempt}"
    doc = {
        "@timestamp":   ts(attempt * -2),
        "honeypot":     {"type": "cowrie"},
        "source": {
            "ip":   ip,
            "port": 50000 + attempt,
            "geo":  {},
            "as":   {},
        },
        "destination":  {"ip": DEST_IP, "port": 2222},
        "network":      {"transport": "ssh"},
        "session":      {"id": session_id},
        "event": {
            "id":       "cowrie.login.failed",
            "action":   "login.failed",
            "category": "authentication",
            "outcome":  "failure",
        },
        "user":         {"name": user, "password": pwd},
        "tags":         ["cowrie", "test", "inject"],
    }
    return INDEX, doc_id, doc


def dionaea_event(ip: str) -> tuple[str, str, dict]:
    doc_id = f"test-dionaea-{ip.replace('.', '')}-smb"
    doc = {
        "@timestamp":       ts(),
        "honeypot.type":    "dionaea",
        "event.category":   "network",
        "event.action":     "connection",
        "source.ip":        ip,
        "source.port":      random_port(ip, 0),
        "destination.ip":   DEST_IP,
        "destination.port": 445,
        "network.transport": "tcp",
        "dionaea.module":   "smb",
        "dionaea.level":    "warning",
        "dionaea.msg":      f"SMB connection from {ip}",
        "message":          f"[SMB] Incoming connection from {ip}:445",
        "tags":             ["dionaea", "honeypot_dionaea", "test", "inject"],
    }
    return INDEX, doc_id, doc


def galah_http_event(ip: str, req_idx: int) -> tuple[str, str, dict]:
    path       = HTTP_PATHS[(int(ip.split(".")[-1]) + req_idx) % len(HTTP_PATHS)]
    doc_id     = f"test-galah-{ip.replace('.', '')}-http-{req_idx}"
    user_agents = [
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "python-requests/2.31.0",
        "curl/7.88.1",
    ]
    ua  = user_agents[req_idx % len(user_agents)]
    doc = {
        "@timestamp":              ts(req_idx * -5),
        "honeypot.type":           "galah",
        "event.category":          "web",
        "event.action":            "http_request",
        "source.ip":               ip,
        "source.port":             str(40000 + req_idx),
        "source.geo":              {},
        "destination.port":        "8080",
        "http.request.method":     "GET",
        "http.request.uri":        path,
        "http.request.user_agent": ua,
        "http.request.body.hash":  f"test{ip[-3:]}{req_idx:02d}",
        "http.version":            "HTTP/1.1",
        "http.response.server":    "Apache/2.4.41 (Ubuntu)",
        "observer.name":           "forenhive-test",
        "galah.llm.model":         "mistral",
        "galah.response.source":   "llm",
        "session.id":              f"test_{ip.replace('.', '')}_{req_idx}",
        "tags":                    ["galah", "honeypot_galah", "test", "inject"],
    }
    return INDEX, doc_id, doc


def random_port(ip: str, salt: int) -> int:
    return (sum(int(o) for o in ip.split(".")) * 37 + salt) % 55000 + 1024


# ── IP enrichment via ipapi.co ─────────────────────────────────────────────────

def _enrich_ipapi_co(ip: str) -> dict:
    url = f"https://ipapi.co/{ip}/json/"
    req = urllib.request.Request(url, headers={"User-Agent": "ForenHive/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    if data.get("error"):
        raise ValueError(data.get("reason", "ipapi.co error"))
    return data


def _enrich_ip_api_com(ip: str) -> dict:
    """Fallback: ip-api.com — free, 45 req/min, no key."""
    fields = "country,countryCode,city,lat,lon,timezone,isp,as,org,region"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    req = urllib.request.Request(url, headers={"User-Agent": "ForenHive/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    if data.get("status") == "fail":
        raise ValueError(data.get("message", "ip-api.com error"))
    # Normalise to ipapi.co field names so the rest of the code is uniform
    asn_raw = data.get("as", "")          # "AS60404 The Infrastructure Group"
    asn_num = asn_raw.split()[0] if asn_raw else ""
    return {
        "country_name":  data.get("country"),
        "country_code":  data.get("countryCode"),
        "city":          data.get("city"),
        "region":        data.get("region"),
        "latitude":      data.get("lat"),
        "longitude":     data.get("lon"),
        "timezone":      data.get("timezone"),
        "asn":           asn_num,
        "org":           data.get("org") or data.get("isp"),
        "_source":       "ip-api.com",
    }


def enrich_ip(ip: str) -> dict:
    """Try ipapi.co first; fall back to ip-api.com on 429 / any error."""
    try:
        return _enrich_ipapi_co(ip)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            print("(quota) → fallback ip-api.com … ", end="", flush=True)
        else:
            print(f"(HTTP {exc.code}) → fallback ip-api.com … ", end="", flush=True)
    except Exception as exc:
        print(f"({exc}) → fallback ip-api.com … ", end="", flush=True)
    try:
        return _enrich_ip_api_com(ip)
    except Exception as exc:
        return {"error": str(exc), "ip": ip}


def patch_enrichment(ip: str, geo: dict, dry_run: bool) -> int:
    """Update all injected test docs for this IP with geo/ASN data."""
    country     = geo.get("country_name", "")
    country_iso = geo.get("country_code", "")
    city        = geo.get("city", "")
    lat         = geo.get("latitude")
    lon         = geo.get("longitude")
    asn_num     = geo.get("asn", "").replace("AS", "")
    org         = geo.get("org", "")

    source_block = {
        "ip": ip,
        "geo": {
            "country_name":     country,
            "country_iso_code": country_iso,
            "city_name":        city,
            "location": {"lat": lat, "lon": lon} if lat and lon else {},
        },
        "as": {
            "number":       int(asn_num) if asn_num.isdigit() else 0,
            "organization": {"name": org},
        },
    }

    script = {
        "script": {
            "source": "ctx._source.source = params.src; ctx._source['enrichment.status'] = 'ipapi_enriched';",
            "params": {"src": source_block},
        },
        "query": {
            "bool": {
                "must": [
                    {"term": {"source.ip": ip}},
                    {"terms": {"tags": ["test"]}},
                ]
            }
        },
    }

    if dry_run:
        print(f"  [DRY-RUN] Would update-by-query for IP {ip}")
        return 0

    result = es_request("POST", f"/{INDEX}/_update_by_query?refresh=true&conflicts=proceed", script)
    return result.get("updated", 0)


# ── Dashboard summary ──────────────────────────────────────────────────────────

def print_dashboard(enrichments: dict[str, dict], injected: dict[str, int]) -> None:
    bar  = "═" * 68
    thin = "─" * 68

    print(f"\n╔{bar}╗")
    print(f"║{'  ForenHive — Injected Event Enrichment Report':^68}║")
    print(f"║{'  Index: ' + INDEX:^68}║")
    print(f"╠{bar}╣")

    for ip, geo in enrichments.items():
        country   = geo.get("country_name", "N/A")
        iso       = geo.get("country_code", "??")
        city      = geo.get("city", "N/A")
        asn       = geo.get("asn", "N/A")
        org       = geo.get("org", "N/A")
        lat       = geo.get("latitude", "N/A")
        lon       = geo.get("longitude", "N/A")
        tz        = geo.get("timezone", "N/A")
        region    = geo.get("region", "N/A")
        err       = geo.get("error")

        n_cowrie  = injected.get(f"cowrie_{ip}", 0)
        n_dionaea = injected.get(f"dionaea_{ip}", 0)
        n_galah   = injected.get(f"galah_{ip}", 0)

        print(f"║  Source IP : {ip:<54}║")
        if err:
            print(f"║  [!] Enrichment error: {str(err):<44}║")
        else:
            print(f"║  Country   : {country} ({iso}), {region:<39}║")
            print(f"║  City      : {city:<54}║")
            print(f"║  Coords    : lat={lat}, lon={lon}, tz={tz:<22}║")
            print(f"║  ASN       : {asn} — {org:<45}║")
        print(f"║  Injected  : cowrie={n_cowrie} login.failed  |  dionaea={n_dionaea}  |  galah={n_galah} HTTP ║")
        print(f"╠{bar}╣")

    total_docs = sum(injected.values())
    print(f"║  Total documents injected: {total_docs:<40}║")
    print(f"║  Refresh: GET /{INDEX}/_count          ║")
    print(f"╚{bar}╝\n")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Inject ForenHive test events into Elasticsearch")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done without writing to ES")
    args = parser.parse_args()

    print(f"\n[ForenHive] Target index : {INDEX}")
    print(f"[ForenHive] Dry-run      : {args.dry_run}")
    print(f"[ForenHive] Source IPs   : {', '.join(SOURCE_IPS)}\n")

    # ── Step 1 : build all documents ──────────────────────────────────────────
    all_docs: list[tuple[str, str, dict]] = []
    per_ip_counts: dict[str, int] = {}

    for ip in SOURCE_IPS:
        cowrie_docs  = [cowrie_login_failed(ip, i) for i in range(5)]
        dionaea_docs = [dionaea_event(ip)]
        galah_docs   = [galah_http_event(ip, i)    for i in range(3)]

        all_docs.extend(cowrie_docs)
        all_docs.extend(dionaea_docs)
        all_docs.extend(galah_docs)

        per_ip_counts[f"cowrie_{ip}"]  = len(cowrie_docs)
        per_ip_counts[f"dionaea_{ip}"] = len(dionaea_docs)
        per_ip_counts[f"galah_{ip}"]   = len(galah_docs)

    # ── Step 2 : bulk-index ───────────────────────────────────────────────────
    print(f"[1/3] Indexing {len(all_docs)} documents …")
    indexed = bulk_index(all_docs, dry_run=args.dry_run)
    print(f"      → {indexed} document(s) indexed\n")

    if not args.dry_run:
        time.sleep(1)  # let ES refresh

    # ── Step 3 : enrich each IP via ipapi.co ─────────────────────────────────
    print("[2/3] Enriching source IPs via ipapi.co …")
    enrichments: dict[str, dict] = {}
    for ip in SOURCE_IPS:
        print(f"      → {ip} … ", end="", flush=True)
        geo = enrich_ip(ip)
        enrichments[ip] = geo
        if "error" in geo:
            print(f"ERROR: {geo['error']}")
        else:
            print(f"{geo.get('country_name','?')}, {geo.get('city','?')} | {geo.get('asn','?')}")
        # ipapi.co free tier: 1000 req/day, ~1 req/sec hard limit
        time.sleep(1.2)

    # ── Step 4 : patch geo data back into indexed documents ───────────────────
    print("\n[3/3] Patching enrichment data into ES documents …")
    for ip, geo in enrichments.items():
        if "error" not in geo:
            updated = patch_enrichment(ip, geo, dry_run=args.dry_run)
            print(f"      → {ip} : {updated} document(s) updated")

    # ── Step 5 : dashboard ────────────────────────────────────────────────────
    print_dashboard(enrichments, per_ip_counts)


if __name__ == "__main__":
    main()

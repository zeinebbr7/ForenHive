#!/usr/bin/env python3
"""
smb_analyzer.py — ForenHive Forensic Engine
============================================
Rôle    : extraction et corrélation des preuves SMB/NTLM (attaques Windows).
Entrée  : Dionaea SQLite (/opt/dionaea/var/lib/dionaea/dionaea.sqlite)
          + Zeek NTLM logs (/usr/local/zeek/logs/**/ntlm*.log.gz).
Sortie  : 1 "suspect profile" par IP source + index ES `forenhive-smb-analysis`.
Appelé  : par `engine.py` (phase analyse SMB) ; aussi en CLI standalone.
Deps    : `enricher.IPEnricher` (GeoIP + AbuseIPDB + Shodan), Elasticsearch.

═══════════════════════════════════════════════════════════════════════════════
ANALYSEUR SMB — DÉTECTION D'ATTAQUES RÉSEAU WINDOWS
═══════════════════════════════════════════════════════════════════════════════
SOURCES DE DONNÉES CROISÉES :
  1. Dionaea SQLite : connexions, tentatives d'exploitation, payloads
     capturés. Tables : `connections` + `downloads`.
  2. Zeek NTLM logs : authentifications Windows (NTLM v1/v2) capturées
     par l'IDS réseau. Champs clés : `auth_success`, `user`, `domain`.

DÉTECTIONS CLÉS (contribution au risk score) :
  • EternalBlue (CVE-2017-0144) : exploit SMBv1, signature réseau
    spécifique. Vecteur ransomware WannaCry/NotPetya. → +40 pts CRITIQUE
  • Énumération SMB : scan de partages, sessions null, reconnaissance. → +30
  • EPMapper : énumération des services via port 135 (MS-RPC).        → +15

USAGE CLI :
    python smb_analyzer.py [--days N] [--no-enrich] [--no-es]
═══════════════════════════════════════════════════════════════════════════════
"""

import argparse
import gzip
import json
import logging
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import config
from elasticsearch import Elasticsearch
from enricher import IPEnricher

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("smb_analyzer")


def _ts_to_iso(epoch: float) -> str:
    """Convert Unix timestamp to tz-aware ISO 8601 UTC string."""
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


# ── Constants ──────────────────────────────────────────────────────────────────

DIONAEA_DB = os.environ.get("DIONAEA_DB", "/opt/dionaea/var/lib/dionaea/dionaea.sqlite")
ZEEK_LOGS = os.environ.get("ZEEK_LOGS_DIR", "/usr/local/zeek/logs")
ES_INDEX = "forenhive-smb-analysis"

# UUID → service name (covers all UUIDs in the Dionaea registry)
DCERPC_UUID_MAP = {
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC",
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": "DCOM",
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC",
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL",
    "12345778-1234-abcd-ef00-0123456789ab": "LSARPC",
    "12345778-1234-abcd-ef00-0123456789ac": "SAMR",
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC",
    "6bffd098-a112-3610-9833-012892020162": "browser",
    "82273fdc-e32a-18c3-3f78-827929dc23ea": "eventlog",
    "338cd001-2244-31f1-aaaa-900038001003": "winreg",
    "12345678-1234-abcd-ef00-0123456789ab": "netlogon",
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "epmp",
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "IOXIDResolver",
}

# SRVSVC opnum → (name, CVE/MS advisory)
SRVSVC_OPS = {
    14: ("NetShareAdd", ""),
    15: ("NetShareEnum", ""),
    16: ("NetrShareGetInfo", ""),
    21: ("NetServerGetInfo", ""),
    28: ("NetrRemoteTOD", ""),
    31: ("NetPathCanonicalize", "MS08-067"),
    32: ("NetPathCompare", "MS08-067"),
    34: ("NetNameCanonicalize", ""),
}

# ── Step 1 — Dionaea SQLite extraction ─────────────────────────────────────────


def extract_dionaea(db_path: str) -> dict:
    """
    Returns a dict keyed by source IP, each value being:
      connections     list of {connection_id, ts, remote_port}
      dcerpc_binds    list of {uuid, service, transfersyntax, ts}
      dcerpc_requests list of {uuid, service, opnum, op_name, advisory, ts}
      downloads       list of {md5, ts}
      epmapper_count  int
    """
    if not Path(db_path).exists():
        log.error(f"Dionaea DB not found: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Load full DCE/RPC service registry from Dionaea itself
    uuid_to_service = dict(DCERPC_UUID_MAP)
    cur.execute("SELECT dcerpcservice_uuid, dcerpcservice_name FROM dcerpcservices")
    for r in cur.fetchall():
        uuid_to_service[r["dcerpcservice_uuid"].lower()] = r["dcerpcservice_name"]

    # Load opnum registry
    cur.execute("""SELECT ds.dcerpcservice_uuid, so.dcerpcserviceop_opnum,
                          so.dcerpcserviceop_name, so.dcerpcserviceop_vuln
                   FROM dcerpcserviceops so
                   JOIN dcerpcservices ds ON so.dcerpcservice = ds.dcerpcservice""")
    opnum_registry = {}  # (uuid, opnum) → (name, vuln)
    for r in cur.fetchall():
        opnum_registry[(r[0].lower(), r[1])] = (r[2], r[3])

    data = defaultdict(
        lambda: {
            "connections": [],
            "dcerpc_binds": [],
            "dcerpc_requests": [],
            "downloads": [],
            "epmapper_count": 0,
        }
    )

    # SMB connections
    cur.execute("""
        SELECT connection, connection_timestamp, remote_host, remote_port
        FROM   connections
        WHERE  connection_protocol = 'smbd'
        ORDER  BY connection_timestamp
    """)
    for r in cur.fetchall():
        ip = r["remote_host"]
        data[ip]["connections"].append(
            {
                "connection_id": r["connection"],
                "ts": datetime.fromtimestamp(
                    r["connection_timestamp"], tz=UTC
                ).isoformat(),
                "remote_port": r["remote_port"],
            }
        )

    # DCE/RPC binds over SMB
    cur.execute("""
        SELECT d.connection, d.dcerpcbind_uuid, d.dcerpcbind_transfersyntax,
               c.remote_host, c.connection_timestamp
        FROM   dcerpcbinds d
        JOIN   connections c ON d.connection = c.connection
        WHERE  c.connection_protocol = 'smbd'
    """)
    seen_binds = set()
    for r in cur.fetchall():
        ip = r["remote_host"]
        uuid = r["dcerpcbind_uuid"].lower()
        key = (ip, uuid)
        if key in seen_binds:
            continue
        seen_binds.add(key)
        svc = uuid_to_service.get(uuid, uuid)
        data[ip]["dcerpc_binds"].append(
            {
                "uuid": r["dcerpcbind_uuid"],
                "service": svc,
                "transfersyntax": r["dcerpcbind_transfersyntax"],
                "ts": datetime.fromtimestamp(
                    r["connection_timestamp"], tz=UTC
                ).isoformat(),
            }
        )

    # DCE/RPC requests over SMB
    cur.execute("""
        SELECT r.connection, r.dcerpcrequest_uuid, r.dcerpcrequest_opnum,
               c.remote_host, c.connection_timestamp
        FROM   dcerpcrequests r
        JOIN   connections c ON r.connection = c.connection
        WHERE  c.connection_protocol = 'smbd'
    """)
    for r in cur.fetchall():
        ip = r["remote_host"]
        uuid = r["dcerpcrequest_uuid"].lower()
        opnum = r["dcerpcrequest_opnum"]
        svc = uuid_to_service.get(uuid, uuid)
        op_name, advisory = opnum_registry.get((uuid, opnum), (f"opnum_{opnum}", ""))
        data[ip]["dcerpc_requests"].append(
            {
                "uuid": r["dcerpcrequest_uuid"],
                "service": svc,
                "opnum": opnum,
                "op_name": op_name,
                "advisory": advisory,
                "ts": datetime.fromtimestamp(
                    r["connection_timestamp"], tz=UTC
                ).isoformat(),
            }
        )

    # File downloads via SMB
    cur.execute("""
        SELECT d.download_md5_hash, c.remote_host, c.connection_timestamp
        FROM   downloads d
        JOIN   connections c ON d.connection = c.connection
        WHERE  c.connection_protocol = 'smbd'
    """)
    for r in cur.fetchall():
        ip = r["remote_host"]
        data[ip]["downloads"].append(
            {
                "md5": r["download_md5_hash"],
                "ts": datetime.fromtimestamp(
                    r["connection_timestamp"], tz=UTC
                ).isoformat(),
            }
        )

    # Epmapper (port 135) — same attacker probing RPC endpoint mapper before SMB
    cur.execute("""
        SELECT remote_host, COUNT(*) AS cnt
        FROM   connections
        WHERE  connection_protocol = 'epmapper'
        GROUP  BY remote_host
    """)
    for r in cur.fetchall():
        ip = r["remote_host"]
        if ip in data:
            data[ip]["epmapper_count"] = r["cnt"]

    conn.close()
    log.info(
        f"Dionaea: {len(data)} unique source IPs across {sum(len(v['connections']) for v in data.values())} SMB connections"
    )
    return dict(data)


# ── Step 2 — Zeek NTLM log parsing ────────────────────────────────────────────


def extract_zeek_ntlm(logs_dir: str, target_ips: set) -> dict:
    """
    Walks all ntlm*.log.gz (and ntlm.log) under logs_dir.
    Returns per-IP dict:
      usernames  set → list
      hostnames  set → list
      domains    set → list
      attempts   int
      records    list of raw dicts
    """
    ntlm = defaultdict(
        lambda: {
            "usernames": set(),
            "hostnames": set(),
            "domains": set(),
            "attempts": 0,
            "records": [],
        }
    )

    logs_path = Path(logs_dir)
    if not logs_path.exists():
        log.warning(f"Zeek logs dir not found: {logs_dir} — skipping NTLM correlation")
        return {}

    # Collect all ntlm log files (compressed + live)
    files = sorted(logs_path.rglob("ntlm*.log.gz")) + sorted(logs_path.rglob("ntlm.log"))
    if not files:
        log.warning("No Zeek NTLM log files found")
        return {}

    total_records = 0
    for fpath in files:
        try:
            if str(fpath).endswith(".gz"):
                fh = gzip.open(fpath, "rt", encoding="utf-8", errors="replace")
            else:
                fh = open(fpath, encoding="utf-8", errors="replace")

            with fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    src_ip = rec.get("id.orig_h", "")
                    if not src_ip:
                        continue

                    total_records += 1
                    d = ntlm[src_ip]
                    d["attempts"] += 1

                    username = rec.get("username", "")
                    hostname = rec.get("hostname", "")
                    domain = rec.get("domainname", "")

                    if username:
                        d["usernames"].add(username)
                    if hostname:
                        d["hostnames"].add(hostname)
                    if domain:
                        d["domains"].add(domain)

                    d["records"].append(
                        {
                            "ts": rec.get("ts", 0),
                            "username": username,
                            "hostname": hostname,
                            "domain": domain,
                            "src_port": rec.get("id.orig_p"),
                            "dst_ip": rec.get("id.resp_h", ""),
                        }
                    )
        except Exception as e:
            log.warning(f"Failed to parse {fpath}: {e}")

    # Convert sets to sorted lists
    for ip, d in ntlm.items():
        d["usernames"] = sorted(d["usernames"])
        d["hostnames"] = sorted(d["hostnames"])
        d["domains"] = sorted(d["domains"])

    log.info(
        f"Zeek NTLM: {total_records} records → {len(ntlm)} unique source IPs (from {len(files)} files)"
    )
    return dict(ntlm)


# ── Step 3 — Risk scoring ──────────────────────────────────────────────────────


def _compute_risk(smb: dict, ntlm: dict, enrichment: dict) -> tuple[int, list]:
    """Returns (score 0-100, threat_indicators list)."""
    score = 0
    indicators = []

    conn_count = len(smb.get("connections", []))
    reqs = smb.get("dcerpc_requests", [])
    downloads = smb.get("downloads", [])
    epmapper = smb.get("epmapper_count", 0)

    # Connection volume
    if conn_count >= 50:
        score += 15
        indicators.append(f"High SMB connection volume: {conn_count} connections")
    elif conn_count >= 10:
        score += 8

    # Share enumeration (NetShareEnum)
    share_enum = [r for r in reqs if r.get("op_name") == "NetShareEnum"]
    if share_enum:
        score += 30
        indicators.append(f"Share enumeration (SRVSVC NetShareEnum) × {len(share_enum)}")

    # EternalBlue / MS08-067 probe
    ms_vulns = [r for r in reqs if r.get("advisory")]
    if ms_vulns:
        score += 40
        vulns = list({r["advisory"] for r in ms_vulns})
        indicators.append(f"Exploit probe targeting: {', '.join(vulns)}")

    # File drops via SMB
    if downloads:
        score += 20
        hashes = list({d["md5"] for d in downloads})
        indicators.append(
            f"File transfer via SMB: {len(downloads)} transfers, {len(hashes)} unique MD5(s): {', '.join(hashes)}"
        )

    # epmapper pre-scan (Metasploit pattern: scan 135 then 445)
    if epmapper > 0:
        score += 15
        indicators.append(
            f"RPC endpoint mapper pre-scan (port 135): {epmapper} connections — typical Metasploit/Impacket pattern"
        )

    # NTLM auth attempts
    if ntlm:
        attempts = ntlm.get("attempts", 0)
        if attempts > 0:
            score += min(10, attempts * 2)
            indicators.append(
                f"NTLM authentication: {attempts} attempt(s), username(s): {ntlm.get('usernames', [])}"
            )

    # Reputation from enrichment
    rep = (enrichment or {}).get("reputation", {})
    abuse_score = rep.get("abuse_score", 0)
    if abuse_score >= 50:
        score += 20
        indicators.append(f"AbuseIPDB score: {abuse_score}/100")
    elif abuse_score > 0:
        score += 5

    # Infrastructure tags (e.g. VPN, proxy, Tor)
    privacy = (enrichment or {}).get("privacy", {})
    if privacy.get("is_tor"):
        score += 10
        indicators.append("Tor exit node")
    if privacy.get("is_vpn") or privacy.get("is_proxy"):
        score += 5
        indicators.append("VPN/proxy detected")

    # Cap at 100
    score = min(100, score)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, indicators


# ── Step 4 — Suspect profile builder ──────────────────────────────────────────


def build_profile(ip: str, smb: dict, ntlm: dict, enrichment: dict) -> dict:
    conns = smb.get("connections", [])
    reqs = smb.get("dcerpc_requests", [])
    downloads = smb.get("downloads", [])

    # Summarize DCE/RPC operations
    dcerpc_ops = []
    seen_ops = set()
    for r in reqs:
        key = (r["uuid"], r["opnum"])
        if key not in seen_ops:
            seen_ops.add(key)
            dcerpc_ops.append(
                {
                    "service": r["service"],
                    "opnum": r["opnum"],
                    "op_name": r["op_name"],
                    "advisory": r["advisory"],
                }
            )

    # Unique download hashes
    download_hashes = list({d["md5"] for d in downloads})

    # Timeline boundaries
    timestamps = [c["ts"] for c in conns]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    # Classify the source
    import ipaddress

    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = False
    classification = "internal_host" if is_private else "external_attacker"

    risk_score, risk_level, indicators = _compute_risk(smb, ntlm, enrichment)

    profile = {
        "source_ip": ip,
        "classification": classification,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "analysis_ts": datetime.now(UTC).isoformat(),
        "smb_activity": {
            "connection_count": len(conns),
            "epmapper_prescan": smb.get("epmapper_count", 0),
            "share_enumerated": any(r["op_name"] == "NetShareEnum" for r in reqs),
            "dcerpc_services_bound": list({b["service"] for b in smb.get("dcerpc_binds", [])}),
            "dcerpc_operations": dcerpc_ops,
            "file_transfers": {
                "count": len(downloads),
                "unique_md5s": download_hashes,
            },
        },
        "ntlm_auth": {
            "attempts": ntlm.get("attempts", 0) if ntlm else 0,
            "usernames": ntlm.get("usernames", []) if ntlm else [],
            "hostnames": ntlm.get("hostnames", []) if ntlm else [],
            "domains": ntlm.get("domains", []) if ntlm else [],
        },
        "enrichment": enrichment,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "indicators": indicators,
        },
    }
    return profile


# ── Step 5 — Elasticsearch indexing ───────────────────────────────────────────


def index_profiles(es: Elasticsearch, profiles: list):
    from elasticsearch.helpers import bulk

    def gen():
        for p in profiles:
            yield {
                "_index": ES_INDEX,
                "_id": p["source_ip"],
                "_source": p,
            }

    success, errors = bulk(es, gen(), raise_on_error=False)
    if errors:
        log.warning(f"ES bulk errors: {errors}")
    log.info(f"Indexed {success}/{len(profiles)} profiles → {ES_INDEX}")


# ── Step 6 — Pretty printer ────────────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",  # yellow
    "MEDIUM": "\033[94m",  # blue
    "LOW": "\033[92m",  # green
}
RESET = "\033[0m"


def print_report(profiles: list):
    print()
    print("=" * 72)
    print("  ForenHive — SMB Forensic Analysis Report")
    print(f"  Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 72)
    print(f"  Total suspect profiles: {len(profiles)}")
    print()

    # Sort by risk score descending
    for p in sorted(profiles, key=lambda x: x["risk"]["score"], reverse=True):
        ip = p["source_ip"]
        risk = p["risk"]
        smb = p["smb_activity"]
        ntlm = p["ntlm_auth"]
        enrich = p.get("enrichment") or {}
        geo = enrich.get("geo", {})
        rep = enrich.get("reputation", {})
        infra = enrich.get("infrastructure", {})
        clr = RISK_COLOR.get(risk["level"], "")

        print(f"  {clr}{'─' * 68}{RESET}")
        print(f"  {clr}  [{risk['level']:8s}  {risk['score']:3d}/100]  {ip}{RESET}")
        print(f"  {'─' * 68}")
        print(f"    Classification : {p['classification']}")
        print(f"    First seen     : {p['first_seen']}")
        print(f"    Last seen      : {p['last_seen']}")

        # Geo / reputation
        if geo:
            loc = ", ".join(filter(None, [geo.get("city"), geo.get("country")]))
            asn = f"AS{geo.get('asn')} {geo.get('org', '')}" if geo.get("asn") else ""
            print(f"    Location       : {loc or 'unknown'}")
            if asn:
                print(f"    ASN            : {asn}")
        if rep:
            print(
                f"    AbuseIPDB      : {rep.get('abuse_score', 0)}/100  ({rep.get('total_reports', 0)} reports)"
            )
        if infra.get("open_ports"):
            print(f"    Open ports     : {infra['open_ports']}")
        if infra.get("vulns"):
            print(f"    Known vulns    : {infra['vulns']}")

        # SMB summary
        print(f"    SMB connections: {smb['connection_count']}")
        if smb.get("epmapper_prescan"):
            print(f"    Epmapper scans : {smb['epmapper_prescan']} (port 135 pre-scan)")
        if smb.get("dcerpc_services_bound"):
            print(f"    DCE/RPC bound  : {', '.join(smb['dcerpc_services_bound'])}")
        if smb.get("dcerpc_operations"):
            ops = [
                f"{o['op_name']} ({o['service']})"
                + (f" ← {o['advisory']}" if o.get("advisory") else "")
                for o in smb["dcerpc_operations"]
            ]
            print(f"    Operations     : {', '.join(ops)}")
        if smb["file_transfers"]["count"]:
            print(
                f"    File transfers : {smb['file_transfers']['count']}  MD5: {', '.join(smb['file_transfers']['unique_md5s'])}"
            )

        # NTLM
        if ntlm["attempts"]:
            print(f"    NTLM attempts  : {ntlm['attempts']}")
            print(f"      Usernames    : {ntlm['usernames']}")
            print(f"      Hostnames    : {ntlm['hostnames']}")
            print(f"      Domains      : {ntlm['domains']}")

        # Threat indicators
        if risk["indicators"]:
            print("    Threat indicators:")
            for ind in risk["indicators"]:
                print(f"      • {ind}")
        print()


# ── Main ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="ForenHive SMB Forensic Analyzer")
    parser.add_argument(
        "--no-enrich", action="store_true", help="Skip IP enrichment (faster, offline)"
    )
    parser.add_argument("--no-es", action="store_true", help="Skip Elasticsearch indexing")
    parser.add_argument("--json-out", metavar="FILE", help="Write full JSON report to FILE")
    args = parser.parse_args()

    # ── 1. Extract Dionaea data ────────────────────────────────────────────────
    log.info(f"Reading Dionaea DB: {DIONAEA_DB}")
    dionaea_data = extract_dionaea(DIONAEA_DB)

    if not dionaea_data:
        log.warning("No SMB connections found in Dionaea DB")
        sys.exit(0)

    all_ips = set(dionaea_data.keys())

    # ── 2. Parse Zeek NTLM logs ───────────────────────────────────────────────
    log.info(f"Parsing Zeek NTLM logs: {ZEEK_LOGS}")
    ntlm_data = extract_zeek_ntlm(ZEEK_LOGS, all_ips)

    # ── 3. IP enrichment ──────────────────────────────────────────────────────
    enrichments = {}
    if not args.no_enrich:
        log.info(f"Enriching {len(all_ips)} IPs ...")
        enricher = IPEnricher()
        enrichments = enricher.enrich_batch(list(all_ips))
    else:
        log.info("Enrichment skipped (--no-enrich)")
        enrichments = {ip: {} for ip in all_ips}

    # ── 4. Build suspect profiles ─────────────────────────────────────────────
    profiles = []
    for ip in sorted(all_ips):
        smb_info = dionaea_data[ip]
        ntlm_info = ntlm_data.get(ip, {})
        enrich = enrichments.get(ip, {})
        profile = build_profile(ip, smb_info, ntlm_info, enrich)
        profiles.append(profile)

    # ── 5. Index to Elasticsearch ─────────────────────────────────────────────
    if not args.no_es:
        try:
            es = Elasticsearch(config.ES_URL, request_timeout=30)
            if es.ping():
                index_profiles(es, profiles)
            else:
                log.warning(f"Elasticsearch unreachable at {config.ES_URL} — skipping indexing")
        except Exception as e:
            log.warning(f"ES indexing failed: {e}")
    else:
        log.info("ES indexing skipped (--no-es)")

    # ── 6. Print report ───────────────────────────────────────────────────────
    print_report(profiles)

    # ── 7. Optional JSON dump ─────────────────────────────────────────────────
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(profiles, f, indent=2, default=str)
        log.info(f"Full JSON report written to {args.json_out}")

    # Summary stats
    critical = sum(1 for p in profiles if p["risk"]["level"] == "CRITICAL")
    high = sum(1 for p in profiles if p["risk"]["level"] == "HIGH")
    medium = sum(1 for p in profiles if p["risk"]["level"] == "MEDIUM")
    low = sum(1 for p in profiles if p["risk"]["level"] == "LOW")
    log.info(
        f"Done. Profiles: {len(profiles)} total — CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} LOW:{low}"
    )


if __name__ == "__main__":
    main()
